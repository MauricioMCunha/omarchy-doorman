from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from client import call, request_secret  # noqa: E402
from broker.broker import Broker, PendingRequest, MAX_PENDING  # noqa: E402

# approve/cancel/pending/stats now require the caller (or its near ancestry)
# to be the trusted UI process — see Broker._peer_is_trusted_ui, which reads
# /proc/<pid>/comm (not /proc/<pid>/exe: reading another same-user process's
# exe needs ptrace-equivalent permission that a systemd --user service is
# denied even with CAP_SYS_PTRACE and zero sandboxing — confirmed while
# building this; comm has no such restriction). Read this process's own
# /proc/self/comm the same way, rather than assuming it matches
# sys.executable's basename (comm reflects how the interpreter was invoked,
# e.g. "python3", not the resolved binary name like "python3.14"). Tests
# point the broker at this process's own comm instead of the real
# "quickshell" to simulate a trusted caller.
TEST_TRUSTED_UI_EXE = Path("/proc/self/comm").read_text(encoding="utf-8").strip()

# Broker._peer_is_sudo_child similarly requires a "request" message's
# connecting peer to have this process's own comm as its immediate parent
# (standing in for the real sudo), instead of the literal "sudo" it expects
# in production — same reasoning as TEST_TRUSTED_UI_EXE above, same value.
TEST_TRUSTED_SUDO_EXE = TEST_TRUSTED_UI_EXE

# _peer_is_sudo_child also requires that same parent to show a genuine
# privilege escalation (real sudo is setuid-root — see
# DEFAULT_TRUSTED_SUDO_REQUIRES_ESCALATION). The test process can't
# actually be root, so brokers that need legitimate request creation to
# succeed pass --trusted-sudo-allow-unprivileged-parent to skip that part
# of the check while still exercising everything else it does.
TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT = "--trusted-sudo-allow-unprivileged-parent"

# Broker._create_request (SPEC.md §6.11) additionally requires the
# connecting peer to hand over an fd (SCM_RIGHTS) for its own
# /proc/self/exe, fstat()-ing to a fixed, root-installed path — see
# DEFAULT_TRUSTED_ASKPASS_PATH in broker.py. Plain client.call()/
# request_secret() connections never attach one, so every broker below
# that needs legitimate request creation to succeed also needs this
# test-only bypass, unless the test is specifically exercising the identity
# check itself.
TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK = "--trusted-askpass-skip-identity-check"

# A real file, used by the *mismatch* test below purely as "a path that
# resolves fine at startup" — the request in that test never attaches an fd
# at all (ordinary client.call(), like any non-askpass caller), so it's
# rejected the same way a genuinely mismatched fd would be, without needing
# root or a compiler.
_ALWAYS_PRESENT_OTHER_PATH = str(Path(__file__).resolve())

# Calling the client directly from this test process would make the
# process's own parent (whatever launched the test runner, not something
# tests control) the "request" peer's parent — not this test process, which
# is what the brokers below are told to trust via --trusted-sudo-exe. So
# every "request" that must succeed is made from a short-lived subprocess
# instead: its parent is this test process, and the helper fills in its own
# real pid, exactly like askpass.py already does with os.getpid().
_SUBPROCESS_CALL_CODE = (
    "import json, os, sys\n"
    "from client import call\n"
    "payload = json.loads(sys.argv[3])\n"
    "if payload.get('type') == 'request': payload['pid'] = os.getpid()\n"
    "print(json.dumps(call(sys.argv[1], sys.argv[2], payload)))\n"
)
_SUBPROCESS_REQUEST_SECRET_CODE = (
    "import json, os, sys\n"
    "from client import request_secret\n"
    "payload = json.loads(sys.argv[3])\n"
    "payload['pid'] = os.getpid()\n"
    "print(json.dumps(request_secret(sys.argv[1], sys.argv[2], payload)))\n"
)


def _call_as_subprocess(socket_path: Path, token: str, payload: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_CALL_CODE, str(socket_path), token, json.dumps(payload)],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
    )
    return json.loads(proc.stdout)


def _request_secret_subprocess(socket_path: Path, token: str, payload: dict) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", _SUBPROCESS_REQUEST_SECRET_CODE, str(socket_path), token, json.dumps(payload)],
        cwd=ROOT, stdout=subprocess.PIPE, text=True,
    )


# Like _call_as_subprocess, but for a test that approves what it created:
# _approve() re-validates the claimed pid's process identity (§6.1), so that
# process has to still be alive when approval happens, not just when the
# request was created — _call_as_subprocess's subprocess has already exited
# by then. Writes the "accepted" response as soon as it arrives (so the
# caller can read request_id/nonce immediately) then keeps the connection
# — and so the process — open until a final decision arrives, writing that
# as a second line.
_SUBPROCESS_REQUEST_AND_HOLD_CODE = (
    "import json, os, socket, sys\n"
    "payload = json.loads(sys.argv[3]); payload['pid'] = os.getpid()\n"
    "msg = {'token': sys.argv[2], 'type': 'request', **payload}\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
    "    conn.connect(sys.argv[1])\n"
    "    conn.sendall((json.dumps(msg) + chr(10)).encode())\n"
    "    reader = conn.makefile('rb')\n"
    "    for _ in range(2):\n"
    "        line = reader.readline()\n"
    "        if not line: break\n"
    "        sys.stdout.write(line.decode()); sys.stdout.flush()\n"
)


def _request_and_hold(socket_path: Path, token: str, payload: dict) -> tuple[dict, subprocess.Popen]:
    proc = subprocess.Popen(
        [sys.executable, "-c", _SUBPROCESS_REQUEST_AND_HOLD_CODE, str(socket_path), token, json.dumps(payload)],
        cwd=ROOT, stdout=subprocess.PIPE, text=True,
    )
    return json.loads(proc.stdout.readline()), proc


# Like _SUBPROCESS_REQUEST_AND_HOLD_CODE, but also hands the broker an fd for
# this process's own /proc/self/exe via SCM_RIGHTS — what the real askpass
# binary does (SPEC.md §6.11) so the broker can fstat() an fd it owns instead
# of stat()-ing the peer's /proc/<pid>/exe by path (doesn't work under this
# project's own systemd hardening — see DEFAULT_TRUSTED_ASKPASS_PATH in
# broker.py). sys.executable is both the configured trusted path and this
# subprocess's own exe (spawned as [sys.executable, "-c", ...], not via a
# shebang), so the fd genuinely matches — no root, no compiler needed.
_SUBPROCESS_REQUEST_AND_HOLD_WITH_IDENTITY_CODE = (
    "import array, json, os, socket, sys\n"
    "payload = json.loads(sys.argv[3]); payload['pid'] = os.getpid()\n"
    "msg = {'token': sys.argv[2], 'type': 'request', **payload}\n"
    "line = (json.dumps(msg) + chr(10)).encode()\n"
    "exe_fd = os.open('/proc/self/exe', os.O_RDONLY)\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
    "    conn.connect(sys.argv[1])\n"
    "    cmsg = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [exe_fd]))]\n"
    "    conn.sendmsg([line], cmsg)\n"
    "    os.close(exe_fd)\n"
    "    reader = conn.makefile('rb')\n"
    "    for _ in range(2):\n"
    "        resp = reader.readline()\n"
    "        if not resp: break\n"
    "        sys.stdout.write(resp.decode()); sys.stdout.flush()\n"
)


def _request_and_hold_with_identity(
    socket_path: Path, token: str, payload: dict
) -> tuple[dict, subprocess.Popen]:
    proc = subprocess.Popen(
        [
            sys.executable, "-c", _SUBPROCESS_REQUEST_AND_HOLD_WITH_IDENTITY_CODE,
            str(socket_path), token, json.dumps(payload),
        ],
        cwd=ROOT, stdout=subprocess.PIPE, text=True,
    )
    return json.loads(proc.stdout.readline()), proc


# For test_command_metadata_is_derived_from_real_sudo_cmdline_not_caller_supplied:
# forks a child that connects to the broker (the peer), while this process
# itself stays alive as that child's real immediate parent — standing in
# for sudo, like TEST_TRUSTED_SUDO_EXE does everywhere else in this file,
# but with a distinctive, test-controlled cmdline (it's passed "marker" as
# one of its own argv entries), so the broker's /proc/<pid>/cmdline-derived
# "command" is something this test can assert on precisely.
_SUBPROCESS_SUDO_PARENT_CODE = (
    "import json, os, socket, sys\n"
    "marker, socket_path, token = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    # Via env, not argv: the payload (which deliberately carries a lying
    # "command") must NOT itself appear in this process's own /proc/<pid>/
    # cmdline, or the test below couldn't tell "derived from the real
    # parent" apart from "the lie just happened to be passed through".
    "payload_json = os.environ['DOORMAN_TEST_PAYLOAD']\n"
    "_ = marker  # only to appear in this process's own /proc/<pid>/cmdline\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    payload = json.loads(payload_json); payload['pid'] = os.getpid()\n"
    "    msg = {'token': token, 'type': 'request', **payload}\n"
    "    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
    "        conn.connect(socket_path)\n"
    "        conn.sendall((json.dumps(msg) + chr(10)).encode())\n"
    "        line = conn.makefile('rb').readline()\n"
    "        sys.stdout.write(line.decode()); sys.stdout.flush()\n"
    "    os._exit(0)\n"
    "else:\n"
    "    os.waitpid(pid, 0)\n"
)


class BrokerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.temp.name) / "broker.sock"
        self.token = "test-token-only"
        self.capability = "test-llm-capability"
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "broker.broker",
                "--socket",
                str(self.socket_path),
                "--token",
                self.token,
                "--llm-capability",
                self.capability,
                "--timeout",
                "2",
                "--trusted-ui-exe",
                TEST_TRUSTED_UI_EXE,
                "--trusted-sudo-exe",
                TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(50):
            if self.socket_path.exists():
                return
            time.sleep(0.02)
        self.fail("broker did not create the socket")

    def tearDown(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=2)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        self.temp.cleanup()

    def test_request_approve_is_single_use(self) -> None:
        created, holder = _request_and_hold(
            self.socket_path,
            self.token,
            {
                "command": "fake-command",
                "cwd": str(ROOT),
                "tty": "test-pty",
                "origin": "llm",
                "capability": self.capability,
            },
        )
        self.addCleanup(lambda: holder.stdout and holder.stdout.close())
        self.addCleanup(holder.wait, timeout=2)
        self.assertTrue(created["ok"])
        pending = call(self.socket_path, self.token, {"type": "pending"})
        # Not "fake-command": the displayed command is now derived from the
        # real sudo parent's own /proc cmdline (SPEC.md §6.12), not trusted
        # from the payload — here that "parent" is this test process
        # itself, standing in for sudo, so it reflects the test runner's own
        # argv. See test_command_metadata_is_derived_from_real_sudo_cmdline
        # for the dedicated, precise assertion on that behavior.
        self.assertTrue(pending["requests"][0]["command"])
        approved = call(
            self.socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": created["request_id"],
                "nonce": created["nonce"],
                "secret": "fake-secret",
            },
        )
        self.assertEqual(approved, {"ok": True})
        replay = call(
            self.socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": created["request_id"],
                "nonce": created["nonce"],
                "secret": "must-not-be-accepted",
            },
        )
        self.assertFalse(replay["ok"])

    def test_wrong_token_is_rejected(self) -> None:
        result = call(self.socket_path, "wrong-token", {"type": "pending"})
        self.assertEqual(result, {"ok": False, "error": "unauthorized"})

    def test_process_cmdline_change_invalidates_identity(self) -> None:
        identity = Broker._process_identity(os.getpid())
        self.assertIsNotNone(identity)
        request = PendingRequest(
            request_id="request",
            nonce="nonce",
            created_at=time.time(),
            expires_at=time.time() + 10,
            metadata={"pid": os.getpid()},
            process_start_time=identity["start_time"],
            process_cmdline="/bin/another-process",
            process_uid=identity["uid"],
        )
        with patch.object(Broker, "_process_identity", return_value=identity):
            self.assertFalse(Broker._identity_matches(request))

    def test_expired_request_is_rejected(self) -> None:
        created = _call_as_subprocess(
            self.socket_path,
            self.token,
            {
                "type": "request",
                "command": "expires",
                "origin": "llm",
                "capability": self.capability,
            },
        )
        time.sleep(2.2)
        result = call(
            self.socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": created["request_id"],
                "nonce": created["nonce"],
                "secret": "fake-secret",
            },
        )
        self.assertFalse(result["ok"])

    def test_askpass_like_request_receives_secret_after_ui_approval(self) -> None:
        askpass = _request_secret_subprocess(
            self.socket_path,
            self.token,
            {
                "command": "sudo -A test",
                "prompt": "Password: ",
                "origin": "llm",
                "capability": self.capability,
            },
        )
        self.addCleanup(lambda: askpass.stdout and askpass.stdout.close())
        self.addCleanup(askpass.wait, timeout=2)
        request = None
        for _ in range(50):
            pending = call(self.socket_path, self.token, {"type": "pending"})
            if pending["requests"]:
                request = pending["requests"][0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(request)
        approval = call(
            self.socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": request["request_id"],
                "nonce": request["nonce"],
                "secret": "fake-secret",
            },
        )
        self.assertEqual(approval, {"ok": True})
        stdout, _ = askpass.communicate(timeout=2)
        self.assertEqual(json.loads(stdout), {"ok": True, "secret": "fake-secret"})

    def test_non_llm_origin_is_rejected(self) -> None:
        result = call(
            self.socket_path,
            self.token,
            {"type": "request", "origin": "terminal", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "invalid_llm_origin"})

    def test_approve_requires_correct_nonce(self) -> None:
        created, holder = _request_and_hold(
            self.socket_path, self.token,
            {"command": "wrong-nonce",
             "origin": "llm", "capability": self.capability},
        )
        self.addCleanup(lambda: holder.stdout and holder.stdout.close())
        self.addCleanup(holder.wait, timeout=2)
        wrong = call(
            self.socket_path, self.token,
            {"type": "approve", "request_id": created["request_id"],
             "nonce": "deliberately-wrong-nonce", "secret": "must-not-leak"},
        )
        self.assertFalse(wrong["ok"])
        correct = call(
            self.socket_path, self.token,
            {"type": "approve", "request_id": created["request_id"],
             "nonce": created["nonce"], "secret": "correct-secret"},
        )
        self.assertTrue(correct["ok"])

    def test_idle_unauthenticated_connection_is_closed_after_handshake_timeout(self) -> None:
        # Regression: without a handshake timeout, a connection that never
        # sends data (not even a token) held the broker's thread forever —
        # a trivial local DoS, with no token needed, against any process of
        # the same user. The broker must close the connection on its own.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket_path))
            conn.settimeout(8.0)
            closed = conn.recv(1)
        self.assertEqual(closed, b"")
        # The broker keeps responding normally to other connections.
        stats = call(self.socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats["ok"])

    def test_cancel_requires_nonce(self) -> None:
        created = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "command": "cancellable",
             "origin": "llm", "capability": self.capability},
        )
        wrong = call(
            self.socket_path, self.token,
            {"type": "cancel", "request_id": created["request_id"], "nonce": "wrong"},
        )
        self.assertFalse(wrong["ok"])
        cancelled = call(
            self.socket_path, self.token,
            {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        )
        self.assertTrue(cancelled["ok"])

    def test_broker_rejects_requests_beyond_max_pending(self) -> None:
        accepted = []
        for i in range(MAX_PENDING):
            result = _call_as_subprocess(
                self.socket_path, self.token,
                {"type": "request", "command": f"request-{i}",
                 "origin": "llm", "capability": self.capability},
            )
            self.assertTrue(result["ok"], result)
            accepted.append(result)

        overflow = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "command": "overflow",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(overflow, {"ok": False, "error": "too_many_pending"})

        # Frees up a slot; a new request should be accepted again.
        cancelled = call(
            self.socket_path, self.token,
            {"type": "cancel", "request_id": accepted[0]["request_id"],
             "nonce": accepted[0]["nonce"]},
        )
        self.assertTrue(cancelled["ok"])
        freed = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "command": "new-slot",
             "origin": "llm", "capability": self.capability},
        )
        self.assertTrue(freed["ok"])

    def test_missing_pid_is_rejected(self) -> None:
        result = call(
            self.socket_path, self.token,
            {"type": "request", "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "invalid_pid"})

    def test_request_claiming_a_different_real_pid_is_rejected(self) -> None:
        # Security review finding: a requester holding the normal request
        # token/capability could claim any PID that happens to exist (not
        # even a real sudo process) instead of its own, get a human to
        # approve what looked like a legitimate request for it, and receive
        # the secret itself on its own connection — the response always goes
        # back over whoever is actually connected, never over the claimed
        # pid. pid 1 (init/systemd) always exists and is never this test
        # process, so this is exactly that attack. Must be rejected before
        # ever reaching process-identity lookups.
        result = call(
            self.socket_path, self.token,
            {"type": "request", "pid": 1, "command": "impersonation-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "pid_mismatch"})

    def test_request_from_non_sudo_parent_is_rejected(self) -> None:
        # Security review follow-up (issue #9558): pid_mismatch alone only
        # stops claiming someone else's pid. A requester reporting its own
        # real pid passed that check — this is the actual case the reviewer
        # flagged, since it's exactly what a compromised agent would do: no
        # spoofing needed, just connect directly instead of going through a
        # real sudo/askpass chain. This broker, unlike self.process, gets no
        # --trusted-sudo-exe override, so it requires the real "sudo" as the
        # peer's parent — which this test's subprocess, spawned directly by
        # the test process, never has, even though its own identity
        # (pid/start_time/cmdline/uid) is entirely genuine.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-no-sudo-parent.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        result = _call_as_subprocess(
            socket_path, self.token,
            {"type": "request", "command": "direct-connect-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "not_sudo_child"})

    def test_request_with_spoofed_sudo_comm_but_no_root_privilege_is_rejected(self) -> None:
        # Security review follow-up (issue #9558): comm alone is forgeable
        # — /proc/<pid>/comm is just a label any process can set for itself
        # (prctl(PR_SET_NAME), or by rewriting argv[0]) — so an agent could
        # rename itself "sudo", then have a child connect with its own real
        # pid and pass the old check without ever touching a real sudo. This
        # broker is told to trust this test process's comm as "sudo" (like
        # self.process already is, for every other test), but — unlike
        # self.process — gets no --trusted-sudo-allow-unprivileged-parent, so
        # it still requires the real default: the parent must show a genuine
        # privilege escalation, which this test process (an ordinary,
        # non-root process) cannot have without actually becoming root.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-spoofed-comm.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        result = _call_as_subprocess(
            socket_path, self.token,
            {"type": "request", "command": "spoofed-comm-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "not_sudo_child"})

    def test_askpass_helper_prints_only_approved_secret(self) -> None:
        import os

        env = os.environ.copy()
        env.update({
            "DOORMAN_SOCKET": str(self.socket_path),
            "DOORMAN_TOKEN": self.token,
            "DOORMAN_LLM_CAPABILITY": self.capability,
            "DOORMAN_COMMAND": "sudo -A id",
        })
        result: dict[str, object] = {}

        def approve() -> None:
            for _ in range(50):
                pending = call(self.socket_path, self.token, {"type": "pending"})
                if pending["requests"]:
                    item = pending["requests"][0]
                    result.update(call(
                        self.socket_path,
                        self.token,
                        {"type": "approve", "request_id": item["request_id"],
                         "nonce": item["nonce"], "secret": "fake-secret"},
                    ))
                    return
                time.sleep(0.02)

        import threading
        thread = threading.Thread(target=approve)
        thread.start()
        helper = subprocess.run(
            [sys.executable, "-m", "broker.askpass", "Password: "],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        thread.join(timeout=2)
        self.assertEqual(helper.returncode, 0)
        self.assertEqual(helper.stdout, "fake-secret\n")
        self.assertEqual(helper.stderr, "")

    def test_askpass_survives_approval_slower_than_old_five_second_timeout(self) -> None:
        # Regression: request_secret() used to inherit the handshake timeout
        # (5s) for reading the result, which only arrives once the UI
        # decides. A real human approval is commonly slower than that.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-slow.sock"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "broker.broker",
                "--socket",
                str(socket_path),
                "--token",
                self.token,
                "--llm-capability",
                self.capability,
                "--timeout",
                "20",
                "--trusted-ui-exe",
                TEST_TRUSTED_UI_EXE,
                "--trusted-sudo-exe",
                TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        askpass = _request_secret_subprocess(
            socket_path,
            self.token,
            {
                "command": "sudo -A slow-test",
                "prompt": "Password: ",
                "origin": "llm",
                "capability": self.capability,
            },
        )
        self.addCleanup(lambda: askpass.stdout and askpass.stdout.close())
        self.addCleanup(askpass.wait, timeout=2)
        request = None
        for _ in range(50):
            pending = call(socket_path, self.token, {"type": "pending"})
            if pending["requests"]:
                request = pending["requests"][0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(request)

        time.sleep(6.0)  # exceeds the client's old 5s SOCKET_TIMEOUT

        approval = call(
            socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": request["request_id"],
                "nonce": request["nonce"],
                "secret": "slow-secret",
            },
        )
        self.assertEqual(approval, {"ok": True})
        stdout, _ = askpass.communicate(timeout=2)
        self.assertEqual(json.loads(stdout), {"ok": True, "secret": "slow-secret"})

    def test_untrusted_caller_cannot_approve_cancel_pending_or_stats(self) -> None:
        # Regression: a process with a valid session token — anything
        # running as the same user, since the session files are only 0600,
        # including an agent that read them to create its own request —
        # could self-approve straight over the socket, with no UI and no
        # human. Confirmed manually before this fix. Here the broker runs
        # with the real default --trusted-ui-exe ("quickshell"), which the
        # test process is not, so approve/cancel/pending/stats must fail
        # even with the correct token; only "request" (creation, which is
        # what an agent legitimately needs to do) keeps working.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-untrusted.sock"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "broker.broker",
                "--socket",
                str(socket_path),
                "--token",
                self.token,
                "--llm-capability",
                self.capability,
                "--timeout",
                "2",
                # Deliberately no --trusted-ui-exe override: this test needs
                # the real default ("quickshell"), which the test process is
                # not, to confirm the untrusted-caller rejection below.
                # --trusted-sudo-exe is unrelated to that and still needs
                # overriding, or even the legitimate "request" creation a
                # few lines down would fail.
                "--trusted-sudo-exe",
                TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        created = _call_as_subprocess(
            socket_path, self.token,
            {"type": "request", "command": "self-approval-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertTrue(created["ok"], created)

        for message in (
            {"type": "pending"},
            {"type": "stats"},
            {"type": "approve", "request_id": created["request_id"],
             "nonce": created["nonce"], "secret": "forged-secret"},
            {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        ):
            result = call(socket_path, self.token, message)
            self.assertEqual(
                result, {"ok": False, "error": "untrusted_caller"}, message,
            )

    def test_retry_with_same_sudo_pid_is_tagged_as_new_attempt(self) -> None:
        # sudo reinvokes SUDO_ASKPASS (a new pid) under the same parent sudo
        # process when the previous attempt's password is rejected by PAM.
        # askpass forwards that parent pid as "sudo_pid"; the broker only
        # uses it to label the UI ("attempt 2"), never to know whether the
        # password was right. The previous attempt is also never read back
        # by the askpass that created it (sudo already killed that
        # process), so the broker has to end it itself when the new one
        # arrives — otherwise it would sit around until it expired, and the
        # UI could select that dead entry instead of the current attempt.
        first_askpass = _request_secret_subprocess(
            self.socket_path, self.token,
            {"sudo_pid": 999999, "command": "sudo -A id",
             "origin": "llm", "capability": self.capability},
        )
        self.addCleanup(lambda: first_askpass.stdout and first_askpass.stdout.close())
        self.addCleanup(first_askpass.wait, timeout=2)
        pending = None
        for _ in range(50):
            pending = call(self.socket_path, self.token, {"type": "pending"})
            if pending["requests"]:
                break
            time.sleep(0.02)
        self.assertTrue(pending and pending["requests"], pending)
        self.assertEqual(pending["requests"][0]["attempt"], 1)

        second = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "sudo_pid": 999999,
             "command": "sudo -A id", "origin": "llm", "capability": self.capability},
        )
        self.assertTrue(second["ok"], second)
        pending = call(self.socket_path, self.token, {"type": "pending"})
        self.assertEqual(len(pending["requests"]), 1, pending)
        self.assertEqual(pending["requests"][0]["attempt"], 2)
        self.assertEqual(pending["requests"][0]["request_id"], second["request_id"])

        first_stdout, _ = first_askpass.communicate(timeout=2)
        self.assertEqual(json.loads(first_stdout), {"ok": False, "error": "superseded_by_retry"})

        # A different sudo_pid (an unrelated command) starts fresh.
        unrelated = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "sudo_pid": 999998,
             "command": "sudo -A whoami", "origin": "llm", "capability": self.capability},
        )
        self.assertTrue(unrelated["ok"], unrelated)
        pending = call(self.socket_path, self.token, {"type": "pending"})
        by_id = {item["request_id"]: item for item in pending["requests"]}
        self.assertEqual(by_id[unrelated["request_id"]]["attempt"], 1)

        # A request without sudo_pid (a caller that doesn't send the field)
        # never enters correlation and never breaks the normal flow.
        no_sudo_pid = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request",
             "command": "sudo -A ls", "origin": "llm", "capability": self.capability},
        )
        self.assertTrue(no_sudo_pid["ok"], no_sudo_pid)
        pending = call(self.socket_path, self.token, {"type": "pending"})
        by_id = {item["request_id"]: item for item in pending["requests"]}
        self.assertEqual(by_id[no_sudo_pid["request_id"]]["attempt"], 1)

    def test_stats_reports_request_lifecycle(self) -> None:
        created = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "command": "metric",
             "origin": "llm", "capability": self.capability},
        )
        call(
            self.socket_path, self.token,
            {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        )
        stats = call(self.socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats["ok"])
        self.assertEqual(stats["requests"], 1)
        self.assertEqual(stats["cancelled"], 1)
        self.assertEqual(stats["approved"], 0)

    def test_request_with_mismatched_askpass_identity_is_rejected(self) -> None:
        # Issue #9558, 4th finding: not_sudo_child only validates the
        # peer's *parent* (that it's a real, escalated sudo). sudo lets the
        # caller pick SUDO_ASKPASS, so the peer itself — the process that
        # actually holds this connection and would receive the secret —
        # could still be the attacker's own script, genuinely spawned by a
        # genuine sudo. The broker only accepts a peer that hands it an fd
        # (SCM_RIGHTS) whose fstat() matches a fixed, root-installed path;
        # this test points that path at a real file and — like a plain
        # client that never attaches an fd at all — doesn't send one, so
        # there's nothing to match (identity_fd is None): exercising the
        # same rejection a genuinely mismatched fd would also hit, without
        # needing root or a compiler (see the next test for the
        # missing-path case, and the one after for the real positive path).
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-askpass-mismatch.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--trusted-askpass-path", _ALWAYS_PRESENT_OTHER_PATH,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        result = _call_as_subprocess(
            socket_path, self.token,
            {"type": "request", "command": "untrusted-askpass-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "untrusted_askpass_helper"})

    def test_request_is_rejected_when_askpass_path_is_missing(self) -> None:
        # The install step (scripts/doorman-install-askpass) was never run,
        # or the installed file was removed — the broker must fail loudly
        # (askpass_identity_unavailable) rather than silently fall back to
        # the pre-#9558 guarantee. Also confirms this is surfaced through
        # `stats`, so the UI can show "Doorman: setup incomplete" instead
        # of relying on someone to read the broker's own stderr.
        missing_path = f"/nonexistent/doorman-askpass-test-missing-{uuid.uuid4().hex}"
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-askpass-missing-path.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--trusted-askpass-path", missing_path,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        result = _call_as_subprocess(
            socket_path, self.token,
            {"type": "request", "command": "unavailable-path-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "askpass_identity_unavailable"})
        stats = call(socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats["ok"])
        self.assertFalse(stats["askpass_identity_available"])

    def test_request_with_real_trusted_askpass_identity_is_accepted(self) -> None:
        # The genuine positive path: a peer that hands the broker an fd
        # (SCM_RIGHTS) for its own /proc/self/exe, which really does fstat()
        # to the configured trusted path. In production that path is the
        # root-installed C binary; here it's simply sys.executable, and the
        # connecting peer is spawned as [sys.executable, "-c", ...] (not via
        # a shebang, which would make the interpreter the exe and the
        # script just an argument) so its own exe genuinely is that same
        # interpreter binary — no root, no compiler, and no setgid fixture
        # needed, unlike the gid-based check this replaced (SPEC.md §6.11).
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-askpass-real-identity.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--trusted-askpass-path", sys.executable,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        payload = {"command": "real-identity-attempt", "origin": "llm", "capability": self.capability}
        created, proc = _request_and_hold_with_identity(socket_path, self.token, payload)
        self.addCleanup(lambda: proc.stdout and proc.stdout.close())
        self.addCleanup(proc.wait, timeout=5)
        self.assertTrue(created.get("ok"), created)

    def test_command_metadata_is_derived_from_real_sudo_cmdline_not_caller_supplied(self) -> None:
        # Issue #9558: the displayed "command" must reflect what will
        # actually run, not whatever the caller puts in the request
        # payload — a caller that controls its own SUDO_ASKPASS also
        # controls that field, and could show the human a harmless-looking
        # lie while a different command actually executes. Spawns a
        # sudo-parent stand-in with a known, distinctive cmdline, has the
        # child report a deliberately different, lying "command", and
        # asserts the broker shows the real one, not the lie.
        marker = f"doorman-cmdline-marker-{uuid.uuid4().hex[:12]}"
        lying_command = "deliberately-wrong-command-should-not-be-shown"
        payload_json = json.dumps(
            {"command": lying_command, "origin": "llm", "capability": self.capability},
        )
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-cmdline.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "5",
                "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("broker did not create the socket")

        env = os.environ.copy()
        env["DOORMAN_TEST_PAYLOAD"] = payload_json
        sudo_parent = subprocess.Popen(
            [
                sys.executable, "-c", _SUBPROCESS_SUDO_PARENT_CODE,
                marker, str(socket_path), self.token,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, text=True, env=env,
        )
        self.addCleanup(lambda: sudo_parent.stdout and sudo_parent.stdout.close())
        created_line = sudo_parent.stdout.readline()
        sudo_parent.wait(timeout=5)
        created = json.loads(created_line)
        self.assertTrue(created.get("ok"), created)

        pending = call(socket_path, self.token, {"type": "pending"})
        self.assertEqual(len(pending["requests"]), 1, pending)
        shown_command = pending["requests"][0]["command"]
        self.assertIn(marker, shown_command)
        self.assertNotIn(lying_command, shown_command)


if __name__ == "__main__":
    unittest.main()
