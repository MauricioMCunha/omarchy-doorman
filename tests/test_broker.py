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

# Broker._handle (SPEC.md §6.11) additionally requires the connecting
# peer's real /proc/<pid>/exe — resolved out-of-process by the
# identity-helper, never by the broker itself — to match a fixed,
# root-installed path. Plain client.call()/request_secret() connections are
# ordinary Python processes, not that binary, so every broker below that
# needs legitimate request creation to succeed also needs this test-only
# bypass, unless the test is specifically exercising the identity check
# itself.
TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK = "--trusted-askpass-skip-identity-check"

# A real file, used as the identity-helper's configured trusted path in
# tests that want the helper reachable but every real peer to mismatch it —
# no process's /proc/<pid>/exe ever resolves to this test file, so the
# helper always answers "no match" without needing root or a compiler.
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


# For test_fork_then_exec_on_connecting_peer_is_rejected: connects, then
# forks — the parent immediately execve()s into a stand-in "trusted" binary
# (standing in for "becomes the trusted askpass exe"), while the child
# sleeps briefly and then drives the rest of the protocol on the same,
# shared, already-connected socket. This is the exact live-tested attack
# from docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md,
# "Validated findings" item 3: SO_PEERCRED's pid is captured once at
# connect() time and never updates, so a check performed any later than
# accept()-time (before any data is read) would see this pid's post-exec
# identity, not the real one that opened the connection.
_SUBPROCESS_FORK_EXEC_ATTACK_CODE = (
    "import json, os, socket, sys, time\n"
    "socket_path, token, payload_json = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "payload = json.loads(payload_json)\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "s.connect(socket_path)\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    time.sleep(0.3)\n"
    "    payload['pid'] = os.getppid()\n"
    "    msg = {'token': token, 'type': 'request', **payload}\n"
    "    s.sendall((json.dumps(msg) + chr(10)).encode())\n"
    "    line = s.makefile('rb').readline()\n"
    "    sys.stdout.write(line.decode()); sys.stdout.flush()\n"
    "    os._exit(0)\n"
    "else:\n"
    "    os.execv('/usr/bin/true', ['/usr/bin/true'])\n"
)

# For test_fork_before_connect_on_connecting_peer_is_rejected: forks BEFORE
# calling connect() at all, so the parent's post-connect() critical path is
# execve() alone, with no fork() call in it to pay for. This is the
# "Addendum 2" (2026-11-08) attack: the original SIGSTOP mitigation ran
# inside _handle, which only starts after serve()'s main accept loop has
# already spawned a new thread for the connection — that thread-dispatch
# latency alone was enough for this faster attacker to win the race. See
# docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md,
# "Addendum 2".
_SUBPROCESS_PRECONNECT_FORK_ATTACK_CODE = (
    "import json, os, socket, sys, time\n"
    "socket_path, token, payload_json = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "payload = json.loads(payload_json)\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "pid = os.fork()\n"  # fork BEFORE connect() -- this is the point
    "if pid == 0:\n"
    "    time.sleep(0.3)\n"
    "    payload['pid'] = os.getppid()\n"
    "    msg = {'token': token, 'type': 'request', **payload}\n"
    "    s.sendall((json.dumps(msg) + chr(10)).encode())\n"
    "    line = s.makefile('rb').readline()\n"
    "    sys.stdout.write(line.decode()); sys.stdout.flush()\n"
    "    os._exit(0)\n"
    "else:\n"
    "    s.connect(socket_path)\n"
    "    os.execv('/usr/bin/true', ['/usr/bin/true'])\n"
)

# For test_scm_rights_fd_is_ignored_identity_still_checked_against_real_peer_exe:
# the broker no longer has any SCM_RIGHTS-handling code at all (Task 2's own
# point — the identity-helper query replaced it), so a peer that still tries
# the old trick — attaching an fd for some other, real, root-owned-looking
# path via SCM_RIGHTS — gets nothing special: the fd is simply never read,
# and the connecting peer's own real /proc/<pid>/exe (this Python
# interpreter) is what the identity-helper is asked about, which mismatches
# the broker's configured trusted path regardless of what was attached.
_SUBPROCESS_SEND_FOREIGN_OPATH_FD_CODE = (
    "import array, json, os, socket, sys\n"
    "socket_path, token, trusted_path, payload_json = sys.argv[1:5]\n"
    "payload = json.loads(payload_json); payload['pid'] = os.getpid()\n"
    "msg = {'token': token, 'type': 'request', **payload}\n"
    "line = (json.dumps(msg) + chr(10)).encode()\n"
    "foreign_fd = os.open(trusted_path, os.O_PATH)\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
    "    conn.connect(socket_path)\n"
    "    cmsg = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [foreign_fd]))]\n"
    "    conn.sendmsg([line], cmsg)\n"
    "    os.close(foreign_fd)\n"
    "    resp = conn.makefile('rb').readline()\n"
    "    sys.stdout.write(resp.decode()); sys.stdout.flush()\n"
)


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
        # Never started — pairs with TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK
        # below to prove the skip path never even tries to reach a helper,
        # not just that it happens to succeed because one is running. See
        # test_skip_identity_check_never_contacts_identity_helper.
        self.unstarted_identity_helper_socket = Path(self.temp.name) / "never-started-helper.sock"
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
                "--identity-helper-socket",
                str(self.unstarted_identity_helper_socket),
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

    def _start_identity_helper(self, trusted_path: str) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "helper.sock"
        process = subprocess.Popen(
            [sys.executable, "-m", "identity_helper.identity_helper",
             "--socket", str(socket_path), "--trusted-askpass-path", trusted_path],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                return socket_path
            time.sleep(0.02)
        self.fail("identity helper did not create its socket")

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
                # Irrelevant to what this test exercises (not_sudo_child);
                # without it, the identity check — now run unconditionally
                # before the sudo checks — would fail first against the
                # default, unreachable production identity-helper socket.
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
                # Irrelevant to what this test exercises (not_sudo_child);
                # without it, the identity check — now run unconditionally
                # before the sudo checks — would fail first against the
                # default, unreachable production identity-helper socket.
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

    def test_skip_identity_check_never_contacts_identity_helper(self) -> None:
        # self.process already runs with TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK
        # and an --identity-helper-socket that was never started (no helper
        # process at all) — if a request still succeeds, the broker never
        # tried to reach it.
        result = _call_as_subprocess(
            self.socket_path, self.token,
            {"type": "request", "command": "skip-check-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertTrue(result["ok"], result)

    def test_trusted_ui_call_succeeds_through_sigstop_sigcont_round_trip(self) -> None:
        # _check_peer_identity now SIGSTOPs every connecting peer before
        # querying the identity-helper, then SIGCONTs it in a finally —
        # including trusted-UI connections (approve/cancel/pending/stats),
        # which will always come back "no_match" (Quickshell/bridge.py is
        # never the askpass binary) but must still complete normally: the
        # cached outcome is only ever consulted for kind == "request" (see
        # _handle). Every other test either skips the identity check
        # entirely (TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK, which never calls
        # _check_peer_identity/SIGSTOP at all) or leaves the helper
        # unreachable, so none of them actually exercise "helper is up,
        # genuinely answers no_match, caller is still SIGSTOP'd+SIGCONT'd
        # and still gets its response" for a UI-type call. This test's own
        # connection *is* the peer that gets SIGSTOP'd+SIGCONT'd — if that
        # round trip ever failed to resume it (the exact bug the plan's
        # SIGSTOP addendum calls out — a crash between SIGSTOP and SIGCONT
        # leaves the peer stopped forever), this test would hang and time
        # out rather than merely fail an assertion.
        helper_socket = self._start_identity_helper("/usr/bin/true")
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-ui-sigstop.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
                "--identity-helper-socket", str(helper_socket),
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

        # This call's own connection is the one that gets SIGSTOP'd and
        # SIGCONT'd by the broker, synchronously, before it ever reads this
        # message — a hang here (bounded by the socket's own timeout in
        # client.call) rather than a clean response would mean the resume
        # path is broken.
        pending = call(socket_path, self.token, {"type": "pending"})
        self.assertTrue(pending["ok"], pending)
        stats = call(socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats["ok"], stats)
        # The helper was reachable at startup — this is about the helper
        # being up and genuinely answering "no_match" for this UI call, not
        # about the degraded-helper case (see
        # test_request_is_rejected_when_identity_helper_is_unreachable).
        self.assertTrue(stats["askpass_identity_available"])

    def test_request_with_mismatched_askpass_identity_is_rejected(self) -> None:
        # Issue #9558, 4th finding: not_sudo_child only validates the
        # peer's *parent* (that it's a real, escalated sudo). sudo lets the
        # caller pick SUDO_ASKPASS, so the peer itself — the process that
        # actually holds this connection and would receive the secret —
        # could still be the attacker's own script, genuinely spawned by a
        # genuine sudo. The broker now settles that by asking the
        # identity-helper whether the connecting peer's own real
        # /proc/<pid>/exe matches the trusted path; here the helper is
        # pointed at a real file that no process's exe ever resolves to, so
        # a perfectly ordinary client (no SCM_RIGHTS, no trickery at all)
        # is rejected the same way a genuinely mismatched peer would be.
        helper_socket = self._start_identity_helper(_ALWAYS_PRESENT_OTHER_PATH)
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
                "--identity-helper-socket", str(helper_socket),
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

    def test_request_is_rejected_when_helper_has_no_matching_trusted_path(self) -> None:
        # The install step (scripts/doorman-install-askpass) was never run,
        # or the installed file was removed — the identity-helper itself
        # (Task 1) always answers "no match" in that case rather than
        # erroring, so from the broker's point of view this looks exactly
        # like any other mismatched peer: untrusted_askpass_helper, not a
        # distinct "unavailable" error. (Degraded-helper-process case is
        # test_request_is_rejected_when_identity_helper_is_unreachable,
        # below — that's the one that still needs its own error code and
        # its own `stats` surfacing.)
        missing_path = f"/nonexistent/doorman-askpass-test-missing-{uuid.uuid4().hex}"
        helper_socket = self._start_identity_helper(missing_path)
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
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--identity-helper-socket", str(helper_socket),
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
            {"type": "request", "command": "unavailable-trusted-path-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "untrusted_askpass_helper"})

    def test_request_is_rejected_when_identity_helper_is_unreachable(self) -> None:
        # Degraded-state check (SPEC.md's own design item 5): the
        # identity-helper unit is stopped or never started at all — the
        # broker must refuse every request loudly (identity_helper_unreachable)
        # rather than silently falling back to accepting, and must surface
        # that through `stats` too. UI-style calls (pending/stats) are
        # unaffected: they never consult the identity-helper at all.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-helper-down.sock"
        missing_helper_socket = Path(temp.name) / "no-such-helper.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path), "--token", self.token,
                "--llm-capability", self.capability, "--timeout", "2",
                "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--identity-helper-socket", str(missing_helper_socket),
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
            {"type": "request", "command": "helper-down-attempt",
             "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "identity_helper_unreachable"})
        stats = call(socket_path, self.token, {"type": "stats"})
        self.assertFalse(stats["askpass_identity_available"])
        # UI-style calls still work while the helper is down.
        pending = call(socket_path, self.token, {"type": "pending"})
        self.assertTrue(pending["ok"])

    def test_request_with_real_trusted_askpass_identity_is_accepted(self) -> None:
        # The genuine positive path: a peer whose own real /proc/<pid>/exe
        # really does match the identity-helper's configured trusted path.
        # In production that path is the root-installed C binary; here it's
        # simply sys.executable, and the connecting peer is spawned as
        # [sys.executable, "-c", ...] (not via a shebang, which would make
        # the interpreter the exe and the script just an argument) so its
        # own exe genuinely is that same interpreter binary — no root, no
        # compiler, and no SCM_RIGHTS fd needed at all, unlike the mechanism
        # this replaced (SPEC.md §6.11).
        helper_socket = self._start_identity_helper(sys.executable)
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
                "--identity-helper-socket", str(helper_socket),
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
        created, proc = _request_and_hold(socket_path, self.token, payload)
        self.addCleanup(lambda: proc.stdout and proc.stdout.close())
        self.addCleanup(proc.wait, timeout=5)
        self.assertTrue(created.get("ok"), created)

    def test_fork_then_exec_on_connecting_peer_is_rejected(self) -> None:
        # Live-tested attack from docs/superpowers/specs/
        # 2026-11-05-askpass-identity-6th-design.md, "Validated findings"
        # item 3: the connecting process forks right after connect(), the
        # parent immediately execve()s into a stand-in trusted binary while
        # the forked child drives the rest of the protocol on the same,
        # already-connected socket. SO_PEERCRED's pid is captured once at
        # connect() time and never updates, so this would fool any identity
        # check performed after data is read from the peer. The broker's
        # own check runs at accept()-time, before any read, and sees the
        # real, pre-exec identity (this Python interpreter) — which doesn't
        # match "/usr/bin/true" regardless.
        helper_socket = self._start_identity_helper("/usr/bin/true")
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-fork-exec-attack.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--identity-helper-socket", str(helper_socket),
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

        payload = json.dumps({"command": "fork-exec-attack", "origin": "llm", "capability": self.capability})
        proc = subprocess.Popen(
            [sys.executable, "-c", _SUBPROCESS_FORK_EXEC_ATTACK_CODE,
             str(socket_path), self.token, payload],
            cwd=ROOT, stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: proc.stdout and proc.stdout.close())
        self.addCleanup(proc.wait, timeout=3)
        out = proc.stdout.readline()
        self.assertEqual(json.loads(out), {"ok": False, "error": "untrusted_askpass_helper"})

    def test_fork_before_connect_on_connecting_peer_is_rejected(self) -> None:
        # "Addendum 2" (2026-11-08, final whole-branch review): a faster
        # attacker forks BEFORE calling connect(), so their post-connect()
        # critical path is execve() alone — no fork() call left to pay for.
        # The original SIGSTOP mitigation sent SIGSTOP from inside _handle,
        # which only starts running after serve()'s main accept loop has
        # already spawned a new thread for this connection; that
        # thread-dispatch latency alone was enough for this attack to win
        # the race (confirmed live, 5/5 vulnerable). The fix moves the
        # SIGSTOP into serve()'s own main accept loop, synchronously,
        # before any thread is spawned — see
        # _stop_peer_for_identity_check and docs/superpowers/specs/
        # 2026-11-05-askpass-identity-6th-design.md, "Addendum 2".
        helper_socket = self._start_identity_helper("/usr/bin/true")
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-preconnect-fork-attack.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--identity-helper-socket", str(helper_socket),
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

        payload = json.dumps({"command": "preconnect-fork-attack", "origin": "llm", "capability": self.capability})
        proc = subprocess.Popen(
            [sys.executable, "-c", _SUBPROCESS_PRECONNECT_FORK_ATTACK_CODE,
             str(socket_path), self.token, payload],
            cwd=ROOT, stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: proc.stdout and proc.stdout.close())
        self.addCleanup(proc.wait, timeout=3)
        out = proc.stdout.readline()
        self.assertEqual(json.loads(out), {"ok": False, "error": "untrusted_askpass_helper"})

    def test_scm_rights_fd_is_ignored_identity_still_checked_against_real_peer_exe(self) -> None:
        # The broker no longer has any SCM_RIGHTS-handling code at all —
        # this is Task 2's own point. A peer that still tries the old
        # trick (attaching an fd for some other real path via SCM_RIGHTS)
        # gets nothing special from it: the fd is simply never read, and
        # the connecting peer's own real /proc/<pid>/exe (this Python
        # interpreter, not /usr/bin/true) is what's actually checked.
        helper_socket = self._start_identity_helper("/usr/bin/true")
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-opath-bypass.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--identity-helper-socket", str(helper_socket),
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

        payload = json.dumps({"command": "opath-bypass-attempt", "origin": "llm", "capability": self.capability})
        proc = subprocess.Popen(
            [sys.executable, "-c", _SUBPROCESS_SEND_FOREIGN_OPATH_FD_CODE,
             str(socket_path), self.token, "/usr/bin/true", payload],
            cwd=ROOT, stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: proc.stdout and proc.stdout.close())
        self.addCleanup(proc.wait, timeout=3)
        out = proc.stdout.readline()
        self.assertEqual(json.loads(out), {"ok": False, "error": "untrusted_askpass_helper"})

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

    def test_stats_reflects_identity_helper_becoming_available_after_startup(self) -> None:
        # self.askpass_identity_available used to be set once, at __init__
        # time, by pinging the identity-helper — if the broker started
        # before the helper's socket existed (a real possibility: the
        # helper unit is Type=simple, so After= only orders process start,
        # not socket readiness), the flag stayed stuck False for the whole
        # session even once the helper came up. Fix: _stats() now re-pings
        # live on every call. This starts a broker pointed at a helper
        # socket that doesn't exist yet, confirms stats reports False, then
        # starts the helper at that same path and confirms a later stats
        # call reports True — proving the flag isn't just the __init__-time
        # snapshot anymore.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        helper_socket_path = Path(temp.name) / "late-starting-helper.sock"
        socket_path = Path(temp.name) / "broker-late-helper.sock"
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--token", self.token,
                "--llm-capability", self.capability,
                "--timeout", "2",
                "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
                "--identity-helper-socket", str(helper_socket_path),
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

        stats_before = call(socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats_before["ok"], stats_before)
        self.assertFalse(stats_before["askpass_identity_available"])

        # Now bring the helper up at the exact path the broker was told
        # about, without restarting the broker.
        helper_process = subprocess.Popen(
            [sys.executable, "-m", "identity_helper.identity_helper",
             "--socket", str(helper_socket_path), "--trusted-askpass-path", "/usr/bin/true"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: helper_process.stderr and helper_process.stderr.close())
        self.addCleanup(lambda: helper_process.stdout and helper_process.stdout.close())
        self.addCleanup(helper_process.wait, timeout=2)
        self.addCleanup(helper_process.terminate)
        for _ in range(50):
            if helper_socket_path.exists():
                break
            time.sleep(0.02)
        else:
            self.fail("identity helper did not create its socket")

        stats_after = call(socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats_after["ok"], stats_after)
        self.assertTrue(stats_after["askpass_identity_available"])


if __name__ == "__main__":
    unittest.main()
