from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from client import call, request_secret  # noqa: E402
from broker.broker import Broker, PendingRequest, MAX_PENDING  # noqa: E402

# approve/cancel/pending/stats now require the caller (or its near ancestry)
# to be the trusted UI process — see Broker._trusted_ui_peer_uid, which reads
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

# Shape B: Broker._handle admits a "request" only if the peer's effective gid
# (SO_PEERCRED) equals the trusted askpass gid. Plain client connections in
# tests are ordinary processes, so brokers that need legitimate request
# creation pass this test-only bypass, unless the test exercises the egid gate
# itself (those pass --trusted-askpass-gid instead).
TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK = "--trusted-askpass-skip-identity-check"

# The single configured login user (--owner-uid): in tests, the test runner.
TEST_OWNER_UID = os.getuid()
TEST_EGID = os.getegid()


# askpass (request) socket path -> its sibling control (UI verbs) socket path.
_CONTROL_SOCKETS: dict[Path, Path] = {}


def _ctl(socket_path: Path) -> Path:
    """The control socket of the broker whose askpass socket is socket_path."""
    return _CONTROL_SOCKETS[socket_path]


def _other_gid() -> int:
    """A gid that is not this process's egid."""
    return TEST_EGID + 1 if TEST_EGID + 1 != TEST_EGID else TEST_EGID + 2

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
    "payload = json.loads(sys.argv[2])\n"
    "if payload.get('type') == 'request': payload['pid'] = os.getpid()\n"
    "print(json.dumps(call(sys.argv[1], payload)))\n"
)
_SUBPROCESS_REQUEST_SECRET_CODE = (
    "import json, os, sys\n"
    "from client import request_secret\n"
    "payload = json.loads(sys.argv[2])\n"
    "payload['pid'] = os.getpid()\n"
    "print(json.dumps(request_secret(sys.argv[1], payload)))\n"
)


def _call_as_subprocess(socket_path: Path, payload: dict) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_CALL_CODE, str(socket_path), json.dumps(payload)],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
    )
    return json.loads(proc.stdout)


def _request_secret_subprocess(socket_path: Path, payload: dict) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", _SUBPROCESS_REQUEST_SECRET_CODE, str(socket_path), json.dumps(payload)],
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
    "payload = json.loads(sys.argv[2]); payload['pid'] = os.getpid()\n"
    "msg = {'type': 'request', **payload}\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
    "    conn.connect(sys.argv[1])\n"
    "    conn.sendall((json.dumps(msg) + chr(10)).encode())\n"
    "    reader = conn.makefile('rb')\n"
    "    for _ in range(2):\n"
    "        line = reader.readline()\n"
    "        if not line: break\n"
    "        sys.stdout.write(line.decode()); sys.stdout.flush()\n"
)


def _request_and_hold(socket_path: Path, payload: dict) -> tuple[dict, subprocess.Popen]:
    proc = subprocess.Popen(
        [sys.executable, "-c", _SUBPROCESS_REQUEST_AND_HOLD_CODE, str(socket_path), json.dumps(payload)],
        cwd=ROOT, stdout=subprocess.PIPE, text=True,
    )
    return json.loads(proc.stdout.readline()), proc


# For test_scm_rights_fd_is_ignored_…: the broker has no SCM_RIGHTS/recvmsg
# handling at all (it never reads a file descriptor from the peer — that is
# what keeps the O_PATH/fstat bypass structurally closed). A peer that still
# attaches an fd via SCM_RIGHTS gets nothing special: the fd is silently
# ignored and the request is judged purely on egid / §6.1.
_SUBPROCESS_SEND_FOREIGN_OPATH_FD_CODE = (
    "import array, json, os, socket, sys\n"
    "socket_path, trusted_path, payload_json = sys.argv[1:4]\n"
    "payload = json.loads(payload_json); payload['pid'] = os.getpid()\n"
    "msg = {'type': 'request', **payload}\n"
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
    "marker, socket_path = sys.argv[1], sys.argv[2]\n"
    # Via env, not argv: the payload (which deliberately carries a lying
    # "command") must NOT itself appear in this process's own /proc/<pid>/
    # cmdline, or the test below couldn't tell "derived from the real
    # parent" apart from "the lie just happened to be passed through".
    "payload_json = os.environ['DOORMAN_TEST_PAYLOAD']\n"
    "_ = marker  # only to appear in this process's own /proc/<pid>/cmdline\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    payload = json.loads(payload_json); payload['pid'] = os.getpid()\n"
    "    msg = {'type': 'request', **payload}\n"
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
    def _start_broker(
        self, name: str, *extra: str, timeout: str = "2", owner_uid: int = TEST_OWNER_UID,
    ) -> Path:
        """Starts a broker (cleaned up automatically) and returns its socket path."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / f"{name}.sock"
        control_path = Path(temp.name) / f"{name}-control.sock"
        _CONTROL_SOCKETS[socket_path] = control_path
        self.addCleanup(_CONTROL_SOCKETS.pop, socket_path, None)
        process = subprocess.Popen(
            [
                sys.executable, "-m", "broker.broker",
                "--socket", str(socket_path),
                "--control-socket", str(control_path),
                "--owner-uid", str(owner_uid),
                "--timeout", timeout,
                *extra,
            ],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists() and control_path.exists():
                return socket_path
            time.sleep(0.02)
        self.fail("broker did not create the socket")

    def setUp(self) -> None:
        # Most tests do not exercise the egid gate, so the default broker
        # skips it (and ALSO gets --trusted-askpass-gid so serve() can chgrp
        # the socket exactly like production). Egid-gate tests start their own.
        self.socket_path = self._start_broker(
            "broker",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
        )

    def test_request_approve_is_single_use(self) -> None:
        created, holder = _request_and_hold(
            self.socket_path,
            {
                "command": "fake-command",
                "cwd": str(ROOT),
                "tty": "test-pty",
            },
        )
        self.addCleanup(lambda: holder.stdout and holder.stdout.close())
        self.addCleanup(holder.wait, timeout=2)
        self.assertTrue(created["ok"])
        pending = call(_ctl(self.socket_path), {"type": "pending"})
        # Not "fake-command": the displayed command is now derived from the
        # real sudo parent's own /proc cmdline (SPEC.md §6.12), not trusted
        # from the payload — here that "parent" is this test process
        # itself, standing in for sudo, so it reflects the test runner's own
        # argv. See test_command_metadata_is_derived_from_real_sudo_cmdline
        # for the dedicated, precise assertion on that behavior.
        self.assertTrue(pending["requests"][0]["command"])
        approved = call(
            _ctl(self.socket_path),
            {
                "type": "approve",
                "request_id": created["request_id"],
                "nonce": created["nonce"],
                "secret": "fake-secret",
            },
        )
        self.assertEqual(approved, {"ok": True})
        replay = call(
            _ctl(self.socket_path),
            {
                "type": "approve",
                "request_id": created["request_id"],
                "nonce": created["nonce"],
                "secret": "must-not-be-accepted",
            },
        )
        self.assertFalse(replay["ok"])

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
            {
                "type": "request",
                "command": "expires",
            },
        )
        time.sleep(2.2)
        result = call(
            _ctl(self.socket_path),
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
            {
                "command": "sudo -A test",
                "prompt": "Password: ",
            },
        )
        self.addCleanup(lambda: askpass.stdout and askpass.stdout.close())
        self.addCleanup(askpass.wait, timeout=2)
        request = None
        for _ in range(50):
            pending = call(_ctl(self.socket_path), {"type": "pending"})
            if pending["requests"]:
                request = pending["requests"][0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(request)
        approval = call(
            _ctl(self.socket_path),
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

    def test_approve_requires_correct_nonce(self) -> None:
        created, holder = _request_and_hold(
            self.socket_path, {"command": "wrong-nonce"},
        )
        self.addCleanup(lambda: holder.stdout and holder.stdout.close())
        self.addCleanup(holder.wait, timeout=2)
        wrong = call(
            _ctl(self.socket_path), {"type": "approve", "request_id": created["request_id"],
              "nonce": "deliberately-wrong-nonce", "secret": "must-not-leak"},
        )
        self.assertFalse(wrong["ok"])
        correct = call(
            _ctl(self.socket_path), {"type": "approve", "request_id": created["request_id"],
              "nonce": created["nonce"], "secret": "correct-secret"},
        )
        self.assertTrue(correct["ok"])

    def test_idle_unauthenticated_connection_is_closed_after_handshake_timeout(self) -> None:
        # Regression: without a handshake timeout, a connection that never
        # sends data held the broker's thread forever —
        # a trivial local DoS, against any process of
        # the same user. The broker must close the connection on its own.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket_path))
            conn.settimeout(8.0)
            closed = conn.recv(1)
        self.assertEqual(closed, b"")
        # The broker keeps responding normally to other connections.
        stats = call(_ctl(self.socket_path), {"type": "stats"})
        self.assertTrue(stats["ok"])

    def test_cancel_requires_nonce(self) -> None:
        created = _call_as_subprocess(
            self.socket_path, {"type": "request", "command": "cancellable"},
        )
        wrong = call(
            _ctl(self.socket_path), {"type": "cancel", "request_id": created["request_id"], "nonce": "wrong"},
        )
        self.assertFalse(wrong["ok"])
        cancelled = call(
            _ctl(self.socket_path), {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        )
        self.assertTrue(cancelled["ok"])

    def test_broker_rejects_requests_beyond_max_pending(self) -> None:
        accepted = []
        for i in range(MAX_PENDING):
            result = _call_as_subprocess(
                self.socket_path,     {"type": "request", "command": f"request-{i}"},
            )
            self.assertTrue(result["ok"], result)
            accepted.append(result)

        overflow = _call_as_subprocess(
            self.socket_path, {"type": "request", "command": "overflow"},
        )
        self.assertEqual(overflow, {"ok": False, "error": "too_many_pending"})

        # Frees up a slot; a new request should be accepted again.
        cancelled = call(
            _ctl(self.socket_path), {"type": "cancel", "request_id": accepted[0]["request_id"],
              "nonce": accepted[0]["nonce"]},
        )
        self.assertTrue(cancelled["ok"])
        freed = _call_as_subprocess(
            self.socket_path, {"type": "request", "command": "new-slot"},
        )
        self.assertTrue(freed["ok"])

    def test_missing_pid_is_rejected(self) -> None:
        result = call(
            self.socket_path, {"type": "request"},
        )
        self.assertEqual(result, {"ok": False, "error": "invalid_pid"})

    def test_request_claiming_a_different_real_pid_is_rejected(self) -> None:
        # Security review finding: a requester could claim any PID that
        # happens to exist (not even a real sudo process) instead of its own, get a human to
        # approve what looked like a legitimate request for it, and receive
        # the secret itself on its own connection — the response always goes
        # back over whoever is actually connected, never over the claimed
        # pid. pid 1 (init/systemd) always exists and is never this test
        # process, so this is exactly that attack. Must be rejected before
        # ever reaching process-identity lookups.
        result = call(
            self.socket_path, {"type": "request", "pid": 1, "command": "impersonation-attempt"},
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
        socket_path = self._start_broker(
            "broker-no-sudo-parent",
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
        )

        result = _call_as_subprocess(
            socket_path, {"type": "request", "command": "direct-connect-attempt"},
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
        socket_path = self._start_broker(
            "broker-spoofed-comm",
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
        )

        result = _call_as_subprocess(
            socket_path, {"type": "request", "command": "spoofed-comm-attempt"},
        )
        self.assertEqual(result, {"ok": False, "error": "not_sudo_child"})

    def test_askpass_helper_prints_only_approved_secret(self) -> None:
        import os

        env = os.environ.copy()
        env.update({
            "DOORMAN_SOCKET": str(self.socket_path),
            "DOORMAN_COMMAND": "sudo -A id",
        })
        result: dict[str, object] = {}

        def approve() -> None:
            for _ in range(50):
                pending = call(_ctl(self.socket_path), {"type": "pending"})
                if pending["requests"]:
                    item = pending["requests"][0]
                    result.update(call(
                        _ctl(self.socket_path),
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
        socket_path = self._start_broker(
            "broker-slow",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
            timeout="20",
        )

        askpass = _request_secret_subprocess(
            socket_path,
            {
                "command": "sudo -A slow-test",
                "prompt": "Password: ",
            },
        )
        self.addCleanup(lambda: askpass.stdout and askpass.stdout.close())
        self.addCleanup(askpass.wait, timeout=2)
        request = None
        for _ in range(50):
            pending = call(_ctl(socket_path), {"type": "pending"})
            if pending["requests"]:
                request = pending["requests"][0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(request)

        time.sleep(6.0)  # exceeds the client's old 5s SOCKET_TIMEOUT

        approval = call(
            _ctl(socket_path),
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
        socket_path = self._start_broker(
            "broker-untrusted",
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
        )

        created = _call_as_subprocess(
            socket_path, {"type": "request", "command": "self-approval-attempt"},
        )
        self.assertTrue(created["ok"], created)

        for message in (
            {"type": "pending"},
            {"type": "stats"},
            {"type": "approve", "request_id": created["request_id"],
             "nonce": created["nonce"], "secret": "forged-secret"},
            {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        ):
            result = call(_ctl(socket_path), message)
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
            self.socket_path, {"sudo_pid": 999999, "command": "sudo -A id"},
        )
        self.addCleanup(lambda: first_askpass.stdout and first_askpass.stdout.close())
        self.addCleanup(first_askpass.wait, timeout=2)
        pending = None
        for _ in range(50):
            pending = call(_ctl(self.socket_path), {"type": "pending"})
            if pending["requests"]:
                break
            time.sleep(0.02)
        self.assertTrue(pending and pending["requests"], pending)
        self.assertEqual(pending["requests"][0]["attempt"], 1)

        second = _call_as_subprocess(
            self.socket_path, {"type": "request", "sudo_pid": 999999,
             "command": "sudo -A id"},
        )
        self.assertTrue(second["ok"], second)
        pending = call(_ctl(self.socket_path), {"type": "pending"})
        self.assertEqual(len(pending["requests"]), 1, pending)
        self.assertEqual(pending["requests"][0]["attempt"], 2)
        self.assertEqual(pending["requests"][0]["request_id"], second["request_id"])

        first_stdout, _ = first_askpass.communicate(timeout=2)
        self.assertEqual(json.loads(first_stdout), {"ok": False, "error": "superseded_by_retry"})

        # A different sudo_pid (an unrelated command) starts fresh.
        unrelated = _call_as_subprocess(
            self.socket_path, {"type": "request", "sudo_pid": 999998,
             "command": "sudo -A whoami"},
        )
        self.assertTrue(unrelated["ok"], unrelated)
        pending = call(_ctl(self.socket_path), {"type": "pending"})
        by_id = {item["request_id"]: item for item in pending["requests"]}
        self.assertEqual(by_id[unrelated["request_id"]]["attempt"], 1)

        # A request without sudo_pid (a caller that doesn't send the field)
        # never enters correlation and never breaks the normal flow.
        no_sudo_pid = _call_as_subprocess(
            self.socket_path, {"type": "request",
             "command": "sudo -A ls"},
        )
        self.assertTrue(no_sudo_pid["ok"], no_sudo_pid)
        pending = call(_ctl(self.socket_path), {"type": "pending"})
        by_id = {item["request_id"]: item for item in pending["requests"]}
        self.assertEqual(by_id[no_sudo_pid["request_id"]]["attempt"], 1)

    def test_stats_reports_request_lifecycle(self) -> None:
        created = _call_as_subprocess(
            self.socket_path, {"type": "request", "command": "metric"},
        )
        call(
            _ctl(self.socket_path), {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        )
        stats = call(_ctl(self.socket_path), {"type": "stats"})
        self.assertTrue(stats["ok"])
        self.assertEqual(stats["requests"], 1)
        self.assertEqual(stats["cancelled"], 1)
        self.assertEqual(stats["approved"], 0)

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
            {"command": lying_command},
        )
        socket_path = self._start_broker(
            "broker-cmdline",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
            timeout="5",
        )

        env = os.environ.copy()
        env["DOORMAN_TEST_PAYLOAD"] = payload_json
        sudo_parent = subprocess.Popen(
            [
                sys.executable, "-c", _SUBPROCESS_SUDO_PARENT_CODE,
                marker, str(socket_path),
            ],
            cwd=ROOT, stdout=subprocess.PIPE, text=True, env=env,
        )
        self.addCleanup(lambda: sudo_parent.stdout and sudo_parent.stdout.close())
        created_line = sudo_parent.stdout.readline()
        sudo_parent.wait(timeout=5)
        created = json.loads(created_line)
        self.assertTrue(created.get("ok"), created)

        pending = call(_ctl(socket_path), {"type": "pending"})
        self.assertEqual(len(pending["requests"]), 1, pending)
        shown_command = pending["requests"][0]["command"]
        self.assertIn(marker, shown_command)
        self.assertNotIn(lying_command, shown_command)

    # ---- Shape B: egid gate, owner-uid pin, installed-binary availability ----

    def test_broker_binds_both_sockets_with_owner_only_fallback_mode(self) -> None:
        # Each socket is chgrp'd to its real doorman group (doorman-askpass /
        # doorman-ui) and set 0660 so only that group can connect. Where the
        # group is absent, or the chgrp is refused because the test user is not
        # a member of it (both common unprivileged cases), the seam falls back
        # to owner-only 0600. The invariant that must hold in EVERY environment:
        # never any access for "other", and never wider than owner+group. We
        # deliberately do NOT pin 0600-vs-0660 here: that depends on which
        # doorman groups exist on the host and whether the test user belongs to
        # them, and pinning it made this test fail spuriously once the plugin
        # was installed and the groups came to exist. See SPEC.md §6.13.
        for path in (self.socket_path, _ctl(self.socket_path)):
            self.assertTrue(stat.S_ISSOCK(path.stat().st_mode), path)
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertIn(mode, (0o600, 0o660), (path, oct(mode)))
            self.assertEqual(mode & 0o007, 0, (path, oct(mode)))  # no access for "other"

    def test_request_on_control_socket_is_rejected_even_with_matching_egid(self) -> None:
        socket_path = self._start_broker(
            "request-on-control",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            "--trusted-askpass-gid", str(TEST_EGID),
        )
        # Same payload is accepted on the askpass socket (egid matches)...
        ok = _call_as_subprocess(socket_path, {"type": "request", "command": "x"})
        self.assertTrue(ok["ok"], ok)
        # ...and refused on the control socket.
        result = _call_as_subprocess(_ctl(socket_path), {"type": "request", "command": "x"})
        self.assertEqual(result, {"ok": False, "error": "wrong_socket"})
        stats = call(_ctl(socket_path), {"type": "stats"})
        self.assertEqual(stats["requests"], 1)

    def test_request_on_control_socket_is_rejected_with_skip_identity_check(self) -> None:
        result = _call_as_subprocess(
            _ctl(self.socket_path), {"type": "request", "command": "x"},
        )
        self.assertEqual(result, {"ok": False, "error": "wrong_socket"})
        self.assertEqual(call(_ctl(self.socket_path), {"type": "stats"})["requests"], 0)

    def test_ui_verbs_on_askpass_socket_are_rejected_even_from_trusted_ui(self) -> None:
        # This process is the "trusted UI" (comm matches, uid is the owner),
        # so these would pass the comm-walk on the control socket.
        created = _call_as_subprocess(
            self.socket_path, {"type": "request", "command": "wrong-socket"},
        )
        self.assertTrue(created["ok"], created)
        for message in (
            {"type": "pending"},
            {"type": "stats"},
            {"type": "approve", "request_id": created["request_id"],
             "nonce": created["nonce"], "secret": "s"},
            {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        ):
            self.assertEqual(
                call(self.socket_path, message),
                {"ok": False, "error": "wrong_socket"}, message,
            )
        # Nothing was approved/cancelled by the refused attempts.
        pending = call(_ctl(self.socket_path), {"type": "pending"})
        self.assertEqual(len(pending["requests"]), 1)
        stats = call(_ctl(self.socket_path), {"type": "stats"})
        self.assertEqual((stats["approved"], stats["cancelled"]), (0, 0))

    def test_happy_paths_each_on_their_own_socket(self) -> None:
        socket_path = self._start_broker(
            "happy",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            "--trusted-askpass-gid", str(TEST_EGID),
        )
        created = _call_as_subprocess(socket_path, {"type": "request", "command": "x"})
        self.assertTrue(created["ok"], created)
        self.assertTrue(call(_ctl(socket_path), {"type": "stats"})["ok"])
        cancelled = call(
            _ctl(socket_path),
            {"type": "cancel", "request_id": created["request_id"], "nonce": created["nonce"]},
        )
        self.assertEqual(cancelled, {"ok": True})

    def test_control_socket_does_not_apply_the_egid_gate_to_ui_verbs(self) -> None:
        # The UI never carries the askpass egid; a non-matching trusted gid
        # must not block control verbs from the trusted UI.
        socket_path = self._start_broker(
            "ctl-no-egid",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-askpass-gid", str(_other_gid()),
        )
        self.assertTrue(call(_ctl(socket_path), {"type": "stats"})["ok"])

    def test_request_is_rejected_when_peer_egid_is_not_the_trusted_gid(self) -> None:
        socket_path = self._start_broker(
            "broker-egid-mismatch",
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            "--trusted-askpass-gid", str(_other_gid()),
        )
        result = _call_as_subprocess(socket_path, {"type": "request", "command": "x"})
        self.assertEqual(result, {"ok": False, "error": "untrusted_askpass_helper"})

    def test_request_is_accepted_when_peer_egid_matches_the_trusted_gid(self) -> None:
        socket_path = self._start_broker(
            "broker-egid-match",
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            "--trusted-askpass-gid", str(TEST_EGID),
        )
        result = _call_as_subprocess(socket_path, {"type": "request", "command": "x"})
        self.assertTrue(result["ok"], result)

    def test_request_is_rejected_when_peer_uid_is_not_the_owner_uid(self) -> None:
        socket_path = self._start_broker(
            "broker-wrong-owner",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK,
            "--trusted-askpass-gid", str(TEST_EGID),
            owner_uid=TEST_OWNER_UID + 1,
        )
        result = _call_as_subprocess(socket_path, {"type": "request", "command": "x"})
        self.assertEqual(result, {"ok": False, "error": "pid_mismatch"})
        # The UI side of the pin: a trusted-looking UI peer with the wrong uid.
        self.assertEqual(
            call(_ctl(socket_path), {"type": "stats"}), {"ok": False, "error": "untrusted_caller"},
        )

    def test_peer_credentials_parses_pid_uid_gid_in_order(self) -> None:
        # Distinct values prove gid is the third field, not aliased to uid
        # (on a dev box uid == gid, which would hide an offset mistake).
        conn = SimpleNamespace(getsockopt=lambda *a, **k: struct.pack("3i", 111, 222, 333))
        self.assertEqual(Broker._peer_credentials(conn), (111, 222, 333))

    def _in_process_broker(self, **kwargs) -> Broker:
        kwargs.setdefault("trusted_askpass_skip_identity_check", True)
        # Construction logs "askpass unavailable" to stderr; keep output clean.
        with contextlib.redirect_stderr(io.StringIO()):
            return Broker(Path("/nonexistent/unused.sock"), 5.0, TEST_OWNER_UID, **kwargs)

    def _pending_request(self, owner_uid: int | None) -> PendingRequest:
        identity = Broker._process_identity(os.getpid())
        return PendingRequest(
            request_id="rid", nonce="nonce", created_at=time.time(),
            expires_at=time.time() + 30, metadata={"pid": os.getpid()},
            process_start_time=identity["start_time"],
            process_cmdline=identity["cmdline"], process_uid=identity["uid"],
            owner_uid=owner_uid,
        )

    def test_approve_and_cancel_require_ui_uid_to_match_request_owner_uid(self) -> None:
        for verb, ok_key in (("approve", "ok"), ("cancel", "ok")):
            for ui_uid, expected in ((TEST_OWNER_UID + 1, False), (TEST_OWNER_UID, True)):
                broker = self._in_process_broker()
                request = self._pending_request(TEST_OWNER_UID)
                broker.pending["rid"] = request
                a, b = socket.socketpair()
                self.addCleanup(a.close)
                self.addCleanup(b.close)
                message = {"request_id": "rid", "nonce": "nonce", "secret": "s"}
                getattr(broker, f"_{verb}")(a, message, ui_uid)
                a.shutdown(socket.SHUT_WR)
                response = json.loads(b.makefile("rb").readline())
                self.assertEqual(response[ok_key], expected, (verb, ui_uid, response))
                self.assertEqual(request.delivered, expected)

    def test_approve_and_cancel_fail_closed_when_request_has_no_owner_uid(self) -> None:
        for verb in ("approve", "cancel"):
            broker = self._in_process_broker()
            request = self._pending_request(None)
            broker.pending["rid"] = request
            a, b = socket.socketpair()
            self.addCleanup(a.close)
            self.addCleanup(b.close)
            getattr(broker, f"_{verb}")(
                a, {"request_id": "rid", "nonce": "nonce", "secret": "s"}, TEST_OWNER_UID,
            )
            self.assertFalse(request.delivered, verb)

    def test_askpass_identity_available_reflects_installed_binary(self) -> None:
        missing = Path(tempfile.gettempdir()) / f"doorman-no-such-binary-{uuid.uuid4().hex}"
        # Live, over the wire: group resolvable (pinned gid) but no binary.
        socket_path = self._start_broker(
            "broker-no-binary",
            "--trusted-ui-exe", TEST_TRUSTED_UI_EXE,
            "--trusted-askpass-gid", str(TEST_EGID),
            "--askpass-binary", str(missing),
        )
        stats = call(_ctl(socket_path), {"type": "stats"})
        self.assertTrue(stats["ok"], stats)
        self.assertFalse(stats["askpass_identity_available"])
        # The skip seam reports available regardless.
        self.assertTrue(call(_ctl(self.socket_path), {"type": "stats"})["askpass_identity_available"])

        gid = TEST_EGID
        good = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_ISGID | 0o755, st_uid=0, st_gid=gid)
        cases = {
            "setgid root:group binary": (good, True),
            "no setgid bit": (SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_gid=gid), False),
            "not owned by root": (SimpleNamespace(st_mode=good.st_mode, st_uid=1000, st_gid=gid), False),
            "wrong group": (SimpleNamespace(st_mode=good.st_mode, st_uid=0, st_gid=gid + 1), False),
        }
        for label, (fake_stat, expected) in cases.items():
            broker = self._in_process_broker(
                trusted_askpass_skip_identity_check=False, trusted_askpass_gid=gid,
                askpass_binary=Path("/fake/doorman-askpass"),
            )
            with patch("broker.broker.os.stat", return_value=fake_stat):
                self.assertEqual(broker._compute_askpass_identity_available(), expected, label)
        # Unresolvable group => unavailable even with a perfect binary.
        broker = self._in_process_broker(
            trusted_askpass_skip_identity_check=False, askpass_binary=Path("/fake/doorman-askpass"),
        )
        with patch("broker.broker.os.stat", return_value=good), \
                patch("broker.broker.grp.getgrnam", side_effect=KeyError("doorman-askpass")):
            self.assertFalse(broker._compute_askpass_identity_available())

    def test_scm_rights_fd_is_ignored_request_judged_purely_on_egid_and_proc_checks(self) -> None:
        # Structural: the broker never reads a file descriptor from the peer
        # (no recvmsg / SCM_RIGHTS / pidfd) — this is what keeps the O_PATH
        # /fstat bypass closed. Asserted on the AST so comments don't matter.
        import ast
        tree = ast.parse((ROOT / "broker" / "broker.py").read_text(encoding="utf-8"))
        forbidden = {
            "recvmsg", "recvmsg_into", "recv_fds", "SCM_RIGHTS", "CMSG_LEN",
            "CMSG_SPACE", "SO_PASSCRED", "pidfd_open", "SIGSTOP", "SIGCONT",
        }
        used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
        }
        self.assertFalse(forbidden & used, forbidden & used)

        # Behavioural: an fd attached via SCM_RIGHTS changes nothing. Judged on
        # egid: mismatched gid is rejected, matching gid is accepted.
        payload = json.dumps({"command": "opath-bypass-attempt"})
        for gid, expected in ((_other_gid(), {"ok": False, "error": "untrusted_askpass_helper"}), (TEST_EGID, None)):
            socket_path = self._start_broker(
                f"broker-opath-{gid}",
                "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
                TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
                "--trusted-askpass-gid", str(gid),
            )
            proc = subprocess.Popen(
                [sys.executable, "-c", _SUBPROCESS_SEND_FOREIGN_OPATH_FD_CODE,
                 str(socket_path), "/usr/bin/true", payload],
                cwd=ROOT, stdout=subprocess.PIPE, text=True,
            )
            self.addCleanup(lambda p=proc: p.stdout and p.stdout.close())
            self.addCleanup(proc.wait, timeout=3)
            response = json.loads(proc.stdout.readline())
            if expected is None:
                self.assertTrue(response["ok"], response)
            else:
                self.assertEqual(response, expected)


if __name__ == "__main__":
    unittest.main()
