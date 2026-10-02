from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
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
        self.assertEqual(pending["requests"][0]["command"], "fake-command")
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


if __name__ == "__main__":
    unittest.main()
