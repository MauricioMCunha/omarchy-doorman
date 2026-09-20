from __future__ import annotations

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

from services.secure_input_broker.client import call, request_secret  # noqa: E402
from services.secure_input_broker.broker import Broker, PendingRequest  # noqa: E402


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
                "services.secure_input_broker.broker",
                "--socket",
                str(self.socket_path),
                "--token",
                self.token,
                "--llm-capability",
                self.capability,
                "--timeout",
                "2",
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
        self.fail("broker não criou o socket")

    def tearDown(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=2)
        if self.process.stdout:
            self.process.stdout.close()
        if self.process.stderr:
            self.process.stderr.close()
        self.temp.cleanup()

    def test_request_approve_is_single_use(self) -> None:
        created = call(
            self.socket_path,
            self.token,
            {
                "type": "request",
                "pid": os.getpid(),
                "command": "comando-ficticio",
                "cwd": str(ROOT),
                "tty": "teste-pty",
                "origin": "llm",
                "capability": self.capability,
            },
        )
        self.assertTrue(created["ok"])
        pending = call(self.socket_path, self.token, {"type": "pending"})
        self.assertEqual(pending["requests"][0]["command"], "comando-ficticio")
        approved = call(
            self.socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": created["request_id"],
                "nonce": created["nonce"],
                "secret": "segredo-ficticio",
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
                "secret": "nao-deve-ser-aceito",
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
        created = call(
            self.socket_path,
            self.token,
            {
                "type": "request",
                "pid": os.getpid(),
                "command": "expira",
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
                "secret": "segredo-ficticio",
            },
        )
        self.assertFalse(result["ok"])

    def test_askpass_like_request_receives_secret_after_ui_approval(self) -> None:
        import threading

        result: dict[str, object] = {}

        def askpass() -> None:
            result.update(
                request_secret(
                    self.socket_path,
                    self.token,
                    {
                        "pid": os.getpid(),
                        "command": "sudo -A teste",
                        "prompt": "Password: ",
                        "origin": "llm",
                        "capability": self.capability,
                    },
                )
            )

        thread = threading.Thread(target=askpass)
        thread.start()
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
                "secret": "segredo-ficticio",
            },
        )
        self.assertEqual(approval, {"ok": True})
        thread.join(timeout=2)
        self.assertEqual(result, {"ok": True, "secret": "segredo-ficticio"})

    def test_non_llm_origin_is_rejected(self) -> None:
        result = call(
            self.socket_path,
            self.token,
            {"type": "request", "origin": "terminal", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "invalid_llm_origin"})

    def test_approve_requires_correct_nonce(self) -> None:
        created = call(
            self.socket_path, self.token,
            {"type": "request", "pid": os.getpid(), "command": "nonce-errado",
             "origin": "llm", "capability": self.capability},
        )
        wrong = call(
            self.socket_path, self.token,
            {"type": "approve", "request_id": created["request_id"],
             "nonce": "nonce-errado-de-proposito", "secret": "nao-deve-vazar"},
        )
        self.assertFalse(wrong["ok"])
        correct = call(
            self.socket_path, self.token,
            {"type": "approve", "request_id": created["request_id"],
             "nonce": created["nonce"], "secret": "segredo-correto"},
        )
        self.assertTrue(correct["ok"])

    def test_idle_unauthenticated_connection_is_closed_after_handshake_timeout(self) -> None:
        # Regressão: sem timeout no handshake, uma conexão que nunca envia
        # dados (nem token) prendia a thread do broker para sempre — DoS
        # local trivial, sem precisar do token, contra qualquer processo do
        # mesmo usuário. O broker deve fechar a conexão sozinho.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.socket_path))
            conn.settimeout(8.0)
            closed = conn.recv(1)
        self.assertEqual(closed, b"")
        # O broker segue respondendo normalmente a outras conexões.
        stats = call(self.socket_path, self.token, {"type": "stats"})
        self.assertTrue(stats["ok"])

    def test_cancel_requires_nonce(self) -> None:
        created = call(
            self.socket_path, self.token,
            {"type": "request", "pid": os.getpid(), "command": "cancelável",
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

    def test_missing_pid_is_rejected(self) -> None:
        result = call(
            self.socket_path, self.token,
            {"type": "request", "origin": "llm", "capability": self.capability},
        )
        self.assertEqual(result, {"ok": False, "error": "invalid_pid"})

    def test_askpass_helper_prints_only_approved_secret(self) -> None:
        import os

        env = os.environ.copy()
        env.update({
            "SECURE_INPUT_SOCKET": str(self.socket_path),
            "SECURE_INPUT_TOKEN": self.token,
            "SECURE_INPUT_LLM_CAPABILITY": self.capability,
            "SECURE_INPUT_COMMAND": "sudo -A id",
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
                         "nonce": item["nonce"], "secret": "segredo-ficticio"},
                    ))
                    return
                time.sleep(0.02)

        import threading
        thread = threading.Thread(target=approve)
        thread.start()
        helper = subprocess.run(
            [sys.executable, "-m", "services.secure_input_broker.askpass", "Password: "],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        thread.join(timeout=2)
        self.assertEqual(helper.returncode, 0)
        self.assertEqual(helper.stdout, "segredo-ficticio\n")
        self.assertEqual(helper.stderr, "")

    def test_askpass_survives_approval_slower_than_old_five_second_timeout(self) -> None:
        # Regressão: request_secret() costumava herdar o timeout de handshake
        # (5s) para a leitura do resultado, que só chega quando a UI decide.
        # Uma aprovação humana real é comumente mais lenta que isso.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "broker-slow.sock"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "services.secure_input_broker.broker",
                "--socket",
                str(socket_path),
                "--token",
                self.token,
                "--llm-capability",
                self.capability,
                "--timeout",
                "20",
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
            self.fail("broker não criou o socket")

        import threading

        result: dict[str, object] = {}

        def askpass() -> None:
            result.update(
                request_secret(
                    socket_path,
                    self.token,
                    {
                        "pid": os.getpid(),
                        "command": "sudo -A teste-lento",
                        "prompt": "Password: ",
                        "origin": "llm",
                        "capability": self.capability,
                    },
                )
            )

        thread = threading.Thread(target=askpass)
        thread.start()
        request = None
        for _ in range(50):
            pending = call(socket_path, self.token, {"type": "pending"})
            if pending["requests"]:
                request = pending["requests"][0]
                break
            time.sleep(0.02)
        self.assertIsNotNone(request)

        time.sleep(6.0)  # excede o antigo SOCKET_TIMEOUT de 5s do cliente

        approval = call(
            socket_path,
            self.token,
            {
                "type": "approve",
                "request_id": request["request_id"],
                "nonce": request["nonce"],
                "secret": "segredo-lento",
            },
        )
        self.assertEqual(approval, {"ok": True})
        thread.join(timeout=2)
        self.assertEqual(result, {"ok": True, "secret": "segredo-lento"})

    def test_stats_reports_request_lifecycle(self) -> None:
        created = call(
            self.socket_path, self.token,
            {"type": "request", "pid": os.getpid(), "command": "métrica",
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
