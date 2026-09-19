from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.secure_input_broker.client import call, request_secret  # noqa: E402


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

    def test_expired_request_is_rejected(self) -> None:
        created = call(
            self.socket_path,
            self.token,
            {
                "type": "request",
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


if __name__ == "__main__":
    unittest.main()
