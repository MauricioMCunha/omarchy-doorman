# tests/test_identity_helper.py
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def _query(socket_path: Path, pid: int) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3.0)
        conn.connect(str(socket_path))
        conn.sendall((json.dumps({"pid": pid}) + "\n").encode())
        line = conn.makefile("rb").readline(256)
    return json.loads(line)

class IdentityHelperTest(unittest.TestCase):
    def _start(self, trusted_path: str) -> Path:
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

    def test_identifies_matching_pid_as_trusted(self) -> None:
        socket_path = self._start(sys.executable)
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            cwd=ROOT,
        )
        self.addCleanup(proc.wait, timeout=3)
        self.addCleanup(proc.terminate)
        self.assertEqual(_query(socket_path, proc.pid), {"ok": True})

    def test_rejects_non_matching_pid(self) -> None:
        socket_path = self._start("/usr/bin/true")
        self.assertEqual(_query(socket_path, os.getpid()), {"ok": False})

    def test_rejects_nonexistent_pid(self) -> None:
        socket_path = self._start("/usr/bin/true")
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait(timeout=2)
        self.assertEqual(_query(socket_path, proc.pid), {"ok": False})

    def test_malformed_message_does_not_crash_helper(self) -> None:
        socket_path = self._start("/usr/bin/true")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3.0)
            conn.connect(str(socket_path))
            conn.sendall(b"not json at all\n")
        self.assertEqual(_query(socket_path, os.getpid()), {"ok": False})

    def test_missing_trusted_path_rejects_everything_without_crashing(self) -> None:
        socket_path = self._start("/nonexistent/doorman-fixture-missing")
        self.assertEqual(_query(socket_path, os.getpid()), {"ok": False})

if __name__ == "__main__":
    unittest.main()
