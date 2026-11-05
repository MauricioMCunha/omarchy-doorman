from __future__ import annotations
import os, socket, subprocess, sys, tempfile, threading, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _compile(tmp_dir: Path) -> Path:
    binary = tmp_dir / "doorman-askpass"
    subprocess.run(
        ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
         "-o", str(binary), str(ROOT / "askpass" / "doorman-askpass.c")],
        check=True,
    )
    return binary

class _FakeBroker:
    """Accepts one connection, reads one line, replies 'ok: false,
    error: test_stub' — enough to prove the askpass binary reached the
    socket it was told to, without needing a real broker."""
    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path
        self.received: bytes | None = None
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(str(socket_path))
        self._srv.listen(1)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        conn, _ = self._srv.accept()
        with conn:
            conn.settimeout(3.0)
            self.received = conn.makefile("rb").readline(16384)
            conn.sendall(b'{"ok":false,"error":"test_stub"}\n')

    def close(self) -> None:
        self._srv.close()
        self._thread.join(timeout=2)

class AskpassBinaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.binary = _compile(self.tmp_path)

    def _run_askpass(self, env: dict[str, str]) -> subprocess.CompletedProcess:
        full_env = os.environ.copy()
        full_env.update(env)
        return subprocess.run([str(self.binary)], env=full_env, capture_output=True, timeout=5)

    def test_ignores_xdg_runtime_dir_and_doorman_socket_in_production(self) -> None:
        # Uses DOORMAN_RUNTIME_DIR_DEV_OVERRIDE (not
        # DOORMAN_SOCKET_DEV_OVERRIDE), so the socket path is still derived
        # from runtime_dir the production way. This deliberately never
        # touches this machine's real, getuid()-derived production runtime
        # dir — asserting against that path would be environment-coupled
        # and dangerous: if a real broker is running there, the binary
        # could connect to it for real and pop a live approval prompt in
        # the real Quickshell UI in the middle of a test run. Instead, this
        # isolates the two "ignored in production" claims with hard
        # evidence: the token content actually sent, and which of two fake
        # listeners actually received a connection.
        runtime_dir = self.tmp_path / "runtime"
        runtime_dir.mkdir()
        (runtime_dir / "token").write_text("test-token\n")
        (runtime_dir / "llm-capability").write_text("test-capability\n")
        real_socket = runtime_dir / "broker.sock"
        fake_real = _FakeBroker(real_socket)
        self.addCleanup(fake_real.close)

        evil_runtime_dir = self.tmp_path / "evil-xdg-runtime-dir" / "omarchy-doorman"
        evil_runtime_dir.mkdir(parents=True)
        (evil_runtime_dir / "token").write_text("evil-token\n")
        (evil_runtime_dir / "llm-capability").write_text("evil-capability\n")
        attacker_socket = self.tmp_path / "attacker.sock"
        fake_attacker = _FakeBroker(attacker_socket)
        self.addCleanup(fake_attacker.close)

        self._run_askpass({
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(runtime_dir),
            "XDG_RUNTIME_DIR": str(self.tmp_path / "evil-xdg-runtime-dir"),
            "DOORMAN_SOCKET": str(attacker_socket),
        })
        self.assertIsNone(fake_attacker.received)
        self.assertIsNotNone(fake_real.received)
        self.assertIn(b'"token":"test-token"', fake_real.received)

    def test_dev_override_env_vars_are_honored(self) -> None:
        runtime_dir = self.tmp_path / "runtime"
        runtime_dir.mkdir()
        (runtime_dir / "token").write_text("test-token\n")
        (runtime_dir / "llm-capability").write_text("test-capability\n")
        socket_path = self.tmp_path / "broker.sock"
        fake = _FakeBroker(socket_path)
        self.addCleanup(fake.close)
        result = self._run_askpass({
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(runtime_dir),
            "DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path),
        })
        self.assertIsNotNone(fake.received)
        self.assertIn(b'"token":"test-token"', fake.received)

    def test_symlinked_token_file_is_rejected_even_when_target_is_readable(self) -> None:
        runtime_dir = self.tmp_path / "runtime"
        runtime_dir.mkdir()
        readable_target = self.tmp_path / "world-readable-but-wrong-file"
        readable_target.write_text("not the real token\n")
        os.chmod(readable_target, 0o644)
        (runtime_dir / "token").symlink_to(readable_target)
        (runtime_dir / "llm-capability").write_text("test-capability\n")
        socket_path = self.tmp_path / "broker.sock"
        fake = _FakeBroker(socket_path)
        self.addCleanup(fake.close)
        result = self._run_askpass({
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(runtime_dir),
            "DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path),
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(fake.received)

if __name__ == "__main__":
    unittest.main()
