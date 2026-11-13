from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, threading, unittest
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
        # Only DOORMAN_SOCKET_DEV_OVERRIDE selects the connect target;
        # XDG_RUNTIME_DIR and DOORMAN_SOCKET must be ignored.
        real_socket = self.tmp_path / "broker.sock"
        fake_real = _FakeBroker(real_socket)
        self.addCleanup(fake_real.close)
        attacker_socket = self.tmp_path / "attacker.sock"
        fake_attacker = _FakeBroker(attacker_socket)
        self.addCleanup(fake_attacker.close)

        self._run_askpass({
            "DOORMAN_SOCKET_DEV_OVERRIDE": str(real_socket),
            "XDG_RUNTIME_DIR": str(self.tmp_path / "evil-xdg-runtime-dir"),
            "DOORMAN_SOCKET": str(attacker_socket),
        })
        self.assertIsNone(fake_attacker.received)
        self.assertIsNotNone(fake_real.received)

    def test_request_has_exact_field_set_without_token_capability_origin(self) -> None:
        socket_path = self.tmp_path / "broker.sock"
        fake = _FakeBroker(socket_path)
        self.addCleanup(fake.close)
        result = self._run_askpass({"DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path)})
        self.assertNotEqual(result.returncode, 0)  # fake replies ok:false
        self.assertIsNotNone(fake.received)
        req = json.loads(fake.received)
        self.assertEqual(
            set(req), {"type", "pid", "sudo_pid", "command", "cwd", "tty", "prompt"})
        self.assertEqual(req["type"], "request")
        self.assertEqual(req["prompt"], "Password: ")

    def test_does_not_read_token_files_from_runtime_dir_env(self) -> None:
        # A stale env var from the removed design must have no effect.
        socket_path = self.tmp_path / "broker.sock"
        fake = _FakeBroker(socket_path)
        self.addCleanup(fake.close)
        self._run_askpass({
            "DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path),
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(self.tmp_path / "nonexistent"),
        })
        self.assertIsNotNone(fake.received)
        self.assertNotIn(b"token", fake.received)

    def test_approved_decision_prints_secret(self) -> None:
        socket_path = self.tmp_path / "broker.sock"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(socket_path))
        srv.listen(1)
        self.addCleanup(srv.close)

        def serve() -> None:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(3.0)
                f = conn.makefile("rb")
                f.readline(16384)
                conn.sendall(b'{"ok":true}\n')
                conn.sendall(b'{"ok":true,"secret":"p\\"w\\\\x"}\n')

        th = threading.Thread(target=serve, daemon=True)
        th.start()
        result = self._run_askpass({"DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path)})
        th.join(timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'p"w\\x\n')

    def test_process_is_non_dumpable_at_runtime(self) -> None:
        socket_path = self.tmp_path / "broker.sock"
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(socket_path))
        srv.listen(1)
        self.addCleanup(srv.close)
        env = os.environ.copy()
        env["DOORMAN_SOCKET_DEV_OVERRIDE"] = str(socket_path)
        proc = subprocess.Popen([str(self.binary)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            srv.settimeout(3.0)
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(3.0)
                conn.makefile("rb").readline(16384)  # binary is now blocked reading our reply
                # /proc/<pid>/status has no Dumpable: line. The kernel
                # instead makes the files inside /proc/<pid> (e.g. environ)
                # root-owned for a non-dumpable process (a dumpable one's
                # are owned by its own euid).
                self.assertEqual(os.stat(f"/proc/{proc.pid}/environ").st_uid, 0)
                # Control: the same check on a dumpable process must differ,
                # so the assertion above is not vacuous.
                ctl = subprocess.Popen(["sleep", "5"])
                try:
                    self.assertEqual(os.stat(f"/proc/{ctl.pid}/environ").st_uid, os.getuid())
                finally:
                    ctl.kill()
                    ctl.wait()
        finally:
            proc.kill()
            proc.communicate()

if __name__ == "__main__":
    unittest.main()
