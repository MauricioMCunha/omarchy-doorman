#!/usr/bin/env python3
"""Doorman's identity-helper service.

A separate systemd --user unit, deliberately not a child process of the
broker, so it is not subject to the broker's own mount-namespace hardening
(ProtectSystem=strict/ProtectHome=read-only/PrivateTmp=true/
ProtectKernelTunables=true/ProtectControlGroups=true), which blocks reading
another process's /proc/<pid>/exe regardless of capabilities — see
docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md. Given a
pid, this answers one question: does /proc/<pid>/exe identify the same file
(device+inode, never a path string — SPEC.md §6.11) as the trusted,
root-installed askpass binary?
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path

MAX_LINE = 256
DEFAULT_TRUSTED_ASKPASS_PATH = "/usr/local/lib/omarchy-doorman/doorman-askpass"


class IdentityHelper:
    def __init__(self, socket_path: Path, trusted_askpass_path: str) -> None:
        self.socket_path = socket_path
        try:
            st = os.stat(trusted_askpass_path)
            self._trusted_identity: tuple[int, int] | None = (st.st_dev, st.st_ino)
        except OSError:
            self._trusted_identity = None
            print(
                f"doorman identity-helper: trusted askpass path "
                f"{trusted_askpass_path!r} doesn't exist — every identity "
                "check will answer 'no match' until "
                "scripts/doorman-install-askpass has been run as root.",
                file=sys.stderr, flush=True,
            )

    def serve(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        try:
            existing = self.socket_path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode):
                raise RuntimeError(f"socket path is not a Unix socket: {self.socket_path}")
            if existing.st_uid != os.getuid():
                raise RuntimeError("Unix socket belongs to another user")
            self.socket_path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, stat.S_IRUSR | stat.S_IWUSR)
            server.listen(16)
            print(f"doorman identity-helper listening on {self.socket_path}", flush=True)
            while True:
                conn, _ = server.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3.0)
            self._send(conn, {"ok": self._answer(conn)})

    def _answer(self, conn: socket.socket) -> bool:
        try:
            line = self._recv_line(conn)
        except OSError:
            return False
        if not line:
            return False
        try:
            message = json.loads(line)
            pid = int(message["pid"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return False
        return self._identifies_trusted_askpass(pid)

    @staticmethod
    def _recv_line(conn: socket.socket) -> bytes | None:
        buf = bytearray()
        while len(buf) <= MAX_LINE:
            chunk = conn.recv(MAX_LINE + 1 - len(buf))
            if not chunk:
                return None
            buf += chunk
            if b"\n" in chunk:
                break
        newline_idx = buf.find(b"\n")
        if newline_idx == -1 or len(buf) > MAX_LINE:
            return None
        return bytes(buf[:newline_idx])

    def _identifies_trusted_askpass(self, pid: int) -> bool:
        if self._trusted_identity is None or pid <= 0:
            return False
        try:
            fd = os.open(f"/proc/{pid}/exe", os.O_PATH)
        except OSError:
            return False
        try:
            st = os.fstat(fd)
        finally:
            os.close(fd)
        return (st.st_dev, st.st_ino) == self._trusted_identity

    @staticmethod
    def _send(conn: socket.socket, payload: dict) -> None:
        try:
            conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--trusted-askpass-path", default=None)
    args = parser.parse_args()
    trusted_askpass_path = (
        args.trusted_askpass_path
        or os.environ.get("DOORMAN_TRUSTED_ASKPASS_PATH")
        or DEFAULT_TRUSTED_ASKPASS_PATH
    )
    IdentityHelper(args.socket, trusted_askpass_path).serve()


if __name__ == "__main__":
    main()
