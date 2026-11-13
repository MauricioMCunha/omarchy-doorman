#!/usr/bin/env python3
"""Askpass entrypoint bundled with the installed doorman plugin."""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from .client import request_secret
except ImportError:  # run directly by Quickshell's Process or by sudo askpass
    from client import request_secret


def session_paths() -> Path:
    runtime_dir = Path(
        os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    ) / "omarchy-doorman"
    socket_path = Path(os.environ.get("DOORMAN_SOCKET", runtime_dir / "broker.sock"))
    return socket_path


def main() -> int:
    socket_path = session_paths()
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Password: "
    try:
        result = request_secret(
            Path(socket_path),
            {
                "pid": os.getpid(),
                # sudo execs this script directly (fork+exec); the ppid is
                # sudo's own process, stable for the whole passwd_tries loop.
                # It's the signal the broker uses to tell that two requests
                # are retries of the same command — see RETRY_WINDOW_SECONDS
                # in broker.py.
                "sudo_pid": os.getppid(),
                "command": os.environ.get("DOORMAN_COMMAND", "sudo"),
                "cwd": os.getcwd(),
                "tty": os.environ.get("DOORMAN_TTY", ""),
                "prompt": prompt,
                "screen": os.environ.get("DOORMAN_SCREEN", ""),
            },
        )
    except (OSError, RuntimeError, ValueError):
        return 1
    if not result.get("ok") or not isinstance(result.get("secret"), str):
        return 1
    sys.stdout.write(result["secret"] + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
