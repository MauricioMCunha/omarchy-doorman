#!/usr/bin/env python3
"""Askpass entrypoint bundled with the installed doorman plugin."""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from .client import request_secret
except ImportError:  # execução direta pelo Process do Quickshell ou sudo askpass
    from client import request_secret


def session_paths() -> tuple[Path, Path, Path]:
    runtime_dir = Path(
        os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    ) / "omarchy-doorman"
    socket_path = Path(os.environ.get("DOORMAN_SOCKET", runtime_dir / "broker.sock"))
    return socket_path, runtime_dir / "token", runtime_dir / "llm-capability"


def main() -> int:
    socket_path, token_path, capability_path = session_paths()
    try:
        token = token_path.read_text(encoding="utf-8").strip()
        capability = capability_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return 2
    if not token or not capability:
        return 2
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Password: "
    try:
        result = request_secret(
            Path(socket_path),
            token,
            {
                "pid": os.getpid(),
                "command": os.environ.get("DOORMAN_COMMAND", "sudo"),
                "cwd": os.getcwd(),
                "tty": os.environ.get("DOORMAN_TTY", ""),
                "prompt": prompt,
                "origin": "llm",
                "capability": capability,
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
