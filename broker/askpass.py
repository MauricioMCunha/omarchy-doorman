#!/usr/bin/env python3
"""Helper compatível com sudo askpass.

O helper imprime somente a resposta aprovada pelo broker. Nunca registra o
valor recebido.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .client import request_secret


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("prompt", nargs="?", default="Password: ")
    args = parser.parse_args()
    socket_path = os.environ.get("DOORMAN_SOCKET")
    token = os.environ.get("DOORMAN_TOKEN")
    if not socket_path or not token:
        return 2
    try:
        result = request_secret(
            Path(socket_path),
            token,
            {
                "pid": os.getpid(),
                "command": os.environ.get("DOORMAN_COMMAND", "sudo askpass"),
                "cwd": os.getcwd(),
                "tty": os.environ.get("DOORMAN_TTY", ""),
                "prompt": args.prompt,
                "origin": "llm",
                "capability": os.environ.get("DOORMAN_LLM_CAPABILITY", ""),
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
