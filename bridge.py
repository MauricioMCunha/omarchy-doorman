#!/usr/bin/env python3
"""Bridge sem segredo em argumentos para a UI do Doorman."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .client import call
except ImportError:  # execução direta pelo Process do Quickshell
    from client import call


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("pending")
    sub.add_parser("stats")
    approve = sub.add_parser("approve")
    approve.add_argument("request_id")
    approve.add_argument("nonce")
    cancel = sub.add_parser("cancel")
    cancel.add_argument("request_id")
    cancel.add_argument("nonce")
    args = parser.parse_args()
    token = args.token_file.read_text(encoding="utf-8").strip()
    if args.action == "pending":
        result = call(args.socket, token, {"type": "pending"})
    elif args.action == "stats":
        result = call(args.socket, token, {"type": "stats"})
    elif args.action == "cancel":
        result = call(args.socket, token, {"type": "cancel", "request_id": args.request_id, "nonce": args.nonce})
    else:
        secret = sys.stdin.readline().rstrip("\n")
        result = call(args.socket, token, {"type": "approve", "request_id": args.request_id, "nonce": args.nonce, "secret": secret})
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
