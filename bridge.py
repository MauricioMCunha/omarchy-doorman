#!/usr/bin/env python3
"""Secret-free bridge for the Doorman UI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from .client import call
except ImportError:  # run directly by Quickshell's Process
    from client import call


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
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
    if args.action == "pending":
        result = call(args.socket, {"type": "pending"})
    elif args.action == "stats":
        result = call(args.socket, {"type": "stats"})
    elif args.action == "cancel":
        result = call(args.socket, {"type": "cancel", "request_id": args.request_id, "nonce": args.nonce})
    else:
        secret = sys.stdin.readline().rstrip("\n")
        result = call(args.socket, {"type": "approve", "request_id": args.request_id, "nonce": args.nonce, "secret": secret})
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
