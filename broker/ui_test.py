#!/usr/bin/env python3
"""Terminal test UI; use only with a fake secret."""

from __future__ import annotations

import argparse
import getpass
import time
from pathlib import Path

try:
    from .client import call
except ImportError:  # invoked outside the package, with the repo root on PYTHONPATH
    from client import call


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--fake-secret", default="test-do-not-use-in-production")
    args = parser.parse_args()
    response = call(args.socket, args.token, {"type": "pending"})
    requests = response.get("requests", [])
    if not requests:
        print("no pending request")
        return
    item = requests[0]
    print(f"Command: {item['command']}")
    print(f"PID: {item['pid']} | TTY: {item['tty']}")
    print(f"Valid for: {max(0, int(item['expires_at'] - time.time()))}s")
    secret = args.fake_secret
    # getpass is only used when explicitly requested for local tests.
    if args.fake_secret == "__prompt__":
        secret = getpass.getpass("Fake secret: ")
    result = call(
        args.socket,
        args.token,
        {
            "type": "approve",
            "request_id": item["request_id"],
            "nonce": item.get("nonce", ""),
            "secret": secret,
        },
    )
    print("authorization sent" if result.get("ok") else f"failed: {result.get('error')}")


if __name__ == "__main__":
    main()
