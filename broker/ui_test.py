#!/usr/bin/env python3
"""UI de teste em terminal; usar exclusivamente com segredo fictício."""

from __future__ import annotations

import argparse
import getpass
import time
from pathlib import Path

from .client import call


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--fake-secret", default="teste-nao-usar-em-producao")
    args = parser.parse_args()
    response = call(args.socket, args.token, {"type": "pending"})
    requests = response.get("requests", [])
    if not requests:
        print("nenhuma solicitação pendente")
        return
    item = requests[0]
    print(f"Comando: {item['command']}")
    print(f"PID: {item['pid']} | TTY: {item['tty']}")
    print(f"Validade: {max(0, int(item['expires_at'] - time.time()))}s")
    secret = args.fake_secret
    # getpass só é usado quando explicitamente solicitado para testes locais.
    if args.fake_secret == "__prompt__":
        secret = getpass.getpass("Segredo fictício: ")
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
    print("autorização enviada" if result.get("ok") else f"falha: {result.get('error')}")


if __name__ == "__main__":
    main()
