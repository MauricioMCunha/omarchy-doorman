"""Cliente mínimo do protocolo Unix local do Doorman."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any

SOCKET_TIMEOUT = 5.0
MAX_LINE = 16 * 1024
# Alinhado à folga que o broker aplica ao aguardar a decisão da UI
# (timeout + 1.0s, limitado a 300s no broker). Ver services/doorman_broker/broker.py.
DECISION_WAIT_MARGIN = 2.0
MAX_DECISION_WAIT = 305.0


def call(socket_path: Path, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    message = {"token": token, **payload}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(SOCKET_TIMEOUT)
        conn.connect(str(socket_path))
        conn.sendall((json.dumps(message, separators=(",", ":")) + "\n").encode())
        line = conn.makefile("rb").readline(MAX_LINE + 1)
    if len(line) > MAX_LINE:
        raise RuntimeError("resposta do broker excede o limite")
    if not line:
        raise RuntimeError("broker encerrou a conexão")
    return json.loads(line)


def request_secret(socket_path: Path, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Create a request and keep the connection open until the UI decides."""
    message = {"token": token, "type": "request", **payload}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(SOCKET_TIMEOUT)
        conn.connect(str(socket_path))
        conn.sendall((json.dumps(message, separators=(",", ":")) + "\n").encode())
        reader = conn.makefile("rb")
        accepted = reader.readline(MAX_LINE + 1)
        if not accepted:
            raise RuntimeError("broker não aceitou a solicitação")
        if len(accepted) > MAX_LINE:
            raise RuntimeError("resposta do broker excede o limite")
        # A decisão da UI pode levar até o prazo do pedido (expires_at), que é
        # muito maior que o timeout de handshake acima. Reaplicar o timeout
        # curto aqui faria a leitura estourar antes do usuário responder.
        try:
            expires_at = json.loads(accepted).get("expires_at")
        except json.JSONDecodeError:
            expires_at = None
        if isinstance(expires_at, (int, float)):
            wait = max(0.0, expires_at - time.time()) + DECISION_WAIT_MARGIN
        else:
            wait = MAX_DECISION_WAIT
        conn.settimeout(min(wait, MAX_DECISION_WAIT))
        result = reader.readline(MAX_LINE + 1)
    if len(result) > MAX_LINE:
        raise RuntimeError("resposta do broker excede o limite")
    if not result:
        raise RuntimeError("broker encerrou a solicitação")
    return json.loads(result)
