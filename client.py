"""Minimal client for Doorman's local Unix protocol."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any

SOCKET_TIMEOUT = 5.0
MAX_LINE = 16 * 1024
# Matches the slack the broker applies while waiting for the UI's decision
# (timeout + 1.0s, capped at 300s on the broker). See broker/broker.py.
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
        raise RuntimeError("broker response exceeds the limit")
    if not line:
        raise RuntimeError("broker closed the connection")
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
            raise RuntimeError("broker did not accept the request")
        if len(accepted) > MAX_LINE:
            raise RuntimeError("broker response exceeds the limit")
        # The UI's decision can take up to the request's deadline (expires_at),
        # which is much longer than the handshake timeout above. Reapplying
        # the short timeout here would time out the read before the user
        # responds.
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
        raise RuntimeError("broker response exceeds the limit")
    if not result:
        raise RuntimeError("broker closed the request")
    return json.loads(result)
