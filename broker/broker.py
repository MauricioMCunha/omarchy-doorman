#!/usr/bin/env python3
"""Broker Unix-socket mínimo para o protótipo doorman.

O broker mantém o segredo somente durante a resposta da solicitação. Ele não
faz logging do payload secreto e invalida cada pedido após um único consumo.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import stat
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_LINE = 16 * 1024
DEFAULT_TIMEOUT = 30.0
HANDSHAKE_TIMEOUT = 5.0
# Defesa em profundidade: alguém que já tem o token/capability (um processo
# comprometido do próprio usuário) ainda poderia abrir muitos pedidos
# concorrentes, cada um prendendo uma thread por até timeout+1s. Isso não
# afeta o uso normal, que raramente tem mais de um pedido pendente por vez.
MAX_PENDING = 20
# Nome de processo (/proc/<pid>/comm) do processo confiável que pode
# aprovar/cancelar/listar pedidos. Configurável só para testes — em produção
# é sempre o Quickshell real. Ver Broker._peer_is_trusted_ui.
DEFAULT_TRUSTED_UI_EXE = "quickshell"
# Quantos saltos de processo pai a mais, além do próprio chamador, o
# broker segue procurando o executável confiável (bridge.py roda como
# filho direto do Quickshell — 1 salto basta na prática; a folga cobre um
# wrapper de shell futuro sem exigir outra mudança).
_TRUSTED_UI_MAX_HOPS = 4


@dataclass
class PendingRequest:
    request_id: str
    nonce: str
    created_at: float
    expires_at: float
    metadata: dict[str, Any]
    process_start_time: str | None = None
    process_cmdline: str | None = None
    process_uid: int | None = None
    delivered: bool = False
    decision_event: threading.Event = field(default_factory=threading.Event)
    secret: str | None = None
    error: str | None = None


class Broker:
    def __init__(
        self,
        socket_path: Path,
        session_token: str,
        llm_capability: str,
        timeout: float,
        trusted_ui_exe: str = DEFAULT_TRUSTED_UI_EXE,
    ) -> None:
        self.socket_path = socket_path
        self.session_token = session_token
        self.llm_capability = llm_capability
        self.timeout = timeout
        self.trusted_ui_exe = trusted_ui_exe
        self.pending: dict[str, PendingRequest] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.started_at = time.time()
        self.metrics = {"approved": 0, "cancelled": 0, "expired": 0, "requests": 0}
        self.last_activity_at: float | None = None

    def serve(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        try:
            existing = self.socket_path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode):
                raise RuntimeError(f"caminho do socket não é um socket Unix: {self.socket_path}")
            if existing.st_uid != os.getuid():
                raise RuntimeError("socket Unix pertence a outro usuário")
            self.socket_path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, stat.S_IRUSR | stat.S_IWUSR)
            server.listen(16)
            cleanup = threading.Thread(target=self._cleanup_loop, daemon=True)
            cleanup.start()
            print(f"doorman broker ouvindo em {self.socket_path}", flush=True)
            while not self.stop_event.is_set():
                try:
                    server.settimeout(1.0)
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            # Sem timeout aqui, qualquer processo do mesmo usuário (mesmo sem
            # token) poderia conectar e nunca enviar dados, prendendo esta
            # thread para sempre. Não há limite de threads concorrentes, então
            # isso vira exaustão local. O handshake é a única leitura desta
            # conexão; respostas subsequentes só enviam, então o timeout curto
            # não afeta a espera longa pela decisão da UI em _create_request.
            conn.settimeout(HANDSHAKE_TIMEOUT)
            try:
                reader = conn.makefile("rb")
                line = reader.readline(MAX_LINE + 1)
            except OSError:
                return
            finally:
                conn.settimeout(None)
            if not line or len(line) > MAX_LINE:
                return
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                self._send(conn, {"ok": False, "error": "invalid_message"})
                return
            if not secrets.compare_digest(str(message.get("token", "")), self.session_token):
                self._send(conn, {"ok": False, "error": "unauthorized"})
                return
            kind = message.get("type")
            if kind == "request":
                if not self._valid_llm_origin(message):
                    self._send(conn, {"ok": False, "error": "invalid_llm_origin"})
                    return
                self._create_request(conn, message)
            elif kind in ("approve", "cancel", "pending", "stats"):
                # Origin=llm + capability só controla quem pode CRIAR um
                # pedido; approve/cancel/pending/stats só checavam o token de
                # sessão, e qualquer processo do mesmo usuário que consegue
                # criar um pedido também consegue ler esse token (é o mesmo
                # arquivo 0600). Sem esta checagem, um agente comprometido
                # podia se autoaprovar direto pelo socket, sem UI e sem
                # humano — confirmado manualmente antes deste fix. SO_PEERCRED
                # é verificado pelo kernel a partir do processo que chamou
                # connect(); não é algo que o processo remoto possa forjar.
                if not self._peer_is_trusted_ui(conn):
                    self._send(conn, {"ok": False, "error": "untrusted_caller"})
                    return
                if kind == "approve":
                    self._approve(conn, message)
                elif kind == "cancel":
                    self._cancel(conn, message)
                elif kind == "pending":
                    self._pending(conn)
                else:
                    self._stats(conn)
            else:
                self._send(conn, {"ok": False, "error": "unknown_type"})

    def _valid_llm_origin(self, message: dict[str, Any]) -> bool:
        return (
            message.get("origin") == "llm"
            and secrets.compare_digest(str(message.get("capability", "")), self.llm_capability)
        )

    def _create_request(self, conn: socket.socket, message: dict[str, Any]) -> None:
        pid = self._positive_pid(message.get("pid"))
        if pid is None:
            self._send(conn, {"ok": False, "error": "invalid_pid"})
            return
        identity = self._process_identity(pid)
        if identity is None:
            self._send(conn, {"ok": False, "error": "process_not_found"})
            return
        metadata = {
            "pid": pid,
            "command": str(message.get("command", ""))[:1000],
            "cwd": str(message.get("cwd", ""))[:1000],
            "tty": str(message.get("tty", ""))[:300],
            "prompt": str(message.get("prompt", "Password: "))[:300],
            "screen": str(message.get("screen", ""))[:200],
        }
        request = PendingRequest(
            request_id=uuid.uuid4().hex,
            nonce=secrets.token_urlsafe(24),
            created_at=time.time(),
            expires_at=time.time() + self.timeout,
            metadata=metadata,
            process_start_time=identity["start_time"],
            process_cmdline=identity["cmdline"],
            process_uid=identity["uid"],
        )
        with self.lock:
            if len(self.pending) >= MAX_PENDING:
                overflow = True
            else:
                overflow = False
                self.pending[request.request_id] = request
                self.metrics["requests"] += 1
                self.last_activity_at = time.time()
        if overflow:
            self._send(conn, {"ok": False, "error": "too_many_pending"})
            return
        self._send(
            conn,
            {
                "ok": True,
                "request_id": request.request_id,
                "nonce": request.nonce,
                "expires_at": request.expires_at,
            },
        )
        request.decision_event.wait(self.timeout + 1.0)
        with self.lock:
            secret = request.secret
            error = request.error or "expired"
            self.pending.pop(request.request_id, None)
        if secret is not None:
            self._send(conn, {"ok": True, "secret": secret})
        else:
            self._send(conn, {"ok": False, "error": error})

    def _pending(self, conn: socket.socket) -> None:
        now = time.time()
        with self.lock:
            items = [
                {
                    "request_id": r.request_id,
                    "nonce": r.nonce,
                    **r.metadata,
                    "expires_at": r.expires_at,
                }
                for r in self.pending.values()
                if not r.delivered and r.expires_at > now
            ]
        self._send(conn, {"ok": True, "requests": items})

    def _stats(self, conn: socket.socket) -> None:
        now = time.time()
        with self.lock:
            payload = {
                "ok": True,
                "uptime": max(0, int(now - self.started_at)),
                "pending": sum(
                    1 for request in self.pending.values()
                    if not request.delivered and request.expires_at > now
                ),
                "last_activity_at": self.last_activity_at,
                **self.metrics,
            }
        self._send(conn, payload)

    def _approve(self, conn: socket.socket, message: dict[str, Any]) -> None:
        request_id = str(message.get("request_id", ""))
        nonce = str(message.get("nonce", ""))
        secret = message.get("secret")
        with self.lock:
            request = self.pending.get(request_id)
            identity_valid = request is not None and self._identity_matches(request)
            valid = (
                request is not None
                and not request.delivered
                and secrets.compare_digest(request.nonce, nonce)
                and request.expires_at > time.time()
                and identity_valid
                and isinstance(secret, str)
                and len(secret) <= 4096
            )
            if valid:
                request.delivered = True
                request.secret = secret
                self.metrics["approved"] += 1
                self.last_activity_at = time.time()
                request.decision_event.set()
        if not valid:
            self._send(conn, {"ok": False, "error": "invalid_or_expired_request"})
            return
        # O segredo só é retornado nesta resposta e nunca é escrito pelo broker.
        self._send(conn, {"ok": True})

    def _cancel(self, conn: socket.socket, message: dict[str, Any]) -> None:
        request_id = str(message.get("request_id", ""))
        nonce = str(message.get("nonce", ""))
        with self.lock:
            request = self.pending.get(request_id)
            removed = (
                request is not None
                and not request.delivered
                and secrets.compare_digest(request.nonce, nonce)
            )
            if removed:
                request.delivered = True
                request.error = "cancelado_pelo_usuario"
                self.metrics["cancelled"] += 1
                self.last_activity_at = time.time()
                request.decision_event.set()
        self._send(conn, {"ok": removed})

    @staticmethod
    def _positive_pid(value: Any) -> int | None:
        try:
            pid = int(value)
        except (TypeError, ValueError):
            return None
        return pid if pid > 0 else None

    def _peer_is_trusted_ui(self, conn: socket.socket) -> bool:
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except OSError:
            return False
        pid, uid, _gid = struct.unpack("3i", creds)
        if pid <= 0 or uid != os.getuid():
            return False
        for _ in range(_TRUSTED_UI_MAX_HOPS):
            info = self._process_ppid_and_comm(pid)
            if info is None:
                return False
            ppid, comm = info
            if comm == self.trusted_ui_exe:
                return True
            if ppid <= 1:
                return False
            pid = ppid
        return False

    @staticmethod
    def _process_ppid_and_comm(pid: int) -> tuple[int, str] | None:
        # Comparar /proc/<pid>/exe (o caminho real do binário, não forjável
        # por argv[0]/prctl) seria mais forte que comm — mas ler o exe de
        # outro processo, mesmo do mesmo usuário, exige permissão equivalente
        # a ptrace, e um serviço systemd --user recebe essa permissão negada
        # (EACCES) mesmo com CAP_SYS_PTRACE concedido e zero hardening extra
        # (confirmado testando; a mesma leitura funciona normalmente fora do
        # systemd). /proc/<pid>/comm não exige essa permissão. Isso troca
        # "impossível de forjar" por "exige um passo deliberado" (renomear o
        # processo via prctl/argv[0]) — pior que o ideal, mas muito melhor
        # que aceitar qualquer chamador com o token, que é o que existia
        # antes deste fix.
        try:
            comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
        except OSError:
            comm = ""
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            # Mesmo truque de _process_identity: o nome do processo pode ter
            # espaços/parênteses, então lê os campos após o último ")". Nesse
            # recorte o ppid é o campo 1 (0-indexado).
            fields = stat_text.rsplit(")", 1)[1].split()
            ppid = int(fields[1])
        except (OSError, IndexError, ValueError):
            return None
        return ppid, comm

    @staticmethod
    def _process_identity(pid: int) -> dict[str, Any] | None:
        proc = Path(f"/proc/{pid}")
        try:
            stat_text = (proc / "stat").read_text(encoding="utf-8")
            # O nome do processo pode conter espaços; use os campos após o
            # último ")" para manter o índice do start time estável.
            fields = stat_text.rsplit(")", 1)[1].split()
            cmdline = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(
                "utf-8", "replace"
            ).strip()
            uid_line = next(
                line for line in (proc / "status").read_text(encoding="utf-8").splitlines()
                if line.startswith("Uid:")
            )
            return {"start_time": fields[19], "cmdline": cmdline, "uid": int(uid_line.split()[1])}
        except (OSError, IndexError, StopIteration, ValueError):
            return None

    @classmethod
    def _identity_matches(cls, request: PendingRequest) -> bool:
        if (
            request.process_start_time is None
            or request.process_cmdline is None
            or request.process_uid is None
        ):
            return False
        identity = cls._process_identity(int(request.metadata["pid"]))
        return identity is not None and (
            identity["start_time"] == request.process_start_time
            and identity["cmdline"] == request.process_cmdline
            and identity["uid"] == request.process_uid
        )

    def _cleanup_loop(self) -> None:
        while not self.stop_event.wait(1.0):
            now = time.time()
            with self.lock:
                expired = [rid for rid, req in self.pending.items() if req.expires_at <= now]
                for rid in expired:
                    request = self.pending.get(rid)
                    if request and not request.delivered:
                        request.delivered = True
                        request.error = "expired"
                        self.metrics["expired"] += 1
                        self.last_activity_at = time.time()
                        request.decision_event.set()

    @staticmethod
    def _send(conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        except OSError:
            # O cliente pode ter cancelado a conexão após receber o aceite.
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--llm-capability", default=None)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--trusted-ui-exe", default=None)
    args = parser.parse_args()
    token = args.token or os.environ.get("DOORMAN_TOKEN")
    capability = args.llm_capability or os.environ.get("DOORMAN_LLM_CAPABILITY")
    if not token or not capability:
        parser.error("use --token/DOORMAN_TOKEN e --llm-capability/DOORMAN_LLM_CAPABILITY")
    trusted_ui_exe = (
        args.trusted_ui_exe
        or os.environ.get("DOORMAN_TRUSTED_UI_EXE")
        or DEFAULT_TRUSTED_UI_EXE
    )
    Broker(args.socket, token, capability, max(1.0, min(args.timeout, 300.0)), trusted_ui_exe).serve()


if __name__ == "__main__":
    main()
