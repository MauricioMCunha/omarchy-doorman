#!/usr/bin/env python3
"""Minimal Unix-socket broker for the doorman prototype.

The broker holds the secret only for the duration of the request's response.
It never logs the secret payload and invalidates each request after a
single use.
"""

from __future__ import annotations

import argparse
import array
import json
import os
import secrets
import socket
import stat
import struct
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_LINE = 16 * 1024
DEFAULT_TIMEOUT = 30.0
HANDSHAKE_TIMEOUT = 5.0
# Defense in depth: someone who already has the token/capability (a
# compromised process of the same user) could still open many concurrent
# requests, each holding a thread for up to timeout+1s. This doesn't affect
# normal use, which rarely has more than one pending request at a time.
MAX_PENDING = 20
# Process name (/proc/<pid>/comm) of the trusted process allowed to
# approve/cancel/list requests. Configurable only for tests — in production
# it's always the real Quickshell. See Broker._peer_is_trusted_ui.
DEFAULT_TRUSTED_UI_EXE = "quickshell"
# Process name (/proc/<pid>/comm) a request's connecting peer's immediate
# parent must have for the request to be accepted at all. Configurable only
# for tests — in production it's always the real sudo. See
# Broker._peer_is_sudo_child.
DEFAULT_TRUSTED_SUDO_EXE = "sudo"
# Whether that same parent must also show a genuine privilege escalation
# (its effective uid differing from its own real uid) to be accepted.
# /proc/<pid>/comm is just a label any process can set for itself
# (prctl(PR_SET_NAME), or by rewriting argv[0]) — including renaming itself
# "sudo" with no privilege at all, so comm alone isn't enough. Real sudo is
# setuid-root and keeps its real uid as the invoking user while its
# effective uid is 0 for as long as it's waiting on askpass (confirmed by
# inspecting a live `sudo -A` invocation). A same-user process can't
# reproduce that pairing without actually executing a genuine setuid-root
# binary — and since exec() replaces the whole process image, it can't
# rename itself afterwards either; whatever binary it execs keeps running
# its own code, not the attacker's. That's out of this project's threat
# model (see SPEC.md §6.1) if it ever becomes possible. Always required in
# production; only tests, which cannot become root, turn it off.
DEFAULT_TRUSTED_SUDO_REQUIRES_ESCALATION = True
# Fixed, root-installed path (scripts/doorman-install-askpass) the askpass
# helper's own /proc/self/exe — sent to the broker as a file descriptor over
# this connection's handshake (SCM_RIGHTS, see _recv_line_with_fd) — must
# resolve to for the request to be accepted. Even a peer that passes every
# check above can still be the attacker's own script: sudo lets the
# *caller* pick the SUDO_ASKPASS helper, so an agent that invokes real sudo
# directly (bypassing this project's PATH-shadow wrapper) can point
# SUDO_ASKPASS at code it wrote itself, which is a genuine, genuinely
# privilege-escalated child of a real sudo — passing pid_mismatch and
# not_sudo_child — yet is still caller-writable code that would receive the
# plaintext secret in its own memory once a human approves (issue #9558).
#
# This used to be checked by the broker itself stat()-ing the connecting
# peer's /proc/<pid>/exe. That doesn't work under this project's own
# systemd hardening: ProtectSystem=strict/ProtectHome=read-only/
# PrivateTmp=true force the broker into a private, unprivileged Linux user
# namespace, and reading another process's /proc/<pid>/exe from outside its
# namespace needs a ptrace-equivalent capability (CAP_SYS_PTRACE) the
# broker, by design, never has — confirmed live (PermissionError(13) on
# every attempt, including the legitimate one). Passing the fd instead
# sidesteps that entirely: the askpass binary opens its *own*
# /proc/self/exe (always allowed — a process introspecting itself needs no
# special permission) and hands the broker that exact file descriptor over
# the socket; the broker just fstat()s an fd it already owns, which needs
# no cross-process permission at all. The installed binary is also
# `0711` (execute-only for non-root, see scripts/doorman-install-askpass),
# so an attacker can't fake this by opening the trusted path directly and
# sending THAT fd instead — only a process that actually exec'd this exact
# file can open its own exe link. See SPEC.md §6.11.
# Configurable only for tests; production always uses this fixed path.
DEFAULT_TRUSTED_ASKPASS_PATH = "/usr/local/lib/omarchy-doorman/doorman-askpass"
# How many extra parent-process hops, beyond the caller itself, the broker
# follows while looking for the trusted executable (bridge.py runs as a
# direct child of Quickshell — 1 hop is enough in practice; the slack covers
# a future shell wrapper without needing another change).
_TRUSTED_UI_MAX_HOPS = 4
# When sudo rejects the password it reinvokes SUDO_ASKPASS in a new child
# process (a new pid on every attempt), but the parent sudo process stays
# the same for the whole passwd_tries loop. askpass forwards that parent
# pid as "sudo_pid"; if two requests arrive with the same sudo_pid within
# this window, the second one can only exist because sudo asked again —
# and sudo only does that after PAM rejected a password attempt (Doorman's
# own cancel/expiry make askpass exit without printing anything, which
# aborts sudo instead of triggering another attempt). The broker never
# knows whether the password itself was right — it only infers that there
# was an earlier attempt, so the UI can signal that to the user.
RETRY_WINDOW_SECONDS = 20.0


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
    attempt: int = 1
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
        trusted_sudo_exe: str = DEFAULT_TRUSTED_SUDO_EXE,
        trusted_sudo_requires_escalation: bool = DEFAULT_TRUSTED_SUDO_REQUIRES_ESCALATION,
        trusted_askpass_path: str = DEFAULT_TRUSTED_ASKPASS_PATH,
        trusted_askpass_skip_identity_check: bool = False,
    ) -> None:
        self.socket_path = socket_path
        self.session_token = session_token
        self.llm_capability = llm_capability
        self.timeout = timeout
        self.trusted_ui_exe = trusted_ui_exe
        self.trusted_sudo_exe = trusted_sudo_exe
        self.trusted_sudo_requires_escalation = trusted_sudo_requires_escalation
        self.trusted_askpass_path = trusted_askpass_path
        # Test-only: lets a test exercise request creation without a real
        # root-installed fixture at a fixed path. Never set in production —
        # see DEFAULT_TRUSTED_ASKPASS_PATH above.
        self.trusted_askpass_skip_identity_check = trusted_askpass_skip_identity_check
        self._askpass_unavailable_last_logged = 0.0
        if trusted_askpass_skip_identity_check:
            self._trusted_askpass_identity: tuple[int, int] | None = None
            self.askpass_identity_available = True
        else:
            try:
                st = os.stat(trusted_askpass_path)
                self._trusted_askpass_identity = (st.st_dev, st.st_ino)
                self.askpass_identity_available = True
            except OSError:
                self._trusted_askpass_identity = None
                self.askpass_identity_available = False
                self._log_askpass_unavailable()
        self.pending: dict[str, PendingRequest] = {}
        # sudo_pid -> {"attempt": int, "last_seen": float, "request_id": str}.
        # See RETRY_WINDOW_SECONDS.
        self._sudo_pid_attempts: dict[int, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.started_at = time.time()
        self.metrics = {"approved": 0, "cancelled": 0, "expired": 0, "requests": 0}
        self.last_activity_at: float | None = None

    def _log_askpass_unavailable(self) -> None:
        self._askpass_unavailable_last_logged = time.time()
        print(
            f"doorman broker: trusted askpass path {self.trusted_askpass_path!r} "
            "doesn't exist or isn't reachable by this process — askpass "
            "requests will be refused (askpass_identity_unavailable) until "
            "scripts/doorman-install-askpass has been run as root. This is "
            "deliberate: it's quieter to fail loudly here than to silently "
            "accept the weaker, pre-#9558 guarantee.",
            file=sys.stderr,
            flush=True,
        )

    def serve(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.socket_path.parent, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        try:
            existing = self.socket_path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISSOCK(existing.st_mode):
                raise RuntimeError(f"socket path is not a Unix socket: {self.socket_path}")
            if existing.st_uid != os.getuid():
                raise RuntimeError("Unix socket belongs to another user")
            self.socket_path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, stat.S_IRUSR | stat.S_IWUSR)
            server.listen(16)
            cleanup = threading.Thread(target=self._cleanup_loop, daemon=True)
            cleanup.start()
            print(f"doorman broker listening on {self.socket_path}", flush=True)
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
            # Without a timeout here, any process of the same user (even
            # without a token) could connect and never send data, holding
            # this thread forever. There's no cap on concurrent threads, so
            # that becomes local exhaustion. The handshake is the only read
            # on this connection; subsequent responses only send, so the
            # short timeout doesn't affect the long wait for the UI's
            # decision in _create_request.
            conn.settimeout(HANDSHAKE_TIMEOUT)
            line: bytes | None = None
            identity_fd: int | None = None
            try:
                line, identity_fd = self._recv_line_with_fd(conn)
            finally:
                conn.settimeout(None)
            try:
                if not line:
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
                    self._create_request(conn, message, identity_fd)
                elif kind in ("approve", "cancel", "pending", "stats"):
                    # Origin=llm + capability only controls who can CREATE a
                    # request; approve/cancel/pending/stats used to only check
                    # the session token, and any process of the same user that
                    # can create a request can also read that token (it's the
                    # same 0600 file). Without this check, a compromised agent
                    # could self-approve straight over the socket, with no UI
                    # and no human — confirmed manually before this fix.
                    # SO_PEERCRED is verified by the kernel from the process that
                    # called connect(); it's not something the remote process
                    # can forge.
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
            finally:
                if identity_fd is not None:
                    os.close(identity_fd)

    def _recv_line_with_fd(self, conn: socket.socket) -> tuple[bytes | None, int | None]:
        """Reads one '\n'-terminated line, bounded to MAX_LINE — the same
        contract conn.makefile(...).readline() used to have — but via
        recvmsg(), so an SCM_RIGHTS fd attached to the handshake (the
        askpass identity fd, SPEC.md §6.11) is captured instead of silently
        dropped. Every other caller (approve/cancel/pending/stats from the
        trusted UI) never attaches one; recvmsg() behaves like a plain recv
        for them, just with an always-empty ancillary-data list."""
        buf = bytearray()
        received_fd: int | None = None
        ancillary_size = socket.CMSG_SPACE(struct.calcsize("i"))
        while len(buf) <= MAX_LINE:
            try:
                chunk, ancdata, _flags, _addr = conn.recvmsg(
                    MAX_LINE + 1 - len(buf), ancillary_size
                )
            except OSError:
                chunk = b""
            for level, cmsg_type, data in ancdata if chunk else ():
                if level != socket.SOL_SOCKET or cmsg_type != socket.SCM_RIGHTS:
                    continue
                fds = array.array("i")
                fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])
                for fd in fds:
                    if received_fd is None:
                        received_fd = fd
                    else:
                        # Nothing legitimate ever sends more than one; don't
                        # leak whatever this extra one is.
                        os.close(fd)
            if not chunk:
                if received_fd is not None:
                    os.close(received_fd)
                return None, None
            buf += chunk
            if b"\n" in chunk:
                break
        newline_idx = buf.find(b"\n")
        if newline_idx == -1 or len(buf) > MAX_LINE:
            if received_fd is not None:
                os.close(received_fd)
            return None, None
        return bytes(buf[:newline_idx]), received_fd

    def _valid_llm_origin(self, message: dict[str, Any]) -> bool:
        return (
            message.get("origin") == "llm"
            and secrets.compare_digest(str(message.get("capability", "")), self.llm_capability)
        )

    def _create_request(
        self, conn: socket.socket, message: dict[str, Any], identity_fd: int | None
    ) -> None:
        pid = self._positive_pid(message.get("pid"))
        if pid is None:
            self._send(conn, {"ok": False, "error": "invalid_pid"})
            return
        # The "pid" field above is self-reported in the message payload — an
        # agent holding the normal request token/capability could otherwise
        # claim to be any PID that happens to exist (not even a real sudo
        # process), get a human to approve what looks like a legitimate
        # request for it, and receive the secret itself on this very
        # connection, since the response goes back over whoever is actually
        # connected, not over the claimed pid. Requiring the kernel-verified
        # peer of this connection to equal the claimed pid closes that: the
        # only process that can ever receive the secret for a given pid is
        # that pid's own connection. This is exactly what askpass.py already
        # does (it reports os.getpid(), its own real pid), so it changes
        # nothing for the legitimate flow.
        creds = self._peer_credentials(conn)
        if creds is None or creds[1] != os.getuid() or creds[0] != pid:
            self._send(conn, {"ok": False, "error": "pid_mismatch"})
            return
        # Closes the pid_mismatch check's remaining gap: it only stops a
        # requester from claiming a PID that isn't its own connection —
        # a process reporting its own real pid still passed. Nothing bound
        # the displayed operation to a genuine sudo/askpass chain, so an
        # agent could connect directly with its own truthful pid and a
        # convincing "command", and receive the password itself once a
        # human approved what looked like a legitimate request. Requiring
        # the peer's immediate parent to be a real sudo process means the
        # only way to ever receive a secret is to be the process sudo
        # itself just spawned to ask for one — exactly what askpass.py is.
        sudo_parent_pid = self._resolve_sudo_parent_pid(conn)
        if sudo_parent_pid is None:
            self._send(conn, {"ok": False, "error": "not_sudo_child"})
            return
        # Closes the not_sudo_child/escalation check's remaining gap: those
        # only validate the peer's *parent* (that it's a real, escalated
        # sudo). sudo itself lets the caller pick SUDO_ASKPASS, so the peer
        # process — the one that actually holds this connection and would
        # receive the secret — could still be the attacker's own script,
        # genuinely spawned by a genuine sudo. The askpass binary proves it
        # is the trusted, root-installed one by handing over an fd to its
        # own /proc/self/exe (SCM_RIGHTS, captured in _recv_line_with_fd);
        # fstat()-ing an fd this process already owns needs no permission
        # over the peer at all, unlike stat()-ing the peer's /proc/<pid>/exe
        # by path (tried first — doesn't work under this project's own
        # systemd hardening, see DEFAULT_TRUSTED_ASKPASS_PATH above and
        # SPEC.md §6.11). The installed binary's own file isn't readable by
        # this user (0711), only executable, so an attacker can't send the
        # fd of the trusted path opened directly instead of genuinely
        # exec'ing it.
        if not self.trusted_askpass_skip_identity_check:
            if not self.askpass_identity_available:
                self._send(conn, {"ok": False, "error": "askpass_identity_unavailable"})
                return
            fd_id = self._fd_identity(identity_fd) if identity_fd is not None else None
            if identity_fd is None or fd_id != self._trusted_askpass_identity:
                self._send(conn, {"ok": False, "error": "untrusted_askpass_helper"})
                return
        identity = self._process_identity(pid)
        if identity is None:
            self._send(conn, {"ok": False, "error": "process_not_found"})
            return
        # The displayed "command" must reflect what will actually run, not
        # whatever string the caller puts in the request payload — a caller
        # that controls its own SUDO_ASKPASS also controls this field, and
        # could show the human a harmless-looking lie while a different
        # command actually executes (issue #9558). sudo's own cmdline, read
        # from the verified real sudo parent above, can't be rewritten by
        # the caller without compromising the real sudo binary itself — see
        # SPEC.md §6.12.
        real_command = self._read_proc_cmdline(sudo_parent_pid)
        metadata = {
            "pid": pid,
            "command": (real_command or "(unable to read the sudo command)")[:1000],
            "cwd": str(message.get("cwd", ""))[:1000],
            "tty": str(message.get("tty", ""))[:300],
            "prompt": str(message.get("prompt", "Password: "))[:300],
            "screen": str(message.get("screen", ""))[:200],
        }
        sudo_pid = self._positive_pid(message.get("sudo_pid"))
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
                if sudo_pid is not None:
                    now = time.time()
                    previous = self._sudo_pid_attempts.get(sudo_pid)
                    if previous is not None and now - previous["last_seen"] <= RETRY_WINDOW_SECONDS:
                        request.attempt = int(previous["attempt"]) + 1
                        stale = self.pending.get(previous["request_id"])
                        if stale is not None and not stale.delivered:
                            # The previous attempt will never be read back:
                            # the askpass that created it already died (sudo
                            # killed that process and called askpass again).
                            # Without this it would sit in the pending list
                            # until it expired on its own, and the UI could
                            # end up selecting that dead entry instead of the
                            # current attempt.
                            stale.delivered = True
                            stale.error = "superseded_by_retry"
                            stale.decision_event.set()
                    self._sudo_pid_attempts[sudo_pid] = {
                        "attempt": request.attempt,
                        "last_seen": now,
                        "request_id": request.request_id,
                    }
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
                    "attempt": r.attempt,
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
                "askpass_identity_available": self.askpass_identity_available,
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
        # The secret is returned only in this response and never written by the broker.
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
                request.error = "cancelled_by_user"
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

    @staticmethod
    def _peer_credentials(conn: socket.socket) -> tuple[int, int] | None:
        # Verified by the kernel from the process that called connect(); not
        # something the remote process can forge, unlike anything carried in
        # the message payload itself (see _create_request's pid check).
        try:
            creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        except OSError:
            return None
        pid, uid, _gid = struct.unpack("3i", creds)
        if pid <= 0:
            return None
        return pid, uid

    @staticmethod
    def _fd_identity(fd: int) -> tuple[int, int] | None:
        try:
            st = os.fstat(fd)
        except OSError:
            return None
        return st.st_dev, st.st_ino

    def _peer_is_trusted_ui(self, conn: socket.socket) -> bool:
        creds = self._peer_credentials(conn)
        if creds is None:
            return False
        pid, uid = creds
        if uid != os.getuid():
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

    def _peer_is_sudo_child(self, conn: socket.socket) -> bool:
        return self._resolve_sudo_parent_pid(conn) is not None

    def _resolve_sudo_parent_pid(self, conn: socket.socket) -> int | None:
        # Deliberately a single hop, not a walk like _peer_is_trusted_ui's:
        # sudo's askpass mechanism forks and execs the helper directly, with
        # no shell in between (confirmed in this project's own wrapper
        # scripts), so the real chain is always exactly peer -> sudo. Walking
        # further up would accept a caller that merely has sudo somewhere in
        # its ancestry, not one sudo itself just spawned to ask a password.
        # Returns the verified parent pid (so callers can also read its real
        # cmdline, see _read_proc_cmdline) rather than just True/False.
        creds = self._peer_credentials(conn)
        if creds is None:
            return None
        pid, uid = creds
        if uid != os.getuid():
            return None
        info = self._process_ppid_and_comm(pid)
        if info is None:
            return None
        parent_pid, _own_comm = info
        if parent_pid <= 1:
            return None
        parent = self._process_comm_and_uids(parent_pid)
        if parent is None:
            return None
        parent_comm, parent_real_uid, parent_effective_uid = parent
        # comm alone was shown to be forgeable (issue #9558): a process can
        # rename itself "sudo" via prctl with no privilege at all. Pairing it
        # with a genuine privilege escalation closes that — see
        # DEFAULT_TRUSTED_SUDO_REQUIRES_ESCALATION above for why that part
        # can't be forged by a same-user process.
        privilege_escalated = parent_effective_uid != parent_real_uid
        if (
            parent_comm == self.trusted_sudo_exe
            and parent_real_uid == os.getuid()
            and (privilege_escalated or not self.trusted_sudo_requires_escalation)
        ):
            return parent_pid
        return None

    @staticmethod
    def _read_proc_cmdline(pid: int) -> str | None:
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return None
        parts = [part for part in raw.split(b"\0") if part]
        if not parts:
            return None
        return " ".join(part.decode("utf-8", "replace") for part in parts)

    @staticmethod
    def _process_ppid_and_comm(pid: int) -> tuple[int, str] | None:
        # Comparing /proc/<pid>/exe (the binary's real path, not forgeable
        # via argv[0]/prctl) would be stronger than comm — but reading
        # another process's exe, even from the same user, requires
        # ptrace-equivalent permission, and a systemd --user service gets
        # that permission denied (EACCES) even with CAP_SYS_PTRACE granted
        # and zero extra hardening (confirmed by testing; the same read
        # works normally outside systemd). /proc/<pid>/comm doesn't require
        # that permission. This trades "impossible to forge" for "requires
        # a deliberate step" (renaming the process via prctl/argv[0]) —
        # worse than ideal, but much better than accepting any caller with
        # the token, which is what existed before this fix.
        try:
            comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
        except OSError:
            comm = ""
        try:
            stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            # Same trick as _process_identity: the process name can contain
            # spaces/parentheses, so read the fields after the last ")". In
            # that slice, ppid is field 1 (0-indexed).
            fields = stat_text.rsplit(")", 1)[1].split()
            ppid = int(fields[1])
        except (OSError, IndexError, ValueError):
            return None
        return ppid, comm

    @staticmethod
    def _process_comm_and_uids(pid: int) -> tuple[str, int, int] | None:
        # Returns (comm, real_uid, effective_uid). comm is forgeable, as
        # above; a real_uid/effective_uid mismatch is not — the kernel only
        # reports one for a process that actually executed a setuid binary.
        # See DEFAULT_TRUSTED_SUDO_REQUIRES_ESCALATION. (The broker's own
        # sandboxing remaps uids it can't resolve in its user namespace to
        # the kernel's overflow uid rather than denying the read outright —
        # confirmed live: real sudo's actual "0" effective uid shows up here
        # as that overflow value, not 0. Comparing real_uid != effective_uid
        # instead of effective_uid == 0 doesn't care which one it is.)
        try:
            comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
        except OSError:
            return None
        try:
            status_text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
            uid_line = next(
                line for line in status_text.splitlines() if line.startswith("Uid:")
            )
            fields = uid_line.split()
            real_uid, effective_uid = int(fields[1]), int(fields[2])
        except (OSError, IndexError, StopIteration, ValueError):
            return None
        return comm, real_uid, effective_uid

    @staticmethod
    def _process_identity(pid: int) -> dict[str, Any] | None:
        proc = Path(f"/proc/{pid}")
        try:
            stat_text = (proc / "stat").read_text(encoding="utf-8")
            # The process name can contain spaces; use the fields after the
            # last ")" to keep the start-time index stable.
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
            if (
                not self.askpass_identity_available
                and now - self._askpass_unavailable_last_logged > 60.0
            ):
                self._log_askpass_unavailable()
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
                stale_sudo_pids = [
                    spid for spid, info in self._sudo_pid_attempts.items()
                    if now - info["last_seen"] > RETRY_WINDOW_SECONDS
                ]
                for spid in stale_sudo_pids:
                    del self._sudo_pid_attempts[spid]

    @staticmethod
    def _send(conn: socket.socket, payload: dict[str, Any]) -> None:
        try:
            conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        except OSError:
            # The client may have dropped the connection after receiving the accept.
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--token", default=None)
    parser.add_argument("--llm-capability", default=None)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--trusted-ui-exe", default=None)
    parser.add_argument("--trusted-sudo-exe", default=None)
    parser.add_argument(
        "--trusted-sudo-allow-unprivileged-parent", action="store_true", default=False,
    )
    parser.add_argument("--trusted-askpass-path", default=None)
    parser.add_argument(
        "--trusted-askpass-skip-identity-check", action="store_true", default=False,
    )
    args = parser.parse_args()
    token = args.token or os.environ.get("DOORMAN_TOKEN")
    capability = args.llm_capability or os.environ.get("DOORMAN_LLM_CAPABILITY")
    if not token or not capability:
        parser.error("use --token/DOORMAN_TOKEN and --llm-capability/DOORMAN_LLM_CAPABILITY")
    trusted_ui_exe = (
        args.trusted_ui_exe
        or os.environ.get("DOORMAN_TRUSTED_UI_EXE")
        or DEFAULT_TRUSTED_UI_EXE
    )
    trusted_sudo_exe = (
        args.trusted_sudo_exe
        or os.environ.get("DOORMAN_TRUSTED_SUDO_EXE")
        or DEFAULT_TRUSTED_SUDO_EXE
    )
    trusted_sudo_requires_escalation = not (
        args.trusted_sudo_allow_unprivileged_parent
        or os.environ.get("DOORMAN_TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT") == "1"
    )
    trusted_askpass_path = (
        args.trusted_askpass_path
        or os.environ.get("DOORMAN_TRUSTED_ASKPASS_PATH")
        or DEFAULT_TRUSTED_ASKPASS_PATH
    )
    trusted_askpass_skip_identity_check = (
        args.trusted_askpass_skip_identity_check
        or os.environ.get("DOORMAN_TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK") == "1"
    )
    Broker(
        args.socket, token, capability, max(1.0, min(args.timeout, 300.0)),
        trusted_ui_exe, trusted_sudo_exe, trusted_sudo_requires_escalation,
        trusted_askpass_path, trusted_askpass_skip_identity_check,
    ).serve()


if __name__ == "__main__":
    main()
