# Askpass identity, 6th design — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close both open findings on commit `67a6a06` (the O_PATH/fstat bypass of the askpass identity check, and the symlink/env file-exfiltration via `cap_dac_read_search`) by replacing the `SCM_RIGHTS`+fstat mechanism with a synchronous, accept-time peer-identity check performed by a new, separate systemd unit, plus independent fixes for the symlink-exfil and environment-trust findings.

**Architecture:** A new `omarchy-doorman-identity-helper.service` (a `--user` unit, deliberately not a child of the broker, so it keeps none of the broker's mount-namespace-creating hardening) answers one question over a small Unix-socket protocol: does a given pid's `/proc/<pid>/exe` identify the same file (device+inode) as the trusted, root-installed askpass binary? The broker queries it synchronously, immediately at `accept()`, before reading anything else from the peer — defeating the validated `fork()`+shared-socket timing attack — with a `pidfd_open()` held for the duration of that one query to close the pid-reuse window during the IPC hop. The askpass binary goes back to being privilege-free (no capability, no fd-passing); it independently gets an `O_NOFOLLOW`+canonical-path check on its token-file reads, and stops trusting `XDG_RUNTIME_DIR`/`DOORMAN_SOCKET` from the environment in production.

**Tech Stack:** Python 3 standard library only (broker, identity helper, tests); C11 (askpass binary, compiled with `cc -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2`); `systemd --user` units; Bash (install/run scripts).

**Spec:** [`docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md`](../specs/2026-11-05-askpass-identity-6th-design.md) — read both documents; this plan assumes the spec's "Validated findings" and "Non-goals" sections without repeating their reasoning.

## Global Constraints

- Python stdlib only, no third-party dependency (matches `pyproject.toml` / CI's `dependency-review-action`).
- The askpass binary stays a single, dependency-free C11 source file: no `exec`, no library beyond libc, builds clean under `cc -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2`.
- No file capability, `setuid`, or `setgid` bit anywhere in the new design (design doc Goals).
- Never weaken, remove, or work around any existing directive in `packaging/omarchy-doorman.service` (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`, or any other). If a task seems to require this, stop and flag it instead of shipping it (design doc anti-goals).
- Identity comparisons are always device+inode (`fstat()`), never a path string (`SPEC.md` §6.11).
- Fail closed, fail loud: any ambiguity (helper unreachable, malformed message, missing trusted path, timeout) rejects the request with a distinct error — never a silent accept (`SPEC.md` §2).
- `python3 -m unittest discover -s tests -p 'test_*.py'` must keep passing after every task.
- The `DOORMAN_SOCKET`/`XDG_RUNTIME_DIR` env-trust fix is scoped to `askpass/doorman-askpass.c` only — the one binary an attacker can reach by invoking `/usr/bin/sudo` directly with `SUDO_ASKPASS` set, bypassing every wrapper this project ships. `scripts/doorman-sudo`, `scripts/run-doorman-broker`, and `scripts/doorman-run` already run under the invoking user's own deliberate choice to use them, not an attacker bypassing them — don't change their env handling, only their comments where stale (Task 5).

## Review Focus

- A peer's pid exits between `SO_PEERCRED` capture and the identity-helper's `/proc/<pid>/exe` read (the process already gone) — the helper must answer "no match," not crash or hang, and the broker must reject cleanly. Covered by Task 1's `test_rejects_nonexistent_pid` and Task 2's unreachable/mismatch tests.
- UI connections (`approve`/`cancel`/`pending`/`stats`) must keep working even though every accepted connection now triggers an identity-helper query that UI connections never consult — including while the helper is unreachable. Covered by Task 2's `test_untrusted_caller_cannot_approve_cancel_pending_or_stats` (unchanged) staying green with the new `_handle` structure, plus a new assertion that UI calls succeed while the broker's configured helper socket doesn't exist.
- A malformed or oversized message sent directly at the identity-helper's own socket must not crash the helper process or wedge its accept loop for the next connection. Covered by Task 1's `test_malformed_message_does_not_crash_helper`.
- The askpass binary's `O_NOFOLLOW`+canonical-path check must reject a symlinked token/capability file even when the symlink's target is a file this user could otherwise read — isolating that defense from the (already-sufficient-on-its-own) capability removal. Covered by Task 3's `test_symlinked_token_file_is_rejected_even_when_target_is_readable`.
- `--trusted-askpass-skip-identity-check` must bypass the identity-helper query entirely — no connection attempt at all — so the bulk of the existing test suite keeps running without a live helper process. Covered by Task 2's `test_skip_identity_check_never_contacts_identity_helper`.

---

## Task 1: Identity-helper service

**Files:**
- Create: `identity_helper/__init__.py`
- Create: `identity_helper/identity_helper.py`
- Create: `packaging/omarchy-doorman-identity-helper.service`
- Create: `scripts/run-doorman-identity-helper`
- Test: `tests/test_identity_helper.py`

**Interfaces:**
- Produces: `IdentityHelper(socket_path: Path, trusted_askpass_path: str)` with `.serve() -> None` (blocks, like `Broker.serve()`). Wire protocol consumed by Task 2: client connects `AF_UNIX`/`SOCK_STREAM`, sends one line `{"pid": <int>}\n`, reads back one line `{"ok": <bool>}\n`. No further fields, no auth beyond the socket's own filesystem permissions (matches the broker's own "same-uid, same-filesystem-permission" trust boundary; see `SPEC.md` §6.9's token-file precedent).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_identity_helper.py
from __future__ import annotations
import json, os, socket, subprocess, sys, tempfile, time, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

def _query(socket_path: Path, pid: int) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(3.0)
        conn.connect(str(socket_path))
        conn.sendall((json.dumps({"pid": pid}) + "\n").encode())
        line = conn.makefile("rb").readline(256)
    return json.loads(line)

class IdentityHelperTest(unittest.TestCase):
    def _start(self, trusted_path: str) -> Path:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        socket_path = Path(temp.name) / "helper.sock"
        process = subprocess.Popen(
            [sys.executable, "-m", "identity_helper.identity_helper",
             "--socket", str(socket_path), "--trusted-askpass-path", trusted_path],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(lambda: process.stderr and process.stderr.close())
        self.addCleanup(lambda: process.stdout and process.stdout.close())
        self.addCleanup(process.wait, timeout=2)
        self.addCleanup(process.terminate)
        for _ in range(50):
            if socket_path.exists():
                return socket_path
            time.sleep(0.02)
        self.fail("identity helper did not create its socket")

    def test_identifies_matching_pid_as_trusted(self) -> None:
        socket_path = self._start(sys.executable)
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            cwd=ROOT,
        )
        self.addCleanup(proc.wait, timeout=3)
        self.addCleanup(proc.terminate)
        self.assertEqual(_query(socket_path, proc.pid), {"ok": True})

    def test_rejects_non_matching_pid(self) -> None:
        socket_path = self._start("/usr/bin/true")
        self.assertEqual(_query(socket_path, os.getpid()), {"ok": False})

    def test_rejects_nonexistent_pid(self) -> None:
        socket_path = self._start("/usr/bin/true")
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait(timeout=2)
        self.assertEqual(_query(socket_path, proc.pid), {"ok": False})

    def test_malformed_message_does_not_crash_helper(self) -> None:
        socket_path = self._start("/usr/bin/true")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3.0)
            conn.connect(str(socket_path))
            conn.sendall(b"not json at all\n")
        self.assertEqual(_query(socket_path, os.getpid()), {"ok": False})

    def test_missing_trusted_path_rejects_everything_without_crashing(self) -> None:
        socket_path = self._start("/nonexistent/doorman-fixture-missing")
        self.assertEqual(_query(socket_path, os.getpid()), {"ok": False})

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_identity_helper -v`
Expected: FAIL/ERROR on every test — `identity_helper.identity_helper` doesn't exist yet.

- [ ] **Step 3: Implement `identity_helper/__init__.py`**

```python
"""Doorman's identity-helper service."""
```

- [ ] **Step 4: Implement `identity_helper/identity_helper.py`**

```python
#!/usr/bin/env python3
"""Doorman's identity-helper service.

A separate systemd --user unit, deliberately not a child process of the
broker, so it is not subject to the broker's own mount-namespace hardening
(ProtectSystem=strict/ProtectHome=read-only/PrivateTmp=true/
ProtectKernelTunables=true/ProtectControlGroups=true), which blocks reading
another process's /proc/<pid>/exe regardless of capabilities — see
docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md. Given a
pid, this answers one question: does /proc/<pid>/exe identify the same file
(device+inode, never a path string — SPEC.md §6.11) as the trusted,
root-installed askpass binary?
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import threading
from pathlib import Path

MAX_LINE = 256
DEFAULT_TRUSTED_ASKPASS_PATH = "/usr/local/lib/omarchy-doorman/doorman-askpass"


class IdentityHelper:
    def __init__(self, socket_path: Path, trusted_askpass_path: str) -> None:
        self.socket_path = socket_path
        try:
            st = os.stat(trusted_askpass_path)
            self._trusted_identity: tuple[int, int] | None = (st.st_dev, st.st_ino)
        except OSError:
            self._trusted_identity = None
            print(
                f"doorman identity-helper: trusted askpass path "
                f"{trusted_askpass_path!r} doesn't exist — every identity "
                "check will answer 'no match' until "
                "scripts/doorman-install-askpass has been run as root.",
                file=sys.stderr, flush=True,
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
            print(f"doorman identity-helper listening on {self.socket_path}", flush=True)
            while True:
                conn, _ = server.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(3.0)
            try:
                line = self._recv_line(conn)
            except OSError:
                return
            if not line:
                return
            try:
                message = json.loads(line)
                pid = int(message["pid"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                return
            self._send(conn, {"ok": self._identifies_trusted_askpass(pid)})

    @staticmethod
    def _recv_line(conn: socket.socket) -> bytes | None:
        buf = bytearray()
        while len(buf) <= MAX_LINE:
            chunk = conn.recv(MAX_LINE + 1 - len(buf))
            if not chunk:
                return None
            buf += chunk
            if b"\n" in chunk:
                break
        newline_idx = buf.find(b"\n")
        if newline_idx == -1 or len(buf) > MAX_LINE:
            return None
        return bytes(buf[:newline_idx])

    def _identifies_trusted_askpass(self, pid: int) -> bool:
        if self._trusted_identity is None or pid <= 0:
            return False
        try:
            fd = os.open(f"/proc/{pid}/exe", os.O_PATH)
        except OSError:
            return False
        try:
            st = os.fstat(fd)
        finally:
            os.close(fd)
        return (st.st_dev, st.st_ino) == self._trusted_identity

    @staticmethod
    def _send(conn: socket.socket, payload: dict) -> None:
        try:
            conn.sendall((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--trusted-askpass-path", default=None)
    args = parser.parse_args()
    trusted_askpass_path = (
        args.trusted_askpass_path
        or os.environ.get("DOORMAN_TRUSTED_ASKPASS_PATH")
        or DEFAULT_TRUSTED_ASKPASS_PATH
    )
    IdentityHelper(args.socket, trusted_askpass_path).serve()


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_identity_helper -v`
Expected: PASS, all 5 tests.

- [ ] **Step 6: Create the packaging unit file `packaging/omarchy-doorman-identity-helper.service`**

```ini
[Unit]
Description=Omarchy Doorman Identity Helper
After=graphical-session.target
PartOf=graphical-session.target

[Service]
Type=simple
WorkingDirectory=/home/mauriciocunha/DEV/omarchy-doorman
ExecStart=/home/mauriciocunha/DEV/omarchy-doorman/scripts/run-doorman-identity-helper
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
RuntimeDirectory=omarchy-doorman-identity-helper
RuntimeDirectoryMode=0700
ReadWritePaths=%t/omarchy-doorman-identity-helper
UMask=0077

# Deliberately omits PrivateTmp=, ProtectSystem=, ProtectHome=,
# ProtectKernelTunables=, ProtectControlGroups= — each one independently
# blocks reading another process's /proc/<pid>/exe by putting this unit in
# its own private mount namespace (2026-11-05 "Validated findings" item 1,
# docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md). Keeps
# every other directive confirmed in that same finding not to break the
# check.
RestrictAddressFamilies=AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
RemoveIPC=true
CapabilityBoundingSet=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=graphical-session.target
```

- [ ] **Step 7: Create the runner script `scripts/run-doorman-identity-helper`**

```bash
#!/usr/bin/env bash
set -euo pipefail

runtime_dir="${XDG_RUNTIME_DIR:?}/omarchy-doorman-identity-helper"
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$runtime_dir"
cd "$project_dir"
exec /usr/bin/python3 -m identity_helper.identity_helper \
  --socket "$runtime_dir/helper.sock"
```

Make it executable: `chmod +x scripts/run-doorman-identity-helper`.

- [ ] **Step 8: Commit**

```bash
git add identity_helper/ packaging/omarchy-doorman-identity-helper.service \
  scripts/run-doorman-identity-helper tests/test_identity_helper.py
git commit -m "feat(doorman): add identity-helper service for askpass identity checks"
```

---

## Task 2: Broker — replace SCM_RIGHTS with the identity-helper query

**Files:**
- Modify: `broker/broker.py`
- Modify: `packaging/omarchy-doorman.service` (add `Wants=`/`After=` on the new unit)
- Test: `tests/test_broker.py`

**Interfaces:**
- Consumes: Task 1's `identity_helper` wire protocol (`{"pid": <int>}\n` → `{"ok": <bool>}\n` over `AF_UNIX`).
- Produces: `Broker.__init__(..., identity_helper_socket: Path, trusted_askpass_skip_identity_check: bool = False)` (replaces the old `trusted_askpass_path` parameter in that same position). New CLI flag `--identity-helper-socket` / env `DOORMAN_IDENTITY_HELPER_SOCKET` (replaces `--trusted-askpass-path`/`DOORMAN_TRUSTED_ASKPASS_PATH` on the broker's own CLI — that env var moves to the identity helper, Task 1, unchanged by name). New wire error codes on a `request`: `identity_helper_unreachable` (helper didn't answer in time or at all) and the retained `untrusted_askpass_helper` (helper answered, said no match). `askpass_identity_available` keeps its name and its `stats`/`Panel.qml` surfacing, now meaning "the identity-helper was reachable when the broker started" (computed once in `__init__`, same timing as the code it replaces).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_broker.py`, replacing the three existing SCM_RIGHTS-based identity tests (`test_request_with_mismatched_askpass_identity_is_rejected`, `test_request_is_rejected_when_askpass_path_is_missing`, `test_request_with_real_trusted_askpass_identity_is_accepted` — delete these three and their now-unused helpers `_SUBPROCESS_REQUEST_AND_HOLD_WITH_IDENTITY_CODE`/`_request_and_hold_with_identity`/`_ALWAYS_PRESENT_OTHER_PATH`) and adding a shared fixture plus new tests:

```python
# Shared fixture, added to BrokerTest:
def _start_identity_helper(self, trusted_path: str) -> Path:
    temp = tempfile.TemporaryDirectory()
    self.addCleanup(temp.cleanup)
    socket_path = Path(temp.name) / "helper.sock"
    process = subprocess.Popen(
        [sys.executable, "-m", "identity_helper.identity_helper",
         "--socket", str(socket_path), "--trusted-askpass-path", trusted_path],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    self.addCleanup(lambda: process.stderr and process.stderr.close())
    self.addCleanup(lambda: process.stdout and process.stdout.close())
    self.addCleanup(process.wait, timeout=2)
    self.addCleanup(process.terminate)
    for _ in range(50):
        if socket_path.exists():
            return socket_path
        time.sleep(0.02)
    self.fail("identity helper did not create its socket")

# New SUBPROCESS_*_CODE constants, module level:
_SUBPROCESS_FORK_EXEC_ATTACK_CODE = (
    "import json, os, socket, sys, time\n"
    "socket_path, token, payload_json = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "payload = json.loads(payload_json)\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "s.connect(socket_path)\n"
    "pid = os.fork()\n"
    "if pid == 0:\n"
    "    time.sleep(0.3)\n"
    "    payload['pid'] = os.getppid()\n"
    "    msg = {'token': token, 'type': 'request', **payload}\n"
    "    s.sendall((json.dumps(msg) + chr(10)).encode())\n"
    "    line = s.makefile('rb').readline()\n"
    "    sys.stdout.write(line.decode()); sys.stdout.flush()\n"
    "    os._exit(0)\n"
    "else:\n"
    "    os.execv('/usr/bin/true', ['/usr/bin/true'])\n"
)

_SUBPROCESS_SEND_FOREIGN_OPATH_FD_CODE = (
    "import array, json, os, socket, sys\n"
    "socket_path, token, trusted_path, payload_json = sys.argv[1:5]\n"
    "payload = json.loads(payload_json); payload['pid'] = os.getpid()\n"
    "msg = {'token': token, 'type': 'request', **payload}\n"
    "line = (json.dumps(msg) + chr(10)).encode()\n"
    "foreign_fd = os.open(trusted_path, os.O_PATH)\n"
    "with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:\n"
    "    conn.connect(socket_path)\n"
    "    cmsg = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [foreign_fd]))]\n"
    "    conn.sendmsg([line], cmsg)\n"
    "    os.close(foreign_fd)\n"
    "    resp = conn.makefile('rb').readline()\n"
    "    sys.stdout.write(resp.decode()); sys.stdout.flush()\n"
)

# New test methods on BrokerTest:

def test_skip_identity_check_never_contacts_identity_helper(self) -> None:
    # self.process already runs with TRUSTED_ASKPASS_SKIP_IDENTITY_CHECK and
    # an --identity-helper-socket that was never started (no helper process
    # at all) — if a request still succeeds, the broker never tried to
    # reach it.
    result = _call_as_subprocess(
        self.socket_path, self.token,
        {"type": "request", "command": "skip-check-attempt",
         "origin": "llm", "capability": self.capability},
    )
    self.assertTrue(result["ok"], result)

def test_request_with_mismatched_askpass_identity_is_rejected(self) -> None:
    helper_socket = self._start_identity_helper(_ALWAYS_PRESENT_OTHER_PATH)
    temp = tempfile.TemporaryDirectory()
    self.addCleanup(temp.cleanup)
    socket_path = Path(temp.name) / "broker-askpass-mismatch.sock"
    process = subprocess.Popen(
        [
            sys.executable, "-m", "broker.broker",
            "--socket", str(socket_path),
            "--token", self.token,
            "--llm-capability", self.capability,
            "--timeout", "2",
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            "--identity-helper-socket", str(helper_socket),
        ],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    self.addCleanup(lambda: process.stderr and process.stderr.close())
    self.addCleanup(lambda: process.stdout and process.stdout.close())
    self.addCleanup(process.wait, timeout=2)
    self.addCleanup(process.terminate)
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.02)
    else:
        self.fail("broker did not create the socket")

    result = _call_as_subprocess(
        socket_path, self.token,
        {"type": "request", "command": "untrusted-askpass-attempt",
         "origin": "llm", "capability": self.capability},
    )
    self.assertEqual(result, {"ok": False, "error": "untrusted_askpass_helper"})

def test_request_is_rejected_when_helper_has_no_matching_trusted_path(self) -> None:
    missing_path = f"/nonexistent/doorman-askpass-test-missing-{uuid.uuid4().hex}"
    helper_socket = self._start_identity_helper(missing_path)
    # ... spawn a broker pointed at helper_socket, same shape as above ...
    result = _call_as_subprocess(
        socket_path, self.token,
        {"type": "request", "command": "unavailable-trusted-path-attempt",
         "origin": "llm", "capability": self.capability},
    )
    self.assertEqual(result, {"ok": False, "error": "untrusted_askpass_helper"})

def test_request_is_rejected_when_identity_helper_is_unreachable(self) -> None:
    temp = tempfile.TemporaryDirectory()
    self.addCleanup(temp.cleanup)
    socket_path = Path(temp.name) / "broker-helper-down.sock"
    missing_helper_socket = Path(temp.name) / "no-such-helper.sock"
    process = subprocess.Popen(
        [
            sys.executable, "-m", "broker.broker",
            "--socket", str(socket_path), "--token", self.token,
            "--llm-capability", self.capability, "--timeout", "2",
            "--trusted-sudo-exe", TEST_TRUSTED_SUDO_EXE,
            TRUSTED_SUDO_ALLOW_UNPRIVILEGED_PARENT,
            "--identity-helper-socket", str(missing_helper_socket),
        ],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    self.addCleanup(lambda: process.stderr and process.stderr.close())
    self.addCleanup(lambda: process.stdout and process.stdout.close())
    self.addCleanup(process.wait, timeout=2)
    self.addCleanup(process.terminate)
    for _ in range(50):
        if socket_path.exists():
            break
        time.sleep(0.02)
    else:
        self.fail("broker did not create the socket")

    result = _call_as_subprocess(
        socket_path, self.token,
        {"type": "request", "command": "helper-down-attempt",
         "origin": "llm", "capability": self.capability},
    )
    self.assertEqual(result, {"ok": False, "error": "identity_helper_unreachable"})
    stats = call(socket_path, self.token, {"type": "stats"})
    self.assertFalse(stats["askpass_identity_available"])
    # UI-style calls still work while the helper is down.
    pending = call(socket_path, self.token, {"type": "pending"})
    self.assertTrue(pending["ok"])

def test_request_with_real_trusted_askpass_identity_is_accepted(self) -> None:
    helper_socket = self._start_identity_helper(sys.executable)
    # ... spawn a broker pointed at helper_socket (no skip-identity-check) ...
    payload = {"command": "real-identity-attempt", "origin": "llm", "capability": self.capability}
    created, proc = _request_and_hold(socket_path, self.token, payload)
    self.addCleanup(lambda: proc.stdout and proc.stdout.close())
    self.addCleanup(proc.wait, timeout=5)
    self.assertTrue(created.get("ok"), created)

def test_fork_then_exec_on_connecting_peer_is_rejected(self) -> None:
    helper_socket = self._start_identity_helper("/usr/bin/true")
    # ... spawn a broker pointed at helper_socket ...
    payload = json.dumps({"command": "fork-exec-attack", "origin": "llm", "capability": self.capability})
    proc = subprocess.Popen(
        [sys.executable, "-c", _SUBPROCESS_FORK_EXEC_ATTACK_CODE,
         str(socket_path), self.token, payload],
        cwd=ROOT, stdout=subprocess.PIPE, text=True,
    )
    self.addCleanup(proc.wait, timeout=3)
    out = proc.stdout.readline()
    self.assertEqual(json.loads(out), {"ok": False, "error": "untrusted_askpass_helper"})

def test_scm_rights_fd_is_ignored_identity_still_checked_against_real_peer_exe(self) -> None:
    helper_socket = self._start_identity_helper("/usr/bin/true")
    # ... spawn a broker pointed at helper_socket ...
    payload = json.dumps({"command": "opath-bypass-attempt", "origin": "llm", "capability": self.capability})
    proc = subprocess.Popen(
        [sys.executable, "-c", _SUBPROCESS_SEND_FOREIGN_OPATH_FD_CODE,
         str(socket_path), self.token, "/usr/bin/true", payload],
        cwd=ROOT, stdout=subprocess.PIPE, text=True,
    )
    self.addCleanup(proc.wait, timeout=3)
    out = proc.stdout.readline()
    self.assertEqual(json.loads(out), {"ok": False, "error": "untrusted_askpass_helper"})
```

(The three new/rewritten tests that need a broker subprocess follow the exact `subprocess.Popen([sys.executable, "-m", "broker.broker", ...])` + socket-wait boilerplate already used throughout this file — give each one its own `tempfile.TemporaryDirectory()` and `--identity-helper-socket` pointed at the relevant `_start_identity_helper(...)` result, matching the pattern shown in full for `test_request_with_mismatched_askpass_identity_is_rejected` above.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_broker -v`
Expected: FAIL — `broker.broker` has no `--identity-helper-socket` flag yet, and `_create_request`/`_handle` haven't changed.

- [ ] **Step 3: Implement the broker changes in `broker/broker.py`**

Remove entirely: the `import array` line; the `DEFAULT_TRUSTED_ASKPASS_PATH` constant and its long comment (lines 60–90); `_recv_line_with_fd` (lines 280–322); `_fd_identity` (lines 575–581); the `identity_fd` parameter and handling in `_handle` and `_create_request`; the `if not self.trusted_askpass_skip_identity_check: ...` block inside `_create_request` (lines 383–390); the `--trusted-askpass-path` CLI flag and its env var resolution in `main()`.

Add `import signal` to the module's import block (needed by `_check_peer_identity`'s `SIGSTOP`/`SIGCONT`/`SIGKILL` calls, added live on 2026-11-05 — see the Addendum in the spec and the updated `_check_peer_identity` below).

Add a module-level constant:

```python
IDENTITY_HELPER_TIMEOUT = 3.0
```

Replace the `trusted_askpass_path`/`_trusted_askpass_identity`/`askpass_identity_available` block in `Broker.__init__` (old lines 136–163) with:

```python
def __init__(
    self,
    socket_path: Path,
    session_token: str,
    llm_capability: str,
    timeout: float,
    trusted_ui_exe: str = DEFAULT_TRUSTED_UI_EXE,
    trusted_sudo_exe: str = DEFAULT_TRUSTED_SUDO_EXE,
    trusted_sudo_requires_escalation: bool = DEFAULT_TRUSTED_SUDO_REQUIRES_ESCALATION,
    identity_helper_socket: Path | None = None,
    trusted_askpass_skip_identity_check: bool = False,
) -> None:
    self.socket_path = socket_path
    self.session_token = session_token
    self.llm_capability = llm_capability
    self.timeout = timeout
    self.trusted_ui_exe = trusted_ui_exe
    self.trusted_sudo_exe = trusted_sudo_exe
    self.trusted_sudo_requires_escalation = trusted_sudo_requires_escalation
    self.identity_helper_socket = identity_helper_socket or Path(_default_identity_helper_socket())
    self.trusted_askpass_skip_identity_check = trusted_askpass_skip_identity_check
    self._askpass_unavailable_last_logged = 0.0
    if trusted_askpass_skip_identity_check:
        self.askpass_identity_available = True
    else:
        self.askpass_identity_available = self._ping_identity_helper()
        if not self.askpass_identity_available:
            self._log_askpass_unavailable()
    ...  # self.pending, self._sudo_pid_attempts, self.lock, etc. unchanged
```

(`identity_helper_socket` must come after parameters that already have defaults, so it needs one too — `None` here, resolved to the same computed default `main()` uses via `_default_identity_helper_socket()`, defined as a module-level function used by both. Every production/test caller should still pass it explicitly; the default only avoids a `SyntaxError` and covers a hypothetical direct instantiation.)

Update `_log_askpass_unavailable`'s message to reference the identity-helper unit instead of the install script:

```python
def _log_askpass_unavailable(self) -> None:
    self._askpass_unavailable_last_logged = time.time()
    print(
        f"doorman broker: identity-helper at {self.identity_helper_socket!r} "
        "was not reachable at startup — askpass requests will be refused "
        "(identity_helper_unreachable) until omarchy-doorman-identity-helper"
        ".service is running. This is deliberate: it's quieter to fail "
        "loudly here than to silently accept the weaker, pre-#9558 "
        "guarantee.",
        file=sys.stderr,
        flush=True,
    )
```

Add three new methods (near `_peer_credentials`):

```python
def _ping_identity_helper(self) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(IDENTITY_HELPER_TIMEOUT)
            conn.connect(str(self.identity_helper_socket))
    except OSError:
        return False
    return True

def _query_identity_helper(self, pid: int) -> str:
    """Returns "match", "no_match", or "unreachable"."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(IDENTITY_HELPER_TIMEOUT)
            conn.connect(str(self.identity_helper_socket))
            conn.sendall((json.dumps({"pid": pid}) + "\n").encode())
            line = conn.makefile("rb").readline(256)
    except OSError:
        return "unreachable"
    try:
        resp = json.loads(line)
    except json.JSONDecodeError:
        return "unreachable"
    return "match" if resp.get("ok") is True else "no_match"

def _check_peer_identity(self, conn: socket.socket) -> str:
    # Called unconditionally for every accepted connection, immediately in
    # _handle, before any data is read from the peer. A check performed
    # any later, OR any check that merely races the query against the
    # peer's own fork()+exec(), can be fooled — confirmed live, 2026-11-05,
    # against the real identity-helper (3/3 vulnerable without the SIGSTOP
    # below; the broker<->helper round trip measured ~1-1.6ms, comfortably
    # enough for an attacker's fork()+execve() to complete first). See
    # docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md,
    # "Validated findings" item 3 and its Addendum.
    creds = self._peer_credentials(conn)
    if creds is None or creds[1] != os.getuid():
        return "no_match"
    pid = creds[0]
    try:
        # Freezes the peer before it can call fork()/execve() at all — not
        # a speed race, since SIGSTOP cannot be caught, blocked, or ignored
        # by the target (POSIX). Uses the uid-based signal permission
        # model, a different kernel path from ptrace_may_access() (which
        # finding 1 showed the broker's own sandboxing blocks) — confirmed
        # live under the broker's full real hardening stack: sending
        # SIGSTOP/SIGCONT to an ordinary sibling process needs no special
        # permission and raises nothing. Must happen before pidfd_open and
        # before the helper query, in that order, every time.
        #
        # IMPORTANT: the peer is ALWAYS resumed via SIGCONT below,
        # regardless of whether the identity matched — never killed here.
        # This connection may be a trusted-UI connection (approve/cancel/
        # pending/stats), whose own exe is Quickshell/bridge.py and will
        # legitimately never match the askpass trusted path; killing on
        # "no_match" would kill the UI on every single interaction. The
        # security property this buys is simpler than "kill the attacker":
        # it just guarantees the *snapshot* taken before resuming is the
        # peer's true, pre-fork/exec identity, which the cached outcome
        # then persists for _handle to act on once the message's kind is
        # known. What happens to the peer process *after* being resumed is
        # irrelevant — the broker's decision was already made.
        os.kill(pid, signal.SIGSTOP)
    except OSError:
        return "no_match"
    try:
        try:
            # Pins this exact pid against kernel reuse for the duration of
            # the broker<->helper round trip (pidfd_open(2)); without this,
            # a pid reused by an unrelated process mid-query would be a
            # narrower version of the same bug this whole design exists to
            # close. The peer is already stopped by now, so this isn't
            # closing the fork/exec race — just the separate pid-reuse one.
            pidfd = os.pidfd_open(pid, 0)
        except OSError:
            return "no_match"
        try:
            return self._query_identity_helper(pid)
        finally:
            os.close(pidfd)
    finally:
        # MUST run no matter how the block above exits (return, or an
        # exception neither try above caught) — a stopped peer that's
        # never resumed hangs forever. Confirmed the hard way: an
        # unrelated bug in this mitigation's own validation harness
        # crashed the query step after SIGSTOP had already been sent, and
        # the test process hung permanently stopped until something
        # external killed it. Always SIGCONT, never SIGKILL here — see the
        # comment above the SIGSTOP call for why killing on "no_match"
        # would be wrong (it would kill every legitimate UI connection).
        try:
            os.kill(pid, signal.SIGCONT)
        except OSError:
            pass  # ESRCH (peer already gone) — nothing left to resume
```

Replace `_recv_line_with_fd` with a plain `_recv_line` (same bounded-line-read contract, no `recvmsg`/ancillary data):

```python
@staticmethod
def _recv_line(conn: socket.socket) -> bytes | None:
    buf = bytearray()
    while len(buf) <= MAX_LINE:
        try:
            chunk = conn.recv(MAX_LINE + 1 - len(buf))
        except OSError:
            chunk = b""
        if not chunk:
            return None
        buf += chunk
        if b"\n" in chunk:
            break
    newline_idx = buf.find(b"\n")
    if newline_idx == -1 or len(buf) > MAX_LINE:
        return None
    return bytes(buf[:newline_idx])
```

Rewrite `_handle` to run the identity check first, cache its result, and only consult it once `kind == "request"`:

```python
def _handle(self, conn: socket.socket) -> None:
    with conn:
        identity_outcome = (
            "match" if self.trusted_askpass_skip_identity_check
            else self._check_peer_identity(conn)
        )
        conn.settimeout(HANDSHAKE_TIMEOUT)
        try:
            line = self._recv_line(conn)
        finally:
            conn.settimeout(None)
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
            if identity_outcome == "unreachable":
                self._send(conn, {"ok": False, "error": "identity_helper_unreachable"})
                return
            if identity_outcome == "no_match":
                self._send(conn, {"ok": False, "error": "untrusted_askpass_helper"})
                return
            if not self._valid_llm_origin(message):
                self._send(conn, {"ok": False, "error": "invalid_llm_origin"})
                return
            self._create_request(conn, message)
        elif kind in ("approve", "cancel", "pending", "stats"):
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
```

In `_create_request`, drop the `identity_fd: int | None` parameter and the whole `if not self.trusted_askpass_skip_identity_check: ...` block (old lines 383–390) — the signature becomes `_create_request(self, conn: socket.socket, message: dict[str, Any]) -> None`, and the function body starts straight at the existing `pid = self._positive_pid(...)` line.

In `main()`, replace the `--trusted-askpass-path` argument with:

```python
parser.add_argument("--identity-helper-socket", type=Path, default=None)
```

and replace its resolution block with:

```python
def _default_identity_helper_socket() -> str:
    return f"/run/user/{os.getuid()}/omarchy-doorman-identity-helper/helper.sock"

...

identity_helper_socket = Path(
    args.identity_helper_socket
    or os.environ.get("DOORMAN_IDENTITY_HELPER_SOCKET")
    or _default_identity_helper_socket()
)
```

(`_default_identity_helper_socket` can live as a module-level function near `main()`.) Update the trailing `Broker(...)` construction call to pass `identity_helper_socket` where `trusted_askpass_path` used to go.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_broker -v`
Expected: PASS, all tests (old and new).

- [ ] **Step 5: Add `Wants=`/`After=` ordering to `packaging/omarchy-doorman.service`**

Add two lines under `[Unit]`, after the existing `After=graphical-session.target`:

```ini
Wants=omarchy-doorman-identity-helper.service
After=omarchy-doorman-identity-helper.service
```

- [ ] **Step 6: Run the full suite**

Run: `python3 -m unittest discover -s tests -p 'test_*.py'`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add broker/broker.py packaging/omarchy-doorman.service tests/test_broker.py
git commit -m "security(doorman): check askpass identity via a synchronous accept-time query to the identity helper, not SCM_RIGHTS"
```

---

## Task 3: Askpass binary — drop the capability, pin paths, add the canonical-path check

**Files:**
- Modify: `askpass/doorman-askpass.c`
- Test: `tests/test_doorman_askpass_c.py`

**Interfaces:**
- Consumes: nothing from Task 1/2 — the binary no longer talks to anything but the broker's plain JSON-line protocol (it drops the `SCM_RIGHTS` half entirely; `broker/broker.py` after Task 2 no longer reads any ancillary data, so this is safe to land in either order, but do it after Task 2 so the compiled-binary test in this task can run its "accepted" round trip against the real, updated broker).
- Produces: a binary with two new environment overrides, test-only: `DOORMAN_RUNTIME_DIR_DEV_OVERRIDE` (replaces reading `XDG_RUNTIME_DIR`) and `DOORMAN_SOCKET_DEV_OVERRIDE` (replaces reading `DOORMAN_SOCKET`). Neither is set anywhere in production (`scripts/doorman-sudo`, `packaging/*.service`); both are consumed only by this task's own test.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_doorman_askpass_c.py
from __future__ import annotations
import os, socket, subprocess, sys, tempfile, threading, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _compile(tmp_dir: Path) -> Path:
    binary = tmp_dir / "doorman-askpass"
    subprocess.run(
        ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
         "-o", str(binary), str(ROOT / "askpass" / "doorman-askpass.c")],
        check=True,
    )
    return binary

class _FakeBroker:
    """Accepts one connection, reads one line, replies 'ok: false,
    error: test_stub' — enough to prove the askpass binary reached the
    socket it was told to, without needing a real broker."""
    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path
        self.received: bytes | None = None
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(str(socket_path))
        self._srv.listen(1)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        conn, _ = self._srv.accept()
        with conn:
            conn.settimeout(3.0)
            self.received = conn.makefile("rb").readline(16384)
            conn.sendall(b'{"ok":false,"error":"test_stub"}\n')

    def close(self) -> None:
        self._srv.close()
        self._thread.join(timeout=2)

class AskpassBinaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.binary = _compile(self.tmp_path)

    def _run_askpass(self, env: dict[str, str]) -> subprocess.CompletedProcess:
        full_env = os.environ.copy()
        full_env.update(env)
        return subprocess.run([str(self.binary)], env=full_env, capture_output=True, timeout=5)

    def test_ignores_xdg_runtime_dir_and_doorman_socket_in_production(self) -> None:
        # Uses DOORMAN_RUNTIME_DIR_DEV_OVERRIDE (not
        # DOORMAN_SOCKET_DEV_OVERRIDE), so the socket path is still derived
        # from runtime_dir the production way. This deliberately never
        # touches this machine's real, getuid()-derived production runtime
        # dir — asserting against that path would be environment-coupled
        # and dangerous: if a real broker is running there, the binary
        # could connect to it for real and pop a live approval prompt in
        # the real Quickshell UI in the middle of a test run. Instead, this
        # isolates the two "ignored in production" claims with hard
        # evidence: the token content actually sent, and which of two fake
        # listeners actually received a connection.
        runtime_dir = self.tmp_path / "runtime"
        runtime_dir.mkdir()
        (runtime_dir / "token").write_text("test-token\n")
        (runtime_dir / "llm-capability").write_text("test-capability\n")
        real_socket = runtime_dir / "broker.sock"
        fake_real = _FakeBroker(real_socket)
        self.addCleanup(fake_real.close)

        evil_runtime_dir = self.tmp_path / "evil-xdg-runtime-dir" / "omarchy-doorman"
        evil_runtime_dir.mkdir(parents=True)
        (evil_runtime_dir / "token").write_text("evil-token\n")
        (evil_runtime_dir / "llm-capability").write_text("evil-capability\n")
        attacker_socket = self.tmp_path / "attacker.sock"
        fake_attacker = _FakeBroker(attacker_socket)
        self.addCleanup(fake_attacker.close)

        self._run_askpass({
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(runtime_dir),
            "XDG_RUNTIME_DIR": str(self.tmp_path / "evil-xdg-runtime-dir"),
            "DOORMAN_SOCKET": str(attacker_socket),
        })
        self.assertIsNone(fake_attacker.received)
        self.assertIsNotNone(fake_real.received)
        self.assertIn(b'"token":"test-token"', fake_real.received)

    def test_dev_override_env_vars_are_honored(self) -> None:
        runtime_dir = self.tmp_path / "runtime"
        runtime_dir.mkdir()
        (runtime_dir / "token").write_text("test-token\n")
        (runtime_dir / "llm-capability").write_text("test-capability\n")
        socket_path = self.tmp_path / "broker.sock"
        fake = _FakeBroker(socket_path)
        self.addCleanup(fake.close)
        result = self._run_askpass({
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(runtime_dir),
            "DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path),
        })
        self.assertIsNotNone(fake.received)
        self.assertIn(b'"token":"test-token"', fake.received)

    def test_symlinked_token_file_is_rejected_even_when_target_is_readable(self) -> None:
        runtime_dir = self.tmp_path / "runtime"
        runtime_dir.mkdir()
        readable_target = self.tmp_path / "world-readable-but-wrong-file"
        readable_target.write_text("not the real token\n")
        os.chmod(readable_target, 0o644)
        (runtime_dir / "token").symlink_to(readable_target)
        (runtime_dir / "llm-capability").write_text("test-capability\n")
        socket_path = self.tmp_path / "broker.sock"
        fake = _FakeBroker(socket_path)
        self.addCleanup(fake.close)
        result = self._run_askpass({
            "DOORMAN_RUNTIME_DIR_DEV_OVERRIDE": str(runtime_dir),
            "DOORMAN_SOCKET_DEV_OVERRIDE": str(socket_path),
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(fake.received)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_doorman_askpass_c -v`
Expected: FAIL — the binary still reads `XDG_RUNTIME_DIR`/`DOORMAN_SOCKET` and has no `O_NOFOLLOW` check.

- [ ] **Step 3: Implement the changes in `askpass/doorman-askpass.c`**

Rewrite the top header comment (lines 1–43) to describe the new design: privilege-free binary, no capability, no `exec`, canonical-path-checked token reads, pinned runtime dir/socket via `getuid()`. State the linking decision explicitly as a one-line comment: **kept dynamically linked** — removing the capability means this binary gains no privilege boundary an `LD_PRELOAD` could cross that the attacker (same uid, already controls the whole invocation environment) didn't already have over any other program they could run instead; static linking would add build complexity and lose automatic libc security patches for no closed threat.

Delete entirely: `send_request_with_identity` (lines 103–130) and the `int identity_fd = open("/proc/self/exe", ...)` block and its error message (lines 397–412). Replace the call site with:

```c
if (write_all(fd, request, (size_t)n) < 0) {
    close(fd);
    return 1;
}
```

Factor the trim loop out of `read_file_trim` into a small shared helper, then add the canonical-path variant:

```c
static void trim_in_place(char *buf, size_t n) {
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                      buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
        buf[--n] = '\0';
    }
    size_t start = 0;
    while (buf[start] == ' ' || buf[start] == '\t' || buf[start] == '\n' ||
           buf[start] == '\r') {
        start++;
    }
    if (start > 0) memmove(buf, buf + start, n - start + 1);
}

/* Opens path with O_NOFOLLOW (blocks the final path component being a
 * symlink), then reads back the fd's own resolved path via
 * /proc/self/fd/<fd> (reflects exactly what was opened — no re-lookup, so
 * no TOCTOU window) and refuses to trust the content unless that resolved
 * path exactly matches expected_path. Closes the 2026-10-25 finding
 * (symlink-following read under an attacker-controlled base directory)
 * independently of runtime_dir already being pinned via getuid() below —
 * defense in depth, not redundant: this also catches an intermediate
 * directory component being a symlink, which O_NOFOLLOW alone does not. */
static char *read_file_trim_canonical(const char *path, const char *expected_path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return NULL;
    char fd_path[64], resolved[800];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(fd_path, resolved, sizeof(resolved) - 1);
    if (n < 0) {
        close(fd);
        return NULL;
    }
    resolved[n] = '\0';
    if (strcmp(resolved, expected_path) != 0) {
        close(fd);
        return NULL;
    }
    FILE *f = fdopen(fd, "rb");
    if (!f) {
        close(fd);
        return NULL;
    }
    char *buf = malloc(MAX_LINE + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t len = fread(buf, 1, MAX_LINE, f);
    fclose(f);
    buf[len] = '\0';
    trim_in_place(buf, len);
    return buf;
}
```

Update `read_file_trim` to call `trim_in_place` instead of its inline copy of the same loop (keep `read_file_trim` itself — nothing else needs the canonical check, e.g. none, since token and capability are the only two files this binary reads; if that turns out to be the only caller, `read_file_trim` can be deleted and `read_file_trim_canonical` used directly — prefer deleting it if so, per "don't keep unused code").

Replace the `runtime_dir`/`token_path`/`cap_path`/`socket_path` construction (old lines 303–330) with:

```c
const char *runtime_override = getenv("DOORMAN_RUNTIME_DIR_DEV_OVERRIDE");
char runtime_dir[768];
if (runtime_override && *runtime_override) {
    snprintf(runtime_dir, sizeof(runtime_dir), "%s", runtime_override);
} else {
    snprintf(runtime_dir, sizeof(runtime_dir), "/run/user/%d/omarchy-doorman",
              (int)getuid());
}

char token_path[800], cap_path[800];
snprintf(token_path, sizeof(token_path), "%s/token", runtime_dir);
snprintf(cap_path, sizeof(cap_path), "%s/llm-capability", runtime_dir);

char *token = read_file_trim_canonical(token_path, token_path);
char *capability = read_file_trim_canonical(cap_path, cap_path);
if (!token || !*token || !capability || !*capability) {
    free(token);
    free(capability);
    return 2;
}

const char *socket_override = getenv("DOORMAN_SOCKET_DEV_OVERRIDE");
char socket_path[800];
if (socket_override && *socket_override) {
    snprintf(socket_path, sizeof(socket_path), "%s", socket_override);
} else {
    snprintf(socket_path, sizeof(socket_path), "%s/broker.sock", runtime_dir);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_doorman_askpass_c -v`
Expected: PASS, all 3 tests.

- [ ] **Step 5: Confirm the strict build still passes**

Run: `cc -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o /tmp/doorman-askpass-check askpass/doorman-askpass.c`
Expected: exits 0, no warnings.

- [ ] **Step 6: Commit**

```bash
git add askpass/doorman-askpass.c tests/test_doorman_askpass_c.py
git commit -m "security(doorman): drop askpass capability/fd-passing, pin runtime paths, add canonical-path check on token reads"
```

---

## Task 4: Install script — drop the capability machinery

**Files:**
- Modify: `scripts/doorman-install-askpass`

**Interfaces:**
- Consumes: Task 3's binary (no longer needs `cap_dac_read_search` to read itself).
- Produces: an installed binary at the same fixed path, `root:root`, mode `0755` (not `0711` — read permission is no longer security-relevant once there is no fd-passing to forge; see design doc's "scripts/doorman-install-askpass" section). No automated test (this step needs root); verified manually in Task 6.

- [ ] **Step 1: Remove the capability machinery**

Delete: the `nosuid` mount-option check block (lines 52–61); the `command -v setcap` check (lines 63–67); the `setcap cap_dac_read_search=ep "$tmp_binary"` line and its surrounding comment (lines 78–81); the `getcap`-based post-install verification block (lines 85–91).

Change `chmod 0711 "$tmp_binary"` to `chmod 0755 "$tmp_binary"`.

Update the final echo to drop the capability from its output:

```bash
echo "doorman-install-askpass: installed $binary_path ($(stat -c '%U:%G %a' -- "$binary_path"))"
echo "doorman-install-askpass: done. Restart the broker (systemctl --user restart omarchy-doorman.service) to pick this up."
```

Rewrite the script's own header comment (lines 1–31) to match: the askpass binary now proves its identity purely via `/proc/<pid>/exe`, checked by the separate identity-helper service — no capability, no `SCM_RIGHTS`, no mode-0711 execute-only requirement. Keep the "outside the plugin's own git checkout" rationale (still true, still needed — `omarchy plugin update`'s `git pull` would still silently rewrite ownership on every update if the binary lived inside the tracked tree).

- [ ] **Step 2: Shellcheck / dry-read**

Run: `bash -n scripts/doorman-install-askpass`
Expected: no syntax errors.

- [ ] **Step 3: Commit**

```bash
git add scripts/doorman-install-askpass
git commit -m "chore(doorman): drop setcap/getcap from the askpass install step, now unneeded"
```

---

## Task 5: Documentation

**Files:**
- Modify: `SPEC.md` (new §6.13, superseding §6.11's mechanism; update §6.7's cross-reference)
- Modify: `README.md` (install steps: add the identity-helper unit, drop setcap/getcap mentions)
- Modify: `docs/architecture.md` (layer 3's description)
- Modify: `docs/publishing-security.md` (append item 11, same style as items 7–10)
- Modify: `scripts/doorman-sudo` (update the now-stale comment about `cap_dac_read_search`/`SCM_RIGHTS`, lines 11–20 — no logic change)

**Interfaces:**
- Consumes: the final, shipped behavior of Tasks 1–4 — do this task last, so the docs describe what actually landed, not what was planned.

- [ ] **Step 1: Add `SPEC.md` §6.13**

After §6.12, add a new §6.13 narrating: the O_PATH/fstat bypass finding (2026-10-08/2026-10-25) that killed §6.11's mechanism; the two reasons the "broker reads the peer's /proc/pid/exe directly" candidate also failed (mount-namespace confinement, fork+shared-socket bypass); the new design (separate identity-helper unit, synchronous accept-time check, pidfd pinning); and the independent symlink-exfil (2026-10-25) and env-trust fixes. Add a one-line pointer from §6.7's "see §6.9 and §6.11 for the full history" to also mention §6.13.

- [ ] **Step 2: Update `README.md`**

In the "Installing" numbered list, add a new step between the current steps 2 and 3 for enabling `omarchy-doorman-identity-helper.service` (same `cp .../packaging/... ~/.config/systemd/user/` + `daemon-reload` + `enable --now` shape as step 2). Rewrite "Why this step needs root" to drop the `cap_dac_read_search` sentence (no longer true) and describe the new mechanism (root-installed binary + a separate identity-helper service verifying `/proc/<pid>/exe`). Update the "Activating, updating, and removing" block's removal steps to also disable/remove the identity-helper unit alongside the broker's.

- [ ] **Step 3: Update `docs/architecture.md`**

Rewrite layer 3's description (lines 9–25) to describe the new mechanism: the askpass binary is privilege-free; a separate identity-helper service verifies `/proc/<pid>/exe` via device+inode `fstat()`, queried synchronously by the broker at accept time. Point to `SPEC.md` §6.13 instead of §6.11.

- [ ] **Step 4: Append `docs/publishing-security.md` item 11**

Same style and tense as items 7–10 (strikethrough title, "Done on \<date\>:" body): describe the O_PATH/fstat bypass and symlink-exfil findings, the two killed candidate designs (mount-namespace confinement, fork+shared-socket bypass), and the shipped fix, with the same "Still only a partial review" closing line the prior items use.

- [ ] **Step 5: Update `scripts/doorman-sudo`'s comment**

Replace the comment block (lines 11–20) describing `cap_dac_read_search`/`SCM_RIGHTS` with a short note that the askpass binary is now privilege-free and proves its identity via a separate identity-helper service checking `/proc/<pid>/exe`. No change to the script's actual logic.

- [ ] **Step 6: Commit**

```bash
git add SPEC.md README.md docs/architecture.md docs/publishing-security.md scripts/doorman-sudo
git commit -m "docs(doorman): describe the 6th askpass-identity design, supersede §6.11"
```

---

## Task 6: Live verification (manual, required before reporting anything fixed)

Not unit-testable — per this project's own repeated lesson (`SPEC.md`'s history, this design doc's anti-goals), a test-suite pass never substitutes for live verification against the real systemd units. Do not report this fixed anywhere, or reopen issue #9558, until every step below has actually been run and observed on this machine.

- [ ] **Step 1:** Copy `packaging/omarchy-doorman-identity-helper.service` to `~/.config/systemd/user/`, `systemctl --user daemon-reload`, `systemctl --user enable --now omarchy-doorman-identity-helper.service`. Confirm `systemctl --user status omarchy-doorman-identity-helper.service` shows it active.
- [ ] **Step 2:** Re-run `sudo scripts/doorman-install-askpass` to install Task 3/4's rebuilt, capability-free binary. Confirm its output shows no capability line and mode `0755`.
- [ ] **Step 3:** Copy the updated `packaging/omarchy-doorman.service` (now with `Wants=`/`After=` on the identity helper) to `~/.config/systemd/user/`, `daemon-reload`, `restart omarchy-doorman.service`. Confirm `systemctl --user status omarchy-doorman.service` is active and its journal shows no "identity-helper unreachable" warning on this normal startup.
- [ ] **Step 4: Legitimate round trip.** Run a real `sudo` command through `doorman-sudo` (or with `SUDO_ASKPASS` pointed at the installed binary directly), approve it in the real Quickshell modal, confirm the command runs with the real password.
- [ ] **Step 5: O_PATH structural closure.** Confirm (by code reading, since the design doc notes this should be impossible by construction) that no code path in the updated `broker/broker.py` reads `recvmsg`/`SCM_RIGHTS`/ancillary data at all. Cross-check against Task 2's `test_scm_rights_fd_is_ignored_identity_still_checked_against_real_peer_exe` passing.
- [ ] **Step 6: Symlink/env-exfiltration reproduction.** Attempt the exact 2026-10-25 scenario live: invoke `/usr/bin/sudo -A` directly (bypassing `doorman-sudo`) with `SUDO_ASKPASS` pointed at the real installed binary, a planted symlink under a caller-controlled `XDG_RUNTIME_DIR`, and a caller-controlled `DOORMAN_SOCKET` pointed at a disposable listener you control. Confirm nothing is exfiltrated (your listener receives no connection, or the binary exits non-zero before getting that far).
- [ ] **Step 7: Fork-timing attack reproduction.** Reproduce Task 2's `test_fork_then_exec_on_connecting_peer_is_rejected` scenario against the real, running broker and identity-helper units (not test subprocesses) — confirm rejection.
- [ ] **Step 8: Degraded-state check.** `systemctl --user stop omarchy-doorman-identity-helper.service`, attempt a real `sudo` round trip, confirm it's refused loudly (`identity_helper_unreachable`, visible to the UI as "Setup incomplete"), restart the unit afterward.
- [ ] **Step 9: Full suite, one more time.** `python3 -m unittest discover -s tests -p 'test_*.py'` and `python3 -m py_compile broker/*.py identity_helper/*.py *.py`.
- [ ] **Step 10:** Only after all of the above: post the fix to issue #9558 (or wherever HANCORE-linux's findings are tracked) and update `project_doorman_askpass_identity_investigation.md`'s memory file to reflect the shipped state.
