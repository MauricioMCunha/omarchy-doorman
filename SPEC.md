> **Note (pre-extraction draft):** written for Doorman's planned standalone
> repository. See the note at the top of `README.md`.

# Doorman — Technical Specification

This document describes what Doorman does, what it explicitly does not do,
the wire protocol between its components, and the reasoning behind each
security property. It is the reference for anyone auditing, extending, or
re-implementing a piece of this system. For the short pitch and install
steps, see [`README.md`](README.md). For machine-checkable functional
requirements and acceptance criteria in MUST/SHOULD form, see the sibling
`openspec/doorman.md` in the monorepo — this document is the narrative
version of the same system.

## 1. Overview

Doorman lets a local process (in practice: a background AI coding agent)
request a privileged secret — a `sudo` password — without ever receiving it
itself. A human approves or denies the request in a local UI; the secret is
delivered directly from that approval to the original requesting process,
over a connection the agent never sees.

Three components:

| Component | What it is | Trust level |
|---|---|---|
| **Broker** | A `systemd --user` Python service owning a private Unix socket | Trusted — holds the session token/capability, mediates every decision |
| **UI (plugin)** | A Quickshell bar widget + modal | Trusted — the only thing that can approve/cancel, runs as the same user |
| **Requesting process** | Whatever called `sudo -A` (an agent's shell, a script) | Untrusted input — supplies metadata, never sees the secret |

## 2. Goals and non-goals

**Goals**

- A privileged secret must never be observable by the requesting process,
  its parent, its logs, or anything reading its stdout/stderr/argv.
- A human must be able to see exactly what is being authorized (command,
  cwd, PID, terminal) before deciding.
- Every decision is single-use, time-bounded, and tied to the specific
  process that asked — not just "some process claiming this PID."
- Failure must be closed: any ambiguity (expired, wrong nonce, changed
  process identity, malformed request) results in no secret being released.

**Non-goals**

- Not a secrets vault or password manager — nothing is persisted.
- Not a `sudoers` replacement or a sandbox — it sits in front of the
  existing `sudo`/`SUDO_ASKPASS` mechanism, unchanged.
- Not a replacement for the system `/usr/bin/sudo` binary or a `sudoers`
  edit — interception is a per-user `PATH` shadow (§6.8), scoped to this
  user's own shells, not a machine-wide change.
- Not protection against a compromised UI process itself, or against an
  attacker who already has an interactive session as the same user and is
  willing to guess a 256-bit token (see §4.3).
- Not multi-user or networked — the socket is local, single-user, and the
  project has no plan to change that.

## 3. Architecture

```
authorized command (sudo / sudo -A / SUDO_ASKPASS)
    └─ askpass helper
         └─ broker (Unix socket, private runtime dir)
              └─ Quickshell plugin (topbar widget + modal)
                   └─ human types the password locally
```

- **Broker** (`broker/broker.py`): single Python process, one thread per
  connection, in-memory state only. Started by `systemd --user` with a
  session token and an "LLM capability" string passed as `--token`/
  `--llm-capability` (or `DOORMAN_TOKEN`/`DOORMAN_LLM_CAPABILITY`), both
  generated fresh per session and stored under a private runtime directory.
- **askpass helper** (`broker/askpass.py`, and a self-contained copy in the
  plugin directory for when `sudo` invokes it directly with no wrapper):
  implements the `SUDO_ASKPASS` contract — reads a prompt on argv, writes
  the secret to stdout, nothing else.
- **bridge** (`bridge.py`): a secret-free CLI the Quickshell `Process` type
  shells out to for `pending`/`stats`/`approve`/`cancel`. The secret is
  piped over stdin on approval, never passed as an argument (arguments are
  visible to every other process on the machine via `/proc/<pid>/cmdline`).
- **UI** (`Panel.qml`, `SecureOverlay.qml`): a topbar widget for
  status/history and a modal `PanelWindow` (Wayland layer-shell, exclusive
  keyboard focus while open) for the actual decision.

## 4. Threat model

### 4.1 In scope

- A malicious or buggy **background agent process** that can set arbitrary
  metadata (command string, cwd, tty) and can read the broker's public
  responses, but does not have the session token/capability and cannot read
  the human's keystrokes into the modal.
- **Process identity drift**: the PID a request was opened for exits and is
  reused by an unrelated process before the human approves.
- **Local resource exhaustion**: another process on the same machine (with
  or without the token) trying to degrade the broker's availability.
- **Replay**: reusing a `request_id`/`nonce` pair after it has already been
  consumed or has expired.

### 4.2 Out of scope

- An attacker with root, or with `ptrace` access to the broker or UI process
  — game over regardless of anything this protocol does.
- Compromise of the Quickshell shell itself, or of the compositor.
- Memory-scraping the password out of the QML process's heap between input
  and delivery — QML/JS have no secure-erase primitive; the password is a
  normal (if short-lived) string in memory like any Qt Quick `TextField`.
- Anything requiring network exposure — the socket is never bound to
  anything but `AF_UNIX`.

### 4.3 Accepted residual risk

- **Nonce comparison entropy, not secrecy through obscurity**: nonces are
  `secrets.token_urlsafe(24)` (24 random bytes, 192 bits of entropy) and compared with
  `secrets.compare_digest` everywhere they gate a decision. A timing attack
  against 192 bits of entropy over a local Unix socket is not a practical
  concern; the constant-time comparison is defense in depth, not the
  primary defense.
- **A same-UID process that already has the token can still open up to
  `MAX_PENDING` (20) concurrent requests**, each pinning a broker thread for
  up to `timeout + 1` seconds. This requires the token/capability, so it is
  a strictly smaller threat than the unauthenticated case fixed in §6.4; the
  cap exists so this stays a soft inconvenience, not a broker crash.

## 5. Protocol

Transport: a single Unix stream socket, `0600`, under a `0700` directory.
Every message is one line of UTF-8 JSON terminated by `\n`, capped at 16 KiB
(`MAX_LINE`); an oversized or unterminated line closes the connection with
no response. The broker reads at most one request line per connection
before dispatching — every request/response pair listed below is a full
connection lifecycle (connect → send → read response(s) → close).

All request objects carry a top-level `"token"` (the session token) checked
with `secrets.compare_digest`. A wrong or missing token gets
`{"ok": false, "error": "unauthorized"}` and nothing else runs.

### 5.1 `request` — open a new authorization request

```jsonc
// →
{
  "token": "…", "type": "request",
  "origin": "llm", "capability": "…",   // must match the broker's configured capability
  "pid": 12345,                          // MUST be a positive integer of a live process
  "command": "sudo apt upgrade",         // free text, truncated to 1000 chars, display only
  "cwd": "/home/user/project",           // truncated to 1000 chars, display only
  "tty": "pts/3",                        // truncated to 300 chars, display only
  "prompt": "[sudo] password for user: ",// truncated to 300 chars, shown verbatim in the UI
  "screen": "DP-2"                       // optional monitor hint, truncated to 200 chars
}
```

The connection is held open. First response (immediately):

```jsonc
// ← (accepted)
{"ok": true, "request_id": "<32 hex chars>", "nonce": "<32-char urlsafe, 24 bytes/192 bits of entropy>", "expires_at": 1234567890.12}
```

or, without a second response (connection closes immediately):

```jsonc
{"ok": false, "error": "invalid_pid"}          // pid missing or <= 0
{"ok": false, "error": "process_not_found"}    // /proc/<pid> unreadable or gone
{"ok": false, "error": "invalid_llm_origin"}   // origin != "llm" or capability mismatch
{"ok": false, "error": "too_many_pending"}     // MAX_PENDING (20) already open
```

If accepted, the connection then blocks (no further reads — see §6.2 on the
handshake timeout) until the request reaches a terminal state, then sends
exactly one more line:

```jsonc
{"ok": true, "secret": "…"}                              // approved
{"ok": false, "error": "expired"}                         // no decision within the deadline
{"ok": false, "error": "cancelado_pelo_usuario"}          // explicit cancel
```

`expires_at` is `created_at + timeout`, where `timeout` is the broker's
`--timeout` (1–300 seconds, default 30). The client should not reuse its own
handshake-read timeout for this second read — it can legitimately take up
to `timeout` seconds. See §6.2.

### 5.2 `approve` — release the secret to the waiting connection

```jsonc
// →
{"token": "…", "type": "approve", "request_id": "…", "nonce": "…", "secret": "…"}
// ←
{"ok": true}
{"ok": false, "error": "invalid_or_expired_request"}
```

Approval requires, atomically, under one lock acquisition: the request
exists, is not yet delivered, the nonce matches (`secrets.compare_digest`),
it hasn't expired, the process identity still matches (§6.1), and the
secret is a string of at most 4096 bytes.

### 5.3 `cancel` — explicit human rejection

```jsonc
// →
{"token": "…", "type": "cancel", "request_id": "…", "nonce": "…"}
// ←
{"ok": true}   // or {"ok": false} if the id/nonce didn't match a live request
```

### 5.4 `pending` — list open requests (for the UI to poll)

```jsonc
// →
{"token": "…", "type": "pending"}
// ←
{"ok": true, "requests": [{"request_id": "…", "nonce": "…", "pid": …, "command": "…", "cwd": "…", "tty": "…", "prompt": "…", "screen": "…", "expires_at": …}]}
```

Only non-delivered, non-expired requests are listed.

### 5.5 `stats` — session metrics (for the UI's status display)

```jsonc
// →
{"token": "…", "type": "stats"}
// ←
{"ok": true, "uptime": 42, "pending": 0, "last_activity_at": 1234567890.1, "approved": 3, "cancelled": 1, "expired": 0, "requests": 4}
```

## 6. Security properties and their rationale

### 6.1 Process identity is re-checked at approval, not just at request time

`_process_identity(pid)` reads `/proc/<pid>/stat` (start time, field 22 by
position after the last `)`, to survive process names containing spaces or
parentheses), `/proc/<pid>/cmdline`, and the `Uid:` line of
`/proc/<pid>/status`. This triple is captured when the request is created
and re-read at approval time; a mismatch on any field fails the approval.
This defeats PID reuse: if the original process exits and the kernel hands
that PID to an unrelated process before a human clicks approve, the stored
start time/cmdline/uid won't match and the approval is rejected.

### 6.2 The handshake timeout is bounded, but the decision wait is not

`_handle()` puts a 5-second (`HANDSHAKE_TIMEOUT`) socket timeout on the
*first* read only — the line carrying the message type and token — then
clears it before doing anything else. This is deliberate: it closes a real
denial-of-service (any same-UID process could open a connection, send
nothing, and pin a broker thread forever, with no token required — fixed
after being found during manual testing), without breaking the legitimate
case where a `request` connection needs to stay open for up to 300 seconds
waiting on a human. A client library must apply the same split: a short
timeout for the handshake read, and a separate timeout — sized from the
`expires_at` the broker already returned — for the decision read. Reusing
the handshake timeout for both (an earlier bug in this project's own
reference client) silently breaks any approval slower than the handshake
window.

### 6.3 Every comparison that gates a decision is constant-time

`session_token`, `llm_capability`, and both nonce checks (`approve` and
`cancel`) use `secrets.compare_digest`. This was inconsistent during
development — `approve` briefly used `==` while `cancel` used
`compare_digest` for the identical check — and was corrected for
consistency; see §4.3 for why the practical exposure was always low given
the nonce's entropy.

### 6.4 Concurrency is bounded at two layers

- **Unauthenticated**: the handshake timeout (§6.2) bounds how long an
  unauthenticated idle connection can hold a thread.
- **Authenticated**: `MAX_PENDING` (20) bounds how many requests a valid
  token holder can have open at once, checked and inserted atomically under
  the broker's single lock to avoid a check-then-act race.

### 6.5 The secret never touches a surface that isn't the approval itself

- Never an argument (`ps`/`/proc/<pid>/cmdline` visible to any local user).
- Never written to a file, including temp files.
- Never logged — the broker's own `print()` calls only ever log the socket
  path at startup.
- The bridge CLI passes it over stdin on `approve`, not argv.
- The askpass helper writes it to stdout, which only `sudo` itself reads.

### 6.6 The socket and its directory are private by construction

Socket file `0600`; its parent directory `0700`; the systemd unit enforces
`UMask=0077`, `RuntimeDirectoryMode=0700`, and `ProtectSystem=strict` /
`ProtectHome=read-only` with the runtime directory as the sole writable
path. On startup, if a stale socket path exists and isn't owned by the
current UID, the broker refuses to bind rather than silently taking over a
path another user's process might be using.

### 6.7 Systemd sandboxing

The unit additionally sets `NoNewPrivileges`, `PrivateTmp`,
`RestrictAddressFamilies=AF_UNIX` (the broker never needs any other socket
family), `CapabilityBoundingSet=` (empty — it needs zero Linux
capabilities), `SystemCallFilter=@system-service`, and a handful of
`Protect*`/`Restrict*` flags (kernel tunables/modules/logs, control groups,
clock, hostname, namespaces, realtime scheduling, SUID/SGID,
`LockPersonality`, `MemoryDenyWriteExecute`). None of these change behavior
for a pure-Python service that only speaks Unix sockets and reads `/proc`;
they remove attack surface the broker was never going to use anyway.

### 6.8 PATH shadowing is what makes interception actually happen

`sudo` prefers a real controlling terminal over `SUDO_ASKPASS` whenever one
is available; `-A` must be passed explicitly by the caller for askpass to
be used at all. An agent that opens its own terminal to run a privileged
command (observed in practice: an unrelated coding-agent CLI spawning a
`foot` window and asking the human to type the password into it) never
touches Doorman, because nothing forced `-A`. Documenting "route privileged
commands through `doorman-run`/`doorman-sudo`" in an agent's own
instructions is not a real fix for a published plugin — it requires every
agent operator to have configured that agent specifically for Doorman,
which defeats the point of publishing it as something that works out of
the box.

The fix is a per-user `PATH` shadow: `ln -s .../scripts/doorman-sudo
~/.local/bin/sudo`. Since `~/.local/bin` precedes `/usr/bin` in a default
Omarchy `PATH` — including in a `bash -lc` login shell, which is how the
agent above spawned its terminal — any caller that resolves `sudo` by name
(the overwhelming majority of scripts and agent tool-calls) reaches
`doorman-sudo` first, which always forwards to the real `sudo -A` unless
the caller already passed an explicit askpass/stdin/non-interactive flag
(see the `doorman-sudo` case statement — note the `--*` guard added
specifically so a long flag merely containing the letters A/S/n, like
`--preserve-env`, isn't mistaken for one of those explicit flags). This is
scoped entirely to this user's own shell environment: `/usr/bin/sudo`,
`/etc/sudoers`, and every other user's session are untouched, and removing
the symlink fully reverts the behavior.

Its one hole is a caller that invokes `/usr/bin/sudo` by absolute path,
which bypasses `PATH` resolution entirely — no user-level shadow can catch
that without replacing the system binary itself, which this project
deliberately does not do (see §2, "Non-goals").

## 7. Known limitations

- The `~/.local/bin/sudo` shadow (§6.8) does not catch a caller that
  invokes `/usr/bin/sudo` by absolute path, or one running in an
  environment where `~/.local/bin` isn't on `PATH` ahead of `/usr/bin`
  (non-interactive systemd units, cron, a stripped-down `PATH`).
- No automated test against a real Quickshell session, real Omarchy, or
  real `sudo` — the test suite drives the broker's own protocol directly
  and via the askpass helper, not the full stack end to end.
- No `qmllint` or static analysis on the QML yet.
- The plugin's manifest `id` is load-bearing for Omarchy's bar layout
  (`~/.config/omarchy/shell.json` tracks placed widgets by id) — renaming it
  requires manually updating that file too; there's no migration path.
- Multiple simultaneous requests from different agent sessions are listed
  with a count but the UI can only act on one at a time (`root.selected`);
  there's no way to triage or batch-decide a queue.

## 8. Acceptance criteria

Every property in §6 has a corresponding automated test in `tests/`:
wrong token, invalid origin, missing PID, process-identity change, request
expiry, approve/replay, wrong-nonce approve and cancel, the askpass helper's
stdout-only contract, the idle-unauthenticated-connection close, the
slow-approval timeout regression, and the `MAX_PENDING` cap with slot
release on cancel. `python3 -m unittest discover -s tests -p 'test_*.py'`
must pass before any change to `broker/broker.py` is considered done.

## 9. Glossary

- **Broker**: the long-running service in §3 that owns the socket and all
  request state.
- **Capability**: a shared secret (like the token, but scoped to identify
  "this caller claims to be the LLM-driven flow") required on every
  `request` message alongside `origin: "llm"`.
- **Nonce**: a per-request random value required, in addition to
  `request_id`, to approve or cancel — prevents an attacker who can guess
  or observe a `request_id` (e.g. from process listings, since it isn't
  secret) from acting on a request they didn't create.
- **Session token**: the broker-wide shared secret every message must
  present; scoped to one broker process's lifetime.
