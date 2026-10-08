# Doorman — Technical Specification

This document describes what Doorman does, what it explicitly does not do,
the wire protocol between its components, and the reasoning behind each
security property. It is the reference for anyone auditing, extending, or
re-implementing a piece of this system. For the short pitch and install
steps, see [`README.md`](README.md). For machine-checkable functional
requirements and acceptance criteria in MUST/SHOULD form, see the sibling
`openspec/doorman.md` in this repository — this document is the narrative
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
- **askpass helper** (`askpass/doorman-askpass.c`, compiled and installed by
  `scripts/doorman-install-askpass`): implements the `SUDO_ASKPASS`
  contract — reads a prompt on argv, writes the secret to stdout, nothing
  else. Installed once by root, outside the plugin's own git checkout,
  owned `root:root`, mode `0711` (executable, not readable, by anyone but
  root) and not writable by the user — this is what lets the broker tell it
  apart from caller-written code that also happens to be a genuine child of
  a genuinely escalated `sudo` (§6.11): the helper hands the broker a file
  descriptor for its own `/proc/self/exe` over the request socket
  (`SCM_RIGHTS`), and the broker compares that against this installed path.
  The binary also carries the `cap_dac_read_search` file capability, set by
  the install script — needed because opening `/proc/self/exe` isn't
  privilege-exempt, so mode `0711` alone would block the legitimate binary
  from reading itself too (§6.11).
  `broker/askpass.py` (and a self-contained copy, `askpass.py`, for when
  `sudo` invokes it directly with no wrapper) are the pre-#9558-finding-4
  Python implementation, kept only as a dev/test fixture — the broker
  rejects them on the production path (`untrusted_askpass_helper`), since
  they never attach that fd at all.
- **bridge** (`bridge.py`): a secret-free CLI the Quickshell `Process` type
  shells out to for `pending`/`stats`/`approve`/`cancel`. The secret is
  piped over stdin on approval, never passed as an argument (arguments are
  visible to every other process on the machine via `/proc/<pid>/cmdline`).
- **UI** (`BarWidget.qml`, `Panel.qml`, `SecureOverlay.qml`): a topbar icon
  plus a status/history popup built on Omarchy's own `BarWidget`/`Panel`/
  `KeyboardPanel` contract (the same pair every first-party bar widget with a
  popup uses — e.g. `omarchy.clock`), and a separate modal `PanelWindow`
  (Wayland layer-shell, exclusive keyboard focus while open) for the actual
  approve/deny decision. The modal is deliberately outside the bar's popout
  system — SecureOverlay must be able to appear (and grab exclusive keyboard
  focus) whether or not the status popup is open.

## 4. Threat model

### 4.1 In scope

- A malicious or buggy **background agent process** that can set arbitrary
  *display* metadata (`cwd`, `tty`; `command` is no longer one of these —
  see §6.12), can read the broker's public responses, and — this was wrong
  in an earlier draft of this document — *does* have the session token and
  capability: they live in files under the same UID the agent runs as,
  exactly like the UI reads them. What the agent cannot do is claim a `pid`
  other than its own real one, create a request at all without a real sudo
  process as its connection's immediate parent (§6.1), invoke real `sudo`
  with its own `SUDO_ASKPASS` and still be the one to receive the secret
  (§6.11), act as the trusted UI (§6.9), or read the human's keystrokes
  into the modal.
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
  "screen": "DP-2",                      // optional monitor hint, truncated to 200 chars
  "sudo_pid": 6789                       // optional, see §6.10; omitted callers just get attempt=1 always
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
{"ok": false, "error": "pid_mismatch"}         // claimed pid isn't this connection's real peer — see §6.1
{"ok": false, "error": "not_sudo_child"}       // peer's parent process isn't sudo — see §6.1
{"ok": false, "error": "askpass_identity_unavailable"} // trusted askpass path not installed — see §6.11
{"ok": false, "error": "untrusted_askpass_helper"}     // peer didn't hand over a matching identity fd — see §6.11
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
{"ok": false, "error": "cancelled_by_user"}               // explicit cancel
{"ok": false, "error": "superseded_by_retry"}             // a newer request with the same sudo_pid arrived — see §6.10
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
{"ok": true, "requests": [{"request_id": "…", "nonce": "…", "pid": …, "command": "…", "cwd": "…", "tty": "…", "prompt": "…", "screen": "…", "expires_at": …, "attempt": 1}]}
```

Only non-delivered, non-expired requests are listed. `attempt` is 1 unless
the request was correlated to an earlier one via `sudo_pid` (§6.10).

### 5.5 `stats` — session metrics (for the UI's status display)

```jsonc
// →
{"token": "…", "type": "stats"}
// ←
{"ok": true, "uptime": 42, "pending": 0, "last_activity_at": 1234567890.1, "approved": 3, "cancelled": 1, "expired": 0, "requests": 4, "askpass_identity_available": true}
```

`askpass_identity_available` is `false` when the trusted askpass path
can't be `stat`'d (the install step was never run, or the installed file
was removed — see §6.11) — every `request` is refused with
`askpass_identity_unavailable` while this is `false`. The UI should
surface this directly rather than require reading the broker's own stderr.

## 6. Security properties and their rationale

### 6.1 Process identity is authenticated at request time, then re-checked at approval

The `pid` field in a `request` message (§5.1) is attacker-controlled input —
an agent holding the normal `origin=llm` token/capability could otherwise
claim to be any PID that happens to exist, not even a real sudo/askpass
process, display a convincing `command`, get a human to approve it, and
receive the secret itself back on its own connection, since the response
always goes to whoever is actually connected, never to the claimed pid.
`_create_request` closes this before doing anything else with the claim: it
reads the connection's real peer via `SO_PEERCRED` (kernel-verified, not
something the remote process can forge — the same primitive §6.9 uses for
the trusted-UI check) and rejects with `pid_mismatch` unless that peer's
pid equals the claimed `pid` and its uid equals the broker's own. This
changes nothing for the legitimate flow: askpass.py reports `os.getpid()`,
its own real pid, so the claim and the connection's real identity are
always the same process to begin with.

That still leaves the actual case a maintainer's security review flagged
on the marketplace submission (issue #9558): `pid_mismatch` only stops
claiming someone *else's* pid — a requester connecting directly and
reporting its own real pid passed it. Nothing bound the request to a
genuine sudo/askpass chain, so an agent could skip sudo entirely, connect
with its own truthful identity and a convincing `command`, and receive the
password itself once a human approved what looked like a legitimate
request. `_create_request` also requires the connecting peer's immediate
parent process to have `comm == "sudo"` (`_peer_is_sudo_child`, same
`/proc/<pid>/comm` primitive as §6.9, one hop only — sudo forks and execs
the askpass helper directly, with no shell in between), rejecting with
`not_sudo_child` otherwise.

The same maintainer then flagged that `comm` check itself: `/proc/<pid>/comm`
is just a label a process can set for itself via `prctl(PR_SET_NAME)` (or by
rewriting `argv[0]`) with no privilege at all, so an agent could rename
itself `"sudo"`, fork a child, and have that child connect with its own
real pid — passing the comm check without ever touching a real sudo.
`_peer_is_sudo_child` now also requires that same parent to show a genuine
privilege escalation: its effective uid must differ from its own real uid
(`_process_comm_and_uids`, reading the `Uid:` line of
`/proc/<pid>/status`). Real sudo is setuid-root and keeps that pairing —
real uid the invoking user, effective uid 0 — for as long as it's waiting
on askpass; confirmed live against an actual `sudo -A` invocation. A
same-user process can't reproduce it without actually executing a genuine
setuid-root binary, and `exec()` replaces the whole process image, so it
can't rename itself into `"sudo"` afterwards either — whatever binary it
execs keeps running that binary's own code, not the attacker's. (The
broker's own sandboxing remaps a uid it can't resolve in its own user
namespace — e.g. root's `0` — to the kernel's overflow uid rather than
denying the read outright; confirmed live that real sudo's effective uid
shows up here as that overflow value, not literally `0`. Comparing
real uid against effective uid, instead of effective uid against a
hardcoded `0`, doesn't care which representation it sees.) The only
process that can ever receive a secret for a given pid is now one sudo
itself — genuinely, not just by name — just spawned to ask for one.

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
`LockPersonality`, `MemoryDenyWriteExecute`). Almost none of these change
behavior for a pure-Python service that only speaks Unix sockets and reads
`/proc`; they remove attack surface the broker was never going to use
anyway. The one exception: `ProtectSystem=strict`/`ProtectHome=read-only`/
`PrivateTmp=true` each independently place the broker in a private,
unprivileged Linux user namespace. Two different things break under this
deployment shape, discovered one after the other while building §6.11:
*credential values* (uid/gid) outside the namespace's minimal mapping
resolve to the kernel's overflow id instead of the real one; and reading
*another process's* `/proc/<pid>/exe` (or `/maps`, `/mem` — anything
`ptrace_may_access()`-gated) is denied outright (`PermissionError`), not
just resolved to the wrong value — the same gate, and the same open
question about its exact mechanism under `systemd --user`, that §6.9
already ran into for a different check. Neither affects plain,
non-ptrace-gated `/proc` reads like `comm`, `status`'s pid/uid lines, or
`cmdline` — which is why §6.1's checks were never affected, and why each
successive version of §6.11's fix had to stop depending on resolving a
value *or* ptrace-reading the peer at all. See §6.9 and §6.11 for the full
history.

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

### 6.9 approve/cancel/pending/stats require being the trusted UI, not just the token

An earlier version of this document (§4.1, now corrected) assumed the agent
doesn't have the session token. That's false: the token and capability live
in files under the same UID the agent runs as, exactly like the UI reads
them — `origin=llm` + capability only gates who can *create* a request.
Manual testing during development confirmed the consequence directly: a
plain shell script that reads those files can create a request and then
immediately call `approve` on it with a fabricated secret, with zero UI, no
human click, and no visible sign anything happened — the broker returned
`{"ok": true}`. A fabricated secret doesn't leak the real password, but it
completely defeats the "a human reviews and approves each command" promise
this project exists for: if an agent ever learns the real password through
any other means (a `.env` file, shell history, a password manager entry
read by accident), self-approval lets it use that password for `sudo`
silently, with no modal, no notification, no countdown — the one layer
Doorman was supposed to add on top of already knowing the password.

The fix gates `approve`, `cancel`, `pending`, and `stats` — every message
type except `request`, which is what an agent legitimately needs — behind
a check that the *connection itself*, not anything in the message, comes
from the trusted UI:

1. `SO_PEERCRED` on the accepted socket gives the kernel's own account of
   the connecting process's PID/UID — not something the remote process can
   spoof, unlike anything it puts in the JSON payload.
2. Starting from that PID, walk up to a few parent hops (bridge.py's
   python3 process is a direct child of Quickshell in practice — verified
   with a live `ps -eo pid,ppid,cmd` while the real UI was polling — one
   hop is enough, extra hops are headroom for a future wrapper) looking for
   a process name that matches the trusted UI (`quickshell` by default,
   `Broker(..., trusted_ui_exe=...)` / `--trusted-ui-exe` elsewhere, for
   tests).

That process name comes from `/proc/<pid>/comm`, not `/proc/<pid>/exe`.
`exe` would be the stronger check — it's the kernel's resolved path to the
actual binary, not spoofable by `argv[0]` or `prctl(PR_SET_NAME)` the way
`comm` is — and was the first implementation. It broke the real UI outright:
reading *another* same-UID process's `/proc/<pid>/exe` requires
ptrace-equivalent permission, and a `systemd --user` service is denied that
(`EACCES`) even after granting it `CAP_SYS_PTRACE` explicitly and stripping
every other sandboxing directive back to nothing — confirmed by bisecting
the unit file directive-by-directive down to zero. The identical read
succeeds immediately from a plain interactive shell with the same UID and
no special capabilities at all. Whatever draws that line (contributors
looking into this further should start with how `systemd --user` scopes
relate to Yama's `ptrace_scope`, since capabilities alone didn't explain
it), it isn't testable input coverage — it's a structural property of this
deployment shape, not a bug in this project's own sandboxing. `comm` needs
no such permission. The trade-off is real: forging `comm` costs an attacker
one deliberate `prctl`/`argv[0]` step instead of nothing, not the
impossible-to-forge guarantee `exe` would have given. Still a large
improvement over no check at all, which is what shipped first.

### 6.10 A rejected password shows up as a retry, not a second, unrelated request

Doorman never validates the password itself — that's `sudo`/PAM's job,
entirely outside the broker. If the user approves with the wrong password,
the secret is still delivered (that's a success from the broker's point of
view), `sudo` rejects it via PAM, and — by default (`Defaults passwd_tries`,
commonly 3) — `sudo` re-invokes `SUDO_ASKPASS` in a brand-new process. Without
correlation, that looks to the broker like a completely unrelated new
request: a second modal, a second notification, with no indication it's the
same command asking again. Confirmed empirically during development
(deliberately wrong password against a disposable local askpass, well under
this machine's `pam_faillock` threshold): the prompt text sudo passes to
askpass on retry does **not** change (`"Sorry, try again."` goes only to
sudo's own stderr, which the askpass child never sees) — so there is no
signal in the request payload itself to detect a retry from.

The fix correlates on the *sudo parent process*, not the payload: `sudo`
forks a new askpass child each retry, but the `sudo` process itself is the
same one throughout the whole `passwd_tries` loop, and both askpass
entrypoints (`broker/askpass.py`,
`askpass.py`) are exec'd directly or via an `exec` shell
wrapper, so `os.getppid()` at that point is always `sudo`'s own PID. That
PID is sent as `sudo_pid` on `request`. The broker keeps a short-lived map
(`_sudo_pid_attempts`, pruned after `RETRY_WINDOW_SECONDS` = 20s) from
`sudo_pid` to the attempt count and the `request_id` it belongs to. A new
request whose `sudo_pid` matches one seen within that window can only exist
because `sudo` asked again — which only happens after a real PAM rejection,
not after Doorman's own cancel/expiry (those make askpass exit without
printing anything, which makes `sudo` abort instead of retrying) — so it's
tagged `attempt = previous.attempt + 1`.

Two consequences the implementation handles explicitly:

- The superseded, previous-attempt request is never actually read again —
  its askpass process already exited after sudo killed it to retry — so
  without help it would sit in `pending` until its own timeout, and the UI
  could end up selecting that dead entry instead of the live one. The
  broker resolves it itself the moment the retry arrives
  (`error: "superseded_by_retry"`), the same `decision_event` mechanism used
  for expiry.
- The UI's own desktop notification for the first attempt would otherwise
  stay on screen, stale, next to a second one for the retry.
  `omarchy-notification-send -p` prints the notification's id; BarWidget.qml
  keeps it and passes it back via `-r <id>` on the next send, updating the
  toast in place instead of stacking a second one. The notification title
  stays constant (`"Authorization pending"`) so `omarchy-notification-dismiss`
  — which matches by title — still clears it when the queue empties.

This is a UX heuristic, not a security control: `sudo_pid` is optional and
self-reported by the caller (any `origin=llm` request can claim any
`sudo_pid`, causing a false "attempt 2" label at worst), and the inference
that a same-`sudo_pid` retry implies "the previous password was wrong"
relies on the observed (not kernel-guaranteed) behavior that Doorman's own
cancel/expiry don't trigger a `sudo` retry. Getting this wrong only affects
what the modal *says*; it never changes whether a request needs a real human
approval, still gated by the exact same checks as any other request.

### 6.11 The askpass helper itself must carry an identity it can't fake

§6.1's checks (`pid_mismatch`, `not_sudo_child`, the privilege-escalation
requirement) all validate the connecting peer's *parent* — that it's a
real, genuinely escalated `sudo`. They don't validate the peer itself.
`sudo` lets the *caller* choose the `SUDO_ASKPASS` helper (there's no
restriction on what that helper is), so an agent that invokes real `sudo`
directly — bypassing this project's own PATH-shadow wrapper entirely, §6.8
— can point `SUDO_ASKPASS` at a script it wrote itself. That script is a
genuine child of a genuinely escalated real `sudo`, so it passes every
check §6.1 can make, yet it's still caller-writable code that would receive
the plaintext secret in its own memory once a human approves — exactly
what "the password never reaches the agent" promises never happens
(reported by HANCORE-linux, issue #9558, as a fourth-round follow-up to the
same request-to-password boundary).

The fix installs the askpass binary (`askpass/doorman-askpass.c`) once, by
root (`scripts/doorman-install-askpass`), at a fixed path *outside* the
plugin's own git checkout, owned `root:root`, mode `0711`, and not writable
or readable by the user the broker and every agent run as (only
executable). The broker resolves that path's device+inode once at startup.
For every `request`, the askpass binary opens its own `/proc/self/exe` and
hands that file descriptor to the broker over the request socket as
`SCM_RIGHTS` ancillary data, alongside the normal JSON request line
(`Broker._recv_line_with_fd`). The broker `fstat()`s the received fd and
compares it against the resolved identity — rejecting a mismatch (or a
connection that never attached an fd at all) with `untrusted_askpass_helper`,
in addition to every check that already applied. `fstat()` on an fd this
process already owns needs no permission over whoever sent it; the only way
to produce a matching fd is to have genuinely `exec`'d that exact file,
since mode `0711` means nothing else can `open()` it by path to send a
substitute.

Opening `/proc/self/exe` is **not** privilege-exempt — confirmed live, the
hard way (below): it goes through the exact same DAC read check as opening
the target file by its real path, so mode `0711` that blocks a forged
`open()`-by-path also blocks the legitimate binary's own self-open. The
installed binary therefore also carries a file capability,
`cap_dac_read_search` (applied by `scripts/doorman-install-askpass` via
`setcap`, after `chown`/`chmod` but before the file is moved into place —
writing to a file's content clears any capability already set on it, so
order matters), letting *that exact binary, once exec'd* bypass this one
read check. Deliberately not `setuid-root`: a memory-safety bug in this
C code can, at worst, read a file it otherwise couldn't — it can't become
arbitrary code execution as root. An attacker's own substitute binary never
inherits this capability (file capabilities only apply at `execve()` of the
specific capability-bearing file), so `open()`-ing the trusted path
directly from attacker code is still just as blocked as before.

This compares the **device and inode number**, not the path as a string.
Two different files can share a path string across different mount
namespaces (an unprivileged user can create one with `unshare --user
--mount` and bind-mount something else over the same-looking path, visible
only to processes in that namespace) without sharing an inode — comparing
resolved identity rather than a rendered string closes that off without
needing to reason about which namespace produced which string.

**This replaces three earlier versions of this fix, each caught by live
verification before shipping.** The first two fail for the same underlying
reason: this project's own hardened systemd unit (§6.6/§6.7) puts the
broker in a private, unprivileged Linux user namespace with zero
capabilities. The third fails for an unrelated reason: a wrong assumption
about `/proc/self/exe` itself.

The first version used a dedicated system group and a `setgid` bit,
verified via the connecting peer's effective gid over `SO_PEERCRED`. Sound
on paper, and initially endorsed by HANCORE-linux — but any uid/gid outside
the broker's namespace's minimal mapping, including the dedicated group's
gid, collapses to the kernel's overflow id when the broker tries to
resolve it (confirmed by comparing `/proc/<broker_pid>/ns/user` against the
host's). A gid-based check is structurally unable to distinguish the
trusted group from any other gid under that sandboxing.

The second version, believing the problem was specifically about resolving
*credential values*, had the broker `stat()` the connecting peer's own
`/proc/<pid>/exe` directly by path instead — no gid, no group, nothing but
device+inode. That assumption was wrong: reading *another process's*
`/proc/<pid>/exe` turns out to need the same ptrace-equivalent permission
§6.9 already ran into and left as an open question (`ptrace_may_access()`
gates it, same as `comm`'s rejected `exe`-based alternative) — confirmed
live here too: every attempt, including the genuinely legitimate one,
failed with `PermissionError(13)`, reproduced identically for both the
real C binary and a disposable Python stand-in with verified-uniform
(real=effective=saved, matching the broker's own) uid/gid credentials —
ruling out a plain uid/gid mismatch and pointing at the same permission
gate §6.9 hit. §6.9's own note is the more honest summary: capabilities
alone don't fully explain it (granting `CAP_SYS_PTRACE` explicitly, with
every other sandboxing directive stripped to zero, still didn't fix that
check), and the exact mechanism — something about how `systemd --user`
services relate to Yama's `ptrace_scope`, as opposed to a plain shell
process with the same UID — is still an open question for a future
contributor to chase down. What matters for this fix is simpler than
explaining why: no version of the broker reading *anything* ptrace-gated
about the peer has worked, tried twice now for two different checks, so
the fix below doesn't try a third time on the *broker* side.

The fd-passing design moves the problem to the *askpass* side instead: it
never asks the broker to resolve a credential value or read anything about
a process it didn't itself grant an fd to — `fstat()` on an already-owned
fd is unconditionally allowed, independent of any namespace relationship
between sender and receiver. That also means the *positive* path can be
exercised in tests without root or a compiler (see `tests/test_broker.py`).
But its first shipped version (mode `0711`, nothing else) assumed opening
`/proc/self/exe` needs no permission at all — plausible-sounding, wrong.
Confirmed live with a disposable copy of the real binary, `chmod 0100`
(owner-execute-only, i.e. the same shape of restriction `0711` puts on the
real binary for its own non-root invoker): `open("/proc/self/exe",
O_RDONLY)` fails with `EACCES`, identical to the real binary's failure mode
for the legitimate caller. Opening your own executable's content goes
through the exact same DAC check as opening it by its real path — the
kernel has no notion of "this process is exempt because it's reading
itself." The capability described above (`cap_dac_read_search`, applied
only to this one binary) is what actually closes that gap; it's a smaller
grant than either of the two broker-side designs it replaced (no gid
resolution, no elevated capability on the broker itself, nothing that
needs to cross the namespace boundary that broke both earlier attempts).

Four things this depends on, each closing a way the fix above could be
reintroduced by accident, not just in theory:

- **Execute-only, on purpose.** Mode `0711` (not `0755`) is what stops an
  attacker from `open()`-ing the trusted path directly and sending *that*
  fd instead of genuinely `exec`-ing it — without it, the fd-passing
  protocol would authenticate "can read this file" rather than "actually
  ran this file," which the user who runs every agent can always do
  regardless.

- **Outside the checkout, on purpose.** `omarchy plugin update` does a
  `git pull` as the unprivileged user — if the binary lived inside the
  tracked tree, that pull would silently rewrite its ownership/mode back to
  something caller-writable on every update, with no error. A fixed,
  root-owned path the plugin's own update path never touches is required,
  not just tidier.
- **Fails loudly, never silently.** If the configured path can't be
  `stat`'d (the install step was never run, or the file was removed), the
  broker does not fall back to the pre-fix guarantee. It sets
  `askpass_identity_available = false`, keeps serving
  `approve`/`cancel`/`pending`/`stats` (no `request` could have succeeded
  anyway, so there's no stale-pending-request risk), surfaces the flag
  through `stats` for the UI to show directly, and rejects every `request`
  with `askpass_identity_unavailable` until it's fixed.

- **The capability has to actually be there, not silently dropped.**
  `scripts/doorman-install-askpass` applies `setcap cap_dac_read_search=ep`
  as the *last* step before the binary is moved into place — writing to a
  file's content strips any capability already on it, so compiling, then
  `chown`/`chmod`, then `setcap`, then `mv` is the only safe order. The
  script also refuses to install onto a `nosuid` mount (that mount option
  silently drops file capabilities at `execve()` time, the same way it
  drops `setuid`/`setgid` — failing to notice would reproduce the exact
  "legitimate caller can't read itself" failure this fix exists to close,
  just one layer further away) and verifies via `getcap` after install that
  the capability actually stuck, rather than assuming `setcap` succeeding
  means it took effect.

Residual trade-off: this only binds *this connection's peer*, the same way
every other check in §6.1 does — it says nothing about a second, different
attack path that doesn't involve this socket at all (out of scope, §4.2).

Verified live, 2026-10-07, all three cases: the legitimate round trip (real
`sudo whoami` → real wrapper → real askpass binary → broker → a human
approving in the real Quickshell modal → `sudo` returning successfully);
the attack this section exists to stop (a script posing as `SUDO_ASKPASS`,
invoked via real `sudo -A` with this project's own PATH-shadow wrapper
bypassed entirely — rejected `untrusted_askpass_helper`, no secret ever
left the broker); and the degraded state (the installed binary temporarily
removed — every `request` rejected `askpass_identity_unavailable`, not
silently accepted).

### 6.12 The displayed command is derived from the real sudo invocation, not the caller

§6.11 closes who can receive the secret. It doesn't, by itself, stop a
caller running the genuinely trusted askpass binary (a legitimate
invocation) from lying about what the human is approving: the request
payload's `command` field used to be taken verbatim from the caller
(`str(message.get("command", ""))`), display-only, with nothing tying it to
what would actually run. A caller that controls its own environment also
controls this field, and could show a harmless-looking string while a
different command actually executes once approved.

The fix reuses state §6.1 already resolves: the connecting peer's verified
immediate parent — the real `sudo` process itself. `sudo`'s own `argv`
(read from `/proc/<sudo_pid>/cmdline`, the kernel's own record of how that
process was actually invoked) is what gets shown, not anything the caller
sends. This can't be rewritten by the caller without compromising the real
`sudo` binary itself, which is out of scope (§4.2) — the same reasoning
§6.1 relies on for the escalation check.

Residual trade-off: if that `/proc` read races the parent process exiting
(the window between the broker verifying it and reading its cmdline), the
displayed command falls back to a visible placeholder, never to the
caller-supplied value — a display gap under an unlikely race, not a
reopened trust boundary.

## 7. Known limitations

- The trusted-UI check (§6.9) matches on `/proc/<pid>/comm`, which a
  process can set to anything via `argv[0]` or `prctl(PR_SET_NAME)`. An
  agent that deliberately spawns a child process named `quickshell` and
  connects from it would pass. This is a real gap, accepted because the
  alternative (`/proc/<pid>/exe`) doesn't work at all under how this
  broker is deployed (see §6.9) — not a claim that `comm` is sufficient
  against a targeted attacker, only that it's better than no check.
- The `~/.local/bin/sudo` shadow (§6.8) does not catch a caller that
  invokes `/usr/bin/sudo` by absolute path, or one running in an
  environment where `~/.local/bin` isn't on `PATH` ahead of `/usr/bin`
  (non-interactive systemd units, cron, a stripped-down `PATH`). Since
  §6.11, this is a UX gap, not a disclosure one: bypassing the shadow no
  longer lets a caller's own askpass receive the secret, so the only cost
  is losing the friendly retry labeling and `DOORMAN_COMMAND` hint that
  come from going through the wrapper.
- §6.11's identity check requires a one-time, root-privileged install step
  (`scripts/doorman-install-askpass`) that didn't exist before — every
  other install step stays fully unprivileged. If that step is skipped, or
  the installed file is later removed, the broker is designed to fail
  loudly (`askpass_identity_unavailable`, surfaced via `stats`), never to
  fall back silently to the pre-#9558-finding-4 guarantee, but it does mean
  Doorman simply doesn't function until the install step has been run.
- No automated test against a real Quickshell session or real Omarchy —
  the test suite drives the broker's own protocol directly and via the
  askpass helper (both the Python dev fixture and a real identity-matching
  peer exercising §6.11's positive path — see
  `test_request_with_real_trusted_askpass_identity_is_accepted`, which
  needs no root or compiler and runs in regular CI). A real `sudo` round
  trip through the installed C binary and a real Quickshell approval still
  needs to be verified live on the maintainer's own machine, outside
  automated CI.
- No `qmllint` or static analysis on the QML yet.
- The plugin's manifest `id` is load-bearing for Omarchy's bar layout
  (`~/.config/omarchy/shell.json` tracks placed widgets by id) — renaming it
  requires manually updating that file too; there's no migration path.
- Multiple simultaneous requests from different agent sessions are listed
  with a count but the UI can only act on one at a time (`root.selected`);
  there's no way to triage or batch-decide a queue.
- The retry heuristic (§6.10) is self-reported (`sudo_pid` is whatever the
  caller sends) and inferred from behavior, not a kernel guarantee — a
  caller could claim an arbitrary `sudo_pid` to make an unrelated request
  falsely show as "attempt 2", or vice versa. Cosmetic only: it never
  changes which checks gate approval.

## 8. Acceptance criteria

Every property in §6 has a corresponding automated test in `tests/`:
wrong token, invalid origin, missing PID, process-identity change, request
expiry, approve/replay, wrong-nonce approve and cancel, the askpass helper's
stdout-only contract, the idle-unauthenticated-connection close, the
slow-approval timeout regression, the `MAX_PENDING` cap with slot release on
cancel, — for §6.9 — that a caller with a valid token but the wrong
process ancestry gets `untrusted_caller` on all four of
approve/cancel/pending/stats, while `request` still succeeds for it, and —
for §6.10 — that a same-`sudo_pid` retry is tagged `attempt = 2`, supersedes
the previous pending request, and that unrelated or `sudo_pid`-less requests
are unaffected; for §6.11 — that a peer who doesn't hand over a matching
identity fd is rejected (`untrusted_askpass_helper`), that a
missing/unresolvable trusted path fails loudly (`askpass_identity_unavailable`,
also surfaced via `stats`) rather than silently skipping the check, and
that a peer whose fd genuinely does match is accepted — no root or
compiler needed for any of the three, unlike either design this
replaced; and for §6.12 — that
the displayed `command` is derived from the real sudo parent's own
`/proc/<pid>/cmdline`, not from a lying caller-supplied payload field.
`python3 -m unittest discover -s tests -p 'test_*.py'` must pass before any
change to `broker/broker.py` is considered done; the askpass helper
additionally builds clean under `-Wall -Wextra -Werror` and under
ASan/UBSan (`.github/workflows/ci.yml`'s `askpass-helper` job) before any
change to `askpass/doorman-askpass.c` is considered done.

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
