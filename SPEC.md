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
| **Broker** | A **system** service (`omarchy-doorman.service`, user `doorman`) owning two Unix sockets (§6.13) | Trusted — mediates every decision; holds no token or capability |
| **UI (plugin)** | A Quickshell bar widget + modal | Trusted — the only thing that can approve/cancel, runs as the login user, reaches the broker through the `doorman-ui` group socket |
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
  attacker who already has an interactive session as the same user and
  chooses to forge the trusted UI's process name (see §7).
- Not multi-user or networked — the sockets are local and the broker is
  pinned to exactly one login user (`--owner-uid`, §6.1); the project has no
  plan to change that.

## 3. Architecture

```
authorized command (sudo / sudo -A / SUDO_ASKPASS)
    └─ askpass helper (setgid doorman-askpass, non-dumpable)
         └─ /run/doorman/askpass.sock ──► broker (system service, user `doorman`)
                                              ▲
Quickshell plugin ─ bridge.py ─ /run/doorman/control.sock ┘
   (topbar widget + modal)            (doorman-ui group)
        └─ human types the password locally
```

- **Broker** (`broker/broker.py`): single Python process, one thread per
  connection, in-memory state only. Runs as the system user `doorman` under
  `omarchy-doorman.service` (§6.7), started by
  `scripts/run-doorman-broker`, which passes it the two socket paths, the
  `doorman-askpass` gid and the single owner uid (`--owner-uid`). It holds no
  token, capability or other secret: there is none (§6.9).
- **askpass helper** (`askpass/doorman-askpass.c`, compiled and installed by
  `scripts/doorman-install-askpass`): implements the `SUDO_ASKPASS`
  contract — reads a prompt on argv, writes the secret to stdout, nothing
  else. Installed once by root at
  `/usr/local/lib/omarchy-doorman/doorman-askpass`, outside the plugin's
  own git checkout, owned `root:doorman-askpass`, mode `2755` (setgid), not
  writable by the user. Its identity is its effective gid, which the kernel
  records for the broker at `connect()` (§6.13) — the helper hands the broker
  nothing to verify and opens no file. It is non-dumpable
  (`prctl(PR_SET_DUMPABLE, 0)`), which §6.13 explains is mandatory.
  `broker/askpass.py` (and a self-contained copy, `askpass.py`, for when
  `sudo` invokes it directly with no wrapper) are the earlier Python
  implementation, kept only as a dev/test fixture — they are not setgid, so
  the broker rejects them on the production path
  (`untrusted_askpass_helper`).
- **bridge** (`bridge.py`): a secret-free, tokenless CLI the Quickshell
  `Process` type shells out to for `pending`/`stats`/`approve`/`cancel`,
  always against `/run/doorman/control.sock` (`--socket`). The secret is
  piped over stdin on approval, never passed as an argument (arguments are
  visible to every other process on the machine via `/proc/<pid>/cmdline`).
- **UI** (`BarWidget.qml`, `Panel.qml`, `SecureOverlay.qml`): a topbar icon
  plus a status/history popup built on Omarchy's own `BarWidget`/`Panel`/
  `KeyboardPanel` contract (the same pair every first-party bar widget with a
  popup uses — e.g. `omarchy.clock`), and a separate modal `PanelWindow`
  (Wayland layer-shell, exclusive keyboard focus while open) for the actual
  approve/deny decision. The modal is deliberately outside the bar's popout
  system — SecureOverlay must be able to appear (and grab exclusive keyboard
  focus) whether or not the status popup is open. The bar widget is
  status-only: it shows broker state and hosts the modal, but has no
  start/stop toggle, since the broker is a system service managed with
  `systemctl` at install time, not from the UI.

## 4. Threat model

### 4.1 In scope

- A malicious or buggy **background agent process** that can set arbitrary
  *display* metadata (`cwd`, `tty`; `command` is no longer one of these —
  see §6.12), and runs as the same login user as the UI. There is no session
  token or capability for it to find or lack (an earlier design had both and
  they were removed, §6.9): its access is whatever the filesystem and socket
  permissions give an ordinary process of that user, which includes
  `doorman-ui` membership and therefore a connection to the control socket.
  What the agent cannot do is claim a `pid` other than its own real one,
  create a request at all without a real sudo process as its connection's
  immediate parent (§6.1), connect to the request socket as anything but the
  setgid askpass binary (§6.13), invoke real `sudo` with its own
  `SUDO_ASKPASS` and still be the one to receive the secret (§6.13), ptrace
  or read the memory of the askpass binary while it holds the secret
  (§6.13), pass itself off as the trusted UI beyond the `comm` limitation in
  §7, or read the human's keystrokes into the modal.
- **Process identity drift**: the PID a request was opened for exits and is
  reused by an unrelated process before the human approves.
- **Local resource exhaustion**: another process on the same machine
  trying to degrade the broker's availability.
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
- **A process that can pass the request gates can still open up to
  `MAX_PENDING` (20) concurrent requests**, each pinning a broker thread for
  up to `timeout + 1` seconds. Creating a request requires the setgid askpass
  egid and a genuine escalated `sudo` parent (§6.1, §6.13), so this is a
  strictly smaller threat than the unauthenticated case fixed in §6.4; the
  cap exists so this stays a soft inconvenience, not a broker crash.

## 5. Protocol

Transport: two Unix stream sockets in `/run/doorman`, both mode `0660`,
owned by the system user `doorman` (§6.13) — `askpass.sock` (group
`doorman-askpass`) serves `request`; `control.sock` (group `doorman-ui`)
serves `approve`, `cancel`, `pending` and `stats`. A verb sent to the wrong
socket gets `{"ok": false, "error": "wrong_socket"}`. Every message is one
line of UTF-8 JSON terminated by `\n`, capped at 16 KiB
(`MAX_LINE`); an oversized or unterminated line closes the connection with
no response. The broker reads at most one request line per connection
before dispatching — every request/response pair listed below is a full
connection lifecycle (connect → send → read response(s) → close).

There is no `"token"` field and no `"origin"`/`"capability"` field: none of
the messages below carries a bearer secret. Authorization is by the socket a
connection arrived on plus the kernel-reported peer credentials (§6.13,
§6.9). A client that still sends those legacy fields is simply ignored.

### 5.1 `request` — open a new authorization request

```jsonc
// → on /run/doorman/askpass.sock only
{
  "type": "request",
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
{"ok": false, "error": "wrong_socket"}         // sent on control.sock — see §6.13
{"ok": false, "error": "untrusted_askpass_helper"}     // peer's effective gid isn't doorman-askpass — see §6.13
{"ok": false, "error": "process_not_found"}    // /proc/<pid> unreadable or gone
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
// on /run/doorman/control.sock only
{"type": "approve", "request_id": "…", "nonce": "…", "secret": "…"}
// ←
{"ok": true}
{"ok": false, "error": "invalid_or_expired_request"}
```

Approval requires, atomically, under one lock acquisition: the request
exists, is not yet delivered, the nonce matches (`secrets.compare_digest`),
it hasn't expired, the process identity still matches (§6.1), the control
connection's peer uid equals the uid recorded when the request was created
(§6.1), and the secret is a string of at most 4096 bytes. As with the other
control verbs, the connection must also pass the trusted-UI check (§6.9),
else `{"ok": false, "error": "untrusted_caller"}`.

### 5.3 `cancel` — explicit human rejection

```jsonc
// →
{"type": "cancel", "request_id": "…", "nonce": "…"}   // control.sock only
// ←
{"ok": true}   // or {"ok": false} if the id/nonce didn't match a live request
```

### 5.4 `pending` — list open requests (for the UI to poll)

```jsonc
// →
{"type": "pending"}   // control.sock only
// ←
{"ok": true, "requests": [{"request_id": "…", "nonce": "…", "pid": …, "command": "…", "cwd": "…", "tty": "…", "prompt": "…", "screen": "…", "expires_at": …, "attempt": 1}]}
```

Only non-delivered, non-expired requests are listed. `attempt` is 1 unless
the request was correlated to an earlier one via `sudo_pid` (§6.10).

### 5.5 `stats` — session metrics (for the UI's status display)

```jsonc
// →
{"type": "stats"}   // control.sock only
// ←
{"ok": true, "uptime": 42, "pending": 0, "last_activity_at": 1234567890.1, "approved": 3, "cancelled": 1, "expired": 0, "requests": 4, "askpass_identity_available": true}
```

`askpass_identity_available` is `false` when the `doorman-askpass` group
doesn't resolve, or the installed binary is missing, isn't a regular file,
lacks the setgid bit, or isn't owned `root:doorman-askpass` (the install
step was never run, or its result was removed or altered — see §6.13). It is
re-evaluated on every `stats` call. While it is `false` no process can carry
the trusted egid, so every `request` is refused (`untrusted_askpass_helper`).
The UI surfaces this directly rather than require reading the broker's own
stderr.

## 6. Security properties and their rationale

### 6.1 Process identity is authenticated at request time, then re-checked at approval

The `pid` field in a `request` message (§5.1) is attacker-controlled input —
an agent could otherwise
claim to be any PID that happens to exist, not even a real sudo/askpass
process, display a convincing `command`, get a human to approve it, and
receive the secret itself back on its own connection, since the response
always goes to whoever is actually connected, never to the claimed pid.
`_create_request` closes this before doing anything else with the claim: it
reads the connection's real peer via `SO_PEERCRED` (kernel-verified, not
something the remote process can forge — the same primitive §6.9 uses for
the trusted-UI check) and rejects with `pid_mismatch` unless that peer's
pid equals the claimed `pid` and its uid equals the configured owner uid.
This changes nothing for the legitimate flow: the askpass helper reports
its own real pid, so the claim and the connection's real identity are
always the same process to begin with.

**Which uid "the owner" is (shape B).** Before the system-service move the
broker ran as the login user, so these comparisons could use the broker's own
uid. It now runs as the dedicated system user `doorman` (§6.13), so
`os.getuid()` would be the wrong reference. Every peer-uid comparison in the
broker — the `pid_mismatch` uid check above, the `not_sudo_child` parent's
real uid, and the trusted-UI check (§6.9) — is against the single configured
`--owner-uid` (the login user, supplied by `scripts/run-doorman-broker`),
never against the broker's own uid. The owner uid is also bound to each
request: `_create_request` records the creating connection's uid in the
request, and `approve`/`cancel` succeed only if the control connection's
peer uid equals it, so a request opened for one uid can never be decided by
a connection from another.

These checks read another uid's `/proc/<pid>/{comm,stat,status,cmdline}`
from a process that is no longer that uid. They are plain, non-ptrace-gated
reads (§6.7) and were validated under this unit's hardening during the
spike (the unit file records this), but they remain part of the final live
verification: the broker, the real `sudo` peer and its parent are all
different uids than in the earlier `systemd --user` deployment, and §6.13
lists that as an unrun check.

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
*first* read only — the line carrying the message — then
clears it before doing anything else. This is deliberate: it closes a real
denial-of-service (any process that could reach the socket could open a
connection, send nothing, and pin a broker thread forever — fixed
after being found during manual testing), without breaking the legitimate
case where a `request` connection needs to stay open for up to 300 seconds
waiting on a human. A client library must apply the same split: a short
timeout for the handshake read, and a separate timeout — sized from the
`expires_at` the broker already returned — for the decision read. Reusing
the handshake timeout for both (an earlier bug in this project's own
reference client) silently breaks any approval slower than the handshake
window.

### 6.3 Every comparison that gates a decision is constant-time

Both nonce checks (`approve` and `cancel`) use `secrets.compare_digest`.
(Earlier revisions also compared a session token and an LLM capability this
way; both were removed with the token layer, §6.9. The uid and gid
comparisons that now gate a decision are integer equality on
kernel-reported values, not secret comparisons.) This was inconsistent during
development — `approve` briefly used `==` while `cancel` used
`compare_digest` for the identical check — and was corrected for
consistency; see §4.3 for why the practical exposure was always low given
the nonce's entropy.

### 6.4 Concurrency is bounded at two layers

- **Idle**: the handshake timeout (§6.2) bounds how long an idle connection
  that never sends a line can hold a thread.
- **Admitted**: `MAX_PENDING` (20) bounds how many requests can be open at
  once, checked and inserted atomically under the broker's single lock to
  avoid a check-then-act race.

### 6.5 The secret never touches a surface that isn't the approval itself

- Never an argument (`ps`/`/proc/<pid>/cmdline` visible to any local user).
- Never written to a file, including temp files.
- Never logged — the broker's own output is the startup line naming the two
  socket paths and the once-a-minute "askpass binary not installed" notice
  (§6.13); neither contains request data.
- The bridge CLI passes it over stdin on `approve`, not argv.
- The askpass helper writes it to stdout, which only `sudo` itself reads.

### 6.6 The sockets and their directory are access-controlled by construction

There are two sockets (§6.13), both created by the broker in `/run/doorman`
and both `chown`ed `doorman:<group>` and `chmod`ed `0660` immediately after
`bind()`:

| Socket | Group | Who the kernel lets connect |
|---|---|---|
| `/run/doorman/askpass.sock` | `doorman-askpass` | members of that group — only the service user — and any process whose *effective* gid is that group, i.e. one that exec'd the setgid askpass binary |
| `/run/doorman/control.sock` | `doorman-ui` | members of `doorman-ui` — the service user and the single login user |

The directory is created by systemd (`RuntimeDirectory=doorman`,
`RuntimeDirectoryMode=0750`), so it is owned `doorman:doorman` and recreated
at each service start. A socket's permission bits are enforced by the
kernel at `connect()`, before the broker sees a byte. If a bind-time
`chgrp` cannot be done (the group does not resolve, or the process lacks the
right to it), the broker refuses to start rather than leave a socket with
the wrong group; the only exception is an explicit test seam, which falls
back to owner-only `0600` — strictly tighter, used only by unprivileged CI.
On startup, if a stale socket path exists and isn't owned by the current
uid, or isn't a socket at all, the broker refuses to bind rather than
silently taking over a path.

Two honest qualifications. First, the control socket's ACL separates the
login user from *other* users, not the trusted UI from the agent: every
process of the login user inherits `doorman-ui` after the re-login, so the
distinction between Quickshell and an agent on that socket rests on the
`comm` check of §6.9 and is bounded by §7. Second, the directory is
`0750 doorman:doorman`; a caller reaches a socket inside it only if the path
is traversable for that caller, and this directory-traversal path for the two
caller groups is one of the items in the live verification (§6.13), not
something the unit-test suite exercises.

### 6.7 Systemd sandboxing

The broker is a **system** unit, `/etc/systemd/system/omarchy-doorman.service`
(installed by `scripts/doorman-install-askpass`, started with
`systemctl enable --now omarchy-doorman.service`), not a `systemd --user`
unit. It sets `User=doorman`, `Group=doorman`,
`SupplementaryGroups=doorman-askpass doorman-ui` (so it may `chgrp` both
sockets), `RuntimeDirectory=doorman`, `RuntimeDirectoryMode=0750`,
`ReadWritePaths=/run/doorman` and `UMask=0007`, and is
`WantedBy=multi-user.target`. Its sockets live in `/run/doorman` and do not
depend on any login session; the UI simply needs them to exist. The
`ExecStart` is `scripts/run-doorman-broker`, with `@PROJECT_DIR@` in the unit
template replaced at install time by the checkout the script was run from.

**Known pending deployment item.** The broker's code is read from that
checkout, which today is under the login user's home (e.g.
`~/.config/omarchy/plugins/mauricio.doorman`). The broker runs as `doorman`
with `ProtectHome=read-only`, and a home directory is normally mode `0700`
for its owner — so `doorman` may be unable to read its own code. `ProtectHome=read-only`
does not grant access; it only removes write access. This is not resolved in
the current tree. Fixing it may require installing the broker code outside
`/home` (as the askpass binary already is, under `/usr/local/lib`); the unit
file carries a comment to the same effect. Until that is settled and
verified, treat the install/run flow as not yet end-to-end proven.

The unit additionally sets `NoNewPrivileges`, `PrivateTmp`,
`RestrictAddressFamilies=AF_UNIX` (the broker never needs any other socket
family), `CapabilityBoundingSet=` (empty — it needs zero Linux
capabilities), `SystemCallFilter=@system-service`, and a handful of
`Protect*`/`Restrict*` flags (kernel tunables/modules/logs, control groups,
clock, hostname, namespaces, realtime scheduling, SUID/SGID,
`LockPersonality`, `MemoryDenyWriteExecute`). Almost none of these change
behavior for a pure-Python service that only speaks Unix sockets and reads
`/proc`; they remove attack surface the broker was never going to use
anyway. The one exception, which is history of the earlier
`systemd --user` deployment: there, `ProtectSystem=strict`/
`ProtectHome=read-only`/`PrivateTmp=true` each independently confined the
broker so that reading *another process's* `/proc/<pid>/exe` (or `/maps`,
`/mem` — anything `ptrace_may_access()`-gated) was denied outright
(`PermissionError`), and credential values outside its minimal mapping
resolved to the kernel's overflow id. Neither affects plain,
non-ptrace-gated `/proc` reads like `comm`, `status`'s pid/uid lines, or
`cmdline` — which is why §6.1's checks were never affected, and why the
current design (§6.13) reads no ptrace-gated file of the peer at all: the
askpass is non-dumpable, which would revoke exactly those reads, and its
identity comes from `SO_PEERCRED` instead. Under the system unit the
broker's checks are the plain reads of §6.1, validated in the spike under
these directives (see the comment in the unit file) but still subject to the
final live verification (§6.13). If a `Protect*` directive were found to
block them, the specific directive would be reconsidered, not the whole
profile. See §6.9, §6.11, and §6.13 for the history.

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

### 6.9 approve/cancel/pending/stats require being the trusted UI; there is no token or capability

**There is no session token and no `origin=llm` capability in the current
design.** Earlier revisions had both: every message carried a `token`, and
`request` additionally carried `origin: "llm"` plus a `capability`, all kept
in files under the user's runtime directory. They were removed completely —
no `token`/`origin`/`capability` field, no `unauthorized` or
`invalid_llm_origin` error, no token file, no `--token`/`--llm-capability`
option on the broker, no `--token-file` on the bridge. The reasons are in the
history below and in §6.13: the token files were readable by exactly the
processes the token was supposed to exclude (same uid), and the askpass
helper's read of them was the root of the 2026-10-25 symlink/environment
finding. What stands in for them is not a replacement secret but the
connection itself:

- `request` is gated by the peer's effective gid on the askpass socket
  (§6.13), then §6.1, then a human approval;
- `approve`, `cancel`, `pending` and `stats` are gated by `doorman-ui`
  membership (the control socket's group ACL, §6.6), the trusted-UI
  process-name walk described next, and the owner-uid binding (§6.1).

*History of why the control verbs are gated at all.* An earlier version of
this document assumed the agent doesn't have the session token. That was
false: the token and capability lived in files under the same UID the agent
runs as, exactly like the UI reads them — `origin=llm` + capability only
gated who could *create* a request.
Manual testing during development confirmed the consequence directly: a
plain shell script that read those files could create a request and then
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
3. The connection's peer uid (step 1) must equal the configured owner uid
   (§6.1) before the walk starts, and that uid is what `approve`/`cancel`
   then compare to the request's recorded owner uid. A connection from any
   other uid is `untrusted_caller` even if it somehow reached the socket.

Reaching the control socket at all additionally requires `doorman-ui`
membership (§6.6). That is an access control against *other* users; it does
not by itself tell the agent from Quickshell, since both run as the login
user and both inherit the group — steps 1–3 do that, and step 2 is bounded by
the `comm` limitation in §7.

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

**2026-11-05 note, added while writing the then-current identity-helper
design (history: that design was later replaced by the current §6.13; the
bisection this note cites now lives in the design record
`docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md`, not in
§6.13):** that design's work performed a later,
more precise bisection of this same broker unit file while designing the
identity-helper, and found that exactly five directives
(`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`,
`ProtectKernelTunables=true`, `ProtectControlGroups=true`) each
independently cause this `EACCES`, and that a caller with *none* of those
five succeeds with no special permission at all — not "stripped to zero"
as stated two paragraphs above. That's a real tension with this section's
own claim: if the bisection described here truly reached zero directives
and still failed, the identity-helper's own unit (which deliberately keeps
roughly fifteen *other* directives and drops only those five) shouldn't
work either, yet it does, confirmed live. This section's "stripped to
zero" characterization may simply have been imprecise, or the bisection
it describes may have been run under different conditions than §6.13's —
that wasn't re-verified before this note was written, and re-verifying it
is out of scope here. Rather than guess which, treat §6.13's
directive-by-directive bisection as the more rigorous, more precise
finding on this exact question, and this section's broader "even stripped
to zero" claim as superseded by it, the same way §6.11's mechanism is
superseded by §6.13's.

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
self-reported by the caller (any request can claim any
`sudo_pid`, causing a false "attempt 2" label at worst), and the inference
that a same-`sudo_pid` retry implies "the previous password was wrong"
relies on the observed (not kernel-guaranteed) behavior that Doorman's own
cancel/expiry don't trigger a `sudo` retry. Getting this wrong only affects
what the modal *says*; it never changes whether a request needs a real human
approval, still gated by the exact same checks as any other request.

### 6.11 The askpass helper itself must carry an identity it can't fake

> **Superseded (history, not current behavior).** Everything in this
> section describes the `SCM_RIGHTS`/`cap_dac_read_search` mechanism, which
> an `O_PATH` bypass defeated during production security review (issue
> #9558). §6.13 describes what replaced it: the broker now reads the peer's
> kernel-recorded effective gid, and no longer receives a file descriptor
> from, or inspects the file behind, the peer at all — so the device+inode
> comparison below no longer exists in the code. An intermediate
> identity-helper/`SIGSTOP` design replaced this one for a time and was in
> turn replaced by §6.13; it is recorded in
> `docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md`. The
> three earlier failed attempts documented below remain the complete record
> of what didn't work here and why. References below to the token,
> capability, `systemd --user` and `/proc/<pid>/exe` describe those earlier
> designs.

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

§6.11 — now superseded by §6.13, which closes the same question with a
different mechanism — closed who can receive the secret. Neither version,
by itself, stops a caller running the genuinely trusted askpass binary (a
legitimate invocation) from lying about what the human is approving: the
request payload's `command` field used to be taken verbatim from the caller
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

### 6.13 Askpass identity is a kernel-recorded credential (the effective gid), not something the broker inspects or is handed

> **Status.** This is the "shape B" design as it exists in the code. It is
> implemented and unit-tested but **has not yet been live-verified end to
> end** against the real system unit, a real `sudo` round trip and a real
> Quickshell session — that is a separate, human-run step (see "What is and
> is not verified" at the end of this section). Issue #9558 is not reopened
> until it passes.

This section supersedes both mechanisms that came before it: §6.11's
`SCM_RIGHTS`/`cap_dac_read_search` fd-passing check, and the intermediate
identity-helper design (a separate `systemd --user` process the broker
queried synchronously at accept time, with a `SIGSTOP`/`pidfd` freeze of the
peer around the query). Neither exists in the code any more: there is no
identity-helper process, no `SIGSTOP`/`SIGCONT`, no `pidfd`, no
`/proc/<pid>/exe` lookup of the peer, no file descriptor read from the peer,
and no session token or capability (§6.9). The broker's own docstring
(`broker/broker.py`) states the same inventory. Why those designs were
abandoned — the `O_PATH` bypass of the fd check (issue #9558), the
mount-namespace confinement that blocks `/proc/<pid>/exe` reads under the
broker's hardening, the fork-then-exec race against any identity check made
after `accept()`, and the later finding that a non-dumpable askpass is
structurally incompatible with an exe-based check — is recorded, with the
live evidence, in
[`docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md`](docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md)
(its "Decision and spike" section and Findings 4 and 5). It is not repeated
here.

**The mechanism.** The broker is a **system** service running as a dedicated
system user, `doorman` (§6.7). Three things work together:

1. *The askpass binary is setgid.* `scripts/doorman-install-askpass`
   compiles `askpass/doorman-askpass.c` and installs it at
   `/usr/local/lib/omarchy-doorman/doorman-askpass`, owned
   `root:doorman-askpass`, mode `2755`. The install script verifies the
   owner and the setgid bit after the move and fails if either did not
   stick. A process that `exec`s this file runs with effective gid
   `doorman-askpass`. The group owns no other file, and the install script
   adds no login user to it (the only account added to it is the service
   user `doorman`, so the broker can `chgrp` its socket).
2. *The kernel enforces it at `connect()`.* The request socket
   `/run/doorman/askpass.sock` is owned `doorman:doorman-askpass`, mode
   `0660`. Because the owner (`doorman`) is not the connecting uid, the
   connector is judged by the group bits: an ordinary process of the login
   user that is not in `doorman-askpass` is refused with `EACCES`. The
   spike confirmed this on the target machine (design record, Q2).
3. *The broker re-checks the credential it was handed by the kernel.* For a
   `request`, `_handle` reads the peer's *effective* gid from `SO_PEERCRED`
   and requires it to equal the `doorman-askpass` gid
   (`_peer_has_trusted_egid`); otherwise the connection gets
   `{"ok": false, "error": "untrusted_askpass_helper"}`. `SO_PEERCRED` is
   recorded by the kernel at `connect()` time, so a later `execve()` in the
   same or a different process cannot change it: a process that connected
   as some other binary and then `exec`s the setgid one does not acquire
   the egid on the existing connection, and a process that connected as the
   setgid binary cannot lose it. The check reads nothing from the peer — no
   message field, no fd, no file — which is why the `O_PATH` class of
   attack has nothing to attach to.

Only the *request* path is gated by egid. Everything else §6.1 checks
(the claimed `pid` equals the peer's real pid, the peer's immediate parent is
a genuine escalated `sudo`, the owner uid) still applies after it and is
unchanged except for which uid it compares against (§6.1).

**Two sockets, per-socket verb routing.** The broker listens on two Unix
sockets, and which listener accepted a connection — not anything the peer
sends — decides the verb set `_handle` will serve:

| Socket | Owner / mode | Verbs served | Gate |
|---|---|---|---|
| `/run/doorman/askpass.sock` | `doorman:doorman-askpass`, `0660` | `request` | peer egid == `doorman-askpass` (this section) + §6.1 + human approval |
| `/run/doorman/control.sock` | `doorman:doorman-ui`, `0660` | `approve`, `cancel`, `pending`, `stats` | `doorman-ui` socket ACL + trusted-UI `comm` walk + owner uid (§6.9) |

A `request` arriving on the control socket, or any of the four control verbs
arriving on the askpass socket, is rejected with
`{"ok": false, "error": "wrong_socket"}` *before* any other gate runs, so a
caller that can reach one socket cannot exercise the other's verbs even if it
would have passed that verb's own gate. An unrecognised `type` gets
`unknown_type`. The askpass binary connects to the fixed
`/run/doorman/askpass.sock` (modulo the test override described below), and
the broker reads no file whose location a caller influences.

**The askpass binary is non-dumpable and ignores the environment.** The
first statement of `main()` in `askpass/doorman-askpass.c` is
`prctl(PR_SET_DUMPABLE, 0)`. This closes the ptrace/memory read of the
plaintext secret (design record, Finding 5): a same-uid process can no
longer `PTRACE_ATTACH` to the askpass while it holds the secret, or read its
memory. The call is **mandatory and not belt-and-suspenders**: after a
setgid `exec`, whether the process is dumpable is governed by the machine's
`fs.suid_dumpable` sysctl. On the spike machine that value left the process
non-dumpable, but a machine with `fs.suid_dumpable=1` would leave it
`dumpable=1` and the ptrace read would succeed. The explicit `prctl` removes
that dependence. Separately, because the exec is setgid the kernel sets
`AT_SECURE=1`, so the dynamic loader ignores `LD_PRELOAD` and other `LD_*`
variables from the caller's environment; the binary stays dynamically linked
and relies on that. Dumpability does not gate `SO_PEERCRED`, so making the
binary non-dumpable does not break the egid check (spike Q4) — which is
exactly what it did break for the earlier `/proc/<pid>/exe` design.

The binary opens no file at all. It connects to the fixed path
`/run/doorman/askpass.sock`, sends one JSON line, and reads one JSON line
back. The 2026-10-25 symlink/`XDG_RUNTIME_DIR`/`DOORMAN_SOCKET`
exfiltration finding is therefore closed by removing the read, not by
guarding it: there is no token file to be tricked into reading, and nothing the binary
holds that it could be tricked into sending to a chosen path. One
environment variable is nonetheless consulted,
`DOORMAN_SOCKET_DEV_OVERRIDE`, which exists only so the binary's own test
suite can point it at a test socket; nothing in the production flow sets it,
but a caller who controls the environment of its own `sudo` invocation can,
and the binary does not refuse it. Its effect is confined to *where the
binary connects*: the binary sends no secret (it only receives one), so
redirecting it to a socket the caller controls discloses nothing it holds,
and a fake broker there can only make that one askpass process receive a
caller-chosen string instead of a password. This is a code-level wrinkle
worth knowing about, not a finding; removing the override from the
production build is a possible hardening.

**Degraded state.** The broker computes `askpass_identity_available`: the
`doorman-askpass` group resolves *and* the binary exists at the fixed path,
is a regular file, has the setgid bit, and is owned `root:doorman-askpass`.
It is re-evaluated on every `stats` (§5.5) and logged to the journal at most
once a minute while false. When it is false no process can carry the trusted
egid, so every `request` is refused with `untrusted_askpass_helper`; the UI
surfaces the flag rather than requiring the journal to be read. (An earlier
revision had a separate `askpass_identity_unavailable` error; the current
code does not emit it.)

**The single-owner pin.** The broker is started with `--owner-uid` (§6.1,
§6.9). `scripts/run-doorman-broker` takes that from `DOORMAN_OWNER_UID` if
set, otherwise from the *sole* login member of the `doorman-ui` group, and
refuses to start if there is not exactly one. Each request records the uid
of the connection that created it, and `approve`/`cancel` require the
control connection's peer uid to equal it. This is a pinned single-user
model, not a multi-user one (§2).

**What is and is not verified.** Closed by design, in the sense that the
code removes the mechanism the finding relied on: the `O_PATH`/fd-passing
bypass (nothing is read from the peer), the symlink/environment
exfiltration (the binary reads no file and uses a fixed path), the
fork-then-exec race (identity is the connect-time egid, not a check made
afterward — for a post-connect fork the child has no ACL access to the
socket and shares no egid; for a pre-connect fork the connector is judged by
its own egid), and the same-uid ptrace/memory read of the secret
(`PR_SET_DUMPABLE`). What has been confirmed live is limited to the four
kernel assumptions in the design record's spike (setgid survives `sudo -A`;
the socket group ACL refuses a non-member; the ancestor ptrace attack is
blocked against a setgid target; `SO_PEERCRED` reads the egid of a
non-dumpable client). **What has not been done:** the end-to-end check
against the real system unit, a real `sudo` round trip and real Quickshell,
including the repeated fork-exec attacker runs, the ptrace attempt against
the real binary, the symlink/environment reproduction, the second-user
rejection and the degraded-state check. Those are enumerated as Task 12 of
`docs/superpowers/plans/2026-11-09-askpass-identity-shape-b.md` and are run
by a human with root; until they pass, the fork-exec race and the ptrace
read are *closed by design, live verification pending*, not "fixed and
verified". The unit-test suite does not substitute for that (this project's
own repeated lesson).

## 7. Known limitations

- The trusted-UI check (§6.9) matches on `/proc/<pid>/comm`, which a
  process can set to anything via `argv[0]` or `prctl(PR_SET_NAME)`. An
  agent that deliberately spawns a child process named `quickshell` and
  connects from it would pass. This is a real gap, accepted because the
  alternative (`/proc/<pid>/exe`) is not available to the broker (see §6.9)
  — not a claim that `comm` is sufficient against a targeted attacker, only
  that it's better than no check. Shape B does not change it: the control
  socket's `doorman-ui` ACL excludes other users, not same-user processes
  (§6.6), and there is no token any more to add a second factor.
- The `~/.local/bin/sudo` shadow (§6.8) does not catch a caller that
  invokes `/usr/bin/sudo` by absolute path, or one running in an
  environment where `~/.local/bin` isn't on `PATH` ahead of `/usr/bin`
  (non-interactive systemd units, cron, a stripped-down `PATH`). Since
  §6.13, this is a UX gap, not a disclosure one: bypassing the shadow no
  longer lets a caller's own askpass receive the secret, so the only cost
  is losing the friendly retry labeling and `DOORMAN_COMMAND` hint that
  come from going through the wrapper.
- The askpass identity (§6.13) requires a one-time, root-privileged install
  step (`scripts/doorman-install-askpass`) that didn't exist before — every
  other install step stays fully unprivileged. If that step is skipped, or
  the installed file is later removed or its setgid bit lost, the broker is
  designed to fail loudly (`stats` reports `askpass_identity_available:
  false` and every `request` is refused with `untrusted_askpass_helper`),
  never to fall back silently to a weaker guarantee, but it does mean
  Doorman simply doesn't function until the install step has been run.
- No automated test against a real Quickshell session or real Omarchy —
  the test suite drives the broker's own protocol directly and via the
  askpass helper, with the trusted egid supplied through a test-only seam
  so no root, real group or setgid binary is needed in regular CI. A real
  `sudo` round trip through the installed setgid C binary, the real socket
  ACLs and a real Quickshell approval still need to be verified live on the
  maintainer's own machine, outside automated CI (§6.13).
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
- **Shape-B residuals (§6.13).**
  - *Group join and re-login.* The login user is added to `doorman-ui` by
    the install script, but supplementary groups are read at login: the UI
    (Quickshell) cannot reach the control socket until the user has logged
    out and back in. The install script says so; until then the widget
    reports the broker as unreachable.
  - *`doorman-ui` has exactly one login member.* `scripts/run-doorman-broker`
    refuses to start unless exactly one login user is in the group (or
    `DOORMAN_OWNER_UID` names one), and every uid check is pinned to that
    uid. Adding a second member is an unsupported configuration, not a
    multi-user feature; a different user who did gain access would still be
    refused by the owner-uid checks (§6.1), but that behavior is part of the
    live verification, not yet confirmed.
  - *`fs.suid_dumpable` dependence.* Whether a setgid `exec` leaves the
    process dumpable depends on that sysctl, which varies by machine. The
    explicit `prctl(PR_SET_DUMPABLE, 0)` in the askpass binary is therefore
    mandatory, not defense in depth; removing it would reopen the same-uid
    ptrace/memory read of the secret on machines where the sysctl is `1`.
  - *The broker code must be readable by `doorman`.* The unit runs as
    `doorman` with `ProtectHome=read-only` against a checkout that is
    currently in the login user's home (§6.7). This may require installing
    the broker code outside `/home`; it is an open deployment item, not
    solved.
  - *Directory traversal for the socket callers.* `/run/doorman` is
    `0750 doorman:doorman` (§6.6); that the askpass binary (egid
    `doorman-askpass`) and the UI (group `doorman-ui`) can reach their
    sockets through it is unverified (§6.13).
  - *Pending final live verification.* The fork-exec race (both the
    post-connect and pre-connect variants) and the ptrace read of the secret
    are closed by design but **not yet live-verified** against the real
    system unit and a real `sudo` round trip (§6.13; Task 12 of
    `docs/superpowers/plans/2026-11-09-askpass-identity-shape-b.md`). Issue
    #9558 is not reopened until that passes.

## 8. Acceptance criteria

Every property in §6 has a corresponding automated test in `tests/`
(except the live-only checks §6.13 names): missing PID, process-identity change, request
expiry, approve/replay, wrong-nonce approve and cancel, the askpass helper's
stdout-only contract, the idle-connection close, the
slow-approval timeout regression, the `MAX_PENDING` cap with slot release on
cancel, — for §6.9 — that a control-socket caller with the wrong
process ancestry gets `untrusted_caller` on all four of
approve/cancel/pending/stats, that no token is required on either socket,
that each socket rejects the other's verbs with `wrong_socket`, that
`approve`/`cancel` are bound to the request's recorded owner uid, and —
for §6.10 — that a same-`sudo_pid` retry is tagged `attempt = 2`, supersedes
the previous pending request, and that unrelated or `sudo_pid`-less requests
are unaffected; for §6.13 — that a peer whose effective gid isn't the
trusted gid is rejected (`untrusted_askpass_helper`), that a missing or non-setgid installed binary
is reported loudly via `stats` rather than silently skipping the check, and
that a peer with the trusted egid is accepted (unprivileged CI pins the gid
through a test-only seam rather than needing a real group or setgid
binary — which is exactly why the real setgid, ACL and ptrace behavior is a
live check, not a unit-test one); and for §6.12 — that
the displayed `command` is derived from the real sudo parent's own
`/proc/<pid>/cmdline`, not from a lying caller-supplied payload field.
`python3 -m unittest discover -s tests -p 'test_*.py'` must pass before any
change to `broker/broker.py` is considered done; the askpass helper
additionally builds clean under `-Wall -Wextra -Werror` and under
ASan/UBSan (`.github/workflows/ci.yml`'s `askpass-helper` job) before any
change to `askpass/doorman-askpass.c` is considered done.

## 9. Glossary

- **Broker**: the long-running system service in §3 that owns both sockets
  and all request state.
- **Control socket**: `/run/doorman/control.sock`, group `doorman-ui`; the
  only socket that serves `approve`, `cancel`, `pending` and `stats` (§6.13).
- **Askpass socket**: `/run/doorman/askpass.sock`, group `doorman-askpass`;
  the only socket that serves `request` (§6.13).
- **Nonce**: a per-request random value required, in addition to
  `request_id`, to approve or cancel — prevents an attacker who can guess
  or observe a `request_id` (e.g. from process listings, since it isn't
  secret) from acting on a request they didn't create.
- **Trusted egid**: the effective gid `doorman-askpass`, carried only by a
  process that exec'd the root-installed setgid askpass binary (§6.13).
  Formerly-described "session token" and "capability" no longer exist.
