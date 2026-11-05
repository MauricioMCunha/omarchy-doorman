# 6th design: binding askpass identity (fix for #9558, open findings on 67a6a06)

## Context and why

GitHub issue `omacom/omarchy-plugin-marketplace#9558` (reviewer: HANCORE-linux)
is **closed** (2026-11-02, no reply within 7 days to a 2026-10-25 finding).
Reopening requires addressing both currently-open findings on commit
`67a6a06` in the same response:

1. **O_PATH/fstat bypass** (2026-10-08, re-confirmed 2026-10-25): the
   broker's identity check (`broker/broker.py`, roughly lines 383-389 and
   576-581) accepts an `open(trusted_path, O_PATH)` descriptor sent over
   `SCM_RIGHTS` just as readily as a genuine self-exe fd, because `O_PATH`
   needs zero permission on the target file and `fstat()`s identically to a
   real open. This defeats the entire device+inode identity-pinning
   mechanism regardless of mode bits or file capabilities.
2. **Symlink/env file-exfiltration** (2026-10-25, verbatim from
   HANCORE-linux): *"the installed `0711` helper with `cap_dac_read_search=ep`
   follows caller-controlled token-file symlinks under `XDG_RUNTIME_DIR` and
   sends their short protected-file contents to caller-selected
   `DOORMAN_SOCKET` without sudo or human approval"* (`askpass/doorman-askpass.c:303–329,364–391`,
   `scripts/doorman-install-askpass:76–82`). Enabled by the combination of
   (a) `cap_dac_read_search` bypassing normal DAC read checks, (b) no
   `O_NOFOLLOW`/canonical-path validation on the token-file open, and (c) no
   authentication of `DOORMAN_SOCKET`.

Four prior design attempts for finding 1 (setgid group, broker-side
`stat()` of the peer's `/proc/<pid>/exe`, SCM_RIGHTS+fstat without a
capability, SCM_RIGHTS+fstat with `cap_dac_read_search`) each failed for a
different, previously-undiagnosed reason — full history in project memory
(`project_doorman_askpass_identity_investigation.md`) and `SPEC.md` §6.9-6.11.
A fifth candidate (have the broker itself read the peer's `/proc/<pid>/exe`
directly, using the pid from `SO_PEERCRED`) was explored and killed on
2026-11-05, same day as this document, for two independent reasons
confirmed by live testing (see "Validated findings" below):

- The broker's own systemd hardening (`ProtectSystem=strict`,
  `ProtectHome=read-only`, `PrivateTmp=true`, and others) puts it in a
  private mount namespace, which blocks reading *any other process's*
  `/proc/<pid>/exe` — including a completely ordinary, unprivileged,
  dumpable target — regardless of capabilities. This is the actual
  explanation for the second design attempt's long-unresolved failure
  (`SPEC.md` §6.11 misattributed it to Yama/ptrace_scope).
- Even if that were solved, `SO_PEERCRED`'s pid is captured once at
  `connect()` time and never updates; a forked sibling of the connecting
  process inherits the live socket and can drive the rest of the protocol
  while the original process separately `execve()`s into the trusted
  binary purely to manipulate what a *later* `/proc/<pid>/exe` check would
  see. A check performed at any point *after* the connection is accepted is
  vulnerable to this. (This also means the existing SCM_RIGHTS mechanism's
  fd could, in principle, be handed off the same way via fork — though it
  isn't the main attack there; O_PATH alone already breaks it without
  needing fork at all.)

This document proposes a sixth design, built only from pieces that have
each been individually confirmed live, today, against this exact machine's
real configuration — not assumed.

## Goals

- Close both open findings (O_PATH/fstat bypass, symlink/env exfiltration)
  in one change.
- No file capability, setuid, or setgid bit anywhere in the new design.
- Preserve the broker's existing mount-namespace hardening
  (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`,
  `ProtectKernelTunables=true`, `ProtectControlGroups=true`, and everything
  else in `omarchy-doorman.service`) completely unchanged.
- Resistant to the `fork()`-plus-shared-socket timing attack described
  above, verified the same way every prior round's fix was: live, on this
  machine, reproducing the actual attack before and after.

## Non-goals / anti-goals

- **Not** a general redesign of `DOORMAN_SOCKET`/`XDG_RUNTIME_DIR` trust.
  Minimal fix only: the production path stops honoring `DOORMAN_SOCKET`
  from the environment (derives the path the same fixed way the install
  script does); an explicit, separately-named dev/test override stays
  available for the test suite. Full mutual authentication of the broker
  socket is out of scope for this round.
- **Not** preserving any part of the existing `SCM_RIGHTS` fd-passing
  mechanism in `askpass/doorman-askpass.c` or `broker/broker.py` — it is
  deleted, not patched, along with the `setcap`/`nosuid`-check/`getcap`
  logic in `scripts/doorman-install-askpass`.
- **Not** relaxing, weakening, or working around any of the broker's
  existing `Protect*`/`Private*` systemd directives. If this design were
  found to require that, it should be rejected and reconsidered, not
  shipped with a quiet hardening regression.
- Would be a failure even if it technically passed tests: shipping this
  without a live reproduction of all three relevant attacks (O_PATH,
  symlink-exfil, fork-timing) failing against the real production units —
  a unit-test-only pass is not sufficient evidence, per this project's own
  repeated history of unit tests passing while the real systemd-sandboxed
  behavior differed.

## Validated findings (live-tested 2026-11-05, this session, on this machine)

1. **Mount-namespace confinement blocks cross-process `/proc/<pid>/exe`
   reads, independent of capabilities or Yama.** Bisected the real
   broker unit's hardening directives one at a time via `systemd-run --user`
   against an ordinary (dumpable, zero-capability) sibling process:
   `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`,
   `ProtectKernelTunables=true`, and `ProtectControlGroups=true` **each
   independently** caused `readlink()`/`open()` of the sibling's
   `/proc/<pid>/exe` to fail with `PermissionError(13)`. Directives that do
   **not** cause this failure: `CapabilityBoundingSet=` (empty),
   `NoNewPrivileges=true`, `RestrictNamespaces=true`, `RestrictSUIDSGID=true`,
   `SystemCallFilter=@system-service`, `LockPersonality=true`,
   `MemoryDenyWriteExecute=true`, `RemoveIPC=true`, `UMask=0077`. A caller
   with **none** of the mount-namespace-creating directives reads the same
   target successfully with zero special permission.
2. **A systemd `--user` unit cannot be granted `AmbientCapabilities` at
   all.** `systemd-run --user -p AmbientCapabilities=CAP_SYS_PTRACE ...`
   fails immediately with `218/CAPABILITIES`. Irrelevant to this design
   (which needs no capability anywhere) but recorded because it explains
   why an earlier attempt's "grant the broker CAP_SYS_PTRACE directly"
   could never have worked, independent of finding 1 above.
3. **A synchronous, accept()-time identity check is not fooled by a later
   `fork()`+`exec()` on the same connection.** Built a real two-process
   test: an "attacker" connects to a plain `AF_UNIX` listener, `fork()`s,
   has the parent `execve()` into `/usr/bin/true` (standing in for "becomes
   the trusted binary"), while the forked child sleeps briefly then sends
   data on the *same, shared* connected socket. A listener that reads
   `SO_PEERCRED` and resolves `/proc/<pid>/exe` **immediately upon
   `accept()`, before reading anything else from the peer** correctly saw
   the attacker's real, pre-exec identity
   (`/usr/bin/python3.14`), not the post-exec one — confirming that
   checking at accept-time, before any further protocol messages are read,
   defeats this specific timing attack. (A second check performed *after*
   reading data showed the original pid had already exited —
   `/usr/bin/true` runs and exits almost instantly — illustrating why a
   deferred check is unsafe even independent of the fork trick: the
   process backing a pid is not a stable thing to inspect "later.")

## Design

### New component: `omarchy-doorman-identity-helper`

A small, separate systemd `--user` unit, **not a child process of the
broker** (started independently by systemd, so it gets its own,
independent mount-namespace treatment per finding 1). Its only job: given a
pid, confirm whether `/proc/<pid>/exe` identifies the same file as the
trusted installed askpass binary, via `fstat()`-based device+inode
comparison (not a path string — per `SPEC.md` §6.11's existing, still-valid
reasoning about mount-namespace path-rendering ambiguity), and report a
simple yes/no plus the checked pid back to the broker.

Hardening for this unit: `NoNewPrivileges=true`, `CapabilityBoundingSet=`
(empty — confirmed unnecessary for this check), a seccomp filter
(`SystemCallFilter=@system-service`), `RestrictAddressFamilies=AF_UNIX`,
and any other directive from the broker's own profile **confirmed in
finding 1 not to break the `/proc/<pid>/exe` read**. Deliberately omits
`ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `ProtectKernelTunables=`,
`ProtectControlGroups=` — the exact set finding 1 identified as the cause.

**Resolved during builder-check review (2026-11-05), author's call:**

- **Pid-reuse across the broker↔helper round trip.** A bare pid number,
  queried over a second process hop, is vulnerable to the target pid being
  reused by an unrelated process mid-round-trip — a narrower but real
  version of the same class of bug this whole design exists to close. Fix:
  the broker calls `pidfd_open(peer_pid, 0)` **immediately at `accept()`**,
  before anything else, and holds that pidfd open for the duration of the
  check. An open pidfd keeps the kernel from reassigning that exact pid
  number to a different process for as long as the pidfd stays open (this
  is one of `pidfd_open`'s designed purposes — see `pidfd_open(2)`), so the
  plain pid number can then be safely handed to the helper: it's pinned
  for the whole exchange, independent of how long the IPC hop takes. The
  helper itself still just does `fstat()`-based device+inode comparison on
  `/proc/<pid>/exe` using that (now-safe) pid.
- **Does the accept-time check actually run before the peer's message type
  is known, without breaking UI (`approve`/`cancel`/`pending`/`stats`)
  connections?** It must not be hooked inside `_create_request` as
  originally phrased above — `_create_request` today only runs after the
  JSON line is already parsed and `kind == "request"` is known
  (`broker/broker.py:246-251`), which is too late, and the broker's single
  listening socket also serves trusted-UI connections whose
  `/proc/<pid>/exe` is Quickshell/bridge.py, not askpass. Correct
  structure: in `_handle`, immediately after `accept()`, unconditionally
  capture `SO_PEERCRED`, open the pinning pidfd, and query the
  identity-helper for *every* accepted connection, before reading any data
  from it — cheap either way, since no data read is required to do this.
  Cache the boolean result on the connection object. Only *consult* that
  cached result later, once the parsed message's `kind` is known to be
  `"request"`; UI connections' cached result is simply never consulted.
  This is a restructuring of `_handle`, not a tweak inside
  `_create_request`.
- **Startup ordering between the two units.** Add
  `Wants=omarchy-doorman-identity-helper.service` and
  `After=omarchy-doorman-identity-helper.service` to the broker's own
  unit, so a normal login doesn't race the two units against each other
  and produce a spurious "helper unreachable" on the very first `sudo`
  attempt after boot.

**Left to the builder:** exact IPC wire format between broker and helper
(a small line-oriented protocol over a dedicated `AF_UNIX` socket is
consistent with the rest of this codebase's style — see
`broker/broker.py`'s existing JSON-line protocol); the helper's own socket
path and permissions (should live under the same `RuntimeDirectory=`
pattern as the broker's own socket, restricted to the invoking user); and
the unit file's exact remaining directive list (start from the broker's
own `omarchy-doorman.service` and remove only the directives finding 1
identified, keeping everything else — don't redesign the hardening
profile from scratch).

### Broker changes (`broker/broker.py`)

- Delete the SCM_RIGHTS receive logic and the `_fd_identity`-style
  fstat-of-received-fd comparison entirely.
- In `_create_request` (or wherever the connection is first handled —
  **builder should confirm the earliest point data can be read from the
  peer and hook the check there**, not later in the flow), immediately
  after obtaining the peer's pid via the existing `SO_PEERCRED` resolution
  (already used for `pid_mismatch`), and **before reading the handshake
  JSON or anything else from the peer socket**, query the identity-helper
  for that pid. Reject the connection (new, distinct error code — do not
  reuse `askpass_identity_unavailable`, which already means "trusted path
  missing at broker startup," or `untrusted_askpass_helper`, which should
  be reserved for "helper says no") if: the helper is unreachable (fail
  loud, never silently accept), the helper times out, or the helper says
  no.
- The three existing, already-shipped checks (`pid_mismatch`,
  `not_sudo_child`, the privilege-escalation-required-on-parent check) stay
  completely unchanged, in whatever order they currently run, with the new
  check additive.
- `askpass_identity_available` (the broker-startup-time flag, already
  surfaced via `stats` and the Quickshell panel per `Panel.qml`) should
  reflect whether the identity-helper itself is reachable at broker
  startup, not whether a specific request's peer matched — keep that
  distinction clear in the code and in whatever gets surfaced to the UI.

### Askpass changes (`askpass/doorman-askpass.c`)

- Remove the `cap_dac_read_search`-dependent self-exe-opening and
  `SCM_RIGHTS`-sending code entirely. The binary goes back to being a
  plain, privilege-free executable: connect to the broker, send the
  request, wait for the decision, print the secret or exit non-zero.
- Keep it as a dedicated, self-contained compiled binary (not a Python
  script invoked via shebang) — confirmed necessary during this review:
  an interpreted script's `/proc/<pid>/exe` is the interpreter binary,
  identical to what any other same-language script would show, making any
  `/proc/<pid>/exe`-based identity check vacuous for a non-compiled askpass.
- **Builder should decide**, and state explicitly, whether to keep this as
  a dynamically-linked ELF (now harmless — no capability means no
  `AT_SECURE`-loss concern either way, since none existed to lose) or
  statically link it anyway as defense-in-depth against `LD_PRELOAD`-style
  injection from an attacker who controls the invocation environment. Both
  are defensible; pick one and write down why.

### `scripts/doorman-install-askpass`

- Remove the `setcap`/`nosuid`-mount-check/`getcap`-verification logic
  entirely — no longer applicable.
- Keep: installing outside the plugin's git checkout, `chown root:root`,
  a non-group/other-writable mode. (Read permission is no longer
  security-relevant the way it was under the capability-based design, but
  the binary's *content* must still not be writable by the unprivileged
  user — that's what actually anchors trust now, since there's no
  capability for an attacker's substitute to lack.)

### Symlink/env-exfiltration fix (independent of the above)

In the askpass binary's token-file-reading code: open with `O_NOFOLLOW`,
and validate the resolved real path matches the expected canonical
location before trusting its content. This closes the 2026-10-25 finding
directly, regardless of which identity-binding mechanism is chosen, and
should be done even though removing `cap_dac_read_search` already closes
it as a side effect — the narrow fix is correct defense-in-depth and
avoids relying on a property (no DAC-bypass capability) staying true
forever.

**Resolved during builder-check review (2026-11-05), author's call:** the
"expected canonical location" must not itself be computed from
`$XDG_RUNTIME_DIR` taken from the environment — that variable is exactly
as attacker-controlled as `DOORMAN_SOCKET` was (the attacker invokes
`/usr/bin/sudo` directly, setting whatever environment they like), so an
`O_NOFOLLOW`+canonical-path check validated against an attacker-chosen
base directory is trivially satisfiable and provides close to no
protection beyond what removing the capability already provides on its
own. The production askpass binary must derive the runtime directory the
same way `DOORMAN_SOCKET` is now pinned: from `getuid()` (e.g.
`/run/user/<uid>/omarchy-doorman`), ignoring the `XDG_RUNTIME_DIR`
environment variable for this purpose in production, with the same
style of distinctly-named dev/test-only override as `DOORMAN_SOCKET`'s.

### `DOORMAN_SOCKET` / `XDG_RUNTIME_DIR` trust (independent, minimal)

Production path: stop honoring `DOORMAN_SOCKET` from the environment;
derive the broker socket path the same fixed way the install script and
`doorman-sudo` already do. Keep a distinctly-named override
(e.g. `DOORMAN_SOCKET_DEV_OVERRIDE` or similar — **builder's call on
naming**) for the existing test suite only, documented as test-only in the
same style as `--trusted-sudo-allow-unprivileged-parent`.

## Verification plan

All of the following must pass live, on this machine, with the real
systemd units (not `systemd-run` replicas, not unit tests alone) before
this is reported as fixed anywhere:

1. Legitimate round trip: real `sudo -A` → real `doorman-sudo` wrapper →
   real (now unprivileged) askpass binary → real broker → real
   identity-helper → real Quickshell modal → human approval → secret
   delivered.
2. O_PATH attack reproduction: craft an attacker askpass sending an
   `O_PATH` fd (or, since the new design never reads an fd from the peer
   at all, confirm there is no code path left that could accept one —
   this finding should be closed structurally, not by a runtime check).
3. Symlink/env-exfiltration reproduction: attempt the exact 2026-10-25
   scenario (planted symlink under a caller-controlled `XDG_RUNTIME_DIR`,
   caller-controlled `DOORMAN_SOCKET`) and confirm it no longer exfiltrates
   anything.
4. Fork-timing attack reproduction: the exact two-process scenario from
   "Validated findings" item 3 above, adapted to the real broker protocol
   (connect as attacker, fork, parent execs the real trusted binary, child
   drives the rest of the handshake) — confirm the broker rejects it.
5. Degraded-state check: stop the identity-helper unit, confirm the broker
   refuses all requests loudly (distinct error code) rather than silently
   falling back to accepting.
6. Full existing test suite (`python -m unittest discover`) still passes,
   with new tests added for cases 2-5 above adapted to the test
   environment (noting, per this project's own repeated lesson, that a
   test-suite pass for case 1/4 does not substitute for the live
   verification in a real systemd context).
