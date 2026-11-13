# Implementation plan: askpass identity "shape B" (7th design)

**Status:** plan only. No production code is written here; a later implementer
executes this task by task.

## Goal

Replace the raceable, ptrace-dumpable `/proc/<pid>/exe` identity mechanism
(identity-helper + `SIGSTOP` + `pidfd` pinning) with a kernel-captured
credential identity: the broker becomes a **system** service run by a dedicated
system user `doorman`; its request socket is owned `doorman:doorman-askpass`
mode `0660`; the installed askpass binary is **setgid `doorman-askpass`**; and
the identity check collapses to "is the connecting peer's `egid` the
`doorman-askpass` gid?", read via `SO_PEERCRED` (kernel-recorded at `connect()`,
unforgeable by a later `execve()`). See
`.superpowers/sdd/2026-11-05-askpass-identity-6th-design/decision.md`,
`…/spike-report.md` (Q1–Q4 all PASS live 2026-11-09), and
`docs/superpowers/specs/2026-11-05-askpass-identity-6th-design.md` (final
section, Findings 4 & 5, both Addenda).

## Target architecture (locked by the human's 3 decisions, 2026-11-09)

- System user `doorman`; system group `doorman-askpass` (owns no files; is the
  setgid group on the installed binary, **memberless** except for `doorman`
  itself); system group `doorman-ui` with **exactly one member**, the single
  configured login user (Decision #1: pin-to-one-user).
- `omarchy-doorman.service` becomes a **system** unit (`User=doorman`,
  `Group=doorman`, `SupplementaryGroups=doorman-askpass doorman-ui`,
  `RuntimeDirectory=doorman` → `/run/doorman`, mode `0750`
  owner `doorman:doorman-askpass`).
- The broker is **pinned to one configured uid** (`--owner-uid`, the login
  user). It rejects every peer whose uid is not that configured uid, on both
  sockets. There is only ever one owner uid in play; each request is still bound
  to its peer uid and the approving UI connection must share it, but no
  multi-distinct-owner plumbing is needed.
- **Request socket** `/run/doorman/askpass.sock`, owner `doorman:doorman-askpass`,
  mode `0660`. Only a process that exec'd the setgid binary carries egid
  `doorman-askpass` and can both pass the socket's group ACL and the broker's
  `SO_PEERCRED` egid check. The invoking user is **not** a member of
  `doorman-askpass`, so egid can *only* come from the setgid exec (no `newgrp`
  hole).
- **Control socket** `/run/doorman/control.sock`, owner `doorman:doorman-ui`,
  mode `0660`, for the trusted UI (`approve`/`cancel`/`pending`/`stats`). The UI
  reaches it via `doorman-ui` membership; it is gated by the §6.9 trusted-UI
  `/proc` comm-walk, the configured-uid pin, and the per-request owner-uid
  binding — **no token** (Decision #3).
- **No token/capability files anywhere** (Decision #3). The askpass reads **no
  file at all** before connecting; the request-path boundary is egid + §6.1 +
  human approval. The control path is gated by `doorman-ui` membership (socket
  ACL) + comm-walk + owner-uid. The broker's `session_token`/`llm_capability`,
  the `token`/`unauthorized` check, `_valid_llm_origin`/`invalid_llm_origin`,
  and the request's `capability`/`origin` fields are all removed.
- The askpass binary calls `prctl(PR_SET_DUMPABLE, 0)` at the very top of
  `main()` — MANDATORY (spike Q3: `fs.suid_dumpable` may leave a setgid exec
  dumpable; the non-dumpable side effect must not be relied on).

## The two findings that MUST remain closed (do not regress)

- **O_PATH / fstat-of-received-fd bypass** — closed *structurally*: shape B
  passes no file descriptor over the socket at all. Every task must keep it so;
  no `SCM_RIGHTS` send/recv may reappear in `broker/broker.py` or
  `askpass/doorman-askpass.c`.
- **Symlink / env file-exfiltration** — now closed **the simplest possible way**
  (a consequence of Decision #3): the askpass reads **no token/capability file**,
  so there is no caller-influenced file open to redirect via a symlink or an
  env-controlled base directory at all. The only path the askpass still forms is
  the fixed socket path `/run/doorman/askpass.sock` (connect target, not a file
  read). `read_file_trim_canonical` and the `DOORMAN_RUNTIME_DIR_DEV_OVERRIDE`
  env var are therefore **deleted**; the `DOORMAN_SOCKET_DEV_OVERRIDE`
  (socket-path, test-only) stays. State this explicitly in the code header and
  SPEC: the 2026-10-25 finding is closed by removing the vulnerable read
  entirely, not merely by guarding it.

## Global constraints

1. Nothing is "fixed" without live reproduction against the **real** units
   (project ironclad norm). Unit-test green ≠ done. Tasks that can only be
   verified live are marked **[LIVE/HUMAN]** and belong to the final task.
2. §6.1's three checks (`pid_mismatch`, `not_sudo_child`, the
   real-uid≠effective-uid escalation check) stay, unchanged in intent, additive
   to the new egid check. Their `/proc` reads (`comm`, `stat`, `status` Uid line,
   `cmdline`) are world-readable and *not* ptrace-gated, so they should survive
   the broker running as a different uid — but this is **decider test 4** and
   MUST be live-verified before claiming done (see Task 12).
3. Every `os.getuid()` comparison in the broker is re-examined: the broker's uid
   is now `doorman`, **not** the invoking user. The invoking user is the single
   configured `--owner-uid`. Every peer-uid comparison is against that configured
   uid (and against the connection's own `SO_PEERCRED` uid), never against
   `os.getuid()`.
4. Preserve the broker's systemd hardening profile intent; only the directives
   that conflict with a system unit (User/Group/RuntimeDirectory) change.
   `omarchy plugin update` is an unprivileged `git pull`; nothing it touches may
   silently re-open a boundary (installed binary + system unit live outside the
   checkout — keep it that way).
5. Keep the suite green task-to-task where possible; the test seam
   `--trusted-askpass-skip-identity-check` stays, and a new
   `--trusted-askpass-gid` seam lets unprivileged CI exercise the egid gate
   without a real setgid binary.

## Decisions (resolved by the human 2026-11-09 — now locked, no longer open)

1. **UI/control connectivity model → TWO-GROUP.** A second group `doorman-ui`
   plus a second socket `/run/doorman/control.sock` (0660 `doorman:doorman-ui`);
   the login user joins `doorman-ui` (one-time re-login to take effect).
   `doorman-askpass` stays memberless, so request-path egid still means "exec'd
   the setgid binary." The bar widget can no longer `systemctl --user`
   start/stop a system unit: **default = status-only widget** (toggle removed).
   An **optional** polkit rule (Task 9b, skippable) scoped to exactly
   start/stop/restart of `omarchy-doorman.service` for the configured user lets
   the toggle keep working for anyone who installs it.

2. **Token/capability → REMOVED entirely (Decision #3).** The askpass reads no
   token/capability file before connecting; the request-path boundary is the
   egid + §6.1 + human approval. Per SPEC §6.9 the token never was a same-uid
   boundary. The UI is gated by `doorman-ui` membership + comm-walk + owner-uid,
   **also without a token** (the simpler defensible option). No token/capability
   files are created or relocated. This also closes the symlink/env finding the
   simplest way — there is no caller-influenced file read left to redirect.

3. **Multi-user scope → PIN TO ONE USER.** The broker serves only the single
   configured `--owner-uid` and rejects every other peer uid on both sockets.
   `doorman-ui` has exactly one member. `PendingRequest.owner_uid` is still set
   per request and the approving UI must match it, but there is never more than
   one owner uid, so no multi-owner plumbing exists.

---

## Tasks

Legend: **[AUTO]** = verifiable by the unprivileged `unittest`/CI suite on this
branch. **[LIVE/HUMAN]** = can only be verified against real systemd units with
root + a real sudo/Quickshell session; folded into Task 12.

### Task 1 — Broker: remove the helper/SIGSTOP machinery, add the egid gate  **[AUTO]**

Files: `broker/broker.py`.

- Delete `_ping_identity_helper`, `_query_identity_helper`,
  `_check_peer_identity`, `_stop_peer_for_identity_check`, the
  `IDENTITY_HELPER_TIMEOUT` constant, the `identity_helper_socket` field/arg/env,
  `_default_identity_helper_socket`, and all `SIGSTOP`/`SIGCONT`/`pidfd_open`
  code. Remove the `stopped_pid` parameter threading from `serve()`/`_handle()`
  (the SIGSTOP in `serve()`'s accept loop goes away).
- Add egid resolution at startup: resolve the `doorman-askpass` gid
  (`grp.getgrnam(...).gr_gid`); store it. New arg `--trusted-askpass-gid`
  (int) + env override for tests; keep `--trusted-askpass-skip-identity-check`.
- Extend `_peer_credentials` (or add `_peer_egid`) to also return the peer's
  gid from the `SO_PEERCRED` `3i` struct (currently discarded).
- In `_handle`, for `kind == "request"`, replace the `identity_outcome` logic
  with: if not skipping, require peer egid == trusted-askpass gid, else reject
  with `untrusted_askpass_helper`. There is no longer an `unreachable` state;
  remove the `identity_helper_unreachable` branch and error.
- Rework `askpass_identity_available` to mean: the `doorman-askpass` group is
  resolvable **and** the installed setgid binary exists at the fixed path with
  its setgid bit and `root:doorman-askpass` ownership. Re-evaluate on each
  `stats` call (replacing the old `_ping_identity_helper` re-check). Keep the
  `Panel.qml`/`stats` surfacing and the startup/periodic log.
- **Remove the token/capability layer entirely (Decision #3).** Delete
  `session_token`/`llm_capability` fields and args/env, the `token` +
  `compare_digest`/`unauthorized` check in `_handle`, `_valid_llm_origin` and the
  `invalid_llm_origin` branch, and the `capability`/`origin` request fields. A
  `request` is now gated purely by egid + §6.1; the control verbs by the gates in
  Task 2/Task 9. Update `--token`/`DOORMAN_TOKEN`/`--llm-capability` handling in
  `main()` (remove them). Update `client.py` and any caller that passes a token.

Verify: new unit tests in Task 3. The egid comparison is exercised in CI by
pointing `--trusted-askpass-gid` at the test runner's own `os.getegid()`
(positive) vs. a different gid (negative) — no real setgid binary needed.

### Task 2 — Broker: re-base uid checks on the peer, add owner-uid binding  **[AUTO]**

Files: `broker/broker.py`.

- Add a single configured `--owner-uid` (int, required in production; the login
  user's uid) resolved in `main()`/`__init__`. Every peer-uid gate below
  compares against this, not `os.getuid()`.
- `_create_request` pid check: replace `creds[1] != os.getuid()` with
  `creds[1] != self.owner_uid`. Capture the peer uid as `owner_uid` on the
  request. Keep `creds[0] != pid` (self-report must equal the connection's real
  pid).
- `_resolve_sudo_parent_pid`: replace `uid != os.getuid()` with
  `uid != self.owner_uid`, and replace `parent_real_uid == os.getuid()` with
  `parent_real_uid == self.owner_uid` (the sudo parent's real uid must be the
  configured user). The escalation check (`parent_real_uid !=
  parent_effective_uid`) is unchanged.
- `_peer_is_trusted_ui`: replace `uid != os.getuid()` with
  `uid != self.owner_uid`; record the UI peer's uid.
- Add `PendingRequest.owner_uid` (always the single configured uid — simple, no
  multi-owner map). In `_approve` and `_cancel`, require the UI connection's peer
  uid == `request.owner_uid`.
- `serve()`: keep the stale-socket owner guard (`st_uid != os.getuid()` is still
  correct — the socket is owned by `doorman` = the broker's own uid). After
  `bind`, replace the `0600` chmod with: `chown` group to `doorman-askpass` and
  `chmod 0660`. (`doorman` is a member of `doorman-askpass` via the unit's
  `SupplementaryGroups`, so the chgrp is permitted.) Bind the second control
  socket (Task 9) here or in a sibling method.

Verify: Task 3 tests (owner-uid binding; sudo-parent uid now compared to peer,
not broker).

### Task 3 — Broker tests: delete helper tests, rewrite identity tests  **[AUTO]**

Files: `tests/test_broker.py`.

- Delete `_start_identity_helper` and every test that depends on it:
  `test_request_with_mismatched_askpass_identity_is_rejected`,
  `test_request_is_rejected_when_helper_has_no_matching_trusted_path`,
  `test_request_is_rejected_when_identity_helper_is_unreachable`,
  `test_request_with_real_trusted_askpass_identity_is_accepted`,
  `test_stats_reflects_identity_helper_becoming_available_after_startup`,
  `test_trusted_ui_call_succeeds_through_sigstop_sigcont_round_trip`,
  `test_fork_then_exec_on_connecting_peer_is_rejected`,
  `test_fork_before_connect_on_connecting_peer_is_rejected`,
  `test_skip_identity_check_never_contacts_identity_helper`. Keep
  `test_scm_rights_fd_is_ignored_…` but recast it as a *structural* assertion
  that the broker never reads `SCM_RIGHTS` (the fd is silently ignored and the
  request is judged purely on egid/§6.1) — this guards the O_PATH closure.
- Update `setUp` broker launch args: drop `--identity-helper-socket`, the
  unstarted-helper path, and `--token`/`--llm-capability`; add
  `--owner-uid` (= `os.getuid()` of the test runner) and `--trusted-askpass-gid`
  (= `os.getegid()` for the positive case, or keep skip for tests that do not
  exercise identity).
- Remove the token/capability test helpers and assertions
  (`test_wrong_token_is_rejected`, `test_non_llm_origin_is_rejected`, and the
  token/capability fields in `_call_as_subprocess`/`_request_*` helpers and
  `client.py` usage). The `type`-based dispatch stays.
- New tests: request rejected with `untrusted_askpass_helper` when peer egid ≠
  trusted gid; request accepted when egid matches; request rejected when peer
  uid ≠ `--owner-uid`; `_approve`/`_cancel` rejected when the UI peer uid ≠ the
  request's `owner_uid`; `askpass_identity_available` reflects installed-binary
  presence (stub the path via arg/env).

Verify: `python3 -m unittest discover -s tests -p 'test_*.py'` green.

### Task 4 — Delete the identity-helper component wholesale  **[AUTO]**

Files/dirs removed: `identity_helper/` (incl. `__init__.py`,
`identity_helper.py`), `packaging/omarchy-doorman-identity-helper.service`,
`scripts/run-doorman-identity-helper`, `tests/test_identity_helper.py`. Remove
the `Wants=`/`After=omarchy-doorman-identity-helper.service` lines from the
broker unit (also touched in Task 8). Grep the tree for `identity_helper` /
`identity-helper` and purge stragglers in comments/docs that are not the
historical SPEC record.

Verify: suite green; `git grep -n identity.helper` only hits SPEC history /
this plan.

### Task 5 — Askpass C: non-dumpable, fixed system paths  **[AUTO build + LIVE]**

Files: `askpass/doorman-askpass.c`, `tests/test_doorman_askpass_c.py`.

- Add `#include <sys/prctl.h>` and `prctl(PR_SET_DUMPABLE, 0);` as the **first**
  statement in `main()`, before reading argv/env — MANDATORY (spike Q3).
- **Remove all file reads (Decision #3).** Delete `read_file_trim_canonical`,
  the token/capability reads, and the `DOORMAN_RUNTIME_DIR_DEV_OVERRIDE`
  handling. The binary no longer reads `token`/`llm-capability` at all, so the
  request JSON drops the `token`, `capability`, and `origin` fields.
- Socket path: fixed `/run/doorman/askpass.sock` (drop the
  `/run/user/<uid>/omarchy-doorman` derivation). Keep only the
  `DOORMAN_SOCKET_DEV_OVERRIDE` (test-only) env var for the connect target.
- Update the file header comment: identity is now the setgid egid + the socket
  ACL; there is no token and no file read, so the 2026-10-25 symlink/env finding
  is closed by *removal of the read*, not by a guard. Document the linking
  decision — keep **dynamically linked**, now safe against `LD_PRELOAD` because
  the setgid exec sets `AT_SECURE=1` (the loader ignores `LD_PRELOAD`/`LD_*` from
  the environment); static linking stays an optional belt-and-suspenders.
  (Confirm `AT_SECURE` live in Task 12 / spike Q3.)
- `tests/test_doorman_askpass_c.py`: remove the token/capability-file fixtures
  and the `DOORMAN_RUNTIME_DIR_DEV_OVERRIDE` / symlink-canonical tests (the code
  they covered is gone); keep the `DOORMAN_SOCKET_DEV_OVERRIDE`-driven
  connect/request/decision tests. Add a test that the compiled binary is
  non-dumpable at runtime if feasible unprivileged (read its own
  `/proc/self/dumpable` via a tiny harness), else leave to Task 12.

Verify: compiles clean under `-Wall -Wextra -Werror -Wpedantic` and ASan/UBSan
(`.github/workflows/ci.yml` askpass-helper job); C test suite green. Real
`sudo -A` preserving the setgid bit is **[LIVE/HUMAN]** (spike Q1).

### Task 6 — Install script: system user/groups, setgid binary, system unit  **[AUTO lint + LIVE]**

Files: `scripts/doorman-install-askpass` (rewritten).

- Still root-only, idempotent, installs **outside** the plugin checkout.
- Create (if absent): system user `doorman` (`useradd --system`, no login,
  no home or a nologin home), group `doorman-askpass`, group `doorman-ui`.
  Add `doorman` to `doorman-askpass` and `doorman-ui` (so the service user can
  chgrp both sockets). Add the invoking user (`$SUDO_USER`) to `doorman-ui`
  (print the "log out/in for the group to take effect" caveat).
- Compile the binary (same flags) and install it: `chown root:doorman-askpass`,
  `chmod 2755` (setgid). Verify the setgid bit and ownership stuck; fail loudly
  otherwise.
- Install the **system** unit to `/etc/systemd/system/omarchy-doorman.service`
  (from `packaging/`, Task 8), `systemctl daemon-reload`, and print the
  `systemctl enable --now` instruction (do not silently enable — leave that to
  the documented step, or do it and say so).
- Remove all `setcap`/`getcap`/`nosuid`-mount-check logic (already gone) and the
  identity-helper install steps.
- Removal counterpart: document (and optionally provide) the clean teardown —
  disable+remove the system unit, remove the binary, `gpasswd -d` the user from
  `doorman-ui`, and remove the `doorman` user and both groups if nothing else
  uses them.

Verify: `bash -n` / shellcheck in CI. Real user/group creation + setgid install
+ unit activation is **[LIVE/HUMAN]** (Task 12).

### Task 7 — Broker runner: write secrets into /run/doorman, drop helper  **[AUTO lint + LIVE]**

Files: `scripts/run-doorman-broker` (rewritten).

- Stop using `XDG_RUNTIME_DIR`. Use `/run/doorman` (provided by the unit's
  `RuntimeDirectory=`, already `0750 doorman:doorman-askpass`).
- **No secret generation at all (Decision #3):** delete the `token` /
  `llm-capability` generation and the `ensure_private_secret` guard. No
  token/capability files are created.
- Determine the single configured owner uid (the login user). Default source:
  the sole member of `doorman-ui` (`getent group doorman-ui`), resolved to a uid;
  or an explicit install-time value. Pass it as `--owner-uid`.
- Invoke `broker.broker` with `--socket /run/doorman/askpass.sock`
  `--control-socket /run/doorman/control.sock`
  `--trusted-askpass-gid` (from `getent group doorman-askpass`)
  `--owner-uid <uid>`, and no identity-helper/token args.

Verify: `bash -n`; full flow **[LIVE/HUMAN]**.

### Task 8 — Broker system unit  **[LIVE]**

Files: `packaging/omarchy-doorman.service` (rewritten).

- `[Service]` `User=doorman`, `Group=doorman`,
  `SupplementaryGroups=doorman-askpass doorman-ui`, `RuntimeDirectory=doorman`,
  `RuntimeDirectoryMode=0750`, `ReadWritePaths=/run/doorman` (or rely on
  RuntimeDirectory). Remove the identity-helper `Wants=`/`After=`.
- `[Install]` `WantedBy=` becomes a system target (e.g.
  `multi-user.target`) since it is no longer a `--user` unit. `After=` the
  graphical/user-runtime availability as appropriate (the socket lives in
  `/run/doorman`, independent of any user session — note this is a behavior
  change from the old `graphical-session.target` user unit; the UI just needs
  the socket to exist).
- Keep the hardening directives whose effect on plain `/proc` reads was
  confirmed harmless. Add a prominent comment that **§6.1's cross-uid `/proc`
  reads under this system uid are decider test 4 and MUST be live-verified**;
  if `ProtectHome`/`ProtectSystem` block reading the invoking user's
  `/proc/<pid>/{comm,stat,status,cmdline}`, those specific directives are
  reconsidered (not the whole profile).
- Drop the hard-coded `WorkingDirectory=/home/mauriciocunha/DEV/...` and
  `ExecStart=` absolute dev paths or templatize them for the install location.

Verify: **[LIVE/HUMAN]** — `systemctl daemon-reload`, `enable --now`, socket
appears `doorman:doorman-askpass 0660`, broker reads a real sudo peer's `/proc`.

### Task 9 — UI / control path  **[AUTO unit + LIVE]**

Files: `broker/broker.py`, `bridge.py`, `BarWidget.qml`, `Panel.qml`.

- Broker: listen on a second socket `/run/doorman/control.sock`
  (`--control-socket`), chown `doorman:doorman-ui`, chmod `0660`. Route
  `approve`/`cancel`/`pending`/`stats` on the control socket; route `request`
  on the askpass socket. (Both still run the single `_handle` dispatch; the
  egid gate only applies to `request`, the comm-walk + owner-uid gate to UI.)
  Reject `request` on the control socket and UI verbs on the askpass socket.
- `bridge.py` + `client.py` + `BarWidget.qml`: **drop `--token-file` / the token
  argument entirely** (Decision #3) — the UI is authenticated by `doorman-ui`
  membership (socket ACL) + comm-walk + owner-uid, with no token. Point
  `--socket` at `/run/doorman/control.sock`. Replace `BarWidget.qml`'s
  `XDG_RUNTIME_DIR`-derived `runtimeDir`/`socketPath` and remove `tokenPath`.
- `BarWidget.qml` service toggle: **default = status-only widget** — remove the
  `systemctl --user start/stop` toggle (a system unit can't be driven
  `--user`); the service is managed at install via `systemctl enable --now`.
  Update `Panel.qml` copy accordingly (the "run doorman-install-askpass" setup
  message stays).

Verify: broker control-socket routing has **[AUTO]** unit tests (two sockets,
verb routing, cross-socket rejection, owner-uid binding, no token required). The
real Quickshell widget and `doorman-ui` connect are **[LIVE/HUMAN]**.

### Task 9b — OPTIONAL: polkit rule for the widget's service toggle  **[LIVE — skippable]**

Files: a new `packaging/omarchy-doorman.rules` (or `.policy`); `BarWidget.qml`.

Only if the human wants the widget's start/stop/restart toggle back. Ship a
polkit rule scoped to **exactly** `systemctl start/stop/restart
omarchy-doorman.service` for the single configured user (match on the unit name
and the user), and have `BarWidget.qml` call `systemctl` (system, via the polkit
path) instead of `--user`. Mark clearly optional in README; the status-only
widget (Task 9) is the default and this task may be skipped entirely.

Verify: **[LIVE/HUMAN]** — toggle works for the configured user and is denied
for any other action/user.

### Task 10 — Docs rewrite  **[AUTO lint / review]**

Files: `SPEC.md`, `README.md`, `docs/architecture.md`, `docs/security.md`,
possibly `openspec/doorman.md`, `manifest.json` if it references units.

- `SPEC.md`: rewrite §6.13 for shape B (system user, setgid socket ACL, egid via
  `SO_PEERCRED`, no helper/SIGSTOP/pidfd); update §6.1 to note the uid
  comparisons now use the configured `--owner-uid`, not the broker uid, plus the
  owner-uid binding; update §6.3/§6.5/§6.9 and §5.1 for the **removal of the
  token/capability layer** (no session token, no `origin=llm` capability, no
  `token`/`unauthorized` check — the UI is gated by `doorman-ui` + comm-walk +
  owner-uid, the request by egid + §6.1); update §6.6/§6.7 for the system unit
  socket ownership/mode, the two sockets, and `RuntimeDirectory=doorman`; fold
  the identity-helper socket limitation out of §7, and add the new residual items
  (group-join/re-login for the UI; `doorman-ui` has exactly one member;
  pinned-to-one-uid model; the `fs.suid_dumpable` / mandatory-`prctl` note).
  Keep §6.11 as history.
- `README.md`: rewrite "Installing" for the system-service flow (one root step:
  `sudo scripts/doorman-install-askpass` creates user/groups + setgid binary +
  installs the system unit; then `systemctl enable --now`; then the sudo
  shadow symlink; then log out/in for `doorman-ui`). Rewrite removal in order.
  Keep "why this step needs root" but re-explain it in terms of the setgid
  binary + socket ACL, not `/proc/<pid>/exe`.

Verify: markdown renders; cross-references resolve; `superpowers:requesting-code-review`
pass before merge.

### Task 11 — Full unprivileged suite + static gates green  **[AUTO]**

- `python3 -m unittest discover -s tests -p 'test_*.py'` passes.
- CI askpass-helper job (`-Wall -Wextra -Werror`, ASan/UBSan) passes.
- `git grep` confirms no `SCM_RIGHTS`, no `identity_helper`, no `SIGSTOP`,
  no `pidfd_open`, no `/proc/<pid>/exe` identity logic remain in broker/askpass.
- `scripts/qmllint-check` passes for the edited QML.

### Task 12 — Live verification against the real units  **[LIVE/HUMAN — root + real sudo/Quickshell required; agents cannot run this]**

This is a human-run step. Enumerated exact checks (all against the real system
units, a real `sudo` round trip, and a real Quickshell session — not
`systemd-run` replicas, not unit tests):

1. **Decider test 1 / spec case 1 — legitimate round trip.** Real `sudo`
   (via the shadow) → real askpass setgid binary → broker → Quickshell modal →
   human approve → secret delivered; exit 0.
2. **Decider test / spike Q1 — setgid survives `sudo -A`.** Confirm the askpass
   runs with `egid=doorman-askpass` under real sudo (not dropped by
   `no_new_privs`).
3. **Spike Q2 — socket ACL.** An ordinary same-uid non-group process gets
   `EACCES` connecting to `/run/doorman/askpass.sock`; confirm owner is
   `doorman` (not the connector) so the group bits govern.
4. **Decider test 4 — §6.1 preserved under the new uid.** With the broker as
   `doorman`, confirm it can still read a real sudo peer's and its parent's
   `/proc/<pid>/{comm,stat,status Uid line,cmdline}`, and that `pid_mismatch`,
   `not_sudo_child`, and the real-uid≠effective-uid escalation check still fire
   correctly (fabricate each failing case). **If `ProtectHome`/`ProtectSystem`
   block these reads, stop and reconsider those directives — do not ship.**
5. **ptrace attack now BLOCKED (Finding 5 / spike Q3).** Ancestor
   `PTRACE_ATTACH` of the real askpass holding the secret fails with `EPERM`;
   confirm `dumpable != 1` and `at_secure=1`. Confirm this holds even if
   `fs.suid_dumpable=1` because of the explicit `prctl`.
6. **O_PATH — structurally closed.** Confirm there is no code path that accepts
   any fd from the peer (grep + an attacker askpass that sends an `SCM_RIGHTS`
   `O_PATH` fd gets it silently ignored and is judged on egid/§6.1 only).
7. **Symlink/env exfiltration reproduction.** The exact 2026-10-25 scenario
   (planted symlink under an attacker `XDG_RUNTIME_DIR`, attacker-chosen
   `DOORMAN_SOCKET`) exfiltrates nothing; the askpass reads only `/run/doorman`.
8. **Fork-exec race — both variants, 20/20.** post-connect `fork()` and
   pre-connect `fork()` attackers: each either fails the socket ACL (no egid) or
   is rejected `untrusted_askpass_helper`; run 20/20 as prior rounds did.
9. **Owner-uid pin (Decision #3 = pin-to-one).** A second, different user's
   `request` on the askpass socket and `approve`/`pending`/`stats` on the control
   socket are both rejected (peer uid ≠ the configured `--owner-uid`), even if
   that user is somehow in a group. Confirm the configured user still works.
10. **Degraded state.** With the setgid binary missing/removed,
    `askpass_identity_available=false` is surfaced via `stats`/Panel and every
    request is refused loudly.

Report every result inline (PASS/FAIL + evidence) before issue #9558 is
reopened. Per the decision doc, #9558 is reopened only after all of the above
pass.

---

## Suggested execution order

Before any of the build tasks: run the **§6.1 cross-uid /proc spike** (Task 0,
below) — it is the last structural unknown and gates whether the system-unit
hardening profile even permits §6.1. Then:

Task 0 (spike, human-run) → 1 → 2 → 3 → 4 (broker + tests land together, suite
stays green) → 5 (askpass, independent, CI green) → 9-broker-half (control socket
+ unit tests) → 6 → 7 → 8 → 9-UI-half (scripts/unit/QML; lint only) → 9b
(optional polkit) → 10 (docs) → 11 (final green gate) → 12 (human live). Tasks
1-5, the broker half of 9, and 11 are fully **[AUTO]**; Task 0, 6-8, the UI half
of 9, 9b, and 12 require the live/root step.

### Task 0 — Gating spike: can a system-unit `doorman` read the user's /proc for §6.1?  **[LIVE/HUMAN — run FIRST]**

Prepared and ready: `/tmp/doorman-6dot1-spike/spike-root.sh` (one human-run
command: `sudo /tmp/doorman-6dot1-spike/spike-root.sh`), written up in
`.superpowers/sdd/2026-11-05-askpass-identity-6th-design/spike2-report.md`. It
launches a probe as `User=doorman` inside a transient **system** unit carrying
the real broker hardening directives (`ProtectSystem=strict`,
`ProtectHome=read-only`, `PrivateTmp=true`, and the rest of
`packaging/omarchy-doorman.service`) and checks whether it can read an ordinary
uid-1000 process's `/proc/<pid>/{comm,stat,status,cmdline}` **and** whether the
`status` `Uid:` line reads back the real uid (1000) rather than the overflow uid
(65534). PASS = all four reads succeed and the uid is real → build proceeds.
FAIL (any read denied, or uid remapped to 65534) → the §6.1 escalation check
cannot work under this profile; stop and reconsider the specific directives
before building the ~11 tasks on top. Self-cleaning (EXIT-trap removes the
transient unit, user, and group).
