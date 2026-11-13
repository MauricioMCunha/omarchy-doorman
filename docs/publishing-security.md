# Security review for publishing

## Trust boundary

The Omarchy catalog validates the manifest and the plugin's structure, but
it doesn't sandbox or audit the code's security. A plugin runs inside
`omarchy-shell`, with the user's permissions. So this review is part of the
project and has to go along with any submission.

## Security decisions

- The plugin doesn't capture global keyboard, PTY, clipboard, or arbitrary
  commands.
- The secret never enters arguments, files, logs, or the agent's messages.
- The UI only approves a request bound to its nonce, deadline, process
  identity and the configured owner uid, and only over the control socket.
- The broker only accepts a request from a process carrying the
  `doorman-askpass` effective gid (the root-installed setgid askpass
  binary), read from `SO_PEERCRED`. There is no session token, `origin`, or
  capability (SPEC.md §6.9, §6.13).
- Two sockets in `/run/doorman`, owned by the system user `doorman`, mode
  `0660`, groups `doorman-askpass` and `doorman-ui`; no session files exist.
- The UI calls absolute executables and the bridge ships alongside the
  plugin; there's no path override via environment variable.
- The service is explicit and reversible; the plugin doesn't silently
  install a service or package. The broker is a system service installed by
  one explicit root step (`scripts/doorman-install-askpass`, with
  `--uninstall`), not a `systemd --user` unit.

## Blockers before submission

1. ~~Publish the plugin as its own repository, instead of submitting this
   monorepo directly.~~ Done on 2026-09-27: this repository is the result
   of that extraction (via `git filter-repo`, preserving authorship and
   history from `omarchy-plugins`). The source monorepo
   (`github.com/MauricioMCunha/omarchy-plugins`) becomes just a lab for
   building/testing new plugins.
2. ~~Add the `BarWidget.qml` entrypoint per the Quattro contract and move
   the panel to the official `Panel`/`KeyboardPanel` lifecycle.~~ Done on
   2026-09-27: `BarWidget.qml` hosts the icon and all the broker's state;
   `Panel.qml` extends `Panel`/`KeyboardPanel` and only reads that state via
   `hostWidget`, the same pattern as `omarchy.clock`. Verified live: icon,
   popup, popout coordination (dismiss-twin on the other monitor), and
   SecureOverlay (which deliberately stays outside that lifecycle — see §3
   of SPEC) all still work.
3. ~~Document installing, activating, stopping, and removing the user
   service.~~ Done on 2026-10-01: the README gained an "Activating,
   updating, and removing" section using the official commands (`omarchy
   plugin add/enable/disable/update/remove`) instead of manually copying
   files — `omarchy plugin add` already validates the manifest, clones it
   as a git checkout, and places the widget without a full shell restart.
   The broker step (the `systemd --user` service) stays manual, since
   `omarchy plugin add` doesn't manage units — documented explicitly as
   such. *(Superseded 2026-11: the broker is now a system service installed
   by `scripts/doorman-install-askpass` and started with
   `systemctl enable --now`; the README documents that flow and its
   `--uninstall` counterpart. Item 12 tracks that change.)*
4. Test on a clean account: installation, shell restart, toggling the
   broker, approval, cancellation, expiry, removal, and rollback.
5. ~~Add dependency review, `qmllint`, Python tests, and secret inspection
   to CI.~~ Partial on 2026-09-27: CI (`.github/workflows/ci.yml`) gained a
   `security` job with `gitleaks` (secret inspection) and
   `dependency-review-action` (runs on PRs; today it's just a trip wire,
   since the project has no third-party dependency — see `pyproject.toml`).
   Python tests were already running. `qmllint` did **not** make it into
   CI: it depends on a real Quickshell/Omarchy install to resolve the
   `qs.*` reserved import and the `Quickshell.*` modules, and neither one
   has a package for Ubuntu/Debian — building Quickshell on every run would
   be disproportionate for this project's size. Instead,
   `scripts/qmllint-check` runs locally (the same machine already used to
   test the plugin) and is documented in the README as a step before
   sending a QML change.

6. ~~Pass `omarchy plugin validate <folder>` — the catalog's official
   manifest/structure validator.~~ Done on 2026-10-01: the `git filter-repo`
   extraction carried `broker/client.py` and `broker/bridge.py` over as
   symlinks (pointing at `../client.py`/`../bridge.py`, a pattern that
   already existed in the original monorepo). `omarchy plugin validate`
   rejects any symlink inside the plugin folder — and since `omarchy plugin
   add` installs straight from the git repository's root, that whole root
   is "the plugin folder". Fixed: `broker/askpass.py` and
   `broker/ui_test.py` now import `client` (an absolute import, via the
   same fallback the root `askpass.py` already used) instead of `.client`
   (relative, which required the symlink); `broker/bridge.py` was never
   imported by anything inside `broker/` and was simply removed. No more
   symlinks in the tree; `omarchy plugin validate` passes clean.

7. ~~Address the marketplace maintainer's security review finding on issue
   [#9558](https://github.com/omacom/omarchy-plugin-marketplace/issues/9558).~~
   Done on 2026-10-02: HANCORE-linux found that `_create_request` trusted
   the self-reported `pid` field in a `request` message with no check that
   it matched who was actually connected — a requester holding the normal
   `origin=llm` token/capability could claim any PID that happened to
   exist, get a human to approve what looked like a legitimate request for
   it, and receive the secret itself on its own connection. Fixed by
   binding the claimed `pid` to the connection's real peer via
   `SO_PEERCRED` (see SPEC.md §6.1), rejecting a mismatch with a new
   `pid_mismatch` error. Regression test added (`tests/test_broker.py`,
   claiming PID 1); verified live against the running broker, not just the
   test suite. This was explicitly a **partial** review — the maintainer's
   note: "the complete source review is still outstanding" — so more
   findings may still come back on this same issue.
8. ~~Address HANCORE-linux's follow-up on the same issue: `pid_mismatch`
   closed claiming someone else's pid, but not a requester reporting its
   own real one.~~ Done on 2026-10-02: an agent could still skip sudo
   entirely, connect directly with its own truthful identity and a
   convincing `command`, and receive the password itself once a human
   approved what looked like a legitimate request — exactly the gap the
   README's "the password never reaches the agent" promise exists to
   close. Fixed by also requiring the connecting peer's immediate parent
   process to be a real `sudo` (`comm == "sudo"`, one hop, the same
   `/proc` primitive §6.9 already used for the trusted-UI check — see
   SPEC.md §6.1), rejecting otherwise with a new `not_sudo_child` error.
   Required reworking most of the test suite's request-creation calls to
   run from real subprocesses instead of the test process itself or a
   thread, since the check needs a genuine parent/child relationship to
   verify. Verified live: a direct, non-sudo-spawned connection reporting
   its own genuine pid is rejected with `not_sudo_child`; a real `sudo`
   round trip through a diagnostic askpass stand-in and through the actual
   wrapper both still work end to end. Still only a partial review.
9. ~~Address HANCORE-linux's second follow-up on the same issue:
   `not_sudo_child` identified sudo solely by its parent's `comm`, which
   Linux lets a process rename for itself.~~ Done on 2026-10-02: an agent
   could `prctl(PR_SET_NAME, "sudo")` on itself, fork a child, and have
   that child connect with its own real pid — passing the comm check
   without ever touching a real sudo. Fixed by also requiring that parent
   to show a genuine privilege escalation: its effective uid must differ
   from its own real uid (`_process_comm_and_uids`, SPEC.md §6.1). Real
   sudo is setuid-root and keeps exactly that pairing while waiting on
   askpass; a same-user process can't reproduce it without actually
   executing a genuine setuid-root binary, and `exec()` replaces the whole
   process image, so it can't rename itself into `"sudo"` afterwards
   either. Building this surfaced that the broker's own systemd sandboxing
   (`ProtectSystem=strict`/`ProtectHome=read-only`) puts it in a minimal
   user namespace that can't resolve uid 0 — real sudo's effective uid
   reads back as the kernel's overflow uid instead of literally `0`, so
   the check compares real uid against effective uid rather than against
   a hardcoded `0`. Regression test added (`tests/test_broker.py`, a
   process that renames itself "sudo" without root); verified live by
   reproducing the maintainer's exact attack (a forked child of a
   self-renamed "sudo" parent, rejected) and a real `sudo -A` invocation
   (accepted) against the running broker. Still only a partial review.

10. ~~Address HANCORE-linux's third follow-up on the same issue
    ([#9558](https://github.com/omacom/omarchy-plugin-marketplace/issues/9558)):
    the uid-escalation fix (item 9) closes who sudo's *parent* must be, but
    not who the connecting *peer itself* is — sudo lets the caller choose
    its own `SUDO_ASKPASS` helper, so an agent that invokes real sudo
    directly (bypassing this project's PATH-shadow wrapper) can point
    `SUDO_ASKPASS` at code it wrote itself, which still passes every check
    on its parent, yet is caller-writable code that would receive the
    plaintext secret.~~ Done on 2026-10-07: proposed fix confirmed in scope
    and direction by the maintainer in the same thread, with three explicit
    conditions: the privileged identity must stay confined to trusted
    (non-caller-writable) code, the displayed operation must be derived
    from the genuine sudo invocation rather than caller-supplied metadata,
    and the system must refuse loudly rather than silently fall back when
    that identity is unavailable.

    First implementation: a dedicated system group (`doorman-askpass`) and
    a small, dependency-free C binary (`askpass/doorman-askpass.c`),
    installed once by root as `setgid`, with the broker checking the
    connecting peer's effective gid via `SO_PEERCRED`. Live verification
    caught a real problem with this design before it shipped: this
    project's own hardened systemd unit (`ProtectSystem=strict`/
    `ProtectHome=read-only`/`PrivateTmp=true`) puts the broker in a
    private, unprivileged Linux user namespace (confirmed by comparing
    `/proc/<broker_pid>/ns/user` against the host's) in which any gid
    outside that namespace's minimal mapping — including the dedicated
    group's — collapses to the kernel's overflow id for both
    `SO_PEERCRED` and `/proc/<pid>/status`. The gid check was structurally
    unable to tell the trusted group apart from any other under the
    project's own documented production hardening, and relaxing that
    hardening to fix it would have traded away real filesystem protection
    for the check.

    Second implementation: having the broker instead compare the
    connecting peer's own `/proc/<pid>/exe` (device+inode, not the path
    string) against the installed binary's, resolved once at startup — no
    gid, no group. This doesn't depend on resolving any credential value,
    so it looked immune to the problem above. Live verification caught a
    *second*, different problem before this shipped either: reading
    *another process's* `/proc/<pid>/exe` needs the same ptrace-equivalent
    permission that an earlier, unrelated check in this project
    (`Broker._peer_is_trusted_ui`'s original design) had already run into
    and left as an open question — a `systemd --user` service is denied
    it (`PermissionError`), reproduced live for both the real C binary and
    a disposable Python stand-in with verified-uniform credentials, ruling
    out a uid/gid mismatch. No fix to that design existed that kept the
    project's own hardening intact.

    Third mechanism (SPEC.md §6.11): the askpass binary opens its own
    `/proc/self/exe` and hands that file descriptor to the broker over the
    request socket via `SCM_RIGHTS`. The broker `fstat()`s the fd it
    already owns and compares it to the installed binary's resolved
    identity; this needs no permission over the peer at all, since it's
    not inspecting the peer, just a file descriptor it was handed. The
    installed binary's mode changed from `0755` to `0711` (root can read;
    nobody else can, only execute) so an attacker can't open the trusted
    path directly and send *that* fd instead of genuinely running it. As
    first shipped, this assumed opening your own `/proc/self/exe` needs no
    special permission — live verification caught a *third* problem before
    this reached users: that assumption is false. Opening it goes through
    the exact same DAC read check as opening the file by its real path, so
    mode `0711` blocked the *legitimate* binary from reading itself too,
    confirmed with a disposable copy chmod'd to the equivalent of `0711`
    for a non-owner caller (`EACCES`, identical to the real binary's
    failure for its own non-root invoker).

    Fourth, current fix: same `SCM_RIGHTS`/`fstat()` design, with the
    installed binary additionally granted the `cap_dac_read_search` Linux
    file capability (via `setcap`, applied by
    `scripts/doorman-install-askpass` after `chown`/`chmod` but before the
    file is moved into place, since writing to a file clears any capability
    already on it). That capability lets *this exact binary, once exec'd*
    bypass the one read check it needs to pass on itself, without running
    as root (deliberately not `setuid`: a memory-safety bug in this C code
    can then only read a file it shouldn't, not execute arbitrary code as
    root) and without granting anything to an attacker's own substitute
    binary (file capabilities apply only at `execve()` of the specific
    capability-bearing file). `scripts/doorman-install-askpass` also
    refuses to install onto a `nosuid` mount — that mount option drops file
    capabilities at exec time the same way it drops `setuid`/`setgid`, and
    verifies via `getcap` after install that the capability actually stuck
    rather than assuming `setcap` succeeding means it took effect. Four
    regression tests (`tests/test_broker.py`): the identity-mismatch
    rejection, the missing-path loud refusal, the command-derivation check,
    and the genuine positive path — which needs no root or compiler, since
    the test peer sends a real fd for `sys.executable`'s own exe over the
    same socket. The askpass binary itself builds clean under
    `-Wall -Wextra -Werror -Wpedantic` and under ASan/UBSan, with a
    hand-tested round trip against a fake broker (including a secret
    containing `"`, `\`, and an embedded newline) and five adversarial
    malformed-response cases, all surviving under the sanitizer build with
    no crash and a clean exit 1.

    Live end-to-end verification, all three cases: the legitimate round
    trip (real `sudo whoami`, through the real `doorman-sudo` wrapper, the
    real installed binary, the broker, and a human approving in the real
    Quickshell modal — `sudo` returned successfully); the attack
    reproduction (a script posing as `SUDO_ASKPASS`, invoked via real
    `sudo -A` with the wrapper bypassed entirely, exactly the scenario this
    item exists to close — rejected `untrusted_askpass_helper`, no secret
    ever left the broker); and the degraded-state check (the installed
    binary temporarily removed — every `request` rejected
    `askpass_identity_unavailable`, confirmed via the real system journal,
    not silently accepted). Still only a partial review.

11. ~~Address HANCORE-linux's reopened finding on the same issue
    ([#9558](https://github.com/omacom/omarchy-plugin-marketplace/issues/9558)):
    the identity mechanism shipped for item 10 (`SCM_RIGHTS` + `fstat()` +
    `cap_dac_read_search`) can be bypassed by sending an `open(trusted_path,
    O_PATH)` descriptor instead of a genuine self-exe fd — `O_PATH` needs no
    permission on the target and `fstat()`s identically to a real open,
    defeating the device+inode pinning regardless of mode bits or
    capability — plus a second, independently reported finding: the
    installed helper's `cap_dac_read_search` follows a caller-controlled
    token-file symlink under a caller-controlled `XDG_RUNTIME_DIR` and sends
    its contents to a caller-controlled `DOORMAN_SOCKET`, with no sudo and
    no human approval.~~ Done on 2026-11-05: closing the `O_PATH` finding
    meant the broker could no longer trust anything the peer handed it as
    proof of identity. The first candidate tried — have the broker read the
    connecting peer's own `/proc/<pid>/exe` directly via the pid
    `SO_PEERCRED` already gives it, the same approach item 10's "second
    implementation" had already tried and failed at — was killed again, now
    for two fully-understood reasons instead of the open question item 10
    left behind: bisecting the broker's own unit file directive-by-directive
    (via `systemd-run --user` against an ordinary sibling process) showed
    `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`,
    `ProtectKernelTunables=true`, and `ProtectControlGroups=true` **each
    independently** block reading another process's `/proc/<pid>/exe` —
    the broker's own mount namespace, not Yama's `ptrace_scope` as item 10
    speculated — and, independent of that, `SO_PEERCRED`'s pid is captured
    once at `connect()` time, so a forked sibling of the connecting process
    can inherit the live socket and drive the protocol while the original
    process execs into the trusted binary purely to fool a check performed
    any time after the connection is accepted.

    Shipped mechanism: a new, separate systemd `--user` unit,
    `omarchy-doorman-identity-helper` (`identity_helper/identity_helper.py`),
    started independently of the broker so it keeps none of its
    mount-namespace-creating hardening directives. It answers one question
    over a small `AF_UNIX` protocol — does a pid's `/proc/<pid>/exe` match
    the trusted installed binary by device+inode — and the broker queries it
    synchronously, for every accepted connection, immediately in `_handle`,
    before reading anything from the peer. Discovered mid-implementation,
    not anticipated in the original design: a same-process identity check
    performed immediately at `accept()` does defeat the fork-then-exec
    bypass (confirmed by an earlier live probe), but the real design's check
    necessarily leaves the broker's process — it has to ask the separate
    helper over its own IPC round trip, measured ~1.0–1.6ms, and
    `fork()`+`execve()` into `/usr/bin/true` reliably won that race,
    reproduced 3/3 times against the real identity-helper. The fix:
    `os.kill(peer_pid, signal.SIGSTOP)`, sent before the pidfd and before
    the helper query, using the POSIX uid-based signal permission model — a
    different kernel path from `ptrace_may_access()`, unaffected by the
    broker's sandboxing, confirmed live under the broker's full real
    hardening stack via `systemd-run --user`. A stopped process can't fork
    or exec no matter how long the query takes, so this isn't a race at
    all; reproduced 5/5 safe with the fix (`SIGSTOP` delivered 0.02–0.03ms
    after `accept()`) versus 3/3 vulnerable without it. The peer is always
    resumed via `SIGCONT` in a `finally` block regardless of match outcome
    — never `SIGKILL`, caught before it reached the implementer: an earlier
    draft killed the peer on no-match, which would have killed every
    trusted-UI (`approve`/`cancel`/`pending`/`stats`) connection, since
    Quickshell/bridge.py legitimately never matches the askpass identity.
    `pidfd_open()`, held for the query's duration, separately pins the pid
    against kernel reuse during the IPC hop — a narrower race than the
    fork/exec one, closed independently.

    The askpass binary (`askpass/doorman-askpass.c`) goes back to being
    privilege-free: no file capability, no `setuid`/`setgid`, no
    `SCM_RIGHTS`, no self-exe open. `scripts/doorman-install-askpass` lost
    the `setcap`/`nosuid`-check/`getcap`-verification logic entirely, and
    the installed mode reverted from `0711` to `0755`. Independently, the
    binary's token/capability reads now open with `O_NOFOLLOW` and verify
    the resolved path via `/proc/self/fd/<fd>` against the expected
    canonical path before trusting the content, closing the symlink finding
    directly; and the production path stopped trusting `XDG_RUNTIME_DIR`/
    `DOORMAN_SOCKET` from the environment at all, deriving both from
    `getuid()` instead, since an attacker who invokes `/usr/bin/sudo`
    directly with `SUDO_ASKPASS` set controls exactly that environment and
    could otherwise aim the canonical-path check at a base directory of
    their own choosing.

    Nine new/updated regression tests across `tests/test_identity_helper.py`
    and `tests/test_broker.py`, plus three in `tests/test_doorman_askpass_c.py`
    covering the `O_NOFOLLOW`/canonical-path check and both environment
    variables being ignored in production. Live-validated during design and
    implementation (not simulated): the mount-namespace bisection above, the
    confirmation that a `systemd --user` unit can't be granted
    `AmbientCapabilities` at all, and the fork-timing reproduction against
    the real, shipped identity-helper (3/3 vulnerable without `SIGSTOP`,
    5/5 safe with it). Full end-to-end live verification against the real
    systemd units and a real `sudo` round trip — not just the test suite —
    is tracked separately and had not yet been run as of this writing; see
    `docs/superpowers/plans/2026-11-05-askpass-identity-6th-design.md`'s
    final task. Still only a partial review. *(The mechanism in this item
    was itself replaced; see item 12.)*

12. **OPEN** — Shape B ("7th design") for the #9558 identity findings:
    implemented, **not yet verified live, and #9558 is not reopened.** What
    changed, as shipped in the code and described in SPEC.md §6.13: the
    broker became a system service (`User=doorman`) with two sockets
    (`askpass.sock`, group `doorman-askpass`; `control.sock`, group
    `doorman-ui`); the askpass binary is installed `root:doorman-askpass`
    `2755` and non-dumpable (`PR_SET_DUMPABLE`); the broker admits a
    `request` only if the peer's effective gid from `SO_PEERCRED` is
    `doorman-askpass`; each socket serves only its own verbs
    (`wrong_socket`); every uid comparison is against the configured
    `--owner-uid` and `approve`/`cancel` are bound to the request's owner uid;
    and the whole token/capability/`origin=llm` layer was removed. The
    identity-helper, `SIGSTOP`, `pidfd` and `/proc/<pid>/exe` mechanisms of
    item 11 no longer exist in the code. Closed by design, live
    verification pending: the `O_PATH` fd bypass (nothing is read from the
    peer), the symlink/environment exfiltration (no file read, fixed socket
    path), the fork-exec race (identity is the connect-time egid), and the
    same-uid ptrace/memory read of the secret (non-dumpable). Confirmed live
    so far: only the four kernel assumptions in the design record's spike.
    Still to do, by a human with root (Task 12 of
    `docs/superpowers/plans/2026-11-09-askpass-identity-shape-b.md`): the
    real-unit end-to-end round trip, setgid surviving real `sudo -A`, the
    socket ACL, §6.1's cross-uid `/proc` reads under the system unit, the
    ptrace attempt against the real binary, the symlink/environment
    reproduction, both fork-exec variants 20/20, the second-user
    rejection, and the degraded-state check. Open deployment item: the
    broker's code lives in the user's home, which `doorman` may not be able
    to read under `ProtectHome=read-only`; it may need to be installed
    outside `/home`. Also unresolved: the `/run/doorman` directory is
    `0750 doorman:doorman`, and that the askpass binary and the UI can
    traverse it to their sockets is unverified. Items 10 and 11 above are
    kept as the record of the earlier designs; the mechanisms they describe
    were replaced.

Don't submit while any blocker above is still open.
