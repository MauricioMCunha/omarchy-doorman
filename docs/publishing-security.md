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
- The UI only approves a request authenticated by token, nonce, deadline,
  and process identity.
- The broker only accepts `origin=llm` with a valid session capability.
- The socket and the session files are private to the user (`0700`/`0600`).
- The UI calls absolute executables and the bridge ships alongside the
  plugin; there's no path override via environment variable.
- The service is explicit and reversible; the plugin doesn't silently
  install a service or package.

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
   such.
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

Don't submit while any blocker above is still open.
