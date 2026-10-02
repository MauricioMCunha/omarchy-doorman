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

Don't submit while any blocker above is still open.
