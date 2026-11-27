# Doorman AUR Privileged-Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Doorman's privileged half (setgid askpass binary, broker, systemd unit) out of the user-writable plugin checkout into a pacman package whose source is SHA-256-pinned, so no privileged step ever reads the mutable checkout.

**Architecture:** The marketplace plugin becomes UI-only. A new `packaging/PKGBUILD` builds an AUR package `omarchy-doorman`: `makepkg` verifies the pinned source hash, compiles the C in its own srcdir, and `pacman` installs root-owned files under `/usr/lib/omarchy-doorman` + `/usr/lib/systemd/system`. Users/groups come from `sysusers.d`; the setgid identity and `daemon-reload` are applied by a pacman `.install` scriptlet (root, post-sysusers). The old checkout installer is deleted.

**Tech Stack:** bash (PKGBUILD/scriptlets), C (existing askpass), Python stdlib (existing broker), systemd (unit + sysusers.d), pacman/makepkg, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-27-doorman-aur-privileged-split-design.md`

## Global Constraints

- Zero third-party Python dependencies — stdlib only.
- License: MIT.
- Hardened C compile flags, verbatim: `-std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=2`.
- Privileged install prefix: `/usr/lib/omarchy-doorman` (not `/usr/local`).
- System unit path: `/usr/lib/systemd/system/omarchy-doorman.service`.
- Setgid binary identity: owner `root`, group `doorman-askpass`, mode `2755`.
- Socket modes and the shape-B credential/egid identity model are unchanged.
- **Anti-goal (hard):** no privileged step reads, compiles, or copies a file from `~/.config/omarchy/plugins/` or any other user-writable checkout.

## Review Focus

- **setgid group missing at chmod time** — the `.install` scriptlet applies `chgrp doorman-askpass`/`chmod 2755` only *after* `sysusers.d` created the group; if ordering is wrong the binary installs without its egid and every sudo fails closed. Covered in Task 3 (scriptlet verifies the gid resolves and the setgid bit stuck).
- **upgrade path drops setgid / stale unit** — `pacman -U` over an existing install replaces files root:root; `post_upgrade()` must re-apply setgid and `daemon-reload`. Covered in Task 3.
- **`doorman-ui` has zero or >1 members** — the broker's runner already refuses to start unless exactly one login member exists; its error message currently names the deleted installer. Covered in Task 5 (message updated; behavior asserted).
- **pinned SHA-256 does not match the tagged tarball** — makepkg must abort (desired). Covered in Task 4 (full `makepkg` build verifies the hash end to end).
- **a privileged read sneaks back in from the checkout** — the whole point. Covered in Task 7 (live install via package, confirm the privileged path touches no checkout file).

---

### Task 1: Self-contained systemd unit

**Files:**
- Modify: `packaging/omarchy-doorman.service`

**Interfaces:**
- Produces: a unit with `WorkingDirectory=/usr/lib/omarchy-doorman` and `ExecStart=/usr/lib/omarchy-doorman/scripts/run-doorman-broker`, no `@PROJECT_DIR@` token (the PKGBUILD in Task 3 installs it verbatim, no `sed`).

- [ ] **Step 1:** Replace both `@PROJECT_DIR@` occurrences with `/usr/lib/omarchy-doorman` and drop the `@PROJECT_DIR@`-substitution comment; keep every other directive (User/Group/SupplementaryGroups/RuntimeDirectory/RuntimeDirectoryMode/NoNewPrivileges/PrivateTmp) unchanged.
- [ ] **Step 2:** Verify no token remains. Run: `grep -c '@PROJECT_DIR@' packaging/omarchy-doorman.service` — Expected: `0`.
- [ ] **Step 3:** Commit. `git add packaging/omarchy-doorman.service && git commit`

### Task 2: sysusers.d definition

**Files:**
- Create: `packaging/omarchy-doorman.sysusers.conf`

**Interfaces:**
- Produces: groups `doorman-askpass`, `doorman-ui`; system user `doorman` (no home, nologin) that is a member of both groups. Installed to `/usr/lib/sysusers.d/omarchy-doorman.conf` by Task 3.

- [ ] **Step 1:** Write the file:
  ```
  g doorman-askpass -
  g doorman-ui      -
  u doorman         - "Omarchy Doorman broker" /nonexistent /usr/bin/nologin
  m doorman         doorman-askpass
  m doorman         doorman-ui
  ```
- [ ] **Step 2:** Verify it parses. Run: `systemd-sysusers --dry-run packaging/omarchy-doorman.sysusers.conf` — Expected: exits 0, no parse error (it lists the entities it would create).
- [ ] **Step 3:** Commit.

### Task 3: PKGBUILD + install scriptlet

**Files:**
- Create: `packaging/PKGBUILD`
- Create: `packaging/omarchy-doorman.install`

**Interfaces:**
- Consumes: Task 1 unit, Task 2 sysusers file, existing `askpass/doorman-askpass.c`, `broker/{__init__,broker}.py`, `scripts/run-doorman-broker`.
- Produces: a buildable package installing the layout under Global Constraints. `pkgname=omarchy-doorman`, `pkgver=0.1.0`.

- [ ] **Step 1:** Write `packaging/PKGBUILD`:
  - metadata: `pkgname=omarchy-doorman`, `pkgver=0.1.0`, `pkgrel=1`, `arch=('x86_64')`, `license=('MIT')`, `depends=('python' 'systemd')`, `install=omarchy-doorman.install`.
  - `source=("$pkgname-$pkgver.tar.gz::https://github.com/MauricioMCunha/omarchy-doorman/archive/refs/tags/v$pkgver.tar.gz")` and `sha256sums=('SKIP')` (pinned in Task 4).
  - `build()`: compile `doorman-askpass.c` with the exact hardened flags into `$srcdir`.
  - `package()`: `install -Dm0755` the compiled binary → `$pkgdir/usr/lib/omarchy-doorman/doorman-askpass`; `install -Dm0644` the two broker modules → `.../broker/`; `install -Dm0755` the runner → `.../scripts/run-doorman-broker`; `install -Dm0644` the unit → `$pkgdir/usr/lib/systemd/system/omarchy-doorman.service`; `install -Dm0644` the sysusers file → `$pkgdir/usr/lib/sysusers.d/omarchy-doorman.conf`; `install -Dm0644 LICENSE → $pkgdir/usr/share/licenses/$pkgname/LICENSE`. (The binary is `0755 root:root` here; setgid is applied by the scriptlet.)
- [ ] **Step 2:** Write `packaging/omarchy-doorman.install` with `post_install()` and `post_upgrade() { post_install "$@"; }`. `post_install` must: `chgrp doorman-askpass /usr/lib/omarchy-doorman/doorman-askpass && chmod 2755` it; verify ownership is `root:doorman-askpass` and the `02000` bit is set (echo + `return 1` on failure); `systemctl daemon-reload`; print the two manual follow-ups — `sudo usermod -aG doorman-ui <your-user>` (then re-login) and `sudo systemctl enable --now omarchy-doorman.service`. (sysusers + daemon-reload also run via pacman hooks; the explicit calls make the scriptlet correct standalone.)
- [ ] **Step 3:** Verify `build()`/`package()` logic without a published tag: run the `build()` compile command by hand against the working tree, then dry-run the `package()` install lines into a throwaway `$pkgdir` (`DESTDIR`-style staging dir) and assert the five target paths exist with the intended modes. Run: a shell snippet staging into `"$(mktemp -d)"`; Expected: all five files present, binary `0755`, unit/sysusers `0644`.
- [ ] **Step 4:** Lint. Run: `namcap packaging/PKGBUILD` — Expected: no errors (warnings about `SKIP` acceptable until Task 4).
- [ ] **Step 5:** Commit.

### Task 4: Release tag, pinned hash, .SRCINFO

**Files:**
- Modify: `packaging/PKGBUILD` (real `sha256sums`)
- Create: `packaging/.SRCINFO`

**Interfaces:**
- Consumes: Task 3 PKGBUILD; a pushed git tag `v0.1.0`.
- Produces: a PKGBUILD whose pinned SHA-256 is the trust anchor, and a matching `.SRCINFO` for AUR.

> Ordering: this task runs after the branch is merged to `main` and tagged. Pushing the tag is a push → requires the user's go-ahead.

- [ ] **Step 1:** Tag `v0.1.0` at the merged commit and push the tag (ask the user before pushing).
- [ ] **Step 2:** Download the GitHub tag tarball and compute its hash. Run: `curl -fsSL <tag tarball URL> | sha256sum`.
- [ ] **Step 3:** Put that hash in `sha256sums` (replace `SKIP`).
- [ ] **Step 4:** Full build that verifies the hash end to end. Run: `cd packaging && makepkg -f` — Expected: downloads the pinned tarball, `Validating source files with sha256sums... Passed`, builds, produces `omarchy-doorman-0.1.0-1-x86_64.pkg.tar.zst`.
- [ ] **Step 5:** Generate SRCINFO. Run: `cd packaging && makepkg --printsrcinfo > .SRCINFO`.
- [ ] **Step 6:** Commit.

### Task 5: Remove the escalation vector; rewrite install docs

**Files:**
- Delete: `scripts/doorman-install-askpass`
- Modify: `scripts/run-doorman-broker` (error-message text)
- Modify: `README.md`, `SPEC.md`, `docs/security.md`, `docs/publishing-security.md`

**Interfaces:**
- Consumes: the package install flow from Tasks 3–4.
- Produces: docs describing `omarchy plugin add` (UI) + `yay -S omarchy-doorman` (broker) + `usermod -aG doorman-ui` + `systemctl enable --now`, and the SHA-pinned AUR source as the trust anchor answering the finding.

- [ ] **Step 1:** Delete `scripts/doorman-install-askpass`.
- [ ] **Step 2:** In `scripts/run-doorman-broker`, change the `doorman-askpass`-group-missing message to reference installing the package (`yay -S omarchy-doorman`), not the deleted script.
- [ ] **Step 3:** Verify no live reference to the deleted script remains. Run: `grep -rn 'doorman-install-askpass' --exclude-dir=.git .` — Expected: hits only under `docs/superpowers/` (historical plans), nothing in scripts/README/SPEC/docs/security.
- [ ] **Step 4:** Rewrite the README install/uninstall sections and update SPEC.md §install and the two docs to the package flow + trust anchor (cite the pinned SHA-256 and `pacman -R` as uninstall).
- [ ] **Step 5:** UI plugin still validates. Run: `omarchy-plugin-validate .` — Expected: rc=0.
- [ ] **Step 6:** Commit.

### Task 6: CI package-build check

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: a job proving the package builds from source (keeps the existing `test`, `askpass-helper`, `security` jobs).

- [ ] **Step 1:** Add a `package` job on an Arch base image (container `archlinux:latest`) that installs `base-devel`, runs `namcap packaging/PKGBUILD`, and builds via `makepkg` (as a non-root build user) against the working tree — using `--skipinteg` on PR branches where the tag tarball isn't published yet, and full integrity on tags.
- [ ] **Step 2:** Validate workflow syntax. Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` — Expected: no exception.
- [ ] **Step 3:** Commit.

### Task 7: Live end-to-end verification (real machine)

**Files:** none (verification only).

- [ ] **Step 1:** Install the built package. Run: `sudo pacman -U packaging/omarchy-doorman-0.1.0-1-x86_64.pkg.tar.zst` (ask before the sudo; reversible via `pacman -R`).
- [ ] **Step 2:** Confirm layout + identity: `stat -c '%U:%G %a' /usr/lib/omarchy-doorman/doorman-askpass` → `root:doorman-askpass 2755`; unit present at `/usr/lib/systemd/system/`.
- [ ] **Step 3:** `sudo usermod -aG doorman-ui $USER`, re-login (or `DOORMAN_OWNER_UID`), then `sudo systemctl enable --now omarchy-doorman.service`; `systemctl status` active.
- [ ] **Step 4:** Real round trip — a benign `sudo id` → Quickshell modal → **human approves** → `uid=0`. NEVER type a wrong password against the real account (faillock).
- [ ] **Step 5:** Confirm the anti-goal: the privileged path references nothing under `~/.config/omarchy/plugins/` (grep the installed unit + runner for home paths; expect none).

### Task 8: Publish to AUR + request re-review (ops — needs the user)

**Files:** none in this repo (the AUR repo is separate).

- [ ] **Step 1:** Push `PKGBUILD` + `.SRCINFO` to the AUR package repo (needs the user's AUR account/SSH key — user action).
- [ ] **Step 2:** Comment on marketplace #15997: describe the UI/package split, the SHA-256-pinned AUR source as the root-controlled trust anchor that removes all privileged checkout reads, link the new commit/tag, and request re-review. (External-facing → user authorizes the post.)
