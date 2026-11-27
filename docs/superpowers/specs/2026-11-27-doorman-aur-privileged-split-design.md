# Design — split Doorman's privileged half into an AUR package

**Date:** 2026-11-27
**Status:** awaiting approval
**Driving finding:** HANCORE-linux, marketplace submission #15997 (High), reviewed `cb9fca6`.

## Intent and why

The marketplace reviewer blocked approval with one High finding: the root
installer `scripts/doorman-install-askpass` compiles and copies files
(`askpass/doorman-askpass.c`, `broker/*.py`, `packaging/omarchy-doorman.service`)
**from the plugin checkout** (`~/.config/omarchy/plugins/mauricio.doorman/`),
which the login user — and therefore the background-agent threat actor Doorman
exists to contain — can write. A process can swap an input between the `[[ -f ]]`
check and the privileged read (TOCTOU); swapping the systemd unit lets the
attacker set `User=`/`ExecStart=`, so the documented `sudo systemctl enable --now`
runs attacker code as root. That is a concrete user→root escalation and it
defeats Doorman's entire reason to exist.

The fix must make the privileged install consume its inputs from an **immutable,
root-verified source outside the mutable checkout**. We do this the canonical
Arch way: ship the privileged half as a pacman package whose source tarball is
pinned by SHA-256 in the PKGBUILD. `makepkg` verifies the hash, builds in its
own integrity-checked srcdir, and `pacman` installs root-owned files — none of
it touching `~/.config/omarchy/plugins/`.

## Goals

- The privileged phase reads **zero** files from the plugin checkout.
- The integrity anchor (a fixed SHA-256 of a tagged release tarball) lives in
  the AUR PKGBUILD, off the user's machine, not in any checkout file.
- Installation is idiomatic Omarchy/Arch: `yay -S omarchy-doorman` (or
  `makepkg`/`pacman -U`).
- The shape-B security model (SO_PEERCRED egid identity, setgid askpass,
  system `doorman` broker, group-ACL'd sockets) is preserved bit-for-bit — only
  *how the files get installed* changes.
- Reversible: `pacman -R omarchy-doorman` cleanly removes everything privileged.

## Non-goals

- No change to the credential/egid identity model — HANCORE did not contest it.
- No change to UI behaviour (BarWidget/Panel/SecureOverlay).
- No change to the sockets, their modes, or the broker's runtime checks.

## Anti-goals (any of these means the design failed)

- **Any** privileged step that reads, compiles, or copies a file from the
  mutable plugin checkout.
- Bottoming the trust out in a clean-worktree check inside the user-controlled
  repo (explicitly rejected by HANCORE).
- Auto-guessing the human login user for the privilege grant.

## Approaches considered

- **A — root fetches a pinned, hash-verified release tarball from inside the
  installer script.** Closes the payload hole but the hash/URL live in the
  installer, which is still in the mutable checkout → bootstrap hole remains;
  risks a second review rejection. Rejected.
- **B — package the privileged half (chosen).** The trust anchor (pacman +
  the PKGBUILD's pinned SHA-256) is genuinely outside the checkout and outside
  the user's control. Canonical Arch answer. Bigger lift, and the submission
  reshapes to "UI plugin + required `omarchy-doorman` package."
- **C — copy the checkout into a root-owned dir and re-verify.** Essentially
  the clean-worktree approach HANCORE already rejected. Dropped.

Within B, distribution channel chosen: **AUR, source pinned by SHA-256**
(over in-repo-PKGBUILD-plus-GPG and prebuilt-signed-package) — most idiomatic
for Omarchy, easy discovery, pacman verifies the fixed hash at build.

## The how (decided)

### Repository & release

- One repo stays. UI files remain at root for the marketplace (`manifest.json`,
  `BarWidget.qml`, `Panel.qml`, `SecureOverlay.qml`, `preview.png`, `README.md`).
- Privileged sources remain in the repo as the *upstream source the package
  builds from*: `askpass/doorman-askpass.c`, `broker/{__init__,__main__,broker}.py`,
  `scripts/run-doorman-broker`, `packaging/omarchy-doorman.service`.
- Cut a version tag `v0.1.0`; GitHub serves a stable tarball at
  `.../archive/refs/tags/v0.1.0.tar.gz`. Its SHA-256 is pinned in the PKGBUILD.
  (Chicken-and-egg: tag first → compute hash → fill PKGBUILD → push AUR.)

### AUR package `omarchy-doorman`

- `source=("$pkgname-$pkgver.tar.gz::<github tag tarball>")` + `sha256sums=(...)`
  — **this fixed hash is the trust anchor.** makepkg aborts on mismatch.
- `build()`: compile `doorman-askpass.c` with the current hardened flags
  (`-std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong
  -D_FORTIFY_SOURCE=2`).
- `package()` installs (all `root:root` at this stage):
  - `/usr/lib/omarchy-doorman/doorman-askpass` (the binary)
  - `/usr/lib/omarchy-doorman/broker/*.py`
  - `/usr/lib/omarchy-doorman/scripts/run-doorman-broker`
  - `/usr/lib/systemd/system/omarchy-doorman.service` — the unit now **hardcodes**
    `/usr/lib/omarchy-doorman`; the `@PROJECT_DIR@` `sed` substitution is gone.
  - `/usr/lib/sysusers.d/omarchy-doorman.conf` (users/groups, below)
- **Install prefix moves `/usr/local/lib` → `/usr/lib`** — `/usr/local` is for
  non-packaged local installs; packaged files belong under `/usr/lib`.

### Users, groups, setgid — via package mechanisms (run as root by pacman)

- `sysusers.d/omarchy-doorman.conf` creates the `doorman-askpass` and
  `doorman-ui` groups and the system user `doorman`, and adds `doorman` to both
  groups. pacman's `systemd-sysusers` hook runs it as root at install.
- A `.install` scriptlet `post_install()`/`post_upgrade()` applies the setgid
  identity **after** the group exists:
  `chgrp doorman-askpass …/doorman-askpass && chmod 2755 …/doorman-askpass`,
  verify the setgid bit stuck, then `systemctl daemon-reload`.
- The **login user is NOT auto-added** to `doorman-ui`. The scriptlet prints the
  exact command (`sudo usermod -aG doorman-ui $USER`) and the single-member
  invariant (the broker refuses to start unless `doorman-ui` has exactly one
  login member) keeps a wrong setup from silently working.

### Marketplace plugin becomes UI-only

- `scripts/doorman-install-askpass` is removed from the user install path
  (the escalation vector is deleted, not patched).
- README install section rewritten:
  1. `omarchy plugin add …` (UI)
  2. `yay -S omarchy-doorman` (privileged broker — the package)
  3. `sudo usermod -aG doorman-ui $USER` (then re-login)
  4. `sudo systemctl enable --now omarchy-doorman.service`
- Submission note on #15997 updated to describe the UI/package split and the
  SHA-256-pinned AUR source as the trust anchor that answers the finding.

### Verification

- Keep existing CI (unittest 3.11/3.13, C strict + ASan/UBSan, gitleaks).
- Add a PKGBUILD lint/build check (`namcap`/`makepkg --nobuild` or a container
  build) so the package provably builds from the pinned source.
- Re-run `omarchy-plugin-validate .` (UI plugin still valid) and the live
  end-to-end sudo→modal→approval round trip after installing via the package.

## Left to the builder

- Exact `.install` scriptlet wording and whether `daemon-reload`/`sysusers` rely
  on pacman's built-in hooks vs. explicit calls.
- Which of `broker/{__init__,__main__,broker}.py` plus the runner are the minimal
  runtime set (mirror today's installer: `__init__.py`, `broker.py`, runner;
  confirm `__main__.py` is needed by the runner). `askpass.py`, `ui_test.py`
  stay out (dev/user-side).
- Where the unprivileged user tools (`scripts/doorman-sudo` shadow wrapper,
  `scripts/doorman-run`) live — ship in the package under `/usr/bin`, or keep
  user-side. Default: ship the `doorman-sudo` wrapper in the package (`/usr/bin`)
  since it's part of the documented flow; it is unprivileged either way.
- `pkgver`/tag mechanics and the AUR `.SRCINFO`.
- README/SPEC/docs wording updates for the new install flow.

## My calls in this doc (please sanity-check while reading)

- Channel = AUR with SHA-256-pinned tarball (you chose this).
- Install prefix `/usr/lib/omarchy-doorman`; unit hardcodes it (no `sed`).
- Users/groups via `sysusers.d`; setgid applied in `.install` post_install.
- Login user added to `doorman-ui` manually (documented), not auto-guessed.
- Delete `scripts/doorman-install-askpass` from the user path rather than keep it.
