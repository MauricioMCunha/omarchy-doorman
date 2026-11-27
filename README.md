# Doorman

**Local, human-approved `sudo` for background AI agents.**

Doorman is an [Omarchy](https://omarchy.org) plugin for people who run coding
agents (Claude Code, Codex, or anything else that can drive a shell) in
background sessions they aren't watching. When one of those agents needs
`sudo`, there's usually no terminal in front of you to type a password into —
and handing the agent your password so it can type it itself defeats the
point of having one. Doorman puts a human decision in between: the agent's
request shows up in a small, local, keyboard-first window only you can see,
and the password never travels anywhere else — not to the agent, not to the
chat transcript, not to a log file.

![Doorman authorization prompt](assets/modal.png)

## Why this exists

Agentic coding tools are increasingly good at running real commands, and
real commands sometimes need root. The usual answers are all
unsatisfying for local dev work:

- **Give the agent passwordless `sudo`** — fast, but now anything the agent
  runs (including a bug in the agent, or a prompt injection from something
  it read) has unrestricted root.
- **Type the password into the agent's own prompt** — the agent (and
  whatever logs its transcript) now has your password.
- **Babysit every session with a visible terminal** — defeats the purpose of
  running things in the background.

Doorman decouples *where a command asks for a password* from *where you type
it*. The requesting process calls the standard `sudo askpass` protocol; a
small local broker holds the request open and shows it to you; you type the
password into a window the agent has no access to; only that specific,
already-decided-and-verified process gets the secret, once, and only through
that broker connection. If you don't respond, or you're not the person who
actually ran the command, or you hit Escape — it fails closed.

## How it works

```
requesting process (sudo -A)
        │
        ▼
   askpass helper  ──(/run/doorman/askpass.sock, group ACL +      ──►  broker
   (setgid binary)      kernel-checked effective gid)                  (system service)
                                                                      │
                                                       shows the request in
                                                             a Quickshell modal
                                                                      │
                                                              you approve / cancel
                                                                      │
        ◄──────────────────────── secret, once ───────────────────────┘
```

- The **broker** is a small Python system service, running as the dedicated
  `doorman` user, that owns two Unix sockets in `/run/doorman`: one for the
  askpass helper's requests, one for the UI's approve/cancel/status calls.
  Who may connect to each is enforced by the kernel through group
  permissions, and the broker re-checks the connecting process's identity
  itself. It never writes the secret to disk, a log, or its own stdout, and
  there is no session token or other bearer secret to steal.
- Every request carries a random `request_id` and a high-entropy `nonce`,
  expires in 1–300 seconds, and can be consumed exactly once. The broker
  re-validates the requesting process's PID, UID, start time, and command
  line at the moment of approval — not just when the request was created —
  so a PID that's been reused or a process whose identity changed can't
  slip through.
- The **UI** is a Quickshell overlay: a topbar widget for status/history (it is status-only — it does not start
  or stop the service), and
  a modal that grabs keyboard focus, shows exactly what's being authorized
  (command, working directory, PID, terminal), counts down the time left to
  decide, and sends a desktop notification if you're looking at a different
  monitor.
- Approving, cancelling, or letting a request expire are the only three
  outcomes. There is no fourth path where the secret leaks sideways.

See [`SPEC.md`](SPEC.md) for the full protocol, threat model, and the
reasoning behind each security property — including the DoS and timing bugs
we found and fixed while building this.

## Installing

> **Status of this flow.** The security model below — the setgid askpass
> identity, the dedicated `doorman` system user, and the socket group ACLs —
> is implemented and was verified end to end on a real machine on 2026-11-13
> (the real `omarchy-doorman.service` unit, a real `sudo` round trip through
> the Quickshell modal to a genuine `uid=0`), with the full unit-test suite
> and `omarchy plugin validate` passing. The privileged half now ships as the
> **`omarchy-doorman` pacman package** (installed under
> `/usr/lib/omarchy-doorman`, not your home checkout); the package-based
> install is pending its own end-to-end live re-check.

Doorman has two parts: the **plugin**, an Omarchy bar widget, and the
**broker**, a **system** service (`omarchy-doorman.service`, running as a
dedicated `doorman` user). `omarchy plugin add` handles the first; the broker
is a package, with one group step and the `sudo` wrapper to wire up by hand.

```bash
# 1. Add and enable the plugin (the bar widget) — validates the manifest,
#    clones it into ~/.config/omarchy/plugins/mauricio.doorman, and places
#    the widget without a full shell restart.
omarchy plugin add https://github.com/MauricioMCunha/omarchy-doorman.git --enable

# 2. Install the broker package (the privileged half). It builds from a
#    SHA-256-pinned release and installs the setgid askpass binary, the
#    broker, and the system unit under /usr/lib/omarchy-doorman, and creates
#    the `doorman` system user and the `doorman-askpass` / `doorman-ui`
#    groups. Nothing is read from the plugin checkout. See "Why a package,
#    and why it needs root" below.
yay -S omarchy-doorman

# 3. Add yourself to the `doorman-ui` group (single-user by design; the
#    package does not guess who you are).
sudo usermod -aG doorman-ui "$USER"

# 4. Start the broker (and have it start at boot).
sudo systemctl enable --now omarchy-doorman.service

# 5. Shadow `sudo` for this user so agents pick it up without any
#    per-agent configuration — see "Wiring up sudo" below for why this
#    step is the one that actually makes Doorman useful.
ln -s ~/.config/omarchy/plugins/mauricio.doorman/scripts/doorman-sudo ~/.local/bin/sudo

# 6. Log out and back in. Group membership is read at login, so the bar
#    widget (which runs as you, inside Quickshell) cannot reach the broker's
#    control socket until you do.
```

Nothing here replaces `/usr/bin/sudo`, edits `sudoers`, or touches anything
under `/usr/share/omarchy/`. The `omarchy-doorman` package (step 2) is the one
privileged part: it creates a system user and two groups, installs one small
setgid binary (owned by root, not writable by you, under `/usr/lib`, outside
this plugin's git checkout) and a system unit. Every step is explicit and
reversible — see **Activating, updating, and removing** below.

**Exactly one login user.** `doorman-ui` must have exactly one login member:
the broker is pinned to that one user's uid and refuses to start otherwise
(a systemd drop-in that sets `DOORMAN_OWNER_UID` overrides it explicitly).
This is a single-user tool by design.

**The bar widget is status-only.** It shows whether the broker is reachable
and healthy, the pending queue and recent activity, and hosts the approval
modal. It does not start or stop the service — that is `systemctl`, above.
If the broker is down it tells you to run `sudo systemctl enable --now
omarchy-doorman.service`; if the askpass binary is missing or lost its
setgid bit it tells you to install the `omarchy-doorman` package.

### Why a package, and why it needs root

**Why a package and not an install script in the checkout.** The privileged
files must not be built or copied from the plugin checkout: that directory is
writable by your login user, hence by a background agent, so a root install
step that compiled its C or installed its systemd unit from there could be
fed attacker-controlled inputs and run them as root. The `omarchy-doorman`
package closes that: `makepkg` verifies the release tarball against a
SHA-256 pinned in the package and builds only from its own integrity-checked
copy, and `pacman` installs root-owned files under `/usr/lib` — none of it
reads the checkout. The trust anchor is the pinned hash, outside your machine.

`sudo` lets *whoever calls it* choose the `SUDO_ASKPASS` helper. Nothing
stops a background agent from invoking real `sudo` directly (bypassing
Doorman's own `sudo` shadow entirely) and pointing `SUDO_ASKPASS` at a
script it wrote itself — which would still look, to the broker, exactly
like a legitimate request, and would receive the real password once a
human approved it. Closing that needs an identity an ordinary, same-user
process cannot fake, and the kernel can provide one:

- The askpass binary is installed once by root, at a fixed path you cannot
  write to, **setgid** to a dedicated group, `doorman-askpass`, that owns
  nothing else and has no human members. Only a process that actually
  executes that file runs with that effective group.
- The broker's request socket is owned by the `doorman` user and the
  `doorman-askpass` group, mode `0660`: the kernel itself refuses to let an
  ordinary process of yours connect to it. The broker then reads the
  connecting process's effective group from `SO_PEERCRED` — recorded by the
  kernel at `connect()`, so exec'ing something else afterwards cannot
  change it — and refuses anything that isn't `doorman-askpass`.
- The broker is a separate system user because a socket owned by *you* would
  let you (and anything running as you) bypass that group check, and because
  a process that can ptrace the broker could do worse. `doorman` owns the
  sockets; you and your agents don't.
- The askpass binary marks itself non-dumpable, so a same-user process
  cannot ptrace it or read its memory while it holds the secret, and, being
  setgid, it ignores `LD_PRELOAD`. It opens no file and connects to a fixed
  socket path.
- The UI talks to a second socket, `control.sock`, owned by `doorman` and
  the `doorman-ui` group — which is why you are added to that group and
  must log out and in.

There is no session token or other bearer secret anywhere in this design.
See [`SPEC.md` §6.13](SPEC.md#613-askpass-identity-is-a-kernel-recorded-credential-the-effective-gid-not-something-the-broker-inspects-or-is-handed)
for the full reasoning and, in its last paragraphs, exactly what has been
verified live — including the fork-exec race and the same-user ptrace read
of the secret, both exercised against the real broker on 2026-11-13.

### Activating, updating, and removing

The plugin and the broker are independent: toggling one doesn't touch the
other.

```bash
# Toggle the bar widget on/off, without touching the installed files
omarchy plugin disable mauricio.doorman
omarchy plugin enable mauricio.doorman

# Stop/resume the broker, without touching the installed files
sudo systemctl stop omarchy-doorman.service
sudo systemctl start omarchy-doorman.service

# Pull the latest plugin code — the bar widget's QML hot-reloads on its own.
# `omarchy plugin update` (an unprivileged git pull) never touches the
# privileged files, which live under /usr/lib.
omarchy plugin update mauricio.doorman

# Update the broker package. Its install scriptlet re-applies the setgid
# identity and reloads systemd; then restart the unit to pick up the change.
yay -Syu omarchy-doorman
sudo systemctl restart omarchy-doorman.service
```

**Removing everything, in order:**

```bash
# 1. Remove the sudo shadow FIRST, before the plugin folder it points into.
#    Only removes it if it's still exactly doorman-sudo.
[ "$(readlink -f ~/.local/bin/sudo 2>/dev/null)" = "$(readlink -f ~/.config/omarchy/plugins/mauricio.doorman/scripts/doorman-sudo 2>/dev/null)" ] \
  && rm -f ~/.local/bin/sudo

# 2. Remove the broker package. Its pre-remove scriptlet stops and disables
#    the unit; pacman then removes the unit, the askpass binary, and the
#    broker under /usr/lib.
sudo pacman -R omarchy-doorman

# 3. Remove the plugin (disables and unloads the widget, then backs up or
#    deletes the plugin folder, since it is a git checkout).
omarchy plugin remove mauricio.doorman --yes

# 4. Optionally drop yourself from `doorman-ui`, then log out and back in.
sudo gpasswd -d "$USER" doorman-ui
```

The `doorman` system user and the `doorman-askpass` / `doorman-ui` groups are
left in place by `pacman -R` (they own nothing once the package is gone).
Remove them by hand if you want: `sudo userdel doorman` and
`sudo groupdel doorman-askpass doorman-ui`.

### Wiring up `sudo`

The whole point of Doorman is that an agent shouldn't need to know it
exists. If it only intercepts `sudo` calls that were deliberately routed
through a wrapper, it's back to being a personal habit, not something that
protects anyone who installs it from the catalog without also editing every
agent's own instructions.

`sudo` itself won't cooperate here: given a real terminal to prompt on, it
prefers that terminal over `SUDO_ASKPASS` regardless of what's in the
environment — `-A` has to be passed explicitly, every time, by whatever
calls `sudo`. Since agents (and plain scripts) almost always resolve `sudo`
by name rather than by absolute path, the fix is to make sure they resolve
*Doorman's* `sudo` first:

```bash
# Recommended: shadow `sudo` for this user's own shells only.
# ~/.local/bin generally precedes /usr/bin in PATH already (Omarchy ships
# this by default); this does not touch /usr/bin/sudo, sudoers, or any
# other user's environment.
ln -s ~/.config/omarchy/plugins/mauricio.doorman/scripts/doorman-sudo ~/.local/bin/sudo
```

With that in place, plain `sudo <command>` — typed by you, or run by an
agent in a background job or a terminal it opened itself — resolves to the
wrapper, which always forwards to the real `sudo -A` unless the caller
already passed `-A`/`-S`/`-n`/`--stdin`/`--non-interactive` explicitly. The
one thing this can't catch is a caller that hardcodes `/usr/bin/sudo` by
absolute path, bypassing `PATH` resolution entirely — but since the askpass
identity check (§6.13), that no longer means the secret leaks: a caller
that bypasses the wrapper still can't make its own `SUDO_ASKPASS` receive
the password, so the residual gap is UX only (no friendly retry labeling,
no `DOORMAN_COMMAND` hint) — see
[`SPEC.md`](SPEC.md#7-known-limitations).

Other integration points still exist for narrower cases:

```bash
# One-off, for a single external command, without shadowing sudo at all:
scripts/doorman-run -- sudo systemctl restart some-service

# Or point SUDO_ASKPASS at the installed helper directly, the way a real
# `sudo -A` invocation (or an agent's own shell) would:
export SUDO_ASKPASS=/usr/lib/omarchy-doorman/doorman-askpass
sudo -A whoami
```

A process running that installed setgid binary is the only thing the broker
will serve a request to in production (SPEC.md §6.13) — only root's install
step can put a file there, not the plain `askpass.py` in the plugin folder.
`askpass.py` still exists, but only as a dev/test fixture: pointing
`SUDO_ASKPASS` at it gets `untrusted_askpass_helper`, by design.

## What Doorman is not

- Not a secrets vault, and not a password manager. It relays one password,
  once, to one already-verified process.
- Not a keylogger-proofing tool, a sandbox, or a replacement for `sudoers`
  policy — it's a human-in-the-loop gate in front of the normal `sudo`
  mechanism.
- Not (yet) audited by anyone other than the people who built it. See the
  status note below before trusting it with anything that matters.

## Project status

Doorman is in **private beta**: solid enough for the exact workflow it was
built for (local dev machine, one user, background coding agents), not yet
reviewed by anyone outside the project. Current gaps before a wider release:

- CI runs the Python test suite, a compile check, and a secret scan on every
  push; `qmllint` still runs manually (see below) — GitHub-hosted runners
  don't have Quickshell/Omarchy installed, and there's no package for either.
- Tested live against a real Quickshell/Omarchy session and real `sudo` — bar
  widget, popup, the approval modal, and a full `sudo` round trip through the
  wrapper all exercised end to end — but only on an existing, already-set-up
  account. Not yet tested from a clean one: fresh `omarchy plugin add`,
  shell reload, broker toggle, approval, cancellation, expiry, removal, and
  rollback, all on an account that never had Doorman on it before.
- Threat model and plugin lifecycle haven't had an independent review.
- The current identity design (a setgid askpass binary plus kernel-checked
  socket ACLs, [`SPEC.md` §6.13](SPEC.md#7-known-limitations)) is
  implemented, unit-tested, and **verified live** on 2026-11-13 against the
  real system unit, a real `sudo` round trip and a real Quickshell session:
  a full round trip to a genuine `uid=0`, the repeated fork-exec attacker
  runs all rejected, and the same-user ptrace read blocked by the
  non-dumpable binary. That verification ran with the broker installed under
  `/usr/local/lib/omarchy-doorman`; the privileged half now ships as the
  `omarchy-doorman` package under `/usr/lib/omarchy-doorman` (see
  **Installing**), whose package-based install is pending its own live
  re-check. That verification was on an already-set-up account, not a clean
  one (see above). The shape-B fix is on `main` (`f108332`); #9558 stayed
  closed and the plugin is resubmitted for review as #15997.

None of that changes what's already true today: the secret never leaves the
approval path, every request is single-use and identity-checked, and the
broker fails closed on anything it can't verify.

## Development

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 -m py_compile broker/*.py *.py
git diff --check
scripts/qmllint-check  # needs a local Omarchy/Quickshell install
```

The test suite covers the two-socket routing and the effective-gid gate,
owner-uid binding, missing/mismatched PID, expiry, approval, replay, wrong
nonce, cancellation, the askpass helper, process-identity changes, the
idle-connection DoS fix, and the concurrent-request cap. It does not
exercise the real setgid binary, the real socket ACLs or a real Quickshell
session; those are live checks. See [`SPEC.md`](SPEC.md#acceptance-criteria) for the full list
mapped to requirements.

## License

MIT. See [`LICENSE`](LICENSE).
