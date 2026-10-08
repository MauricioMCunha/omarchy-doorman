# Doorman architecture

## Layers

1. **Visual plugin** — runs inside Quickshell/Omarchy Shell, presents
   requests, and collects local consent.
2. **Local broker** — a user service with a private Unix socket, nonce,
   timeout, process binding, and buffer cleanup.
3. **Authentication helper** — a small, dependency-free native binary
   (`askpass/doorman-askpass.c`), installed once by root at a fixed path
   outside the plugin's own checkout, owned by root and only executable
   (not readable or writable) by the user. It proves its identity by
   handing the broker a file descriptor for its own executable
   (`SCM_RIGHTS`) rather than the broker trying to inspect the connecting
   process itself — reading another process's `/proc/<pid>/exe` needs a
   permission this project's own systemd hardening denies the broker, so
   the fd is passed instead of inspected. Opening its own `/proc/self/exe`
   isn't privilege-exempt either (same DAC check as opening the file by
   path), so the binary also carries the `cap_dac_read_search` file
   capability, applied by the install script, scoped to this one binary
   only. Limited integration with `sudo
   askpass`, never receiving arbitrary commands from the plugin — and,
   since this is the only thing the broker will hand the secret to, never a
   plain script the agent itself could have written or pointed
   `SUDO_ASKPASS` at. See `SPEC.md` §6.11.
4. **Privileged operation** — `sudo` or `pkexec`, always with a verifiable
   scope and origin.

## Initial flow

```text
authorized command
    └─ sudo / sudo -A / SUDO_ASKPASS
         └─ local broker
              └─ Omarchy plugin
                   └─ user confirms and types locally
```

The password's content never returns to the agent, the chat, the
clipboard, or the log.

## First-version limit

The non-invasive integration can only configure `SUDO_ASKPASS`, without
replacing `sudo`, changing `sudoers`, or capturing commands globally. The
exact behavior depends on sudo's version/policy; on this machine, the
helper isn't called without `-A`, including in a TTY-less run. The optional
wrapper adds `-A` only when the user invokes it directly. The
`doorman-run` launcher creates a temporary PATH for a single process,
letting an LLM runner use `sudo command` without remembering the flag,
without changing the user's global PATH.
