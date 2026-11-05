# Doorman architecture

## Layers

1. **Visual plugin** — runs inside Quickshell/Omarchy Shell, presents
   requests, and collects local consent.
2. **Local broker** — a user service with a private Unix socket, nonce,
   timeout, process binding, and buffer cleanup.
3. **Authentication helper** — a small, dependency-free native binary
   (`askpass/doorman-askpass.c`), installed once by root at a fixed path
   outside the plugin's own checkout, owned by root and not writable by
   the user. Unlike earlier designs, the binary itself is privilege-free:
   no file capability, no `setuid`/`setgid`, and it never opens its own
   `/proc/self/exe` or hands the broker a file descriptor. Instead, a
   separate systemd `--user` unit — `omarchy-doorman-identity-helper`
   (`identity_helper/identity_helper.py`), started independently of the
   broker so it keeps none of the broker's own mount-namespace hardening —
   answers one question: does a given pid's `/proc/<pid>/exe` identify the
   same file (device+inode, via `fstat()`, never a path string) as this
   installed binary? The broker queries that helper synchronously, the
   instant it accepts a connection and before reading anything the peer
   sends, holding a `pidfd` and briefly `SIGSTOP`ping the peer for the
   duration of the query so a process that forks and execs into the
   trusted binary mid-connection can't be mistaken for the real thing —
   the peer is always resumed (`SIGCONT`) once the check completes,
   whatever the answer. Limited integration with `sudo askpass`, never
   receiving arbitrary commands from the plugin — and, since this is the
   only thing the broker will hand the secret to, never a plain script the
   agent itself could have written or pointed `SUDO_ASKPASS` at. See
   `SPEC.md` §6.13.
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
