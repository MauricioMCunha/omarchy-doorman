# Doorman architecture

## Layers

1. **Visual plugin** — runs inside Quickshell/Omarchy Shell, presents
   requests, and collects local consent.
2. **Local broker** — a user service with a private Unix socket, nonce,
   timeout, process binding, and buffer cleanup.
3. **Authentication helper** — limited integration with `sudo askpass`,
   never receiving arbitrary commands from the plugin.
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
