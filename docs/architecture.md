# Doorman architecture

## Layers

1. **Visual plugin** — runs inside Quickshell/Omarchy Shell, presents
   requests, and collects local consent.
2. **Local broker** — a **system** service (`omarchy-doorman.service`,
   running as the dedicated user `doorman`) with two Unix sockets in
   `/run/doorman` — `askpass.sock` for requests and `control.sock` for the
   trusted UI — plus per-request nonce, timeout, process binding, and buffer
   cleanup. It holds no session token or capability.
3. **Authentication helper** — a small, dependency-free native binary
   (`askpass/doorman-askpass.c`), installed once by root at a fixed path
   outside the plugin's own checkout
   (`/usr/local/lib/omarchy-doorman/doorman-askpass`), owned
   `root:doorman-askpass`, mode `2755` (**setgid**). Its identity is the
   effective gid the kernel gives any process that executes it: the request
   socket is owned `doorman:doorman-askpass`, `0660`, so only such a process
   can connect, and the broker re-reads that egid from `SO_PEERCRED`
   (recorded at `connect()`, so a later `execve()` can't change it) and
   refuses anything else. The binary opens no file, connects to the fixed
   path `/run/doorman/askpass.sock` (the one environment variable it
   reads, `DOORMAN_SOCKET_DEV_OVERRIDE`, exists for its own tests; see
   `SPEC.md` §6.13), marks itself non-dumpable
   (`prctl(PR_SET_DUMPABLE, 0)`) so a same-user process can't ptrace it or
   read the secret from its memory, and, being setgid, ignores `LD_PRELOAD`.
   There is no identity-helper process, no `SIGSTOP`, no `pidfd`, and no
   `/proc/<pid>/exe` lookup. Limited integration with `sudo askpass`, never
   receiving arbitrary commands from the plugin. See `SPEC.md` §6.13, which
   also states what has not yet been verified live.
4. **Privileged operation** — `sudo` or `pkexec`, always with a verifiable
   scope and origin.

## Initial flow

```text
authorized command
    └─ sudo / sudo -A / SUDO_ASKPASS
         └─ doorman-askpass (setgid doorman-askpass, non-dumpable)
              └─ /run/doorman/askpass.sock  (doorman:doorman-askpass 0660)
                   └─ broker: egid check via SO_PEERCRED, sudo-parent checks
                        └─ /run/doorman/control.sock (doorman:doorman-ui 0660)
                             └─ Omarchy plugin (bridge.py, status-only widget)
                                  └─ user confirms and types locally
```

Each socket serves only its own verbs: `request` on the askpass socket;
`approve`/`cancel`/`pending`/`stats` on the control socket. The other socket
answers `wrong_socket`.

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
