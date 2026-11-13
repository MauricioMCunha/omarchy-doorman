# Minimal security model

- Two Unix sockets in `/run/doorman`, owned by the system user `doorman`,
  mode `0660`: `askpass.sock` (group `doorman-askpass`) and `control.sock`
  (group `doorman-ui`). The kernel enforces the group ACL at `connect()`.
- A request is admitted only if the connecting process's effective gid
  (read from `SO_PEERCRED`) is `doorman-askpass`, which only a process that
  executed the root-installed setgid askpass binary has; plus the sudo-parent
  checks and a human approval. See `SPEC.md` §6.13 and §6.1.
- Approve/cancel/pending/stats are accepted only on the control socket, from
  a process under the trusted UI, with the configured single owner uid.
- There is no session token or capability: nothing of that kind is stored,
  read, or sent.
- Every request uses a nonce and can be consumed exactly once.
- The request shows the command, PID, directory, terminal, and expiry.
- A change in PID, start time, PTY, or command invalidates the request.
- Short timeout and explicit cancellation.
- No secret in a file, clipboard, log, telemetry, or the agent's response.
- The askpass binary opens no file, connects to a fixed socket path (bar a
  test-only override, `SPEC.md` §6.13), and is non-dumpable, so a same-user process cannot read the secret from it.
- Required tests covering the wrong process, concurrency, expiry, and
  cancellation.

This document doesn't yet authorize use in financial operations or in a
production environment. Release depends on testing and on a review of the
threat model. The current identity design is implemented and unit-tested but
**not yet verified live** against the real system unit and a real `sudo`
round trip (`SPEC.md` §6.13); until that passes, the fork-exec race and the
same-user ptrace read are closed by design, not confirmed closed.
