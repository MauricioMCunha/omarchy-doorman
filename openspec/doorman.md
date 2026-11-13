# OpenSpec: doorman v0.1

## Functional requirements

### R1 — Authenticated request

The broker MUST accept a `request` only on its askpass socket, and only from
a peer whose effective gid (from `SO_PEERCRED`) is the `doorman-askpass`
group's, which only a process that executed the root-installed setgid askpass
binary has. There is no session token, `origin`, or capability. Requests with
no positive PID, whose claimed PID is not the peer's own, whose peer's parent
is not a genuinely escalated `sudo`, or whose process doesn't exist, MUST be
rejected. `approve`/`cancel`/`pending`/`stats` MUST be accepted only on the
control socket, from the trusted UI, with the configured owner uid; each
socket MUST reject the other's verbs (`wrong_socket`). See SPEC.md §6.13.

### R2 — Verifiable context

The request MUST show the command, PID, directory, TTY, prompt, monitor,
nonce, and deadline. The broker MUST capture and revalidate the PID's start
time, UID, and cmdline at the moment of approval, rejecting processes that
have exited or been reused.

### R3 — Single use and expiry

Every request MUST have a cryptographically random `request_id` and nonce,
a deadline between 1 and 300 seconds, and a single terminal state:
approved, cancelled, or expired. Replays MUST fail closed.

### R4 — Secret outside the observation surface

The secret MUST NOT appear in arguments, logs, files, clipboard, UI
responses, or the agent's messages. The helper may write it only to stdout,
for the `sudo askpass` consumer.

### R5 — Authenticated cancellation

Cancellation MUST require a valid request id and nonce. An invalid
cancellation must not change the request.

### R6 — Local transport

The sockets MUST be Unix sockets in `/run/doorman`, owned by the service
user `doorman`, mode `0660`, with group `doorman-askpass` (request socket)
and `doorman-ui` (control socket). The service MUST be a system unit running
as `doorman` using `NoNewPrivileges` and a private temporary directory. The
askpass binary MUST be installed `root:doorman-askpass` mode `2755`, MUST
call `prctl(PR_SET_DUMPABLE, 0)` before handling any secret, and MUST open
no file.

## Acceptance criteria

- `python3 -m unittest discover -s tests -p 'test_*.py'` passes;
- the Graphify diagnostic reports no missing endpoints, loops, or exact
  duplicate edges (edges with distinct relations may show up as an
  informative relational collision);
- tests cover the effective-gid gate, per-socket verb routing, owner-uid
  binding, missing PID, expiry, approval, replay, and cancellation with a
  wrong/correct nonce;
- no real deploy change happens without explicitly installing the unit;
- the live checks in SPEC.md §6.13 (real unit, real `sudo` round trip, fork-exec
  and ptrace attempts, second-user rejection) are run by a human and pass
  before the design is considered verified; they are not yet done.
