# OpenSpec: doorman v0.1

## Functional requirements

### R1 — Authenticated request

The broker MUST accept requests only with a valid session token,
`origin=llm`, and a matching capability. Requests with no positive PID, or
whose process doesn't exist, MUST be rejected.

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

The socket MUST be a Unix socket, created with `0600`, under a `0700`
directory, and the service MUST use `umask 0077`, `NoNewPrivileges`, and a
private temporary directory.

## Acceptance criteria

- `python3 -m unittest discover -s tests -p 'test_*.py'` passes;
- the Graphify diagnostic reports no missing endpoints, loops, or exact
  duplicate edges (edges with distinct relations may show up as an
  informative relational collision);
- tests cover a wrong token, invalid origin, missing PID, expiry,
  approval, replay, and cancellation with a wrong/correct nonce;
- no real deploy change happens without explicitly installing the unit.
