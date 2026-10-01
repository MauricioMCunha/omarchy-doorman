# Minimal security model

- Unix socket with permissions restricted to the user.
- Every request uses a nonce and can be consumed exactly once.
- The request shows the command, PID, directory, terminal, and expiry.
- A change in PID, start time, PTY, or command invalidates the request.
- Short timeout and explicit cancellation.
- No secret in a file, clipboard, log, telemetry, or the agent's response.
- The wrapper doesn't export the token/capability into `sudo`'s
  environment; askpass reads session material directly from the private
  runtime directory.
- Required tests covering the wrong process, concurrency, expiry, and
  cancellation.

This document doesn't yet authorize use in financial operations or in a
production environment. Release depends on testing and on a review of the
threat model.
