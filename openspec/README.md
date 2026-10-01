# Doorman OpenSpec

This folder holds Doorman's executable specification. Every requirement has
acceptance criteria that must be covered by tests, static validation, or a
documented manual check.

The system delivers a local authorization request to a Quickshell UI and
hands a secret back only to the requesting process, over a private Unix
connection. It isn't a vault, doesn't intercept arbitrary prompts, and
doesn't send secrets to the agent, logs, clipboard, or network.

## Normative flow

1. The authorized process calls the `askpass` helper.
2. The broker authenticates the session token and the `llm` origin's
   capability.
3. The broker creates a request with a nonce, a deadline, and the
   process's identity.
4. The UI lists the request and shows the command, PID, terminal, and
   monitor.
5. Approval or cancellation requires the request's nonce and is single-use.
6. The secret is delivered only on the helper's blocked connection; the
   request is then removed.

## Out of scope

- persistent credentials or password recovery;
- financial operations or production without a threat-model review;
- global keyboard, clipboard, PTY, or arbitrary-command capture;
- automatic installation under `/usr/share/omarchy`.
