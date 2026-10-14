# S8-live: S8 live part

Board section: Phase 0: harness and risk spikes.

S8 live part: real Claude and ChatGPT plans, real quota headers and events through one window, Codex refresh through the broker swap, where Anthropic revokes a setup token, both sign-in flows on a phone ([what is needed](../spikes/S8-provider-workers/RESULT.md))

**Needs:** **Mark: Claude and ChatGPT plans**, custom network policy

**State on the board before the 2026-10-08 index split:** queued

## Codex plan-route measurements (D-114)

Codex is now the default plan route (D-114), broker-held. Besides filling CAP-11-plan's qualification record (pinned CLI version, declared endpoints and swap positions, terms URL, date read and verdict), this row measures, against the pinned CLI and a real ChatGPT plan, in a supervised session:

- **Hosted tools.** Which hosted tool types (web search and any other tool OpenAI runs on its side) the pinned CLI puts in a responses request's `tools` array, with #807's managed configuration on and off. The result sets the declaration's allowed client-side tool types for #1014's request-body check (CRED-5 W4's carry-over).
- **Credits after the limit.** Whether a ChatGPT plan draws purchased credits once a Codex pool is used up, and which response field or header signals it (`spikes/S8-provider-workers/RESULT.md` §3 left the `credits` fields open). If it can, CAP-11-plan's declaration treats that signal as used-up or requires credits off (W8's money risk). This is an open measurement, not a SPEC change.
- **Sign-in through the forwarder.** Whether the pinned CLI's device-auth sign-in can be pointed at the forwarder, and the declared auth host its verification URL uses (#1014's sign-in endpoints and auth-host check).
