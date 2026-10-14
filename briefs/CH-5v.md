# CH-5v: Live calls and codes on calls

Board section: Uncovered requirement IDs (CONV-5).

Live calls (SPEC CH-5) and codes on calls (CH-17): carrier voice → modem → broker → speech (local by default; hosted only by explicit policy) → guest. Approval and unlock codes and control words are entered by keypad (DTMF), decoded by the broker, and never reach the speech service or guests. When the owner can't use the keypad, the box texts the pending batch for later. Acceptance A3 includes a code entered by keypad mid-call.

No BOARD row existed for CH-5 or CH-17 (found 2026-10-10 in the assistant-boundaries review); the modem spike S2 waits on hardware.

**Needs:** S2 (hardware: 2 modems + SIM), P2-3w

**Gate:** lenses (security first: the speech service and guests are untrusted; a spoken or recognised code must never approve a request)

**Failure path to test first:** a code spoken on a call, or present in the speech transcript, approves nothing and reaches no guest; only a DTMF digit string decoded by the broker does.

## Scope

Startable now: the simulator-only slice (DTMF decode, withholding from speech, the text fallback) in `broker/modem/at/**` (DTMF decode), `broker/modem/atsim/**` (simulator), `broker/voice/**`, `broker/owner/channel.go`, and their tests. Tier A. Waits on hardware: the S2 qualification of voice quality and latency over USB modems (S2, Mark). `broker/modemlink/**` only for the real-modem step.
