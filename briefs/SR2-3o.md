# SR2-3o: Malformed-request refusals keep a field-level hint for the guest

Board section: Release (finding item 2, lens on #396).

Since SR2-3j a malformed grant-change refusal and a destination refusal reach the guest only as one fixed sentence, so the agent loses the hint of which field was wrong and cannot correct its request. Give each such refusal a fixed `guesterr.Literal` per field or cause (no echoed value, no path), so the guest learns what to fix and still sees no owner or host text.

**Needs:** SR2-3j

**Gate:** security check
