# SEC-stop-with-code: a STOP sent with a code skips the STOP generation, so an older RESUME code still lifts it (CH-2)

Board section: Backlog refill (2026-10-11). Issue #2459. Defect: STOP-gen.

Review finding 1 (Medium, tier A: `broker/owner`), relayed by Mark on 2026-10-19. `control.Parse("STOP 123456")` is not `WordStop`, so `stopNow` skipped it; `route` then stripped the code (CH-14) and passed bare `STOP` on without counting it in the STOP generation or voiding the pending RESUME challenge. While locked, `STOP <wrong code>` was dropped as a wrong code and nothing stopped.

**Requirement:** a STOP with a trailing code is STOP. `stopNow` reads the message without its trailing code, takes it before any code check, counts it in the STOP generation and hands the handler bare `STOP`. The code is never checked, counted or passed on.

**Acceptance tests:** CH-2: `TestStopWithACodeStopsAndVoidsAnEarlierResumeCode` (broker/owner/stopcode_test.go): locked and unlocked, each with a right and a wrong code; each stops, counts one STOP, leaves the unlock window and wrong-code count unchanged, and voids the earlier RESUME code.

**Scope:** broker/owner/channel.go, broker/owner/stopcode_test.go, broker/owner/ASSUMPTIONS.md, briefs/SEC-stop-with-code.md.

**Needs:** —

**Gate:** lenses (security, tier A)

**State on the board:** in review
