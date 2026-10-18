# P2-2w-d2b-s2: Pin the adopt-SIM mutants M7, M12 and M14

Board row: #927 (release, tier A). Parent package: P2-2w d2b (briefs/P2-2w-d2b.md). Source: the #444 Security review, point S2 (reviews/security/2026-10-09-pr444.md), and its re-sign R1 on SR3-1.

Test-only package. Three mutants of the merged adopt-SIM path survive the current tests; each gets a test that passes on main and fails with its mutant applied. No production code changes.

**Requirements:** CH-1, CH-7, CH-19.

**Acceptance tests:**
- M7 (CH-19): `broker/modemlink` `TestAnAdoptionEndsWhenTheBridgeReportsAnotherState`. After an adopt, a report of another swapped SIM offers that SIM with the confirm note, and the same SIM swapped again after an ok line is offered again. Mutant: setState no longer clears `adopted`.
- M12 (CH-1, CH-19): `broker/modem/bridge` `TestAnOkLineReportsNoSIMSerial`. No state the bridge sends with the line ok carries an ICCID. Mutant: `open` returns the SIM's serial with `StateOK`.
- M14 (CH-7, SR3-1): `broker/localsrv` `TestALockDuringTheCodeDropsTheSessionAndAdoptsNothing`. A lock between the token check and the code answers unauthorized, calls `AdoptSIM` zero times, and the same token stays dead. Mutant: adoptSIM's `locks != ses.locks` case disabled.

## Scope

`broker/modemlink/modemlink_test.go`, `broker/modem/bridge/bridge_test.go`, `broker/localsrv/sim_test.go`, `broker/modemlink/ASSUMPTIONS.md` (new), `broker/localsrv/ASSUMPTIONS.md`, this brief.

`broker/modem/bridge/bridge_test.go` is added to the issue's file list: M12 lives in the bridge (`bridge.go` `open`), and modemlink keeps an ok line's serial out of its state, so only the bridge's own reports can show the mutant.

Out of scope: #1295 (setup re-adopts a SIM swapped during setup) is `class:later` and is not started.
