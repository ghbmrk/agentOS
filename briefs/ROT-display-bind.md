# ROT-display-bind: serve the waiting rotation display only to the session that started it

**Owner:** primary lane.
**Priority:** release. **Class:** release. **Implementation risk:** tier A (the display carries the new Owner Card parts and, after its confirm, the new code generator's seed).
**Board section:** Security and architecture review (2026-10-08).
**Requirements:** REC-4, HW-1
**Acceptance tests:** `broker/localui/rotwire_test.go`: `TestRotationDisplayIsTheStartingSessions` (start as A; as B, GET and POST `/rotate/card` are sent home with neither the new parts nor the seed, the vault process sees no commit; A still confirms and gets the result once) and `TestRotationDisplayWithNoStarterIsShownToNone` (a start not posted by a session serves the display to no session). The existing `rotwire_test.go` and `rotation_test.go` tests stay green.
**Dependencies:** ROT-result-bind (#1316, PR #1323), merged: the result binding this row extends to the display.
**Source:** Security S1 on PR #1323, issue #1338.

## Finding

`/rotate/card` serves the waiting rotation's `card.Display` to any signed-in session (ASSUMPTIONS L37: "the signed-in phone is the paired check"). A probe on PR #1323's head showed a session B that did not start the rotation can GET the display and read the new parts, the new recovery key and passphrase included, then post the asked group, be the confirmer and receive the new code generator's otpauth seed on `/rotate/done`, while the starter is sent home. #1316 closed the second-session read after the commit; it is still open before it.

Failure path: a lost or shared phone with a live agentosd session, on the box's Wi-Fi during the confirm window (up to 30 minutes), reads the replacement card the owner is making because of that loss.

## Scope and intended change

Files: `broker/localui/rotwire.go`, `broker/localui/rotation.go`, `broker/localui/rotwire_test.go`, `broker/localui/ASSUMPTIONS.md`, this brief.

- `RotationBegin` gains `Starter`, the starting session's `tokenKey`; it is the page's own and is never sent to the vault process. `rotateStart` sets it from the posting session's cookie, the session that gave the tier-4 proof.
- `Rotation.Start` records it with the display, under `mu`, in the same step that makes the display current, so no window serves a display without its starter.
- `serveCard` serves GET and POST of the display only when the request's session key equals the starter of the display currently waiting; any other session, a request without a session, and a start without a starter are sent to `/home`. The result binding (L46) then follows, since the confirmer is always the starter.
- ASSUMPTIONS: L37 says the display is the starting session's; L46 drops its "#1338's concern" sentence and says the display binding is L37's (#1338). The issue's note on a wrong #1173 reference: main's L46 already cites #1338, not #1173; the row is reworded so the residual it named is closed, citing this issue.

Not in scope: ending agentosd sessions after the code generator is replaced (#1173); the non-`Rotation` `RotationCard` path (tests' stub), which keeps L37's signed-in check.

UX cost: none; the owner confirms on the phone that started. A starter that signs out loses the display and starts again.

## Handoff and estimate

Initial checkpoint: 60k tokens, an estimate rather than a ceiling.
