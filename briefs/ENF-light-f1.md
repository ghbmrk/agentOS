# ENF-light-f1: the trip light lifts only with the cut, keyed by name

Board section: Devices, hardware and image (SPEC §13-14). Work item #4305, items 1 and 3. These are follow-ups from the reviews of #4270 (ENF-light, #4165): Security comment 6543786077 and combined comment 6543788477. Item 4 was split out as #4354, and item 2 (the bulb maps colours by name) is in ENF-l-b2 part b (`briefs/ENF-l-b2.md`), where the bulb driver is written.

**Problem, checked on main 2c3ec6f2:**
1. The owner can clear a trip without lifting its cut. `broker/cmd/agentos-enforcer/state.go` marks only `alert.ChannelPaused` as `Fixed`, so the page offers `ActClear` on an open `alert.Trip` or `alert.RecordMissing`. `page/status.go`'s `stateAct` then calls `Alerts.Resolve`, which refuses only `ChannelPaused`. The light goes off while the core's or the edge's cut still stands. Failure path: the owner taps "clear" on the trip card, the light shows no trip, and the cut box stays cut with nothing in view to say so (KRN-12 Response).
2. When DECOY-d (#3765) adds the two-step core lift ("core reflashed", then REC-5's closing passkey), `alert.Lifted` must run only at the second step. Today `cut.Resume` calls it at the one step there is, which is correct now. A test should pin that `Lifted` is called only when the cut lifts in full, so the two-step change cannot move it.
3. Every trip about the core uses `coreDevice` ("core") and every edge trip uses `edgeDevice` ("edge"), so `Lifted(device)` matches what `Raise` used. Today that holds by convention only.

**Requirements:** KRN-12 (Trips, Response), NET-2 (Texts and calls).

1. `alert.Alerts.Resolve` refuses, with `ErrResolved`, any record whose kind lights the light (`Kind.lights()`: `Trip` and `RecordMissing`). Only `Lifted` closes those. `state.go` marks those kinds `Fixed`, so the page offers no clear on them and points instead to the lift or resume step.
2. **No stuck red light (L3 on #5999, point 1).** `Lifted` becomes the only way to close these alerts, so every path that finds a box open must call it. Today `cut.Resume` and `edgeCut.Lift` return nil on a box that is already open without calling `Lifted`, and `Resume` saves the open state before calling it, so a failed journal append, or a crash between the two, leaves the cut lifted on disk with its trip still open. Change it so that:
   - `Resume` and `Lift` on an already-open box call `Lifted(device)` for that box;
   - `openCut` and `openEdgeCut`, on a record that reads open, close at start-up only the alerts that the record's last saved lift covers. The lift saves the highest alert ID (`alert.Last`) in the record, and the close is `alert.LiftedThrough(device, through)`. A trip raised after that lift, whose record write never landed, stays open and red across a restart (L3 point 1 on #6012). An unconditional `Lifted` cannot tell a saved lift whose close failed from a trip whose cut write failed;
   - each call's error is returned or logged, and a retry closes the alert.
3. **Fixed words.** Rewrite the `Trip` and `RecordMissing` texts in `alert.go`, which today offer "you clear this there", so they name the lift or resume step on the page instead. Rewrite alert ASSUMPTIONS ENF-h-a2 and ENF-h-a4, which promise the owner a clear, to match.
4. A daemon test raises a core trip and checks that the light stays red through every step short of the full lift.
5. A test reads every `alerts.Raise(alert.Trip, …)`, `recordMissing(alerts, …)` and `alerts.Lifted(…)` call site in `broker/cmd/agentos-enforcer` (today `cut.go:52`, `cut.go:89`, `cut.go:148`, `edgecut.go:72`, `edgecut.go:76`, `edgecut.go:112` and `edgecut.go:163`). Each must pass `coreDevice` or `edgeDevice`, never a literal or a computed name.

**Scope:** `broker/enforcer/alert/alert.go`, `broker/enforcer/alert/alert_test.go`, `broker/enforcer/alert/ASSUMPTIONS.md`, `broker/cmd/agentos-enforcer/state.go`, `broker/cmd/agentos-enforcer/cut.go`, `broker/cmd/agentos-enforcer/edgecut.go`, `broker/cmd/agentos-enforcer/daemon_test.go`, `broker/cmd/agentos-enforcer/ASSUMPTIONS.md`, this brief. If a page test pins the old words, add the page test file that does to the claim comment.

**Acceptance tests:**
- KRN-12: `alert::TestResolveRefusesLightingKinds`. `Resolve` on an open `Trip` or `RecordMissing` returns `ErrResolved`, and the light stays red. Catches a light cleared while a cut stands.
- KRN-12: `agentos-enforcer::TestTripCardOffersNoClear`. The page's open alert for a trip is `Fixed`, and `ActClear` on it gets `errFixed`. Catches the page path.
- KRN-12: `agentos-enforcer::TestLiftedOnlyOnFullLift`. A core cut keeps the light red until `Resume` succeeds, and a failed save of the lift leaves it red. Catches an early `Lifted`.
- KRN-12: `agentos-enforcer::TestFailedLiftAlertRetried`. With the alert journal's append made to fail, `Resume` returns the error. A second `Resume` on the now-open box closes the trip and the light goes off, and so does `openCut` after a restart. The same holds for the edge (`Lift`, `openEdgeCut`). Catches a light that stays red for good, as the L3 repro on #5999 showed.
- KRN-12: `agentos-enforcer::TestUnsavedTripStaysRedAfterRestart`. A trip whose record write is refused, then a restart, keeps the trip open and the light red, with or without an earlier lift. Catches a start-up close that clears a trip the owner never lifted (L3 repro on #6012).
- KRN-12: `alert::TestLightingKindsNameTheLiftStep`. The `Trip` and `RecordMissing` words contain no "clear this". Catches a text that sends the owner to a button that no longer exists.
- KRN-12: `agentos-enforcer::TestTripDeviceNamesAreTheBoxConstants`, covering the `Raise`, `recordMissing` and `Lifted` sites. Catches a trip or missing record raised under a name that `Lifted` never matches.

**Guard files:** none.

**Dependencies:** none open. #4290 (ENF-c) is merged. ENF-l-b2 edits other files in the same directory. Under D-320 (#5956, open), overlap alone does not block the build.

**Tier / gate:** tier A (`broker/enforcer`, `broker/cmd/agentos-enforcer`). L3 runs on the strongest model, plus the lens screen and a separate Security accept.

**Usage estimate:** one session, about 80k.
