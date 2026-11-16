# ENF-light-f1: the trip light lifts only with the cut, keyed by name

Board section: Devices, hardware and image (SPEC §13-14). Work item #4305, items 1 and 3. These are follow-ups from the reviews of #4270 (ENF-light, #4165): Security comment 6543786077 and combined comment 6543788477. Item 4 was split out as #4354, and item 2 (the bulb maps colours by name) is in ENF-l-b2 part b (`briefs/ENF-l-b2.md`), where the bulb driver is written.

**Problem, checked on main 2c3ec6f2:**
1. The owner can clear a trip without lifting its cut. `broker/cmd/agentos-enforcer/state.go` marks only `alert.ChannelPaused` as `Fixed`, so the page offers `ActClear` on an open `alert.Trip` or `alert.RecordMissing`. `page/status.go`'s `stateAct` then calls `Alerts.Resolve`, which refuses only `ChannelPaused`. The light goes off while the core's or the edge's cut still stands. Failure path: the owner taps "clear" on the trip card, the light shows no trip, and the cut box stays cut with nothing in view to say so (KRN-12 Response).
2. When DECOY-d (#3765) adds the two-step core lift ("core reflashed", then REC-5's closing passkey), `alert.Lifted` must run only at the second step. Today `cut.Resume` calls it at the one step there is, which is correct now. A test should pin that `Lifted` is called only when the cut lifts in full, so the two-step change cannot move it.
3. Every trip about the core uses `coreDevice` ("core") and every edge trip uses `edgeDevice` ("edge"), so `Lifted(device)` matches what `Raise` used. Today that holds by convention only.

**Requirements:** KRN-12 (Trips, Response), NET-2 (Texts and calls).

1. `alert.Alerts.Resolve` refuses a record whose kind lights the light (`Kind.lights()`: `Trip`, `RecordMissing`) with `ErrResolved`. Only `Lifted` closes those. `state.go` marks those kinds `Fixed`, so the page offers no clear on them and instead points to the lift or resume step.
2. A daemon test raises a core trip and checks that the light stays red through every step short of the full lift.
3. A test reads every `alerts.Raise(alert.Trip, …)` and `alerts.Lifted(…)` call site in `broker/cmd/agentos-enforcer` and checks that each passes `coreDevice` or `edgeDevice`, never a literal or a computed name.

**Scope:** `broker/enforcer/alert/alert.go`, `broker/enforcer/alert/alert_test.go`, `broker/enforcer/alert/ASSUMPTIONS.md`, `broker/cmd/agentos-enforcer/state.go`, `broker/cmd/agentos-enforcer/cut.go` (comment only, naming the step that calls `Lifted`), `broker/cmd/agentos-enforcer/daemon_test.go`, this brief.

**Acceptance tests:**
- KRN-12: `alert::TestResolveRefusesLightingKinds`. `Resolve` on an open `Trip` or `RecordMissing` returns `ErrResolved`, and the light stays red. Catches a light cleared during a standing cut.
- KRN-12: `agentos-enforcer::TestTripCardOffersNoClear`. The page's open alert for a trip is `Fixed`, and `ActClear` on it gets `errFixed`. Catches the page path.
- KRN-12: `agentos-enforcer::TestLiftedOnlyOnFullLift`. A core cut keeps the light red until `Resume` succeeds, and a failed save of the lift leaves it red. Catches an early `Lifted`.
- KRN-12: `agentos-enforcer::TestTripDeviceNamesAreTheBoxConstants`. Catches a trip raised under a name `Lifted` never matches.

**Guard files:** none.

**Dependencies:** none open. #4290 (ENF-c) is merged. ENF-l-b2 edits other files in the same directory. Under D-320 (#5956, open), overlap alone does not block the build.

**Tier / gate:** tier A (`broker/enforcer`, `broker/cmd/agentos-enforcer`). L3 runs on the strongest model, plus the lens screen and a separate Security accept.

**Usage estimate:** one session, about 60k.
