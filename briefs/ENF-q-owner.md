# ENF-q-owner: owner-set relock interval and usual hours in the signed policy

Board section: Devices, hardware and image (SPEC §13-14). Work item #4285, a release finding from ENF-q (#3675). It serves `locks::TestRelocksAfterInterval` and `locks::TestUnusualTimeNeedsSecondAssertion`.

**Problem:** NET-6 makes the relock interval owner-set and leaves the unusual hours to the owner. `broker/enforcer/locks/locks.go` ships both as constants instead: `RelockAfter` is one minute, and the usual hours run `UsualFrom` 07 to `UsualTo` 22 (locks ASSUMPTIONS ENF-q-2, ENF-q-3). The signed policy has no field for either. Failure path: a door that must relock in 10 seconds stays open for a minute, and a household that gets home at 23:30 every night needs two taps and a text for each arrival.

**Decision in this brief (challenge to the issue's sketch).** #4285 proposes that a shorter interval or narrower usual hours count as an asserted tightening. SPEC NET-4's tightening list is closed: removing a destination, cutting a vendor cloud, removing a path, and isolating or removing a device. A new tightening kind would need an L1 spec diff first. So this brief treats every change to either field as a loosening, with the owner's assertion and the 10-minute wait. That matches SPEC as written, and these settings change rarely. Adding them as tightening kinds is a separate SPEC row if the owner ever wants it.

**Requirements:** NET-6 (relock after the owner-set interval; second assertion at an unusual time), NET-4 (Loosening), STO-4 (one signed rule system).

1. `policy.Device` gains `RelockSeconds` and `UsualHours` (from and to as whole hours in the enforcer's zone). Both are valid only on the lock and alarm classes, and are zero elsewhere. Zero means today's defaults (60 s; 07 to 22), so documents already signed keep their meaning. `check()` bounds the interval to 5 to 3,600 s and requires `UsualHours.From` to differ from `UsualHours.To`. A window that wraps midnight is allowed.
2. `Classify` needs no new op. The candidate set does not change, so any change to these fields is a loosening. A test pins that.
3. The page's diff wording names the old and new interval and hours (`describeDevice` in `render.go`).
4. `locks.Gate` reads both fields from the document in force: `Tick` for relock deadlines, and `Act` and `Second` for unusual time, with `Unusual` taking the device's hours. The constants become the defaults. ENF-q-2 and ENF-q-3 are rewritten.

**Scope:** `broker/enforcer/policy/document.go`, `broker/enforcer/policy/policy_test.go`, `broker/enforcer/policy/ASSUMPTIONS.md`, `broker/enforcer/page/render.go`, `broker/enforcer/page/describe_test.go`, `broker/enforcer/locks/locks.go`, `broker/enforcer/locks/locks_test.go`, `broker/enforcer/locks/ASSUMPTIONS.md`, this brief.

**Acceptance tests:**
- NET-6: `locks::TestRelocksAfterInterval`, extended. A lock with `RelockSeconds: 10` relocks at 10 s, and one with zero relocks at 60 s. Catches a constant still in force.
- NET-6: `locks::TestUnusualTimeNeedsSecondAssertion`, extended. With `UsualHours` from 06 to 24, an unlock at 23:30 needs one tap, and with a wrapping window the hours either side of midnight are handled correctly. Catches the hard-coded hours.
- NET-4: `policy::TestRelockAndHoursChangesAreLoosenings`. Shortening, lengthening, narrowing and widening each classify as a loosening. Catches a change that skips the wait.
- STO-4: `policy::TestRelockAndHoursBounds`. Fields on a non-lock class, an interval out of bounds, and an empty window are each refused by `check`. Catches a document that disables relock.
- NET-4: `page::TestDescribeRelockAndHours`. Catches a change the owner cannot see on the confirm screen.

**Guard files:** none.

**Dependencies:** none open. ENF-q (#3675), #4227 and ENF-c (#4290) are merged. Run it before ENF-l-b2 part c (`briefs/ENF-l-b2.md`), which wires `locks.Gate` into the daemon, so that part reads the new fields. If part c merges first, it simply keeps the defaults.

**Tier / gate:** tier A (`broker/enforcer`). L3 runs on the strongest model, plus the lens screen and a separate Security accept.

**Usage estimate:** one session, about 80k.
