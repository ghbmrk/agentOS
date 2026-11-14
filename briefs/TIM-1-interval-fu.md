# TIM-1-interval-fu: the clock guard moves to the interval and an unauthenticated source cannot stretch it

Board section: Migration to the capability kernel (D-139). Work item #5216 (release items 2 to 4 of #5215's reviews); #5147 (KRN-clock) merged first. The agentosd STATUS line and the PLAN ON reply are #5279 (sub B).

**Problem:** SPEC TIM-1 (#5215) replaced the restricted mode with an interval: widenings wait for its start, narrowings fire at its end, and STATUS names each move a wide interval delays (LOG-8). `broker/clock` still describes and texts the restricted mode, gives no single reading of both ends, and lets one unauthenticated source widen the interval without bound: a fake base station's time hours ahead moves `Latest` hours ahead even while the box clock is NTS-authenticated, so every expiry judged on `Latest` fires hours early (issue item 4).

**Requirements:** TIM-1, KEY-4, CLK-2 (the clerk ends a hold only once its own interval's start has passed: the clerk reads `Earliest`).
1. `Guard.Interval` gives `Earliest` and `Latest` from one check; `Earliest` and `Latest` are its ends.
2. While the check's NTP sync is NTS-authenticated, carrier time widens the interval by at most the tolerance; the disagreement still alerts the owner, with its own text, and restricts nothing. With plain NTP, or none, the carrier widens it fully, as before.
3. Owner texts and `Status.IntervalLine` describe the interval (holds and timeouts end by both clocks, expiries by either), not the restricted mode. `Status.Line` stays until #5279 moves agentosd's STATUS line, then goes.
4. `Guard.Now` and `ErrRestricted` stay only for callers that have not moved to the interval (`broker/question`, sub B), documented as such.

**Scope:** `broker/clock` (`clock.go`, its tests, `ASSUMPTIONS.md`), `broker/modem/at/nettime_test.go`, this brief. Not `broker/question` or `broker/cmd/agentosd` (sub B, D-111): their move is a release item.

**Acceptance tests:** `broker/clock/interval_test.go`: `TestTIM1IntervalSpansBothSourcesWhenTheyDisagree`, `TestTIM1IntervalIsNarrowWhileTheyAgree`, `TestTIM1AuthenticatedTimeBoundsAnOutlierCarrier`, `TestTIM1IntervalLine`, `TestTIM1OwnerTextsDescribeTheInterval`. `broker/modem/at/nettime_test.go`: `TestTIM1ModemIsTheGuardsCarrier` (the interval spans both sources), `TestTIM1ForgedCarrierTimeCannotExpireKeys`.

**Tier / gate:** tier A (`broker/clock`): L3 on the strongest model, the tier's lens screen and a separate Security accept.

**Usage estimate:** one session.
