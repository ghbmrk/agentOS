# SEC-stopped-readers: Stopped() readers that start work after a failed STOP (OP-6)

Board section: Backlog refill. Issue #2463. Defect: SEC-failed-stop-latch.

Raised on #2458: a STOP that fails to record breaks the journal (`Halted()` true) without setting `Stopped()`. Each reader of `Stopped()` that can start work outside the journal must read `Halted()`; owner-facing readers (`control/handler.go`, `owner/*`) keep `Stopped()`. #2464 moved the loop scheduler gate and grants `reissueDue`.

**Requirement:** OP-6 ("nothing new starts now").

**Recheck:**
- `grants.flush`'s re-issue hold read `Stopped()`: a request re-issued at boot and still batched was sent after a failed STOP. Defect, fixed here.
- `apply.New`'s default STOP gate read the journal's `Stopped()`: a release handed over before a failed STOP was restarted into, with no journal write, and the restart clears the halt. Defect (the applier is not yet wired in agentosd), fixed here.
- `agentosd` sleeper (`sleepwire.go`, `Stopped: d.Engine().Stopped`): no defect. It sleeps the agent only inside a loop unit the scheduler admitted on `Halted`, and the scheduler's in-run watch ends the unit on `Halted`, which wakes the agent (`defer sl.Wake`).
- Provider routes: no defect. `provider_run` starts behind the worker tools' `Halted` gate (`workerGates`), runs in flight are ended by the reaper (#2535), and routes read `RouteStops` (#2534's scope, untouched).

**Approach:** `flush` reads `g.eng.Halted()`; `apply.New` prefers a journal's `Halted` over its `Stopped`.

**Acceptance tests:** OP-6: `TestOP6FailedStopHoldsAReissuedRequest` (broker/grants/failedstop_test.go), `TestFailedStopHoldsTheRestartIntoAHandedOverRelease` (broker/apply/failedstop_test.go), each with a control case that does send or restart.

**Scope:** broker/grants/gate.go, broker/grants/failedstop_test.go, broker/grants/ASSUMPTIONS.md, broker/apply/apply.go, broker/apply/failedstop_test.go, broker/apply/ASSUMPTIONS.md, briefs/SEC-stopped-readers.md.

**Needs:** —

**Gate:** lenses (security)
