# CRED-route-stop-followup: an unswappable stop outranks a refused login, and the restart tests run on the journal

Board row: #2016 (release findings from PR #2015's reviews). Tier A (credentialed sessions). Follows CRED-route-stop-persist (#1926, PR #2015). Builder: strongest model. Usage estimate: ~100k tokens, checkpoint at 80k.

## Failure paths (verified on main at f651092)

1. **A refused-login stop is never raised to unswappable** (L3 on #2015). `journal.Engine.StopRoute` keeps a route's first cause, and `egress.Proxy.stop` skips both the write and the owner's notice when the route is already stopped. So a route stopped for `login-refused` and then hit by an unswappable exchange stays `login-refused`, and the owner's sign-in (`provagent.Runner.SignedIn`, `egress.Proxy.Resume`) reopens a route only a release may reopen (CRED-5t).
2. **A reopening can lift a stop it did not read** (found while tracing 1). `SignedIn` and `Resume` read the cause, then call `ReopenRoute(route)`, which lifts any cause. A stop raised between the read and the reopen is lifted by a sign-in.
3. **The restart tests run on fake map stores** (L3 on #2015). `provagent/routestop_test.go` and `egress/routestop_test.go` use their own `RouteStops` maps, so the journal's semantics (idempotence, precedence) can drift from them with every test still green.
4. **An unrecorded stop is lost on restart** (Security on #2015). A stop the journal cannot write is held in memory only; after a restart the next run retries the refused login. See Design: this package documents it as a residual, with the reason, and writes no code for it.

## Requirements (from SPEC.md)

- **CRED-5**: a refused login stops the route; no retry until the owner signs in again or resumes. Its unswappable clause (CRED-5t in the code base): an unswappable exchange stops the route until a release requalifies the declaration.
- **OP-11**: the journal is the one durable store, and replay rebuilds state such as "stopped".

Package IDs:
- **CRED-RS-4** An unswappable cause (any cause but `login-refused`) outranks `login-refused`: `StopRoute` with it on a route stopped for `login-refused` writes a second record and replay keeps the higher cause; the same cause or a lower one writes nothing. The proxy raises a stored or held `login-refused` stop to unswappable and tells the owner again, since signing in no longer helps.
- **CRED-RS-5** `ReopenRoute(route, cause)` lifts the stop only while it is recorded with that cause, checked under the engine's lock; another cause stays stopped and returns `ErrRouteCause`, and the reopen record carries the cause it lifted, so replay compares too (a reopen record without a cause, written before this package, lifts any). `SignedIn` and `Resume` reopen `login-refused` only; `Requalify` reopens whatever cause it reads.
- **CRED-RS-6** The provagent and egress restart and write-failure tests run on a `journal.Engine` over a `journal.MemStore` (a failing store for the write-failure ones), so they exercise the journal's own semantics.

**Acceptance tests:**
- CRED-RS-4: `broker/journal/routestop_test.go::TestUnswappableOutranksLoginRefused`; `broker/egress/routestop_test.go::TestProxyRaisesALoginRefusedStop`.
- CRED-RS-5: `broker/journal/routestop_test.go::TestReopenComparesTheCause`, `TestReopenRecordsReplayByCause`; `broker/provagent/routestop_test.go::TestSignedInLeavesAnUnswappableStop`; `broker/egress/routestop_test.go::TestProxyStopSurvivesARestart`.
- CRED-RS-6: `broker/provagent/routestop_test.go::TestStoppedRouteSurvivesARestart`, `TestRouteStopWriteFailureFailsClosed`; `broker/egress/routestop_test.go::TestProxyStopSurvivesARestart`, `TestProxyStopWriteFailureFailsClosed`.

## Design

The precedence rule lives in the journal (`outranks`), used live by `StopRoute` and on replay by `applyRouteStop`, so both agree. A cause the journal does not know ranks as unswappable, as `egress.stopReason` already reads one, so an unknown cause fails closed. The reopen note may now carry a cause; the live API requires one, and a cause-less reopen record from #2015 still replays as an unconditional lift, so journals written since #2015 open unchanged and `recordVersion` is not bumped. Both packages' `RouteStops` interfaces and in-memory defaults take the same rules.

Item 4 is not fixed in code. A failed commit breaks the engine (`ErrBroken`) until the broker restarts, so nothing after it is recorded either; the only way to keep that stop durable is a second store beside the journal, which OP-11 forbids, or a write before every run (a login attempt as an intent), which costs a journal write per run for a disk fault. The residual is recorded in journal A24: after a journal write failure and a restart, the route may retry the refused login once, and that refusal is recorded.

## Scope

`broker/journal/routestop.go`, `broker/journal/routestop_test.go`, `broker/journal/check/routestop_test.go` (the reopen call takes a cause), `broker/journal/ASSUMPTIONS.md` (A24), `broker/provagent/run.go`, `broker/provagent/routestop_test.go`, `broker/egress/exchange.go`, `broker/egress/routestop_test.go`, `broker/core/core.txt` (line 116's reason: provagent's reopen lifts only a `login-refused` stop), this brief.

`broker/egress/proxy.go` and `broker/egress/ASSUMPTIONS.md` stay out (PR #2294 touches them, D-111); the proxy's assumption is recorded in the journal's row, as #2015 did.

## Out of scope

Wiring agentos-egress to the journal. `Resume`'s owner check (CH-10). A durable record of a stop the journal could not write (item 4, above).

## Done

CI green; CRED-RS-4..6 covered by passing tests carrying `REQ: CRED-5, OP-11` and their ID.
