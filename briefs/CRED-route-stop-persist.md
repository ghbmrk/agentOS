# CRED-route-stop-persist: a stopped route stays stopped across a restart

Board row: #1926 (state-machine audit 2026-10-16). Tier A (credentialed sessions). Sequenced after #1925 (PR #2001, merged at 303a820). Builder: strongest model. Usage estimate: ~120k tokens, checkpoint at 100k.

## Failure path (verified on main at 303a820)

`provagent.Runner.stopped` (agentosd's live stop, set when a run ends on a refused login) and `egress.Proxy.stops` (CRED-5t triggers a and b) are maps in memory, kept in step only by caller convention. A broker restart empties both, so a route the provider refused the login on runs again without the owner signing in (CRED-5: no retry, since retries can worsen a restriction), and an unswappable route reopens without a release requalifying it (CRED-5t).

## Requirements (from SPEC.md)

- **CRED-5**: a refused login stops the route; no retry until the owner signs in again or resumes.
- **CRED-5t**: an unswappable exchange stops the route until a release requalifies the declaration.
- **OP-11**: the journal is the one durable store; no component keeps its own durable lifecycle beside it, and replay rebuilds any state such as "stopped".

Package IDs:
- **CRED-RS-1** A route stop and its reopening are journal records (`route_stop`); replay rebuilds which routes are stopped and why, so an engine reopened from the same store still holds the stop. Stopping a stopped route or reopening an open one writes nothing.
- **CRED-RS-2** `provagent.Runner` keeps its stops in that store (`Runner.Stops`; agentosd wires the journal). A new Runner over the same store refuses the stopped provider's runs and tells the owner once more; `SignedIn` reopens only a refused-login stop, and a failed write keeps the route stopped.
- **CRED-RS-3** `egress.Proxy` keeps its stops in the same store shape (`Config.Stops`), so on one journal the two are one projection. `Resume` still refuses an unswappable stop (`ErrRequalify`); `Requalify`, for the release, lifts it; a failed write keeps the route stopped.

**Acceptance tests:**
- CRED-RS-1: `broker/journal/routestop_test.go::TestRouteStopSurvivesReopen`, `TestRouteStopRefusesBadNotes`.
- CRED-RS-2: `broker/provagent/routestop_test.go::TestStoppedRouteSurvivesARestart`, `TestSignedInLeavesAnUnswappableStop`, `TestRouteStopWriteFailureFailsClosed`.
- CRED-RS-3: `broker/egress/routestop_test.go::TestProxyStopSurvivesARestart`, `TestProxyStopWriteFailureFailsClosed`.

## Design

A note record like `sleep` and `egress` (`RecRouteStop`, `RouteStopNote{Route, Event, Cause}`, all identifier-like codes), with a projection on the Engine (`routeStops`) that `apply` updates, so replay rebuilds it. The Engine offers `StopRoute`, `ReopenRoute` and `RouteStopped`; provagent and egress each declare that interface on their side and keep an in-memory default for a caller with no journal (agentos-egress today, which runs no stop hook). The journal's lifecycle intents (`lifecycle.go`) were not reused: a route stop is an observation the broker records, not an effect it dispatches and could undo.

## Scope

`broker/journal/routestop.go` (new), `broker/journal/store.go`, `broker/journal/engine.go`, `broker/journal/routestop_test.go` (new), `broker/journal/ASSUMPTIONS.md`, `broker/provagent/run.go`, `broker/provagent/routestop_test.go` (new), `broker/provagent/signin_test.go` (two checks read the stop through `Stops`), `broker/egress/exchange.go`, `broker/egress/proxy.go`, `broker/egress/routestop_test.go` (new), `broker/egress/ASSUMPTIONS.md`, `broker/cmd/agentosd/main.go` (one wiring line), this brief.

The scope is wider than the row's three files because OP-11 allows no durable store beside the journal, so the stop has to be a journal record. `broker/provagent/ASSUMPTIONS.md` stays out (#1951 touches it, D-111); the Runner's assumption is recorded in the journal's row.

## Out of scope

`broker/provagent/declare.go` (#1951). `broker/holder/` (frozen; #2009). Wiring the proxy in agentos-egress to the journal (it has none, and builds no `RouteFailed` today). `Resume`'s owner check (its caller, CH-10).

## Done

CI green; CRED-RS-1..3 covered by passing tests carrying `REQ: CRED-5, OP-11` and their ID (CRED-5t is the code base's name for CRED-5's unswappable-exchange clause, not a SPEC ID).
