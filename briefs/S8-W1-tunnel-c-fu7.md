# S8-W1-tunnel-c-fu7: one provider worker cannot hold every route call

Board row: issue #1857. Source: PR #1850 delta reviews (Security 6196526329; Potency/UX/L3 6196542425). Class: release. Tier: A (`broker/cmd`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (facts, verified at main f96c6dc).** `broker/cmd/agentos-egress/workerroute.go`: each worker's route socket accepts `routeConns` (8) connections and the process admits `routeCalls` (8) calls across every worker, so one worker alone can hold every call. `newServer` sets no write timeout, so a worker that opens streaming calls and stops reading keeps its slots indefinitely, and every other provider worker gets 503. It fails closed (no credential crosses workers, no memory grows), but it is a cross-worker denial of service.

## Requirement (from SPEC.md and egress ASSUMPTIONS)

- **CRED-5** (SPEC.md:272) with egress assumption K28 (route bounds): each plan worker is served its own route; one worker's route must not deny the others.

Package IDs:
- **WROUTE-SHARE-1** One worker's route holds at most `routeShare` calls, below `routeCalls`. A call past the worker's share is refused with 503 before its body is read and before it takes a process slot; another worker's call still succeeds.
- **WROUTE-SHARE-2** Every reply write on a route carries a write deadline renewed per write and flush (`routeWriteTimeout`). A worker that stops reading its stream has the call cut at the deadline, and its process slot is freed so another worker gets through.

**Acceptance tests:**
- WROUTE-SHARE-1: `TestCRED5OneWorkerCannotHoldEveryRouteCall` (`broker/cmd/agentos-egress/workerroute_test.go`).
- WROUTE-SHARE-2: `TestCRED5StalledResponseFreesItsRouteCall` (same file).

## Design (recommendation)

A per-route share channel (`routeShare = routeCalls / 2`) checked before the process-wide channel in `bounded`, so a refused call costs no process slot. A `deadlineWriter` wraps the route's `ResponseWriter` and calls `http.ResponseController.SetWriteDeadline` before each `WriteHeader`, `Write` and `Flush`, and once after the handler returns for net/http's final flush; it implements `http.Flusher` because `egress.workerRoute` asserts it. Chosen over `http.Server.WriteTimeout`, which bounds the whole response and would cut long legitimate streams. `routeCalls` stays 8, so `tests/test_egress_memory.py` is unchanged.

## Scope

`broker/cmd/agentos-egress/workerroute.go`, `broker/cmd/agentos-egress/workerroute_test.go`, `broker/egress/ASSUMPTIONS.md` (K28 bounds sentence), `briefs/S8-W1-tunnel-c-fu7.md`.

## Out of scope

The /seed 409 (#1858). A cap per lineage (#1878). Two compromised workers together can still hold every call (two shares); the write deadline bounds a stall, not a reader that drains at the provider's pace.

## Done

CI green; WROUTE-SHARE-1 and -2 covered by the acceptance tests, which carry `REQ: CRED-5`.
