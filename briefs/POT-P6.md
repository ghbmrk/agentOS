# POT-P6: Class-conditioned transport evidence

**Status:** draft implementation proposal to primary, requested after potency
review #384. This brief does not claim a BOARD row, change a lane, adopt a
decision, or authorize merge. The explicit request to draft implementation PRs
is the scope for this cross-lane proposal.

## Problem and bounded result

`route.Candidate` currently applies aggregate provider/model HTTP reliability
and header latency to every task class, allowing observations from one class to
reorder another. This package proposes orders from transport evidence keyed by
active task class and exact configured provider/model identity. Every route in a
class must have at least 10 attributable transport observations; otherwise its
entire configured order stays unchanged. Equal scores preserve existing order.

This is a transport-evidence correction, not accepted-task optimization. HTTP
success is not goal acceptance; header latency is not total task latency. The
router currently lacks authenticated completed-task outcome, cost attribution,
and qualified model-version inputs. [POT-P6b](POT-P6b.md) carries that follow-up
with the P2/P3 prerequisites. No feedback field or new exploration path is added.

## Scope

- `broker/route/route.go`: class-specific evidence, atomic candidate snapshots,
  active-identity lifecycle, existing aggregate diagnostics compatibility.
- `broker/route/candidate_test.go`, `broker/route/route_test.go`: regression and
  concurrency tests using synthetic in-process and egress fixtures.
- `broker/change/routing_test.go`: existing adoption/rollback composition
  fixtures supplied with enough class evidence, including sparse deferral.
- `broker/route/ASSUMPTIONS.md`, this brief.

No edits to grants, data-label filtering, pricing, budget/usage accounting,
`routerule` serialization, the vault's structural reorder checks, replay,
graders, held-out suites, adoption/rollback policy, BOARD, LATER, DECISIONS, or
SPEC. D-039's model price ceiling and CHG-2's policy authority remain unchanged.

## Requirements and checks

| Requirement | Retained evidence |
|---|---|
| CAP-9 | Opposite classes can propose opposite provider preferences; sparse and unknown classes cannot borrow evidence; route/model replacement invalidates affected evidence. Existing grant, private-data, output cap and meter tests remain required. |
| ADP-4 | Candidate only proposes an exact permutation of active routes, with minimum class evidence and stable ties; active rules change only through existing `SetRule` caller/adoption. Concurrent observations and rule changes retain coherent snapshots. |

Run route tests with the race detector, related change/routerule tests, repository
Python tests, trace check and doclint. Full broker tests need the repository's
Linux environment; record any host limitation rather than claiming a pass.

## Assumptions and gates

The fixed 10-call minimum is a conservative candidate-generation noise guard,
not statistical confidence, task-class qualification, or a change to adoption
policy. Partial coverage deliberately defers the whole class, so a favored
route cannot displace a route that lacks observations. It does not manufacture
observations; bounded permitted replay coverage is future work.

Exact provider/model identity and the router process lifetime are the available
identity boundary. Removed entries cannot resurrect evidence, including when
old calls finish after removal/readdition. Pure ordering changes retain evidence.
A provider silently changing the model behind the same alias cannot be detected
by this interface; authenticated version requalification remains a P6b gate.

Risk tier: A because the required adoption composition fixture lives in
`broker/change/`; the production change pipeline is unchanged. Builder: strongest
available session model. Fresh strongest-model L3 review must include the threat
check: no new routes/grants/data access, only broker-observed transport evidence,
no stale identity resurrection, no guest-driven evidence cardinality, and no
bypass of price ceilings or held-out/security adoption gates.

Before ready: fresh independent L3 review, risk-tier result, all applicable CI,
and primary-team intake. The draft stays unmerged. No measured owner-effort or
accepted-task gain, live model qualification, or hardware result is claimed.

Usage estimate: one bounded builder package plus fresh review; checkpoint at
focused regressions passing, continue only for necessary validation/fixes.
