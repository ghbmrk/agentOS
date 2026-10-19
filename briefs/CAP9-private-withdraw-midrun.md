# CAP9-private-withdraw-midrun: withdrawing private-data permission stops new requests of an admitted run

Board section: Mark's review findings (2026-10-18). Work item: #2359. **Tier A** (`broker/provagent`, `broker/cmd`, `broker/localui`).

**Why.** `Runner` checks `PrivateOK` once at admission (`broker/provagent/run.go:324-394`, check at :327). The worker route (`broker/cmd/agentos-egress/workerroute.go:477-503`) carries no private-data binding, and withdrawal (`localui/providers.go:88-111`, `agentos-egress/privatechange.go:39-62`) only deletes the marker. Failure path: the owner withdraws permission; an already admitted ChatGPT-plan Codex run with a Private label keeps sending new content requests until it ends (up to 30 minutes).

**Requirements:**
- CAP9-W1: the run's privacy label is bound to the worker route when it is opened.
- CAP9-W2: before forwarding each new content request, the route rechecks the provider's private-data permission and refuses the request once it is gone.
- CAP9-W3: public runs and sign-in traffic on the route are unaffected.

**Acceptance tests:** (REQ: CAP9-W1..W3)
- `broker/cmd/agentos-egress/workerroute_private_test.go::TestWithdrawBeforeFirstContentRequestRefuses` (W2; mutant: check only at open).
- `::TestWithdrawBetweenTwoRequestsRefusesTheSecond` (W2; the first goes, the second is refused).
- `::TestPublicRunAndSignInUnaffectedByWithdraw` (W3).
- `broker/provagent/run_test.go::TestAdmissionBindsPrivateLabelToRoute` (W1; mutant: bind nothing).

**Out of scope.** Requests already dispatched before the withdrawal (the private brief was sent at admission; the 30-minute cap bounds the run).

**Scope:** `broker/cmd/agentos-egress/workerroute.go`, `privatechange.go`, their tests, `broker/provagent/run.go` and its test for the binding, this brief.

**Usage estimate:** 80k tokens; checkpoint at 60k.
