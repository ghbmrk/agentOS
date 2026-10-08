# POT-P3 — Broker-observed replay results (draft)

Explicitly requested draft implementation proposal after potency review #384.
This is submitted to primary for review; it does not claim a lane assignment,
adopted design decision, release qualification, or permission to activate a new
grader. CHG-2 owner approval and independent tier-A L3/threat review remain gates.

## Scope and contract

Paths: `broker/change/{results*,pipeline.go,suite.go,ASSUMPTIONS.md}`,
`broker/replay/{recorded*,replay*,ASSUMPTIONS.md}`,
`broker/loops/{harvest.go,result_test.go,ASSUMPTIONS.md}`,
`broker/cmd/agentosd/{tasks*,learn*,ASSUMPTIONS.md}`, and this brief.

Requirements: CHG-1 (hidden broker expectations and held-out gates), CHG-2
(trusted, versioned grader), LOOP-5 (recordings only; unrecorded effects fail),
OP-7 (permission, execution and quality remain distinct). D-039 forbids a model
judge and live effects in replay.

Implement one versioned `mail.send` contract. An accepted case requires exactly
one broker-observed matching effect ending in `succeeded`. A rejected case can
establish only refusal of that effect: no effect request was attempted. Neither
display prose nor a guest-authored result envelope is evidence. Extra effects,
unknown/failed states, unsupported formats and legacy task evidence fail closed.
Security fixtures retain their existing evaluator/grader path. Cache identity
changes so old verdicts cannot be resumed as observed-effect evidence.

Production harvesting uses the original broker-bound intent fingerprint and
checks the journal's terminal state before adding a case. The daemon requires
observed task evidence. Existing unversioned task cases are retained but fail;
they are not migrated or reclassified. Other mail operations and artifact
quality have no contract in this slice. This may reduce usable suite coverage
and must be reviewed with the held-out gate counts before activation.

## Validation and remaining gates

Tests first: natural-language completion with the right effect; no effect;
wrong account, parameters and recipients; duplicates; extra effects; rejected
effect with changed wording; failed/unknown state; forged envelopes; legacy
and unsupported cases; ordinary security grading. Validate production wiring,
harvesting, cache identity and no new replay effect authority.

This draft does not qualify a whole workflow or demonstrate owner benefit.
POT-P3b covers authenticated feedback revisions, stale expectation invalidation,
and further result classes. Pre-redaction keyed matching/read cassettes remain
separate work: redacted recordings can refuse matching and reduce coverage.
Linux replay/daemon execution, assembled W3/W7-A qualification, CHG-2 approval,
and matched workload trials remain required. Exact test results are recorded
in the PR/handoff; a cross-compile is not a runtime test.
