# POT-P3 — Broker-observed replay results (draft)

Explicitly requested draft implementation proposal after potency review #384.
This is submitted to primary for review; it does not claim a lane assignment,
adopted design decision, release qualification, or permission to activate a new
grader. CHG-2 owner approval and independent tier-A L3/threat review remain gates.

**Merge/activation blocked:** the default daemon redacts all journal free text,
including `mail.send` subject/body/recipients. This draft deliberately withholds
those snapshots, so the default production configuration currently produces
**no usable new `mail.send` cases**. A separately reviewed broker-keyed capture
and recording path (POT-P3a) must pass before activation. Synthetic tests prove this
protocol, not live learning utility; no redaction or logging is loosened here.

## Scope and contract

Paths: `broker/change/{results*,pipeline.go,suite.go,ASSUMPTIONS.md}`,
`broker/replay/{recorded*,replay*,ASSUMPTIONS.md}`,
`broker/loops/{harvest.go,result_test.go,ASSUMPTIONS.md}`,
`broker/guest/{plane.go,mcp.go,ASSUMPTIONS.md}`,
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
An optional trusted MCP observer starts at the authenticated HTTP handler
before request-slot admission or escaped-path refusal. It records effect refusals before `Submit`,
including malformed arguments, broker-state requests, and rate limits.
Unclassified or effect requests still in flight at completion fail closed.
Known reads/lookups and tool fallbacks stop being observed before their
handlers run. The hook carries only socket-bound machine identity and a
broker-classified refusal flag, and changes no live response or authority.
Security fixtures retain their existing evaluator/grader path. Cache identity
changes so old verdicts cannot be resumed as observed-effect evidence.

Production harvesting uses a broker-bound intent fingerprint only when its
snapshot contains no known redaction marker, and
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
harvesting, cache identity and no new replay effect authority. Actual MCP
regressions cover early-refused requests, rate limits, idempotency, ordinary
read/fallback refusals, per-socket identity despite forged identity fields,
owner reply ordering, an effect handler blocked during completion, and eight
owner long polls saturating MaxConns before a refused effect and owner reply.

This draft does not qualify a whole workflow or demonstrate owner benefit.
POT-P3b covers authenticated feedback revisions, stale expectation invalidation,
and further result classes. POT-P3a is the separate keyed capture prerequisite.
It must bind original
effect identity before redaction without storing raw secret-bearing values,
survive restart, preserve FORGET/deletion reach, reject placeholder guesses and
cross-task/account replays, and demonstrate at least one real assembled
accepted `mail.send` case. Read cassettes remain separate work. Accepted outcome
callbacks already wait for dispatch settlement (`grants.reportSent`/`endHeld`);
`outcome_unknown` is explicitly withheld rather than credited as success.
Linux replay/daemon execution, assembled W3/W7-A qualification, CHG-2 approval,
and matched workload trials remain required. Exact test results are recorded
in the PR/handoff; a cross-compile is not a runtime test.
