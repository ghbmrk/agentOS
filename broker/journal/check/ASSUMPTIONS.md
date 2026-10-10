# Journal check: assumptions

Built for SIM-check (briefs/SIM.md) on the P1-1 journal. Each row is a reading
of the brief or the spec that a reviewer may want to change.

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| K1 | A grant is "valid at dispatch" when the intent's authorization stands (no later `denied`, `recheck_failed` or `erased`), no STOP is in force unless the intent is narrowing, and no `meta.grant.revoke` intent naming the same `GrantRef` was observed `succeeded` earlier in the journal. Grant IDs are never reused. | OP-3, A9 | SIM-cap's per-intent grants make the grant a journal fact; the predicate then reads it directly. |
| K2 | Pausing a grant, and a grant's expiry, are not visible here: a pause intent carries the grant in `GrantRef`, but resuming goes through `meta.grant` params, so a pause cannot be closed from the journal alone. Only revocation, which is final, is checked. | OP-3 | SIM-cap. |
| K3 | "Settled or explicitly uncertain" is judged at rest: once Open has written its restart records, every attempt has an observation; a running broker (`Live`) may have attempts in flight. `unknown` may follow only `in_flight`; `succeeded` and `not_applied` are final; a new attempt starts only after the last was `not_applied`. | OP-4 | — |
| K4 | Erased content is what the engine strips (`carries`): submission params and preconditions, observation and cancel evidence. Quality notes are not content (LATER SIM-check l1). Views are anything that can show an intent; the engine's own status is the one wired in. SIM-proj adds its projections as views. | CAP-3 | Add a view per projection. |
| K5 | The predicates walk the whole trail on each call, so the STATUS note costs a full pass per STATUS. The trail is in memory already; SIM-bound and SIM-proj can make it incremental. | — | SIM-bound. |
| K6 | The brief's goal also names fuzz "Cleared" trusting the target's PASS lines; its Change list does not, so that part is left to a later row (LATER SIM-check l3). | — | — |
| K7 | Each rule judges only records OP-5 accepts as belonging to a submitted intent, so one malformed record breaks one rule, and the mutant test can show each rule is needed. | OP-5 | — |
