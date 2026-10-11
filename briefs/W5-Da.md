# W5-Da: Digest delivery contract and durable digest queue

Board section: Integration: wiring merged packages into the box.

**Source drafts:** W5-D1 [#263](https://github.com/ghbmrk/agentOS/pull/263) (contract), W5-D2 [#266](https://github.com/ghbmrk/agentOS/pull/266) (queue), W5-D3 [#267](https://github.com/ghbmrk/agentOS/pull/267) (collector). First slice of the W5-D stack (#263→#435), which is not merged as a stack: it forks 0c97632, conflicts with main in four files and wires nothing into production.

First slice of W5 (release: A11, A15). Specify crash-safe digest snapshots and acknowledgment semantics, then a new `broker/digestqueue` package: bounded persisted batches, acknowledgment, recovery of a send whose outcome is unknown, and recovery of durable source acknowledgments before a fresh collection.

**Requirements:** OP-1, OP-2 (markers in the draft); CH-15 pacing is consumed, not changed.

**Scope:** `docs/learning/digest-delivery-contract.md`, `broker/digestqueue/` (`queue.go`, `collector.go`, tests, `ASSUMPTIONS.md`, `COLLECTION.md`). No change to owner, grants, daemon or change in this slice; wiring is W5-Db/W5-Dc.

**Acceptance:** each contract clause has a named passing test (crash between persist and send, unknown send, duplicate ack, bound reached); race detector on Linux. Keep within ~2k lines; split queue and collector into two PRs if review would exceed the 150k session budget.

**Needs:** W3

## Delivery

Builder model: Sonnet (risk tier B; PILOT-S). Write or keep the failing test first, then the smallest change; one package per session. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR; if it prints a higher tier than B, stop and hand off. Estimate/checkpoint: 40k tokens, not a ceiling (OPERATING §5). Start from current main, not the draft's base: reuse the draft's diff where it still applies and credit the PR in the body; leave the draft open (Mark, 2026-10-09).
