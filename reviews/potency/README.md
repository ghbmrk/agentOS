# Potency review loop

A recurring review of what AgentOS can do for its owner: leverage, reach, autonomy, parallelism, and compounding, measured against the spec's north star (owner-minutes per accepted task, §1). Purely advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

**One of three lenses.** Security, potency, and UX each run their own loop; an arbitrator loop reconciles them toward win-win-win. So every proposal here states its **cost to security** and its **cost to UX**, and flags where the lenses conflict. A proposal that weakens an invariant (Invariant C, REV-2, ARC-1/2, DEP-2) is not made; it is listed under "considered, not proposed" with the reason.

**Cadence:** weekly. Each run reads what changed on `main` since the last reviewed commit (SPEC.md, spike results, merged PRs), and stays quiet when nothing potency-relevant changed.

**Question asked each run:** where does the spec cap capability without buying matching security or UX, and what is the cheapest structural change that lifts the cap?

**Output per run:** `YYYY-MM-DD-potency-review.md` with findings (potency gain, security cost, UX cost, proposal), decisions for Mark, and, when warranted, SPEC.md edits in the same PR.

## Last reviewed

| Run | main at | Review |
|---|---|---|
| 1 | e841b78 | [2026-10-04](2026-10-04-potency-review.md) |
| 2 | f797b7d | [2026-10-05](2026-10-05-potency-review.md) (spec edits proposed as text, awaiting Mark's yes) |
