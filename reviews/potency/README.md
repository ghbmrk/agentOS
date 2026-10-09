# Potency review loop

A recurring review of what AgentOS can do for its owner: leverage, reach, autonomy, parallelism, and compounding, measured against the spec's north star (owner-minutes per accepted task, §1). Purely advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

**One of three lenses.** Security, potency, and UX each run their own loop; an arbitrator loop reconciles them toward win-win-win. So every proposal here states its **cost to security** and its **cost to UX**, and flags where the lenses conflict. A proposal that weakens an invariant (Invariant C, REV-2, ARC-1/2, DEP-2) is not made; it is listed under "considered, not proposed" with the reason.

**Question asked each run:** where does the spec cap capability without buying matching security or UX, and what is the cheapest structural change that lifts the cap?

**Output of a spec-wide run** (only when Mark or L1 asks for one): `YYYY-MM-DD-potency-review.md` with findings (potency gain, security cost, UX cost, proposal), decisions for Mark, and, when warranted, SPEC.md edits in the same PR.

## In the lens screen

Tier A PRs get a Potency pass in the lens screen; tier B PRs get Potency as part of the combined pass. Each run asks the question below of the PR's diff. Verdicts go to `reviews/potency/YYYY-MM-DD-pr<N>.md` (combined passes to `reviews/combined/`), in the L3 format of docs/OPERATING.md §4.

## Checks that replaced findings

Finding kinds CI now catches; the screen no longer looks for them by hand (OPERATING §4).

| Finding kind | Check | Since |
|---|---|---|
| — | none recorded yet | — |

## Spec-wide runs

Weekly runs over all of `main` until 2026-10-07, when the batched lens screen replaced them (DECISIONS D-048).

| Run | main at | Review |
|---|---|---|
| 1 | e841b78 | [2026-10-04](2026-10-04-potency-review.md) |
| 2 | f797b7d | [2026-10-05](2026-10-05-potency-review.md) (spec edits committed after Mark's yes) |

## Records

Per-PR and per-bundle records are the files `YYYY-MM-DD-*.md` in this directory (tier-B combined passes are in `../combined/`), in filename order, so there is no run number to pick. Each opens with a `Record:` line giving PR, package and head SHA; `tools/doclint.py` checks it on files dated 2026-10-09 or later. No run rows are appended to this README, so open PRs do not conflict on it; recurring kinds and the checks that replaced them still are (DOC-4, docs/OPERATING.md §4).

## Recurring kinds (to become checks)

| Kind | Seen on | Check to add | Owner package |
|---|---|---|---|
| A defence can be reverted and the suite still passes (a surviving mutant) | #583 (LATER P3-4b-4c-canary l3), #585 (P3-4b-3r-pass l5, l6), #588 (BOARD P3-4b-3r-confine-r5), #589 (P3-4b-4c-corpus l6), #599 (P3-4b-4c-exhaust l4, l5) | each package's brief names the revert mutant for every defence it adds; the L3 reruns it and rejects a defence whose revert still passes | the next package that adds a defence in `loops`, `loop7`, `machprobe` or `canary` |
| A brief's declared scope omits the test files the change forces | #589 (LATER P3-4b-4c-corpus l5, l7), #585 | `tools/doclint.py` compares a brief's declared scope with the PR's changed test files and flags a test file outside it | the next package that touches `tools/doclint.py` or the brief template |
