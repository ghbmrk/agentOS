# Security review loop

A recurring adversarial review of the spec, spike results, and (once it exists) the code. Advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

It is one of three lenses (security, potency, UX). An arbitrator loop weighs their proposals against each other, so **every proposal states its cost to UX and to potency**.

**Method:** a fixed threat model (assets and adversaries, see run 1) applied to each change: follow every path from each adversary to each asset, and record whether a requirement stops it structurally, only procedurally, or not at all. Security-critical code paths (broker, vault, executors, clean room, update signing) get an explicit threat check (CLAUDE.md).

**Output of a spec-wide run** (only when Mark or L1 asks for one): `YYYY-MM-DD-security-review.md` with findings (severity, adversary, proposal, UX cost, potency cost), a decisions list, and, when warranted, SPEC.md edits in the same PR.

## In the lens screen

Tier A PRs get a Security section in its own fresh session on the strongest model; tier B PRs get Security as part of the combined pass. Each run applies the method below to the PR's diff, not to all of `main`. Verdicts go to `reviews/security/YYYY-MM-DD-pr<N>.md` (combined passes to `reviews/combined/`), in the L3 format of docs/OPERATING.md §4. A later delta on a signed tier-A PR needs a re-sign by the mechanical rule in OPERATING §3.

## Checks that replaced findings

Finding kinds CI now catches; the screen no longer looks for them by hand (OPERATING §4).

| Finding kind | Check | Since |
|---|---|---|
| — | none recorded yet | — |

## Spec-wide runs

Weekly runs over all of `main` until 2026-10-07, when the batched lens screen replaced them (DECISIONS D-048).

| Run | main at | Review |
|---|---|---|
| 1 | e841b78 | [2026-10-04](2026-10-04-security-review.md) |
| 2 | 76ac0b9 | [2026-10-05](2026-10-05-security-review.md) |

## Records

Per-PR and per-bundle records are the files `YYYY-MM-DD-*.md` in this directory (tier-B combined passes are in `../combined/`), in filename order, so there is no run number to pick. Each opens with a `Record:` line giving PR, package and head SHA; `tools/doclint.py` checks it on files dated 2026-10-09 or later. No run rows are appended to this README, so open PRs do not conflict on it; recurring kinds and the checks that replaced them still are (DOC-4, docs/OPERATING.md §4).

## Recurring kinds (to become checks)

None yet.
