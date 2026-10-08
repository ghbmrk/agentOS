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
| Lens 2026-10-08a (#300 #319 #323 #327) | be5a80c | [2026-10-08](2026-10-08-lens-bundle-a.md) |
| Lens 2026-10-08b (#320 #322 #324 #329 #321) | be5a80c | [2026-10-08](2026-10-08-lens-bundle-b.md) |
| Lens 2026-10-08d (#362) | 32c6e67 | [2026-10-08](2026-10-08-pr362.md) |
| Lens 2026-10-08 (#363) | b75d319 (re-signed 196e703) | [2026-10-08](2026-10-08-sec-363.md) |
| Lens 2026-10-08f (#372) | 7b753eb | [2026-10-08](../combined/2026-10-08-pr372.md) |
| Lens 2026-10-08e (#378, #379) | 22e4b5f | [#378](2026-10-08-pr378.md), [#379](2026-10-08-pr379.md) |
| Lens 2026-10-08e (#367 at 9bef9df) | 7b753eb | [2026-10-08](2026-10-08-pr367.md) |
| Lens 2026-10-08e (#370 at 5c21fc2) | 7b753eb | [2026-10-08](2026-10-08-pr370.md) |

## Requested architecture reviews

| Run | main at | Review |
|---|---|---|
| SR3: Mark-requested security and architecture review; eight release work items, not an implementation sign-off | 7b753eb | [2026-10-08](2026-10-08-architecture-review.md) |
