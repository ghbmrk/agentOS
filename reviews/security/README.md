# Security review loop

A recurring adversarial review of the spec, spike results, and (once it exists) the code. Advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

It is one of three lenses (security, potency, UX). An arbitrator loop weighs their proposals against each other, so **every proposal states its cost to UX and to potency**.

**Cadence:** weekly. Each run reads what changed on `main` since the last reviewed commit (SPEC.md, merged PRs, spike results, code) and stays quiet when nothing security-relevant changed.

**Method:** a fixed threat model (assets and adversaries, see run 1) applied to each change: follow every path from each adversary to each asset, and record whether a requirement stops it structurally, only procedurally, or not at all. Security-critical code paths (broker, vault, executors, clean room, update signing) get an explicit threat check (CLAUDE.md).

**Output per run:** `YYYY-MM-DD-security-review.md` with findings (severity, adversary, proposal, UX cost, potency cost), a decisions list, and, when warranted, SPEC.md edits in the same PR.

## Last reviewed

| Run | main at | Review |
|---|---|---|
| 1 | e841b78 | [2026-10-04](2026-10-04-security-review.md) |
| 2 | 76ac0b9 | [2026-10-05](2026-10-05-security-review.md) |
