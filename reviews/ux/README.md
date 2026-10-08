# UX review loop

A recurring review of the owner-facing experience (onboarding and everyday use) against the spec. Purely advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

**Cadence:** weekly. Each run reads what changed on `main` since the last reviewed commit (SPEC.md and merged PRs), and stays quiet when nothing UX-relevant changed.

**Scope:** setup, the text/voice channel, approvals and codes, notifications and digests, the local Wi-Fi UI, moving PCs, recovery as the owner experiences it. Security properties are fixed inputs; a UX proposal that touches one states the tradeoff.

**Output per run:** `YYYY-MM-DD-ux-review.md` with findings (severity, owner effect, proposal), a decisions list for Mark, and, when warranted, SPEC.md edits in the same PR.

## Last reviewed

| Run | main at | Review |
|---|---|---|
| 1 | 3176f2d | [2026-10-04](2026-10-04-ux-review.md) |
| 2 | 044b83b | [2026-10-05](2026-10-05-ux-review.md) |
| 3 | be5a80c | [2026-10-08 lens bundle a](2026-10-08-lens-bundle-a.md): #300, #319, #323, #327 |

## Recurring kinds (to become checks)

- **A problem text names a step that cannot work** (CH-12): UX run 2 (#124, #126, #132, #133) and #327. The next package touching owner texts adds a test that flags it ([2026-10-08](2026-10-08-lens-bundle-a.md#recurring-kind)).
