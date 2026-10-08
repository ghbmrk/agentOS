# UX review loop

A recurring review of the owner-facing experience (onboarding and everyday use) against the spec. Purely advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

**Scope:** setup, the text/voice channel, approvals and codes, notifications and digests, the local Wi-Fi UI, moving PCs, recovery as the owner experiences it. Security properties are fixed inputs; a UX proposal that touches one states the tradeoff.

**Output of a spec-wide run** (only when Mark or L1 asks for one): `YYYY-MM-DD-ux-review.md` with findings (severity, owner effect, proposal), a decisions list for Mark, and, when warranted, SPEC.md edits in the same PR.

## In the lens screen

Tier A PRs get a UX pass in the lens screen; tier B PRs get UX as part of the combined pass. Each run applies the scope below to the PR's diff. Verdicts go to `reviews/ux/YYYY-MM-DD-pr<N>.md` (combined passes to `reviews/combined/`), in the L3 format of docs/OPERATING.md §4.

## Checks that replaced findings

Finding kinds CI now catches; the screen no longer looks for them by hand (OPERATING §4).

| Finding kind | Check | Since |
|---|---|---|
| — | none recorded yet | — |

## Spec-wide runs

Weekly runs over all of `main` until 2026-10-07, when the batched lens screen replaced them (DECISIONS D-048).

| Run | main at | Review |
|---|---|---|
| 1 | 3176f2d | [2026-10-04](2026-10-04-ux-review.md) |
| 2 | 044b83b | [2026-10-05](2026-10-05-ux-review.md) |
| 3 | be5a80c | [2026-10-08 lens bundle a](2026-10-08-lens-bundle-a.md): #300, #319, #323, #327 |
| 4 | be5a80c | [2026-10-08 lens bundle b](2026-10-08-lens-bundle-b.md): #320, #321, #322, #324, #329 (run 3 is bundle a, #339) |
| 5 | d81a971 (PR head) | [2026-10-08 #386](2026-10-08-lens-386.md) |

## Recurring kinds (to become checks)

- **A problem text names a step that cannot work** (CH-12): UX run 2 (#124, #126, #132, #133) and #327. The next package touching owner texts adds a test that flags it ([2026-10-08](2026-10-08-lens-bundle-a.md#recurring-kind)).
