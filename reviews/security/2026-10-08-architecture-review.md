# Security and architecture review — 2026-10-08

Requested by Mark; conducted against main `7b753eb87f606ea2268ca536d429d47989dba196`. This is a findings and intake record, not an implementation acceptance or tier-A lens sign-off. [SR3](../../briefs/SR3.md) covers registration only.

The review examined owner authentication/approvals, effect accounting, model routing, update verification/finalization, mail identity and clean-room persistence. Six findings used synthetic local probes; two are source-only. No live provider billing, production mailbox mutation, hardware boot or power-cut qualification was performed. Local proofs used real package code with synthetic adapters/clocks/keys; the local-session probe called handlers directly and did not exercise Linux socket peer credentials. Those limits are preserved in the briefs.

## Work items

Priority is scheduling guidance; every item is **release**, not later. Primary owns all affected paths under docs/LANES.md. Start with SR3-1; follow with the live routing/accounting/approval boundaries. The update, mail and clean-room items are release conditions before their pending integration. Builders should inspect related PRs again when claiming; an overlapping title is not evidence of resolution.

| Finding | Work item | Priority | Evidence | Release acceptance |
|---|---|---|---|---|
| [F1](#f1) | [SR3-1: Bind local sign-in to the authenticated lock generation](../../briefs/SR3-1.md) | P1 | Synthetic local reproduction | A4, A6, A14 |
| [F2](#f2) | [SR3-2: Enforce pre-allowance rate limits at dispatch](../../briefs/SR3-2.md) | P2 | Synthetic local reproduction | A4, A13 |
| [F3](#f3) | [SR3-3: Show and bind the complete pre-allowance rule at approval](../../briefs/SR3-3.md) | P2 | Synthetic local reproduction | A13, A14 |
| [F4](#f4) | [SR3-4: Make update finalization durable and idempotent](../../briefs/SR3-4.md) | P2 | Synthetic local reproduction | A7 |
| [F5](#f5) | [SR3-5: Preserve IMAP message identity through mutations and undo](../../briefs/SR3-5.md) | P2 | Synthetic local reproduction | A4, A13, A15 |
| [F6](#f6) | [SR3-6: Invalidate verified updates when attestation policy narrows](../../briefs/SR3-6.md) | P2 | Synthetic local reproduction | A7, A14 |
| [F7](#f7) | [SR3-7: Use one validated request for model reservation and routing](../../briefs/SR3-7.md) | P2 | Source-only; confirm by regression | A4 |
| [F8](#f8) | [SR3-8: Commit clean-room output durably before recording completion](../../briefs/SR3-8.md) | P2 | Source-only; confirm by regression | A12 |

## F1

A sign-in can survive the security reset that should invalidate it. The [SR3-1 brief](../../briefs/SR3-1.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F2

Daily pre-allowance limits count authorization time, allowing a later burst. The [SR3-2 brief](../../briefs/SR3-2.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F3

A grant approval card omits the authority it grants. The [SR3-3 brief](../../briefs/SR3-3.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F4

A successful update can become permanently stuck during finalization. The [SR3-4 brief](../../briefs/SR3-4.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F5

Mail mutations lose message identity across an IMAP mailbox reset. The [SR3-5 brief](../../briefs/SR3-5.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F6

A verified release retains an interim trust exception after that exception ends. The [SR3-6 brief](../../briefs/SR3-6.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F7

The model meter and router interpret request fields differently. The [SR3-7 brief](../../briefs/SR3-7.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## F8

Clean-room completion can become durable before its output files. The [SR3-8 brief](../../briefs/SR3-8.md) is the canonical home for the finding's evidence, source anchors, proposed resolution, acceptance tests, scope and UX/potency cost.

## Relationship to existing work

The intake checked main's BOARD/LATER and both pages of open PRs on 2026-10-08. SR3-1 coordinates with W5-D14 [#280](https://github.com/ghbmrk/agentOS/pull/280); SR3-3 is distinct from OSS-10w2 [#370](https://github.com/ghbmrk/agentOS/pull/370); SR3-4/SR3-6 precede release reliance on W5b/P2-1, and SR3-8 precedes W5c. Mail assumption M9 accepts a same-message flag race, not the mailbox-epoch identity change in SR3-5.

Existing image/hardware qualification, worker credential custody, browser/desktop work, TPM binding and update-time floors remain in their current work streams. This intake adds no duplicate catch-all packages for those known gaps. Concurrent BOARD synchronization [#377](https://github.com/ghbmrk/agentOS/pull/377) should preserve these new rows if merged first or rebased.

## Evidence and closure

Briefs contain the observed outcomes and deterministic regression recipes, so future builders do not need access to the originating chat or local artifact paths. The original review's machine-local probe bundle is supplementary and is not checked in or counted as repository test coverage. Implementation must add retained failing-then-passing tests and cite their results.

The common architectural concern is stale authority or identity crossing a boundary: authentication generation, dispatch window, displayed consent, durable settlement, mailbox epoch and trust-policy version. Repairs should establish the invariant at the final effect boundary and include restart/concurrency cases. This is design guidance; each brief bounds its own work, and SPEC.md remains authoritative.

The documentation PR records validation and the independent L3 verdict. Merging SR3 registers work; it does not resolve SR3-1 through SR3-8.
