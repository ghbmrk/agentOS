# SR3: Register the 2026-10-08 security and architecture review

**Owner:** primary coordinator for acceptance; Codex prepares the proposed intake at Mark's explicit request.
**Class:** release intake. **Risk tier:** C (documentation only).
**Needs:** DOC-3 (merged).

## Scope

BOARD.md, LATER.md, briefs/SR3.md, briefs/SR3-1.md through briefs/SR3-8.md, reviews/security/README.md, and reviews/security/2026-10-08-architecture-review.md. Register the findings; do not implement fixes, change SPEC.md, reassign another team's lane, or mark remediation complete.

Mark explicitly requested the review findings become repository work items. This is a proposed cross-lane documentation PR to primary under AGENTS.md item 5. It grants no ongoing Codex implementation lane; future builders must follow docs/LANES.md and claim the relevant row.

## Acceptance

1. All eight findings have a queued BOARD row, a release classification in LATER.md, and a self-contained brief with source evidence, exposure/confidence, primary ownership, scope, coordination, requirements and testable acceptance criteria.
2. The review record maps F1–F8 to SR3-1–SR3-8 and states the audited commit. Reproduced findings remain distinguishable from source-only findings, and related existing work is linked rather than silently duplicated.
3. All added links resolve; doclint, trace check and applicable documentation tests pass. Attempt the required repository suite and report platform limitations honestly.
4. A fresh L3 review accepts the documentation diff before readiness; only the primary coordinator merges. Implementation findings remain open after this intake merges.

No new requirement coverage or runtime safety guarantee is claimed by this package. The remediation briefs name the future tests and tier-A review gates.

## Reuse and estimate

Reuse existing BOARD/brief/LATER/review conventions. Initial documentation checkpoint: 10k tokens, not a ceiling. Builder: Codex using the available strongest model; the repository pilot's Sonnet 5.5 is not available in this session. Preserve existing coordinator work and report this routing exception in the PR.
