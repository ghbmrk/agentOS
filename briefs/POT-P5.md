# POT-P5: Bounded evidence cohorts for templated approval suggestions

**Status:** Draft cross-lane proposal to primary, explicitly requested by Mark after potency review #384. This is not a lane assignment, BOARD claim, or adopted design; keep the PR draft and unmerged pending primary review.

**Problem:** One changed template currently makes an account/action permanently ineligible for an ADP-9 suggestion. The A10 split also labels the first different template avoidable using evidence from the preceding template.

**Requirement IDs:** CAP-6, ADP-9, ADP-11, A10, CH-12, CH-15.

**Scope:** `broker/attention/` and this brief. Reuse the existing proposer, verified-decision contract, fixed-parameter extraction, deterministic rule renderer, Store, and short-ID allocator. No grants gate, owner UI, dispatch, BOARD, LATER, DECISIONS, or SPEC changes.

**Proposed behavior:** Group verified ADP-9 approvals by canonical verb and fixed string parameters beneath the account/action. Each cohort independently earns ten unchanged approvals. Preserve reply thresholds and edit-rate evidence without introducing reply cohorts. NO, UNDO, wrong verdicts, and strict edits conservatively reset all cohorts for the account/action, even when unverified or describing another shape. Keep user-content and CRED-6 exclusions, recipient/amount bounds, median daily caps, and money edit holds. Returned rules are detached drafts; no acceptance or grant API is added.

**Bounds and compatibility:** At most eight cohorts per account/action and 256 account/action classes; full live sets refuse new shapes, without evicting earned evidence. Templated evidence expires after 90 days; daily-count storage is bounded. Preserve valid homogeneous legacy evidence, discard mixed evidence, invalidate legacy suggestion IDs, and reject unsupported/corrupt versions. Pace digest offers to at most one per account per week across actions/cohorts. A declined suggestion conservatively suppresses the whole account/action and each cohort must re-earn twice its threshold, including new shapes.

**Gates:** First reproduce mixed alternating templates, a single outlier, incorrect A10 attribution, account offer flooding, and mutable returned evidence against unchanged code. Then require those tests plus negative-evidence isolation, unchanged ADP-11 light edits, canonical-key distinctions, bounded exhaustion, migration/reload, stale ID rejection, account pacing, and existing exclusions to pass. Run attention tests with the race detector, repository Python/trace/doclint checks, and relevant grant tests. Fresh independent L3/threat review is required before readiness. W7 integration and gate enforcement remain prerequisites to live owner value; this package makes no end-to-end A10 gain claim.

**Estimate:** One bounded proposer change plus review; no new service or inference component. Builder: Codex GPT-6. Draft requires primary review of the proposed limits and migration policy.
