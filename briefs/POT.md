# POT: Implement the 2026-10-08 potency review in bounded slices

**Owner:** primary coordinator; Codex prepares draft proposals at Mark's explicit request, “Draft PRs to implement.” **Class:** release intake. **Risk:** C for this planning change; implementation tiers are listed below.

**Evidence:** [independent potency review, PR #384](https://github.com/ghbmrk/agentOS/pull/384), reviewed main `7b753eb87f606ea2268ca536d429d47989dba196`. This intake was prepared on `16c82cc55afdea8f8622d0e404c80e8bdc5620dd`. Recheck main and related PRs before each implementation. Source findings establish constraints, not measured owner benefit.

## Scope and coordination

This PR adds BOARD/LATER entries and `briefs/POT*.md`. The first implementation drafts are POT-P3, POT-P5 and POT-P6. They are explicit, bounded cross-lane proposals to primary under AGENTS item 5; they do not establish a standing Codex lane, a merged claim, or permission to merge. The remaining rows are unclaimed. Primary accepts the package split and assignments before promotion to ready. No SPEC, DECISIONS, lane ownership, production configuration, or previously queued work changes here.

The implementation PRs are stacked on this planning branch so every draft has a brief and the same dependency record. They remain drafts even after local checks or an independent review. Primary retargets/rebases them after accepting the intake. The author's request authorizes drafting implementations; it does not itself settle CHG-2 grader activation, L1 task semantics, custody qualification, live account trials, or deferred scope.

## Review-to-work map

| Review | Work | Boundary |
|---|---|---|
| P1 | [POT-P1](POT-P1.md) | Extend INT-A/H6/W7-A with one complete recurring workflow |
| P2 | [POT-P2](POT-P2.md) | Task binding and native edit pickup; design before guest protocol changes |
| P3 | [POT-P3](POT-P3.md), [POT-P3b](POT-P3b.md) | First deterministic observed-effect contract; then authenticated outcome revisions |
| P4 | [POT-P4](POT-P4.md) | Later; scoped recall and progressive fetch only after a workload bottleneck |
| P5 | [POT-P5](POT-P5.md) | Bounded templated approval cohorts; no additional authority |
| P6 | [POT-P6](POT-P6.md), [POT-P6b](POT-P6b.md) | First isolate transport evidence by class; then trusted task outcomes and full cost |
| P7 | [POT-P7](POT-P7.md) | Finish existing resource/plan-run composition after custody qualification |
| P8 | [POT-P8](POT-P8.md) | One measured local pipeline under adopted CAP-13, no default expansion |
| P9 | [POT-P9](POT-P9.md) | Later; a typed prior-result handle only if a recurring task requires it |
| P10 | [POT-P10](POT-P10.md) | Qualify existing fork/test/keep first; artifact transfer extension remains later |

## Acceptance and rollout

1. Each proposal maps to a scoped brief with requirements, dependencies, tests, and a completion boundary. The first three implementation drafts make no claim to implement the whole review.
2. POT-P3 and POT-P6 are deliberately split: neither the first outcome contract nor transport statistics complete task quality measurement. Their `b` rows remain release work after those drafts merge.
3. SR3-2 and SR3-3 precede release reliance on unattended effects and approval-rule presentation. SR3-7 precedes compound inference pipelines. Existing security work is not replaced by potency work.
4. Each runtime PR gets tests first, applicable Go/race/Linux checks, fresh L3, and the required lens/security passes. CHG-2 activation is independently approved. A passing component test is not a production workflow qualification.
5. For benefit claims, reuse H6's matched-trial collector and the review's protocol: equal tools/data/accounts/host; AgentOS, unmodified OpenClaw and direct provider CLI; first and repeat use separate; all setup/review/correction/recovery time and all retries/branches included. Predeclare acceptance and owner-effort targets. Do not claim a speedup without measurements.
6. Doclint, trace check and documentation tests pass; report platform limits in PRs. Never commit TRACE.md or mark a runtime row complete on documentation alone.

Initial checkpoint: 15k coordinator tokens, not a ceiling. Builder: available strongest Codex model; the repo's Sonnet 5.5 pilot model is unavailable in this environment. Each implementation draft records its own scope and validation.
