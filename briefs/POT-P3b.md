# POT-P3b: Revise authenticated outcomes and qualify additional graders

**Owner:** primary, unclaimed. **Class:** release, A7/A10/A11. **Tier:** A.
**Requirements:** CHG-1/2, LOOP-5/6, OP-7, CAP-3/5.
**Needs:** POT-P3, POT-P2 for durable result identity; reconcile W7-A [#264](https://github.com/ghbmrk/agentOS/pull/264) and existing W3 forget work.

POT-P3's first observed-effect contract does not establish artifact quality, multi-effect correctness, owner feedback revision, or a workload acceptance measure. Keep these explicit gaps open after that draft merges.

## Scope

Extend the existing harvest/suite/feedback path in bounded slices. Bind authenticated feedback to task/result revision and broker-observed terminal outcomes. Append a superseding revision rather than silently keeping the first result or appending a duplicate case. Freeze suite generation for an evaluation and invalidate its adoption eligibility when the oracle changes. Preserve task-based split identity and contribution bounds across corrections.

Add one deterministic class grader at a time, with versioned required and forbidden effects or artifact checks. Unsupported contracts and unknown results must not pass. Changing suites/graders is independently owner-approved under CHG-2; neither model output nor the candidate may approve its own grader. Inspect cassette capture and missing responses separately: do not synthesize successful external responses to force a pass.

## Acceptance

1. Accept→correct→reject revisions remain authenticated, append-only and idempotent; old/replayed messages do not overwrite a newer revision, and correction cannot multiply suite weight or move dev to holdout.
2. A frozen evaluation against revision N cannot adopt after N+1 arrives. Recovery, concurrent evaluation, duplicate feedback and FORGET/restore preserve that exclusion.
3. Two candidates with identical prose but different observed results grade differently; different prose with the same correct result grades identically. Extra, forbidden, failed, unknown and duplicate effects are rejected. A refusal-only negative case is not presented as proof of positive task quality.
4. Held-out expected outcomes remain broker-only. Candidate data cannot choose a grader/version or supply an observation envelope. Existing security fixtures and no-live-effects replay stay enforced.

Tests first; Linux/race checks, strongest-model L3 with threat check and separate Security/lens passes. Initial checkpoint: 25k tokens per outcome class/revision slice, not a ceiling.
