# POT-P1: Qualify a complete recurring workflow

**Owner:** primary, unclaimed. **Class:** release, A3/A10/A11/A15. **Tier:** A when service wiring changes.
**Requirements:** CAP-4/5, OP-2/4/7/8, CHG-1, REV-2/5.
**Needs:** INT-A [#261](https://github.com/ghbmrk/agentOS/pull/261), H6 [#258](https://github.com/ghbmrk/agentOS/pull/258), W7-A [#264](https://github.com/ghbmrk/agentOS/pull/264), POT-P2/P3; relevant adapter qualification and SR3 fixes before external use. Pending PRs are dependencies to reconcile, not adopted interfaces.

## Scope

Reuse the existing e2e and measurement harnesses. After inspecting those PRs, split one small implementation brief for their actual test paths, production construction and fixtures. Do not build a second harness. The current fake-machine owner-channel test is component evidence only.

One recurring workflow must carry authenticated request → broker-bound task → actual guest → broker/vault → one qualified adapter → native result → authenticated acceptance → a requalified repeat-use improvement. Begin with a simulated service and durable receipts; live accounts require the owner's explicit scope and the adapter gates. Add an event-triggered version only after event data has explicit task provenance and cannot supply owner authority.

## Acceptance

1. Actual service/socket identities, quota/cgroup and label controls are exercised; no allow-all verifier, shared service UID or omitted confinement is presented as production evidence.
2. Restart at receipt, dispatch, result and acknowledgment boundaries: no duplicate effect; pending/unknown is truthful; work is retained without requiring the owner to repeat it.
3. STOP blocks effects and owner cancellation remains available during recovery. An untrusted event cannot create grants or authenticate feedback.
4. Run the matched A10 trial in POT with predefined quality and owner-effort targets; report raw failures and incomplete tasks, not just successful runs. No claim of benefit until this passes.

Record a test-first handoff, exact pinned dependency heads, assumptions and Linux evidence. Strongest-model L3 plus separate Security and UX/Potency lens passes are required. Initial implementation checkpoint: 25k tokens per vertical slice; split before scope exceeds one workflow.
