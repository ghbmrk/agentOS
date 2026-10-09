# Cross-silo follow-up: evidence and limits

Source: main `c422039d41acdb4b70f89c1ece9b0fbd40191799`, inspected through local merge `2873df0748b4c5b84b415be6b9cf5a17cbd6e996` containing the original ARCH1 draft. [Follow-up report](../../2026-10-08-cross-silo-architecture.md). The original README/probe/package results retain their earlier pinned source; they are not silently relabelled as new evidence.

Three bounded source reviews covered data/authority, output composition and heterogeneous hardware. Each checked actual code/spec and distinguished implemented mechanisms, specified-but-unwired behavior, drafts and proposed extensions. References to CAP-11/12 draft code pin `fc2e31bd55e6aaf3b869537a6cb9620746f26ae7` (#221); they are not presented as main or production capability.

The data review ran existing focused tests from `broker/`, with Go 1.26.8 on native Darwin arm64:

```sh
GOCACHE=/path/to/writable/cache GOTOOLCHAIN=local go test -mod=vendor ./recall ./recalltool -run 'TestFullTextWithProvenance|TestStructuredFacts|TestSearchRaisesMachineBeforePrivateResults|TestRenderIsUntrustedContentWithSource|TestDeletionPropagates|TestK7PublicMachinesSearchPublicByDefault|TestNotesTakeLabelAndSourcesFromTheBroker' -count=1
```

Both packages passed (recall 0.302 s; recalltool 0.293 s). The first invocation failed before tests because the default build-cache directory was outside the sandbox; the successful invocation used an external writable cache. These are synthetic component tests of attribution/facts, labels, rendering, deletion and broker-derived note provenance, not a multi-device production proof.

No live credentials/accounts, real sensors/actuators, remote compute hosts, large connected-space benchmark, atomic cross-source snapshot or measured complementarity gain was exercised. The report's scenario matrix and later briefs are proposed falsifiable acceptance work, not test results. Fresh independent review, required local document/Python checks and Linux PR CI for the final delta are recorded in the PR.

Final local document checks passed: doclint, trace regeneration/check and whitespace; generated TRACE.md was restored and is not part of this change. The required native Python suite again ran 214 tests with 6 Linux canary/sweeper failures and 33 skips, no errors. Those Linux-only checks are not claimed green on Darwin; the final Linux PR CI result is recorded separately in the PR.
