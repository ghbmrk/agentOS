# MIG-4-daemon-retry: STATUS's unsettled steps and RETRY reach the kernel

Work item #2783 (MIG-4-untrusted-daemon), slice (b) of the split in `briefs/MIG-4-daemon-owner.md`; serial `cmd/agentosd` chain (D-111): #3077 merged, this, then (c), #2778, #2779, #2780b, #2790. Tier A. Written 2026-10-25 against main at 8b46d82.

**This slice.**
1. `broker/owner/kernelsock`: `Status` (the owner seam's `status` read, as `Step`) and `Retry` (`retry`, kernel/proc's `stepArgs`) on the written-out wire.
2. `broker/daemon/daemon.go` (`bothStops`): STATUS counts the kernel's unsettled steps beside the journal's. Unknown and parked outcomes "may have happened". An unsent step of a live plan is "waiting to run". An unsent step of an ended plan never acted, so it is not counted. A kernel whose steps cannot be read is named in one note, never counted as none in silence. STATUS reads the kernel's stop even while the journal is stopped, so a STOP whose kernel leg failed is named (#3077 Security later 2, comment 6392134748).
3. `broker/daemon/retry.go`: RETRY also offers each step the kernel holds parked, one request each, at the tier the step's own facts give (CH-10, CH-11). A verb that moves money is `MoneyRetry`. A recipient the broker has not looked up is high. The verb is the step's own, so the owner's excluded verbs still bind. The line says it may go twice (CH-12). An approved one runs the kernel's `retry`; a line that cannot be approved by text needs the local page. The owner is told how it ended, in fixed words.
4. `broker/cmd/agentosd/kernel.go`: `storedKernel` converts `kernelsock`'s steps and errors to `daemon`'s (`KernelStep`, `KernelRefused`, `ErrKernelLost`), so the control path still links no socket client (`TestARC2ControlPathCannotReachInference`).

**Not in this slice.** Security's delta release 1 on #3077 (comment 6392134748): RESUME carries the stop generation it lifts, so the kernel refuses a stale one. That needs `kernel` and `kernel/proc`, which grows the trusted core over `tools/trusted_core.txt`, and the core may grow only under a `Trusted-core:` decision from Mark. It stays with (c) or its own row. The kernel's `Unsettled` carries no first-tried time, so the RETRY line cannot name one, as the journal's does. Adding it also grows the core.

**Scope.** `broker/owner/kernelsock/{kernelsock.go,kernelsock_test.go}`, `broker/daemon/{daemon.go,retry.go,kernelstop_test.go,kernelretry_test.go,ASSUMPTIONS.md}`, `broker/cmd/agentosd/{kernel.go,kernel_test.go}`, this brief. No gate file. No old-core import grows.

**Requirement IDs:** CH-2, CH-10, CH-12, KRN-7.

**Acceptance tests:**
- `broker/owner/kernelsock/kernelsock_test.go::TestStatusAndRetryReachTheKernel`: a real running kernel lists no steps and refuses a RETRY of no parked step in its own words; a setup-only kernel holds none and refuses the RETRY.
- `kernelsock_test.go::TestRetrySendsTheKernelsOwnCall`: RETRY's bytes equal kernel/proc's own client's, so the kernel reads the plan and step the owner approved.
- `kernelsock_test.go::TestStatusReadsTheKernelsFrame`: every field `Step` names decodes from `kernel.Unsettled` as the status read encodes it.
- `broker/daemon/kernelretry_test.go::TestSTATUSCountsTheKernelsUnsettledSteps`: the counts and labels; the note when the steps cannot be read; no note for a setup-only kernel.
- `kernelretry_test.go::TestSTATUSNamesAKernelThatMissedTheSTOP`: Security later 2.
- `kernelretry_test.go::TestRETRYRetriesTheKernelsParkedStep`: through the owner channel by text: only the parked step is asked about, and the texted approval retries that plan and step.
- `kernelretry_test.go::TestAKernelRETRYOnlyOnTheOwnersWord`: no approval, or a forged ref, retries nothing; each refusal and a lost answer are told in fixed words and listed again.
- `kernelretry_test.go::TestAKernelRETRYLineTakesItsStepsTier`, `::TestAKernelRETRYOfALocalLineNeedsThePage`.
- `broker/cmd/agentosd/kernel_test.go::TestTheKernelsAnswersInTheOwnerCommandsTerms`.
