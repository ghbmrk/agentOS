# MIG-4-daemon-owner: STOP, RESUME and STATUS reach the kernel

Work item #2783 (MIG-4-untrusted-daemon), slice (a); serial `cmd/agentosd` chain (D-111): #3072 merged, this, then #2783's next slices, #2778, #2779, #2780b, #2790. Tier A. Written 2026-10-25 against main at 23ae7f2.

**Why a split.** #2783 as filed takes `broker/daemon` off `journal` and `grants` whole: the gate, every executor, the retrier, startup reconcile and the unknown outcome move to the kernel, and the last `grants` uses in `cmd/agentosd` go (from #2789). That is about 1k source and 5.2k test lines in `daemon` plus about 45 `cmd/agentosd` importers, past one session (<150k). The slices:
- **(a) this brief.** The owner seam's STOP, RESUME and stop read in `owner/kernelsock`, and the owner commands (control words over SMS and the owner socket, the owner channel, the Wi-Fi page) driving the kernel as well as the journal. Nothing is deleted.
- **(b)** STATUS's unsettled steps and RETRY of a parked step from the kernel (`status`, `retry`), beside the journal's.
- **(c)** the journal engine stops running actions in `daemon`; reconcile, RETRY and unknown outcomes are the kernel's alone; `grants` and `journal` leave `daemon` and `cmd/agentosd` (the #2783 "Done when").

**This slice.**
1. `broker/owner/kernelsock`: `Stop`, `Resume` and `Stopped` (the `changes` read's `Stopped`) on the written-out wire.
2. `broker/daemon/daemon.go` (`bothStops`; in `daemon.go` so the old-core import count does not grow): `Config.Kernel` (`KernelOwner`) wraps the journal engine the owner commands drive. STOP records in both and reports done only when both did (CH-2). RESUME lifts the kernel first, then the journal if it is stopped. STATUS says Stopped when either is; a kernel whose stop cannot be read is never reported stopped, and STATUS names it in one note. A kernel waiting for setup (its refusal, then `setupinfo` open) has nothing to stop.
3. `cmd/agentosd`: `-kernel-store` (default the kernel unit's `ConditionPathExists` path, so the unit and the boot report's canonical command do not change). With no sealed store no kernel can run, so it reads as waiting for setup and STOP works on the setup boot as before.
4. #3072 L3 release 1 (comment 6391349792): tests that a `key.Refusal` answer comes back as `Refused` and that an undecodable result is `ErrLost`. #3072 L3 later 2: the "every every" comment.

**Scope.** `broker/owner/kernelsock/{kernelsock.go,kernelsock_test.go}`, `broker/daemon/{daemon.go,kernelstop_test.go}`, `broker/cmd/agentosd/{kernel.go,kernel_test.go,main.go,ASSUMPTIONS.md}`, this brief. No gate file.

**Requirement IDs:** CH-2, KRN-7.

**Acceptance tests:**
- `broker/owner/kernelsock/kernelsock_test.go::TestStopAndResumeReachTheKernel`: a real running kernel's `OwnerSide` logs STOP and RESUME and reads its stop back; a setup-only kernel refuses the read and RESUME.
- `kernelsock_test.go::TestARefusalAndAnUndecodableAnswer`: a refusal answer is `Refused` with code and detail; a result that does not decode, or a cut answer, is `ErrLost`. Kills #3072's surviving mutants M5b and M9.
- `broker/daemon/kernelstop_test.go::TestSTOPReachesTheKernel`, `::TestSTOPFailsWhileTheKernelDoesNotAnswer`, `::TestAKernelWaitingForSetupHasNothingToStop`: over the owner socket, through `daemon.Run`.
- `broker/cmd/agentosd/kernel_test.go::TestNoSealedStoreIsAKernelWaitingForSetup`.
