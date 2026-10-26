# KRN-retry-bind: a kernel RETRY ask is bound to the step's retry count

Work item: #3082 (from the #3080 reviews, MIG-4-daemon-retry, #2783 b). Tier A. Written 2026-10-26 against main at 1ea8032.

**Waits on #3311 (MIG-4-recovery-e3).** #3311 edits `broker/kernel/proc/kernelsock.go` and `broker/owner/kernelsock/kernelsock.go`, which this package also edits, so under the conflict guard (D-111) the build starts only once #3311 has merged or closed. Build on main after it.

**Needs its own D-159 row.** Item 1 grows the trusted core (`broker/kernel`, `broker/kernel/proc`). Before the build PR can merge, a one-row DECISIONS.md PR adds the next free `D-NNN` (D-184 to D-187 are held by #3301, #3303, #3304 and #3312; take the next one free when the build PR exists): status `active`; text "Trusted-core growth (D-159) for PR #<build PR> (issue #3082, KRN-retry-bind): a kernel RETRY names the step's retry count and the kernel refuses it once the count moved (+N core lines in kernel and kernel/proc); review checks each line"; source "Approved design under D-159: SPEC v1.0 CH-10 (a code bound to that request) and KRN-8 (RETRY at the step's tier) (lane message cmsg_01R91wiieBzMSvPKFsAJVvuKLX2vZYRDWFPWAdtdzhU8Fv)", in the form of D-163 and D-164. That row merges first; the build PR then carries `Trusted-core: D-NNN`. Measure N with `tools/trusted_base.py` on the build head.

## Goal

**1. release (CH-10 "bound to that request", KRN-8; #3080 L3 comment 6392787849 item 2).** A kernel RETRY ask carries no binding to the attempt it asked about. Failure path: the owner texts RETRY twice, so two asks are open for the same plan and index; the owner approves the first, the step is sent again, fails its checks and parks again; the owner then approves the second, older ask, and the step is sent a third time on an approval given before the second send. The journal's path refuses this (`a.attempt != n` in `broker/daemon/retry.go` `decide`); the kernel's does not.

The issue suggested binding to `Checks`. That does not work: `TStepRetried` resets `Checks` to 0 and a re-park happens at `Checks == MaxChecks`, so the value read at both asks is the same 10. `SentAt` is the first send and does not move either. Nothing in `kernel.Unsettled` today changes across a retry and re-park, so the binding needs one new derived count, and the check must run in the kernel, under its lock, so a daemon-side check cannot race a second approval.

Fix:
- `kernel.StepState` gains `Retries int`, incremented when `TStepRetried` applies (the same branch that sets `PRedo`). It is derived from the log on replay; no entry body changes, so old logs replay unchanged.
- `kernel.Unsettled` carries `Retries`.
- `Kernel.Retry(now, plan, index, retries int)` refuses with a new `ErrRetryMoved` ("kernel: the step was retried since that ask") when `st.Retries != retries`, checked after `ErrNotParked` and before `sendCheck`. Nothing is logged on a refusal.
- `kernel/proc`: the `retry` call takes a `retryArgs{Plan, Index, Retries}` (keep `stepArgs` for `cancel` and `undo`); `Owner.Retry` gains the count; the status frame carries `retries`.
- `broker/owner/kernelsock`: `Step.Retries` decoded from the frame; `Owner.Retry(ctx, plan, index, retries)` sends it.
- `broker/daemon`: `KernelStep.Retries`; `KernelOwner.Retry` gains the count; `runKernel` passes `a.step.Retries`, as read when the ask was made. `kernelRefusal` maps `ErrRetryMoved`'s text to fixed words, for example "it was already tried again since you asked; text RETRY to ask again".
- `broker/cmd/agentosd/kernel.go`: `storedKernel` copies the field and passes the count.

**2. later, carried in the same package (KRN-7 "never degrades quietly"; #3080 Security comment 6392777012 later 1).** If the kernel's steps cannot be read and the journal has nothing waiting, RETRY answers "Nothing to retry." while parked steps may exist. It fails closed (nothing is sent twice) but says something untrue.

Fix:
- `owner.Config.Retry` becomes `func() ([]Item, error)`.
- `askRetry`: with an error and no items it answers one fixed line naming the step that works, for example "Part of me is not answering, so I could not check every action to retry. Text RETRY again later." With an error and some items, it asks about those items and adds the same line. With no error and no items it still answers "Nothing to retry."
- `daemon` `retrier.items` returns the kernel's `Status` error, except for a kernel waiting for setup, read as STATUS reads it (`SetupOpen`, `bothStops` in `daemon.go`): a setup-only kernel holds no steps, so that is not an error.

## Lifecycle

| Stage | Outcome |
|---|---|
| Ask made, nothing in between | Approval retries the step once; `Retries` becomes n+1. |
| Ask made, step retried and re-parked by another ask | Approval is refused with `ErrRetryMoved`; nothing logged; owner told in fixed words. |
| Ask made, kernel restarts | The count is rebuilt by replay from anchored entries, so the ask still binds (an unanchored retry is lost on reboot, `TestUnanchoredRetryDoesNotSurviveReboot`, and so is its count). |
| Kernel unreadable at RETRY | The owner is told part of the box is not answering, never "Nothing to retry." |

Integration owner: this package; it wires all of the above into the running path.

## Scope

- `broker/kernel/{state.go,kernel.go,kernel_test.go,ASSUMPTIONS.md}`
- `broker/kernel/proc/{kernelsock.go,kernelsock_test.go}`
- `broker/owner/kernelsock/{kernelsock.go,kernelsock_test.go}`
- `broker/owner/{channel.go,retry_test.go,ASSUMPTIONS.md}`
- `broker/daemon/{daemon.go,retry.go,kernelretry_test.go,kernelstop_test.go,ASSUMPTIONS.md}` (`kernelstop_test.go`'s `fakeKernel.Retry` takes the count)
- `broker/cmd/agentosd/{kernel.go,kernel_test.go}`
- `briefs/KRN-retry-bind.md`

On main at 1ea8032 (grep) nothing else calls `Kernel.Retry` or either `Owner.Retry`, nothing else implements `KernelOwner.Retry`, and `daemon.go` is the only non-test `owner.Config` with a `Retry`. No old-core import grows.

**Guard files:** none (no package added or newly linked; the core's growth is covered by the D-159 row above, not a guard file).

**Requirement IDs:** CH-10, KRN-8, KRN-7.

## Acceptance tests

**Acceptance tests:**
- CH-10, KRN-8: `broker/kernel/kernel_test.go::TestARetryOfAMovedStepIsRefused`: two asks read the same `Retries`; the first retry is sent, fails its checks and parks again; a `Retry` with the old count returns `ErrRetryMoved`, logs nothing, and the step stays parked. Catches a kernel that ignores the count.
- KRN-8: `kernel_test.go::TestRetryCountSurvivesReboot`: after an anchored retry and re-park, a reboot reads the same `Retries`, and a `Retry` with it succeeds. Catches a count kept outside the log's replay.
- KRN-8: `kernel_test.go::TestStatusCarriesTheRetryTierFacts` extended: `Unsettled.Retries` is 0, then 1 after one retry and re-park.
- `broker/kernel/proc/kernelsock_test.go`: the `retry` call carries the count and returns the kernel's refusal; `Owner.Retry` bytes match `owner/kernelsock`'s (`TestRetrySendsTheKernelsOwnCall` extended).
- `broker/owner/kernelsock/kernelsock_test.go::TestStatusReadsTheKernelsFrame` extended: `Retries` decodes.
- CH-10: `broker/daemon/kernelretry_test.go::TestAnOlderKernelRETRYAskRetriesNothing`: two RETRY texts, approve the first, the fake kernel re-parks with `Retries` 1, approve the second: the fake kernel is called with count 0 and refuses, nothing is retried, and the owner is told the fixed refusal words. Catches a daemon that re-reads the count at approval time instead of using the one it asked about.
- KRN-7: `broker/owner/retry_test.go::TestRetrySaysWhenPartOfTheBoxIsNotAnswering`: an error and no items gives the fixed line, never "Nothing to retry."; an error with items asks about them and adds the line.
- KRN-7: `kernelretry_test.go::TestRETRYNamesAKernelThatCannotBeRead`: a kernel whose `Status` fails gives the error to the channel; a setup-only kernel does not.
- `broker/cmd/agentosd/kernel_test.go::TestTheKernelsAnswersInTheOwnerCommandsTerms` extended: the count and `ErrRetryMoved` cross the conversion.

Recurring kinds as acceptance criteria: a problem text names a step that works (reviews/ux README, CH-12), so both new owner lines end with one; each defence's test comment names its revert mutant and the test dies on it (reviews/potency README), here the dropped count check in `Kernel.Retry` and a daemon that re-reads the count at approval; a refusal logs nothing; the kernel's text is matched, never shown.

## Estimate

About 60k tokens, one session, Opus (tier A). Reviews owed on the build PR: L3 on the strongest model, the lens screen, and Security in its own session; not a gate-file PR unless `premerge.py --needs-mark` says otherwise.
