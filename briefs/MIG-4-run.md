# MIG-4-run: the kernel's process and each clerk's process

Work item #2682, part of #2541 (MIG-4, migration step 4). Sub A, tier A. Parent of #2655 (mail clerk run), #2643 (exit reconnect, items b to d), the #2626 allowlist and #2572 Step C.

**Goal.** Today the kernel and the clerks are libraries and tests. This row builds the running system. The kernel runs in its own process and holds the log. Each credentialed clerk runs in its own process, under its own uid, holding its own sealed Secrets file. The kernel reaches each clerk over that clerk's socket.

**Process layout (decided by the coordinator, 2026-10-21, recorded on #2682): option A.** One process per credentialed clerk, with its own uid and Secrets file. The kernel runs in a separate process. Option B, one process holding every clerk's Secrets, is ruled out by CLK-1. Option C, the kernel and a clerk in one process, is allowed only for a clerk with no secret.

**Requirement IDs:** CLK-1, CLK-2, KRN-8, STO-2 (the parts buildable before the sealed store), STO-3.

**Slices.**
1. *This PR.* The new directory `broker/clerk/run`:
   - the kernel host (`OpenKernel`: a locked file log, `kernel.Open`, `kernel.Boot`, every call under one lock);
   - the exit clerk host over a socket (`ListenClerk`, `ServeClerk`, `OpenExit`), with a peer-uid check on both ends;
   - the atomic Secrets writer and the old-format refusal (`OpenSecrets`);
   - the software `AESSealer` under a test key;
   - tests that run the clerk and a fake provider as separate processes.
2. The mail clerk's process with its sealed static slot (#2655): `OpenMail`, `SetMail` and `RemoveMail` in `broker/clerk/run`, with `clerk.Secrets.Login` and `Remove` in `broker/clerk/secrets.go` (the kernel lane waived ownership of these two methods) and an unbound `inbox.Account` judging the kernel's view (#2685, mail lane). The exit's `Reconnect` with the owner's proof (#2643 b, ASSUMPTIONS MIG-4-run-u): `ExitHost` runs a change-account step under the owner's exact passkey approval, naming by digest a grant staged for that plan on the exit process's owner socket (`ListenExitOwner`, `ServeExitOwner`, `ExitOwner`).
3. *3a:* the owner seam and the metering seam served on the kernel's sockets (`ListenKernel`, `ServeKernel`, `OwnerSide`, `MeterSide`, with the callers `Owner` and `Meter`), and the model clerk's process (`ListenModel`, `ServeModel`, `Model`). *3b:* the mail setup on the mail clerk's own socket with the CH-11 notices, and the mail re-read and listing for the planner. Wiring `clerk/model` in place of `broker/meter` and deleting both (#2572 Step C) wait on sub B unhooking their importers.
4. After STO-2: the production Sealer, the boot unlock, the `cmd/` mains with `procguard.Isolate`, and the unit files under `image/`. This slice also deletes `cmd/agentos-egress`, `-holder` and `-checker` once they are covered.

**Not before STO-2 (Mark's #936 answer):** no production Sealer, no boot unlock, no real credential written to disk, no shipped main or unit that loads one.

**Seam with sub B (D-111).** The kernel API the owner side calls is frozen in docs/LANES.md. This row hosts that API in the kernel's process and serves it on a socket in slice 3; sub B writes the callers.

**Acceptance tests:**
- CLK-2 across the socket: `broker/clerk/run/run_test.go::TestCallRunsOnlyAStepTheLogHasInFlight`. A replayed or never-logged request is refused at the clerk's process (`dispatch`), and the provider sees only the one step that was in flight. It fails if the view sent to the clerk claims a dispatch the log lacks.
- KRN-8: `run_test.go::TestKilledClerkDoesNotResend`. The clerk's process is killed while its request sits at the provider. The step is logged unknown, probed through the restarted clerk's process (with a restart of the kernel's process along the way), and parked, with exactly one send. It fails if a lost answer is logged as failed or a probe invites a resend.
- STO-2 (#2643 c): `secrets_test.go::TestSecretsWriteStoppedAtEveryStepLeavesAWholeForm` and `::TestSecretsKilledWriterLeavesAWholeForm`. A write stopped after any step, a torn temporary file, or a writer process killed at random points always leaves a form that loads whole. Both fail on an in-place write.
- #2643 d: `secrets_test.go::TestSecretsOldFormatRefused`. The slot-to-blob form is refused and left as it was.
- #2643 b: `clerk_test.go::TestReconnectNeedsTheOwnersExactApprovalAndTheStagedGrant`: the slot is left as it is for the clerk key alone, the planner's own exact narrowing, a passkey narrowing that is not the exact approval (any verb, change-account and more, this grant and another, no grant named, more than one use, a lasting expiry), another grant's digest, another clerk, or another plan. An exact approval with the grant staged for its plan replaces the slot once and clears the staged grant from memory. `::TestAReconnectClaimingAnotherGrantIsRefused`: a step whose content claims the approved grant while its value names another staged one fails `claim`. `::TestAReconnectThatFailsChangesNothing`: a grant that does not read, or one past the Secrets file's bound, fails `credential`, probes `unknown`, and the file still opens. `::TestReconnectActsOnceAndOnlyAsTheKernelSentIt`: the same step sent again, or an approved step the kernel never dispatched, changes nothing, and a probe answers from what ran. `::TestAReconnectOutlastsOnlyAHoldShorterThanItsApproval`: under a 10-minute novelty window, the reconnect is held and then made; under a 30-minute one, the approval expires, the step ends cancelled and the slot is unchanged. `::TestTheStagedGrantNeverReachesTheLog`: the opened log carries the digest, not the grant, and the owner socket has one call that needs a plan and a grant.
- CLK-1: `run_test.go::TestNoSecretInKernelProcess`. After a step that sent the clerk's secret (the provider confirms it by hash), the secret is in neither the log file, the log's entries nor any readable mapping of the kernel's process. A positive control shows the scan finds a secret that is present.
- CLK-1: `secrets_test.go::TestSecretsFileIsTheClerksOwn`. A directory or file open to other uids, a symlink, or another uid's directory or file is refused. As root, another uid cannot read the file.
- #2655: `mail_test.go::TestMailClerkSignsInWithTheSealedPassword` (a dispatched step lands on the server through a clerk that signed in with the sealed password, which is in neither the clerk's files nor the log), `::TestMailRemovalTakesEffectAtTheNextConnection` (a removal or a wrong password takes effect with no restart; it fails on a credential read once), `::TestMailReplacementSendsNoPasswordToTheOldServer` and `::TestMailSetupStoppedBetweenItsWritesSendsTheOldPassword` (a password goes only to its own account's servers; both fail on one slot for every account), `::TestMailSettingsFileIsTheClerksOwn`, `::TestMailSetupRefusalsKeepTheirWording`, and `broker/clerk/secrets_test.go::TestSecretsRemovePersists` and `::TestSecretsLoginOpensPerConnection`.
- CLK-1, CLK-2: `run_test.go::TestPeersAreCheckedByUID` and `::TestClerkRefusesAViewWithoutTheLedger`. A wrong peer uid on either end sends nothing. A view missing a charged scope's ledger is refused before the clerk runs.
- #2708 item 1: `view_test.go::TestACallPastTheBoundIsNeverSent`. A call one byte past `maxCall` never reaches the clerk. Its step fails as `too-large`, and its probe counts no check. A call exactly at the bound is sent and read whole.

**Declared scope:** `broker/clerk/run/` (new), `broker/core/core.txt` (one `wiring clerk/run` line), `docs/LANES.md` (the frozen seam), this brief. Slice 2 adds `broker/clerk/secrets.go` and its test (two methods, by the kernel lane's waiver).

**Guard files:** `broker/core/core.txt` (the wiring line, so the core test lets the host call the kernel's write paths). `tools/risk_tier.py` needs nothing: a new `broker/` path is tier A by default. `tools/g1_scope_g2.txt` needs nothing: `allow broker/clerk/` already covers the directory. `broker/daemon/arc2_test.go` needs nothing: the daemon imports nothing new.

**Ownership.** The "Kernel and clerk hardening" lane owns `broker/kernel`, `broker/kernel/key`, `broker/clerk/clerk.go` and `exit*.go`. This row consumes them through their existing APIs only. A change it needs there goes to that lane as an exact request. `View.OneOffLine` (from #2674) travels in the view (ASSUMPTIONS MIG-4-run-b).

**Usage estimate:** 250k tokens for slice 1, including reviews.

**Follow-ups MIG-4-run-r (#2700 items 3 to 6, #2704).** Items 1 and 2 are the kernel lane's (#2703); this change stacks on it.
- Item 3: `wire.go::needed` bounds the view's ledger per scope to what that scope's caps can count. Test: `view_test.go::TestViewLedgerIsBoundedByTheCaps` (each cap counts the same on the bounded list as on a year's ledger, at the kernel's time and on a clerk clock behind by `viewSkew`).
- Item 4: `docs/LANES.md` lists `SetLine` and `Reserve` with the owner actions, and the model clerk's metering seam (`AdmitSpend`, `Meter`, `Hold`, `ReadPool`, `AdmitPool`) apart from them.
- Item 5: `view_test.go::TestViewCarriesWhatTheCheckReads`. The view after JSON answers every `kernel.View` method as the log does, for a held and an unheld dispatch.
- Item 6: `view_test.go::TestAFailedWriteIsUnknown`. A call cut off mid-write is `unknown lost`, and a probe is `unknown`.
- #2704: `clerk.Secrets.RemovePrefix` (`broker/clerk/secrets.go`, by the kernel lane's waiver). `SetMail` drops every other mail slot, `RemoveMail` drops every one, and one lock serializes them. Tests: `mail_test.go::TestMailSetupStoppedAtEveryStepSendsOnlyItsOwnPassword` and `broker/clerk/secrets_test.go::TestSecretsRemovePrefix`.
- Declared scope: `broker/clerk/run/`, `broker/clerk/secrets.go` and its test, `docs/LANES.md` (a gate file, so a separate Security accept is needed), and this brief.

**Slice 3a acceptance tests (MIG-4-run-m to o):**
- `kernelsock_test.go::TestEverySocketCallIsTheDirectCall`. Every call on both tables, made through its typed client (`Owner`, `Meter`) and socket on one kernel and directly on a twin, gives the same answer and logs the same entries; every action but the two admits succeeds (retry on a parked step, extend with a real extension), and each read gives the same result on a state where it is not empty.
- `::TestOwnerSocketServesTheSeam`. A refusal keeps its code, a named error is the same value (`errors.Is`), and the reads after a lost answer show what the owner's calls changed.
- `::TestEachSocketServesOnlyItsSide`. No call is on both tables; owner calls on the meter socket and metering calls on the owner socket are refused and log nothing.
- `::TestKernelSocketsCheckPeerUID`. A socket for another uid takes no call, and a caller sends nothing to a socket another uid holds.
- `::TestModelClerkMetersThroughTheKernelSocket`. A model call through the model clerk's socket is metered through the meter socket at the kernel's clock, not the clerk's; a call past the plan's cap is refused with `spend-task`, holds the plan, and never reaches the provider.
- `::TestModelClerkWithoutTheKernelCallsNothing` and `::TestAKernelCallCutOffIsLost`. An unreachable meter socket refuses admission with `log-broken`; a call cut off mid-answer is `ErrLost`, and one never sent `ErrUnreachable`.
- `::TestAProviderErrorStaysInTheModelClerk`. A provider error carrying a canary key reaches the planner as `ErrModelCall`, without the canary.
- `::TestAKernelSocketOutlivesAFailedAccept`, `::TestASocketServesABoundedNumberAtOnce` and `::TestNoErrorCrossesAsSuccess`.
- `kernelsock_test.go::TestAWrappedErrorCrossesAsWhatItWraps` (#2742 item 13): an error wrapping a known sentinel, such as `kernel.ErrRetryRefused` with its code, crosses with its own text and is still that sentinel to `errors.Is`; one wrapping none matches none.
- Declared scope: `broker/clerk/run/` and this brief.

**Slice 3b acceptance tests (MIG-4-run-p to s; #2698 items 1 to 3, 8, 10 to 13):**
- `mailhost_test.go::TestMailSetupRunsOnTheClerksOwnSocket`. Setup, replacement and removal run on the mail process's owner socket; a refusal keeps its wording and a refused replacement is not told; each replacement and removal is told once in the old setup's words; the planner's listing follows the account and is read again on request; with no account a step is `no-account`.
- `::TestEachMailSocketServesOnlyItsSide`. The planner cannot set up, remove, or read the account or status, and the owner's socket has no listing.
- `seen_test.go::TestOpenedFailureKeepsEverySenderAndSaysSo`. A failed `Opened` keeps every listed sender opened today, in the world the account `OpenMail` returns judges VRB-2 in, writes no record and puts a pause line in STATUS.
- `::TestTheSeenRecordIsSealedAndBoundToItsAccount`. The record names no sender in the clear; one altered, sealed for another account or readable by others does not load, one past its bound is refused before it is read or opened, and the next read says the record began again.
- `::TestTheWarmUpsEndIsToldOnce` (day 89 still warms up; day 90 ends it and counts mail read exactly 90 days ago) and `::TestTheSeenRecordFollowsItsAccount`.
- `mail_test.go::TestMailClerkRefusesAStepTheLogHasNotInFlight`.
- Declared scope: `broker/clerk/run/` and this brief.

**Slice 3b follow-up acceptance tests (#2732; MIG-4-run-p to t; #2698 items 2, 5, 6, 16, 21, 22):**
- `mailhost_test.go::TestAMailboxReadHoldsUpNothingElse`. During a read, the owner's status and a step are answered at once; two overlapping re-reads read the mailbox once.
- `::TestSetupWaitsForTheReadInFlight` and `::TestRemovalWaitsForTheReadInFlight`. Setup and removal write nothing while a read is in flight, and land after it. After a removal, no record of read mail is left on disk.
- `::TestAFailedReadKeepsTheLastClerk`. A failed re-read keeps the last listing and clerk and says why in fixed words; a good read clears the line.
- `::TestAStepsRefusedSignInStopsTheClerk` (#2708 item 2). A step whose own sign-in the server refuses fails as `sign-in-refused`. STATUS then names the refusal, and neither a re-read nor the next step signs in again until setup (#2742 item 15).
- `::TestARefusedSignInStopsStepsSigningIn`. While the server refuses the sign-in, a kernel step fails as `sign-in-refused` and a probe answers `unknown`, neither connecting, even with a clerk the account opened before.
- `::TestARefusedSignInWaitsForTheOwner`. After a refused sign-in, re-reads and listings make no connection to the server until the owner sets the account up again.
- `::TestTheOwnerReadsWhetherAnAccountIsSetUp` and `::TestMailSetupRunsOnTheClerksOwnSocket`. The account read never carries the password; reading notices uses none up, and `told` drops only those up to its point.
- `::TestTheWarmUpsEndIsToldUntilShown`. The warm-up's end survives restarts until shown. It is never told after, even when a re-read lands between the owner side's read and its Told, or is still in flight as Told arrives, and a change of account drops an unshown one. `::TestUnreadableSettingsAreToldInFixedWords`.
- `::TestToldMarksOnlyTheAccountShown` (#2742 item 14): a change of account while Told waits for a read, to another account or to another and back, neither marks the account's new record as told nor drops its own warm-up end; the wait runs in a synctest bubble, so the order is fixed. `::TestToldLeavesTheWarmUpEndItDidNotCover` (#2742 item 16 and item 17's second part): a warm-up end that came after the owner side's read stays to be told, and two replacements before the owner looks are one notice.
- `seen_test.go::TestTroubleIsToldInFixedWords`. Every error class gets fixed words and a next step, no server text, quoted and cut names; a refused sign-in and a server offering no password sign-in (#2698 item 32) point to setup, never to trying again, and the latter names the server settings, never a password. `::TestTheWarmUpsEndCountsInPlainWords`.
- `::TestEveryLogOpenedKeepsFitsTheRecord`. The record spends less per entry than `Opened` charges, for addresses of 1 byte to 8 KiB.
- `mail_test.go::TestAFailedOpenedReadOffersNoUnsubscribe`. With the eval set's signed one-click mail, a working read offers its sender and a failed read of opened mail does not, through the account `OpenMail` returns.
