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
2. The mail clerk's process with its sealed static slot (#2655): `OpenMail`, `SetMail` and `RemoveMail` in `broker/clerk/run`, with `clerk.Secrets.Login` and `Remove` in `broker/clerk/secrets.go` (the kernel lane waived ownership of these two methods) and an unbound `inbox.Account` judging the kernel's view (#2685, mail lane). `Reconnect` with an owner-signed proof (#2643 b) follows after KRN-ownerlink.
3. The owner seam served on the kernel's socket for sub B's callers, then `clerk/model` wired in place of `broker/meter` (#2572 Step C).
4. After STO-2: the production Sealer, the boot unlock, the `cmd/` mains with `procguard.Isolate`, and the unit files under `image/`. This slice also deletes `cmd/agentos-egress`, `-holder` and `-checker` once they are covered.

**Not before STO-2 (Mark's #936 answer):** no production Sealer, no boot unlock, no real credential written to disk, no shipped main or unit that loads one.

**Seam with sub B (D-111).** The kernel API the owner side calls is frozen in docs/LANES.md. This row hosts that API in the kernel's process and serves it on a socket in slice 3; sub B writes the callers.

**Acceptance tests:**
- CLK-2 across the socket: `broker/clerk/run/run_test.go::TestCallRunsOnlyAStepTheLogHasInFlight`. A replayed or never-logged request is refused at the clerk's process (`dispatch`), and the provider sees only the one step that was in flight. It fails if the view sent to the clerk claims a dispatch the log lacks.
- KRN-8: `run_test.go::TestKilledClerkDoesNotResend`. The clerk's process is killed while its request sits at the provider. The step is logged unknown, probed through the restarted clerk's process (with a restart of the kernel's process along the way), and parked, with exactly one send. It fails if a lost answer is logged as failed or a probe invites a resend.
- STO-2 (#2643 c): `secrets_test.go::TestSecretsWriteStoppedAtEveryStepLeavesAWholeForm` and `::TestSecretsKilledWriterLeavesAWholeForm`. A write stopped after any step, a torn temporary file, or a writer process killed at random points always leaves a form that loads whole. Both fail on an in-place write.
- #2643 d: `secrets_test.go::TestSecretsOldFormatRefused`. The slot-to-blob form is refused and left as it was.
- CLK-1: `run_test.go::TestNoSecretInKernelProcess`. After a step that sent the clerk's secret (the provider confirms it by hash), the secret is in neither the log file, the log's entries nor any readable mapping of the kernel's process. A positive control shows the scan finds a secret that is present.
- CLK-1: `secrets_test.go::TestSecretsFileIsTheClerksOwn`. A directory or file open to other uids, a symlink, or another uid's directory or file is refused. As root, another uid cannot read the file.
- #2655: `mail_test.go::TestMailClerkSignsInWithTheSealedPassword` (a dispatched step lands on the server through a clerk that signed in with the sealed password, which is in neither the clerk's files nor the log), `::TestMailRemovalTakesEffectAtTheNextConnection` (a removal or a wrong password takes effect with no restart; it fails on a credential read once), `::TestMailReplacementSendsNoPasswordToTheOldServer` and `::TestMailSetupStoppedBetweenItsWritesSendsTheOldPassword` (a password goes only to its own account's servers; both fail on one slot for every account), `::TestMailSettingsFileIsTheClerksOwn`, `::TestMailSetupRefusalsKeepTheirWording`, and `broker/clerk/secrets_test.go::TestSecretsRemovePersists` and `::TestSecretsLoginOpensPerConnection`.
- CLK-1, CLK-2: `run_test.go::TestPeersAreCheckedByUID` and `::TestClerkRefusesAViewWithoutTheLedger`. A wrong peer uid on either end sends nothing. A view missing a charged scope's ledger is refused before the clerk runs.

**Declared scope:** `broker/clerk/run/` (new), `broker/core/core.txt` (one `wiring clerk/run` line), `docs/LANES.md` (the frozen seam), this brief. Slice 2 adds `broker/clerk/secrets.go` and its test (two methods, by the kernel lane's waiver).

**Guard files:** `broker/core/core.txt` (the wiring line, so the core test lets the host call the kernel's write paths). `tools/risk_tier.py` needs nothing: a new `broker/` path is tier A by default. `tools/g1_scope_g2.txt` needs nothing: `allow broker/clerk/` already covers the directory. `broker/daemon/arc2_test.go` needs nothing: the daemon imports nothing new.

**Ownership.** The "Kernel and clerk hardening" lane owns `broker/kernel`, `broker/kernel/key`, `broker/clerk/clerk.go` and `exit*.go`. This row consumes them through their existing APIs only. A change it needs there goes to that lane as an exact request. `View.OneOffLine` (from #2674) travels in the view (ASSUMPTIONS MIG-4-run-b).

**Usage estimate:** 250k tokens for slice 1, including reviews.
