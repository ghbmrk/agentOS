# W3-forget-b1-6: Restore command and the forget log's restore conditions

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md), after W3-forget-b1-7 (#487, merged f1d1e69); SPEC CAP-3, A8, REC-1, REC-2, CH-12.

**Split: two packages, built in order.** b1-6a changes `broker/recovery` only. b1-6b builds the restore command on top of it. One package doesn't fit: no restore command exists yet. Today nothing outside `cmd/agentos-a8scan` imports `broker/recovery`, so the binary, its TPM counter and its destination reader are all new. That is more than one tier-A session of 150k. Each part has its own BOARD row, which links here.

**Requirement IDs:** CAP-3 and A8 as in W3-forget-b1, plus security C3 ("a failed check keeps the restore pending and tells the owner"). The conditions below come from these reviews:
- #409: Security R2 and R3 (comment 6068759285), Security R5 (a)–(d) (6069206966), the L3 delta condition on paths (6069213249), and L3 point 3 on an empty `Layout.ForgetLog` (6068725258).
- #436: Security, second release point (6071291284; moved to b1-6 by 6071419996).
- #487: the handoffs "f4", which is #409 Security L2, and the UX lens point 1 (6073774859).

Each ID below is a condition. Each needs at least one test with a `REQ:` marker.

## b1-6a: forget log hardening in `broker/recovery` (tier A)

- **B6-R2: a corrupted copy does not make the restore `forged` while a good copy exists.**
  - Change: a copy whose header verifies but has an entry whose MAC or chain link fails counts as its verified prefix: the entries before the bad one, with the rest dropped.
  - Unchanged:
    - Two copies whose authentic entries diverge (valid MACs, different entries) still hold the restore as `forged`.
    - The vault's own copy still holds as `forged` on any bad entry, because the vault authenticates it.
    - The counter still catches a rollback.
  - A copy cut below its anchor is unusable (L3 on #519, point 1).
    - The gap: the header MAC covers `Host`, `Base` and `AnchorSeq`, but not the number of entries. `head()` returns `Base` whenever the last entry's `Seq <= AnchorSeq`.
    - So a copy cut to k < `AnchorSeq` entries reads as anchored at `Base`. It is cut either by deleting its tail (possible today) or by a flipped entry under this change.
    - If the vault's log is a prefix of the cut copy, the cut copy wins and the restore reads as checked. Forgets k+1..`AnchorSeq` are lost.
    - Rule: any destination copy whose verified prefix holds fewer than its header's `AnchorSeq` entries is treated as absent. `checkForgetLog` reports it to the caller, so b1-6b names it in its output. This rule does not apply to the vault's own copy.
  - Tests:
    - The reviewer's case: a log anchored on this PC at `AnchorSeq = A` with no forget since, and a backup from before the move (another `Host`). One destination copy is cut to k < A entries by deleting its tail, and another by a flipped entry. In each case the cut copy is ignored and reported, the restore is not checked, and the result matches the cut copy being absent.
    - A copy cut at exactly `AnchorSeq` entries is still usable.
    - One good copy plus one copy with a flipped entry restores as the good copy would. Today `TestRestoreHoldsAForgedOrReplayedEntry/changed` asserts `forged`; update that case to the new result and say so in the PR.
    - The corrupted copy alone is treated as its prefix.
    - Divergent authentic copies still give `forged`.
- **B6-R3: decode caps.**
  - `decodeForgetLog` refuses input over `MaxForgetLog` (4 MiB) before it parses. An over-size copy is treated as not a log, like a foreign copy.
  - Add a reader, `ReadForgetLogCopy(io.Reader) ([]byte, error)`, that reads at most `MaxForgetLog`+1 bytes and refuses anything longer. b1-6b reads every destination copy through it.
  - Tests:
    - A copy one byte over the cap is ignored, and the restore result is the same as with that copy absent.
    - The reader stops reading after the cap: give it an endless reader and assert it returns an error rather than hanging.
- **B6-M: a forget-log-missing restore carries the longest authentic copy (#436 Security, release point 2).**
  - When the restored vault has no log but copies at hand open under the recovery key, `checkForgetLog` returns the longest authentic copy (ID rules as in `checkForgetLog`) with reason `forget-log-missing`.
  - The question's real answer is then that copy's last-forget date, so "Never" is wrong.
  - Settling saves the copy and the forget key derived from the recovery key into the restored vault (`ensureForgetLog` with no counter), so the next append chains on from it.
  - Authentic copies with different log IDs hold the restore as `forged`, since there is no way to tell which one is real.
  - Recommendation over holding: carrying only adds forgets, while a hold would leave the owner with no way forward.
  - Tests:
    - Missing log plus an authentic copy with forgets: the question's answer is that copy's date, "Never" is refused, and the restored vault holds the log and its key.
    - Missing log with no copies: as today.
    - Two IDs: `forged`.
- **B6-D: a failed TPM anchor at `storeBackupKey` falls back to anchoring at the first forget (R5 (d)).**
  - Today a failed `Define` or `Read` fails storing the recovery key after the key and log are already saved.
  - Change: `ensureForgetLog` returns only vault errors. An anchor error leaves the log unanchored (`Host` empty), and `AppendForget` anchors it later.
  - Reasons:
    - Failing would leave a half-stored rotation over a TPM fault the owner can't fix from the card.
    - The fallback costs only a question on a same-PC restore before the first forget, the same as a box with no TPM.
  - Record the decision in ASSUMPTIONS F3.
  - Reword `PendingNotice(PendingUnanchored)` (L3 on #519, point 5, release). After the fallback, "Restoring on your original PC still works" is false on the original PC, and it is already false on a box with no TPM. Use a line that is true in both cases.
  - Tests:
    - A counter whose Define fails: `storeBackupKey` succeeds and the log is unanchored.
    - A later `AppendForget` with a working counter anchors the log.
    - A vault Put failure still fails.
- **B6-L: `Restore` and `RestoreDrive` refuse an empty `Layout.ForgetLog`** (#409 L3 point 3). Without it, no marker is written and the hold is silently off. Test: an empty value returns an error and leaves nothing at dst.
- **B6-V: a backup can be checked without being restored,** for `Options.Newer`.
  - Add `CheckBackup(r io.Reader, rk RecoveryKey) (time.Time, error)`. It opens the prefix and reads the sealed stream to its authenticated end, writing nothing, and returns `Created`.
  - Tests:
    - A good backup returns its date.
    - A truncated backup returns an error.
    - A flipped byte returns an error.
    - A backup made under another recovery key returns an error.
- **B6-N: destination names.**
  - Add `DestForgetLog = "forget-log.json"` and the backup file pattern a destination directory uses, as exported constants, so that W6's backup command writes what b1-6b reads.
  - Record the names in ASSUMPTIONS as a contract with W6.

**Scope:** `broker/recovery/` (`forgetlog.go`, `bundle.go`, `factor.go`, a new file for `CheckBackup` if it is cleaner, their tests), `broker/recovery/ASSUMPTIONS.md` (F3, F4, Q-rows touched), BOARD.md, LATER.md.

**Needs:** W3-forget-b1-7 (merged).

**Estimate:** about 90k tokens, strongest model (tier A: recovery).

## b1-6b: the restore command (tier A)

The command is a new binary, `broker/cmd/agentos-restore`, modelled on `cmd/agentos-a8scan`. It reads the recovery key on stdin, never from a flag or the environment. It takes:
- a backup file, or `-drive` roots;
- `-dest DIR` (repeatable), the backup destinations at hand;
- the production paths, with agentosd's and the vault process's defaults.

It runs on the PC as root while the box's services are stopped.

- **B6-W: wire the inputs.** One test per input:
  - `Options.ForgetLogs`: every `-dest`'s `DestForgetLog`, read through `ReadForgetLogCopy`. An unreadable, absent or over-cap copy is skipped and named in the output.
  - `Options.Counter`: this PC's TPM counter. Move `tpmCounter` from `cmd/agentos-egress/trusted.go` into `broker/tpmseal` as an exported type, used by both binaries. agentos-egress's behaviour must not change, and its existing tests must pass unchanged. With no TPM, the counter is nil, and the restore holds as unanchored (today's design).
  - `Options.Newer`: every backup at the destinations, checked with `CheckBackup`, entered as `Verified` only if the check passes.
  - `Layout.ForgetLog`: always set (B6-a).
- **B6-a: `Layout.ForgetLog` and the marker are `<learn dir>/forget-log.json` (R5 (a), #409 L3 delta).**
  - The command's `-learn` flag defaults to agentosd's `-learn` default.
  - `Layout.ForgetLog` is derived from it.
  - The tie must be one a change to either side alone breaks. For example, put the file name and the default learn dir in a leaf package that both binaries import. agentosd must not import `recovery` (ARC-2 list), so the shared package must not be `recovery`.
  - Test: an end-to-end restore whose check holds writes the marker at the path `restoreHold` reads, so `restoreHold(<learn dir>)` refuses.
- **B6-b: agentosd is stopped before the restored tree is renamed into the live state dir (R5 (b)).**
  - agentosd takes an exclusive `flock` on a lock file in its state root at start, and holds it while running (held mode included).
  - The command takes the same lock without blocking before it moves anything into place, and holds it through the rename. It refuses, changing nothing, if the lock is held.
  - The restore itself extracts to a fresh path beside the target (`Restore` already requires dst not to exist). Only the final swap is under the lock.
  - Tests:
    - With the lock held by another process, the command exits non-zero and the live tree is byte-for-byte unchanged.
    - agentosd's start takes the lock, and a second agentosd refuses.
  - The vault process takes the same lock too (L3 on #519, point 3, release). The restored tree includes its root (`Layout.Vault`/`Keys`), so an agentos-egress left running would keep the old vault open and could write it after the swap.
    - Test: with agentos-egress holding the lock, the command refuses and changes nothing.
- **B6-c: the `State.Pending` cross-check is a b1-5 condition, not built here (R5 (c)).**
  - R5 (c) applies "once agentosd can reach the vault", and b1-5 is the package that gives agentosd the vault.
  - It also needs a release record: `answerHeld` releases without the vault, so `State.Pending` stays set after a correct answer (recovery ASSUMPTIONS Q-follow-ups). A cross-check built now would hold every released box again.
  - b1-6b's part, with a test: every held restore the command runs leaves `State.Pending` equal to the marker's reason, so b1-5 has a value to cross-check.
  - The BOARD b1-5 row carries the condition.
- **B6-F4: the learn dir's forget files are trusted only when private (#409 Security L2; #487 handoff f4).**
  - Recommendation: check owner and mode; don't verify or MAC the files in agentosd.
    - A MAC needs the forget key, which lives in the vault and must stay out of agentosd.
    - Verifying against the vault's own log becomes possible with b1-5 (agentosd reaches the vault, `ExportForgetLog`), which should then replace the file as the replay's source. Add that to b1-5's row.
  - Change:
    - `restoreHold` and `readRestoredForgets` refuse to trust the learn dir unless it is owned by agentosd's effective uid and is not group- or other-writable.
    - They refuse `forget-log.json`, `.pending` and `.confirm` unless each is owned by that uid with mode 0600.
    - A refusal fails closed: the start holds, as for an unreadable marker, and the learning plane stays closed.
    - The command writes those files with agentosd's uid and mode 0600, in a 0700 directory.
  - Record the reasoning in agentosd's ASSUMPTIONS: only agentosd's uid (root) can write the learn dir. localui, the modem bridge and the guest bridge run as other uids.
  - Tests:
    - A learn dir that is group-writable: agentosd holds.
    - A `forget-log.json` with mode 0644, or owned by another uid where the test can arrange it: agentosd holds. Use a mode-only test when not root.
    - After a restore, the command's output files have the required owner and mode.
- **B6-H: the owner at the PC learns of a hold from the command, not a held page (#487 UX point 1).**
  - Decision: held mode serves no page on localui.sock. Reasons:
    - The owner who is at the PC right after a restore is the one who ran this command.
    - A page would be a second surface in a box that opens nothing restored (security C3).
    - The answer comes only over the owner's channel (#436 L3 point 4).
  - The command ends by printing the restore's result. For a hold, the output is:
    - the reason;
    - `PendingNotice`;
    - one line that is true in every agentosd configuration (L3 on #519, point 2). Held mode texts only with `-modem-bridge` (`heldMode.Link` is nil otherwise) and an owner number (`heldOwner` errors when there is no `-owner` and setup never finished). The command cannot see either, so it does not promise a text. The fixed line:
      > "The agent stays on hold until the owner answers. It asks by text when it runs with its texting link and knows the owner's number; check both are set up."
    - Recommended over printing the line only when the box will text: that needs the command to read agentosd's flags and setup record, which is more coupling for one line.
  - LATER `W3-forget-b1-7 a` stays later. If the UX lens still wants the page, it is a new release row, not a blocker on this package.
  - Tests:
    - For each pending reason, the output carries the notice and the fixed line exactly.
    - The line takes no input from agentosd's configuration, so it reads the same with no bridge and no owner. Check that the command's source reads no agentosd flag or setup record.
    - A checked restore prints no hold.

**Scope:**
- `broker/cmd/agentos-restore/` (new: main.go, tests, ASSUMPTIONS.md).
- `broker/tpmseal/` (the counter type and its tests).
- `broker/cmd/agentos-egress/trusted.go` (use the moved type; no behaviour change), and its `main.go` for the lock (B6-b).
- `broker/cmd/agentosd/` (`learn.go` for B6-F4, `main.go` for the lock and the held start, their tests, ASSUMPTIONS.md).
- The leaf package for B6-a.
- `broker/daemon/arc2_test.go`, if the import lists need the new binary.
- BOARD.md and LATER.md.

**Needs:** W3-forget-b1-6a.

**Estimate:** about 120k tokens, strongest model (tier A: cmd, tpmseal, recovery state). If the counter move alone passes ~40k, stop and split it out.

## Not in b1-6 (b1-5 owns these)

- **Box.Counter set by the vault process.** The vault process builds no `recovery.Box` today. b1-5 builds one to serve `AppendForget` and `ExportForgetLog`, so it sets `Counter` to the moved tpmseal type, with a test that it is set. W6 must keep it set.
- **R5 (c),** the `State.Pending` cross-check with a release record (B6-c).
- **Replacing the learn dir file with the vault's log** as the replay's source (B6-F4).
- **f3: AEAD destination copies** (#409 Security L1: destination copies are plaintext, so goal IDs, times and take-back flags are readable at the destination). b1-5 makes the backup side's copies, so it chooses the format. b1-6b's reader must then accept it, and b1-5 updates `ReadForgetLogCopy`. The format change must land in every writer of destination copies: the vault process, through `AppendForget`'s return, and W6's backup command, through `DestForgetLog` (L3 on #519, point 4).
- **The forgetLog-nil test:** that production's `ownerForget.forgetLog` stays nil until the restore check is wired, and is set non-nil only together with it (#409 L3 point 3 ordering).

## Gate

Both parts are tier A. Each needs:
- the strongest model;
- L3 with an explicit threat check: a copy truncated or flipped at a destination, an over-size copy, a deleted or planted marker, a restore while agentosd runs, and a key that never reaches the destination reader;
- the lens screen with its Security section.

The UX lens signs off the command's hold output (CH-12: what still works, and that a text follows).
