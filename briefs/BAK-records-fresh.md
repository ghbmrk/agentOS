# BAK-records-fresh: the log names every backup, so a rolled-back records file cannot hide one from an erase (LOG-4, BAK-1)

Work item: #3316, release finding 1 of #3311's L3 review (comment 6429067559; ASSUMPTION MIG-4-recovery-e3-b in `broker/kernel/proc/ASSUMPTIONS.md`). Tier A.

## The gap

`broker/kernel/proc/backup.go` keeps every backup's `Record` in one file, `records`, sealed under the log key. At start `openBackups` builds the erase's `backup.Set` from that file alone. The seal gives integrity, not freshness: a writer of `/var/lib/agentos-kernel` can put back an older sealed `records`, or delete it (a missing file loads as empty). A backup taken after that copy then drops out of the `Set`. A later erase neither re-seals it nor names it, and its key table still gives the erased subject's key to whoever holds the recovery key (LOG-4: "the confirmation names any it cannot").

## Decisions

1. **The log names every backup before its key table leaves.** A new entry `backup.taken {backup_id, target, recipient, created, upto}` (version 1, in `broker/kernel/backuptarget.go` beside `backup.target`) is written, then anchored (`Log.Anchor`), in `pendingPut.PutTable` under the kernel lock, before the pending `Record` is saved and before the put. `recipient` is the full public `backup.Recipient` (X25519 and ML-KEM-768 keys, about 1.2 KB), because a backup from before a recovery-key rotation re-seals to its own recipient, which the store no longer holds. `upto` is the log head's sequence number in the backup's snapshot (`backupSnap`), so the subjects the backup's first table can give are exactly those whose `subject.opened` has a sequence number at or below it. The entry carries no subject list, which would grow the log by every live subject on every backup. If the write or the anchor fails, nothing is saved or sent and that target's `Taken` carries the error, as a failed record save does today.
2. **The entry is not widening.** It grants nothing, and it must survive `Open` unanchored, so a crash after the write keeps it. The fold refuses an entry whose target the log never added, whose ID is not a backup ID or is already taken, or whose recipient keys have the wrong size.
3. **At start the `Set` is the union of the log and `records`.** `openBackups` reads `State().BackupsTaken()`. A taken backup that `records` lacks is rebuilt: its `Record` gets the logged ID, recipient and creation time, `Generation` 0 (`backup.Rewrap` already takes the highest listed generation), and as `Subjects` every subject opened at or below `upto`, whatever the key table holds now. The key files sit beside `records` and can be deleted with it, so they cannot narrow the list; a live subject whose key is missing makes the re-seal fail, and the erase names the backup held (#3367 L3 and Security). The rebuilt `Kept` is unverified, carries a new `Rebuilt` mark that the `backups` answer shows, and is saved to `records`. From then on it behaves like a pending backup: an erase re-seals it, or names it in `StillHeld` with why, and Tick retries it. No change to `broker/backup` or `broker/kernel/erase.go`'s re-seal.
4. **A record the log does not name is logged at start.** This happens only when the log lost an entry `records` kept (a log rollback the anchors did not catch), or for records written before this build. `Kept` gains `Upto`, saved with the pending record, so the start logs the same entry. A record with no `Upto` (pre-build) is logged with the current head as `upto`, a superset of its subjects, recorded as a limit. A record is never dropped, so the `Set` only grows. Retention is its own row, and it will need a `backup.dropped` entry so a rebuilt start does not bring a dropped backup back.
5. **No alert on a rebuilt backup.** A crash between decision 1's log write and its record save also leaves a logged backup missing from `records`, so a rebuild is not proof of tampering. The `Rebuilt` mark is visible. A security text for it is a later choice, not this row's.

## Lifecycle (integration owner: this package)

| Stage | Outcome |
|---|---|
| Backup taken | `backup.taken` logged and anchored, then the pending record is saved, then the table goes out |
| Log write or anchor fails | nothing saved, nothing sent; `Taken.Error` |
| Crash after the log write, before the record save | start rebuilds it; no table at the target, so an erase over it acts as today's pending backup does |
| `records` rolled back or deleted | start rebuilds every logged backup it lacks; an erase re-seals or names each |
| Log rolled back past an entry, `records` not | start logs the record's entry again from its `Upto` |
| Restart after a rebuild | nothing is rebuilt or logged twice |
| Restore (#3186) | not this row; the restored log's entries name the backups the old box took |

## Scope

`broker/kernel/backuptarget.go` (entry, fold, `Kernel.BackupTaken`, `State().BackupsTaken()`, a helper for subjects opened at or below a sequence number), `broker/kernel/state.go` (the schema line only), `broker/kernel/rederive.go` (`recorded`), `broker/kernel/erase.go` (the sequence number at which each subject was opened: one field and its assignment), `broker/kernel/backuptarget_test.go`, `broker/kernel/proc/backup.go` (decisions 1, 3 and 4; `Kept.Upto`, `Kept.Rebuilt`, `BackupView.Rebuilt`), `broker/kernel/proc/backup_test.go`, both packages' `ASSUMPTIONS.md` (rewrite MIG-4-recovery-e3-b's limit), and this brief.

**Requirement IDs:** LOG-4, BAK-1, LOG-1, LOG-5.

**Acceptance tests:**
- LOG-4, the issue's failure path: `kernel/proc/backup_test.go::TestRolledBackRecordsStillReachEveryBackup`. Take B1, copy `records`, take B2 giving subject S, put the copy back, restart, erase S: B2's table at the target no longer gives S, and the confirmation lists B2 in `Resealed`. Catches the rollback hiding B2.
- LOG-4: `TestDeletedRecordsRebuildFromTheLog`. The same, with `records` deleted.
- LOG-4: `TestRebuiltBackupOffTargetIsNamedHeld`. B2's target unreachable after the rollback: the erase names B2 in `StillHeld`.
- LOG-4: `TestNoTableLeavesWithoutItsEntry`. A failing log write, and separately a failing anchor: no record saved, no table at the target, `Taken.Error` set.
- LOG-4: `TestCrashBetweenEntryAndRecord`. Entry logged, record save fails: the restart rebuilds it, and nothing is rebuilt twice on the next restart.
- LOG-4: `TestRecordAheadOfLogIsLoggedAtStart`. A record whose entry the log lacks is logged once with its `Upto`, and not again on the next start.
- BAK-1: `TestRebuiltBackupKeepsItsRecipient`. After a recovery-key rotation, a rebuilt backup's re-sealed table opens with the old recipient, not the new one.
- LOG-4: `TestRebuildIgnoresDeletedKeyFiles`. Roll back `records` and delete the key files: B2 is rebuilt with every subject opened by its snapshot, and the erase names it in `StillHeld`. Catches a rebuild that trusts the key table.
- LOG-4: `TestRebuiltSubjectsStopAtUpto`. A subject opened after B2's snapshot is never put in B2's re-sealed table. Catches a rebuild that hands newer keys to an old recipient.
- LOG-5: `kernel/backuptarget_test.go::TestBackupTakenIsKnownAndNotWidening`. The entry is known at v1, not widening, and kept unanchored by `Open`; an unknown target, a duplicate ID, a malformed ID and short recipient keys are each refused.
- LOG-1: `kernel/backuptarget_test.go::TestBackupsTakenRebuildFromEmpty`. A replay from empty equals the live `BackupsTaken()`.

**Needs:** #3311 (merged). **Serial (D-111):** `kernel/proc/backup.go` is also in MIG-4-recovery-f1's scope (#3253), and KRN-reseal-unlocked (#3317) moves the re-seal out of the lock through `broker/kernel` (`erase.go`) and the process's Tick and backup paths. Build this only while neither has an open PR, after both in either order. **Guard files:** none (no new package or import). **Gate:** trusted-core growth, so a one-row D-159 PR names LOG-4 and this brief before the build PR (D-159 rule 3).
**Estimate:** about 80k tokens, one session: some 150 lines of code and 350 of tests. Checkpoint at 110k.

## Residual risks

1. The fix is as fresh as the log. A log rolled back to a head no anchor contradicts (no TPM, and no owner-page step yet) loses a `backup.taken` too. That is the log's own STO-1 limit, and decision 4 covers it whenever `records` was not also rolled back.
2. A pre-build record logged with the current head as `upto` (decision 4) can, if later rebuilt, have newer live keys added to its table. Only records written between e3's merge (#3311, 2026-10-26) and this build can lack `Upto`.
