# KRN-content-backup: content/<store> sections in backups, and their restore (BAK-1, LOG-4)

Work item: #3559, the release finding of KRN-content (#3550, ASSUMPTION KRN-content-3). Tier A.

## The gap

Since KRN-content the kernel process keeps sealed items in file stores under `-content-dir`, but `Kernel.Backup` writes only the `log` section. A restore brings back every subject and its key and none of its items, so after a core SSD loss every enrolled face shows as `unknown` (BAK-1).

## Decisions

1. **Taken under the lock.** `backupSnap` takes every item a live subject's logged items name, in each store, by hard link into a fresh `snap-*` directory in the backup directory (a copy where the link fails), so an erase during the write cannot take a file from under it and STOP waits on no item copy where the link works. An erased subject's items are never taken. The snapshot goes after the writes; one a stop left goes at the next start.
2. **One section per store.** `content/<store>`, its items in hash order, each framed as SHA-256 (32 bytes), length (4 bytes, big-endian) and ciphertext. A missing item, or one whose bytes are not its hash's, is left out, so one damaged file never makes a backup that does not restore.
3. **Restore stages, then moves.** `RestoreSections` reads an opened content object: the log section to a writer, each store's items into a staging directory beside the content folder, moved into place only once the object ends whole (MIG-4-recovery-a-6), onto an absent or empty folder. It refuses a bad hash, an over-long or cut frame, a repeated item and a store name a file store does not take (a-10).
4. **Erases are re-applied before a read.** `kernel.OpenContent` deletes again any item of an erase already confirmed, so an erase newer than the backup reaches the restored files at start, before content opens (LOG-4).
5. **Erase reach unchanged.** Items are sealed under subject keys; the backup's key table is re-sealed without an erased subject's key.
6. **Not this row.** Which log a restored box starts on, its check against the anchors and the hold on newer erases are the restore row's (#3186), which calls `RestoreSections`.

## Scope

`broker/kernel/erase.go` (`OpenContent`), `broker/kernel/proc/` (`backup.go`, `restore.go`, tests, `ASSUMPTIONS.md`), this brief.

**Requirement IDs:** BAK-1, LOG-4.

**Gate:** none. `broker/kernel` and `broker/kernel/proc` are trusted core, so the PR names a one-row D-159 decision in its `Trusted-core:` line.

## Acceptance tests

- BAK-1: `kernel/proc/contentbackup_test.go::TestARestoredBackupReadsItsItemBack`: a backup after a seal, restored onto an empty drive, reads the item through `readfor`; a subject erased before the backup has no item restored. *Mutant:* the log section alone.
- LOG-4: `TestAnEraseAfterTheBackupReachesTheRestoredItem`: an erase newer than the backup deletes the restored file at start and `readfor` is `ErrErased`. *Mutant:* no re-delete in `OpenContent`.
- BAK-1: `TestTheSnapshotHoldsItsItems` (link and copy): a store file removed during the write is still carried; a damaged one is left out. *Mutants:* sections read from the store directory; no hash check in `itemsReader`.
- BAK-1: `TestARestoreRefusesContentThatIsNotWhole`: each bad frame, a bad store name and a non-empty folder are refused and leave nothing. *Mutants:* each check dropped; items written straight into place.
- `TestALeftSnapshotIsRemovedAtStart`.
