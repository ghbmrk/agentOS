# KRN-reseal-unlocked: a backup re-seal's I/O runs outside the kernel lock

Work item: #3317. Tier A. Release finding from #3311 (Security finding 2, comment 6429141978; scope addition from the delta Security review, comment 6430035480).

## Goal

KRN-7: STOP never waits on a slow external party. Since #3311 the kernel process re-seals older backups (D-168) under the kernel lock: in `Erase`, in `OpenBackups` on every `Tick`, and after a backup's first table lands. Each re-seal does I/O at the backup's target, so a hung target (a dying USB drive in D state) holds the lock and STOP with it.

1. **Split the re-seal.** Under the lock, `kernel.Reseals` takes what each due re-seal needs (`Backups.Prepare`: the record, the live keys, the erased subjects). Without the lock, the holder runs the I/O (`Reseal.Run`, `backup.Rewrap`'s target work). Under the lock again, `kernel.Resealed` commits it (saves the new Record) and keeps the backoff as it was. A backup is handed out once until it is back, so two re-seals of one table never race.
2. **No kernel call does backup I/O in place** except `kernel.Tick` (`ResealBackups`), which the kernel process does not use. `Erase` names the backups that give the subject's key; `Confirm` reports them once re-sealed. `OpenBackups` only sets the list.
3. **The kernel process** (`proc.Kernel`) runs each re-seal on its own goroutine: `Tick` starts them without waiting, so a hung target holds neither Tick nor STOP; `Erase` and `Backup` wait for theirs, so a hung target delays their reply, never STOP.
4. **The in-flight guard** that refuses a backup's target while its first table is on its way becomes an atomic flag, since the re-seal I/O that reads it now runs without the lock.

## Scope

- `broker/kernel/erase.go`, `kernel.go`, `erase_backup_test.go`, `ASSUMPTIONS.md`.
- `broker/backup/set.go`, `table.go`, `backup.go`, `set_test.go`, `ASSUMPTIONS.md`.
- `broker/kernel/proc/kernel.go`, `backup.go`, `backup_test.go`, `content_test.go`, `reseal_test.go`, `ASSUMPTIONS.md`.
- `briefs/KRN-reseal-unlocked.md`.

**Guard files:** none. The change grows the trusted core (`broker/kernel`, `broker/backup`), so the PR needs a `Trusted-core:` line naming a D-159 row.

## Acceptance tests

- KRN-7: `broker/kernel/proc/reseal_test.go::TestAnEraseAtAHungTargetNeverHoldsStop` (Security's repro on #3311).
- KRN-7: `broker/kernel/proc/reseal_test.go::TestATickAtAHungTargetNeverHoldsStop` (the scope addition).
- KRN-7: `broker/kernel/erase_backup_test.go::TestAResealRunsOnlyWhereItsHolderRunsIt`.
- LOG-4: the existing backup re-seal tests in `broker/kernel`, `broker/backup` and `broker/kernel/proc` pass unchanged in what they assert.

## Estimate

About 60k tokens, single session.
