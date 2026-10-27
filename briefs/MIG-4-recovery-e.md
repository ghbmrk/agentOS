# MIG-4-recovery-e: take backups on the running box (BAK-1), split into e1 to e4

Work item: #3191, slice e of #2865. Tier A. The row is M to L and crosses four trust zones (enrollment and unlock, the kernel log, the kernel process, the owner side), so it splits here, as the row asked. Each slice below is its own work item (e1 #3191, e2 #3250, e3 #3251, e4 #3252) and its own session. This file is the brief for all four; each slice's builder reads the shared part and its own section.

## Shared decisions

1. **The recipient lives in the sealed store.** Only enrollment (and a later REC-4 rotation) holds the recovery key. Enrollment derives `backup.RecipientFor(rk)` and puts its encoding in the sealed store under a new `handoff.RecipientEntry` (`kernel/backup-recipient`), beside `kernel/anchors`. The unlock step reads it and hands it to the kernel on descriptor 3 in `KernelKeys`. It is public, but its integrity matters: a swapped recipient seals every later backup to someone else. The sealed store gives that integrity; a file beside the log would not. A store with no entry (enrolled before e1) hands none, and the kernel then refuses every backup with a fixed reason the owner side shows.
2. **The kernel holds the destinations and does the carrying; the owner side triggers, chooses and tells.** SPEC settles this: a backup target is one of the core's own outbound connections with TLS ending on the core (HW-16), a declared endpoint (HW-17, CLK-14), and the Out rule's fifth exception lets only a kernel component reach it (SPEC.md:546). So a destination is authority (where the box may connect), not a name. It is a tier-4 widening: the owner adds it on the local page with an anchor's signature, and the kernel logs it as a new kind, `TBackupTarget` (name, kind, locator, append-only flag). The kernel process writes each backup straight to the target (`backup.Write` takes the object writer and the `Target`), reads it back and marks it verified itself. The owner side keeps the schedule trigger, the choice page and the only-copy notice. This answers the L3 fix-list on #3255 (issuecomment-6422762339, blocker 1).
3. **One backup per destination.** Each destination gets its own `backup.Write`, so each backup has one `BackupID`, one `Record` and one `Target`. That is the shape #3254's `backup.Set.Add(t Target, rec Record)` takes (one target per backup, `ErrDuplicate` otherwise), and it keeps an append-only target's limits from leaking into another's. Two destinations (BAK-2) are two backups of the same snapshot rule.
4. **The kernel's surface.** Owner-side calls: `backuptarget` (add, with the anchor cosign, the same way `setline` takes one; `kernel/cosign.go`, a `BackupTargetHash` beside `LineHash`), `untarget` (stop new backups to a target, a narrowing, unsigned), `backup` (take one backup now to every current target, return the `Record`s) and `backups` (the current recipient's ID, each target, and the kept `Record`s with their verified marks). There is no owner-reported `verified` call: the kernel reads back, so a lying owner side cannot mark a backup verified (it can still suppress the notice; residual risk 1).
5. **A removed target keeps its erase reach (LOG-4, D-168).** `untarget` stops new backups only. The target stays in the kernel's state, and its backups stay in the `Set`, until every `Record` on it is gone, because an erase must still re-seal the key tables already there. Reaching it to re-seal is still the same declared endpoint, so the Out rule holds.
6. **What counts as a backup (the only-copy notice).** A backup counts only while its `Record.Recipient.ID()` equals the current recipient's ID and the kernel has verified it on a current target. Never by timestamp. A rotation therefore brings the notice back at once, and the owner side's scheduler takes a backup at once when `backups` shows none counting and a target exists (the REC-4 trigger, with no rotation hook in the kernel). The notice also says when only one target counts (BAK-2 asks for two in different failure domains) and names each target that is not append-only (STATUS, per DEV-2 Backups).
7. **Snapshot.** The log is append-only, so the `log` section is the first N bytes of the log file, N read under the kernel's handle before `Write` starts; `Write`'s second open reads the same N bytes (ASSUMPTION MIG-4-recovery-a-7). Each destination's backup reads its own N. Content stores: the kernel opens none yet (`proc/kernel.go`, `OpenContent` with an empty map), so a backup holds `log` and the key table. When a content store lands, its row adds its `content/<store>` section through the same snapshot rule.
8. **Records are kept by the kernel, sealed under the log key.** One file in a kernel-only `-backup-dir`, sealed and synced like the subject-key table, each `Record` with its target's name and its verified mark, so a drive edit cannot swap a `Record`'s recipient, generation or target before an erase re-seals with it. At start the kernel builds a `backup.Set` from these `Record`s and the logged targets and hands it to `Kernel.OpenBackups` (#3254), with the `Set`'s save function writing this file. No spool: the kernel writes to the target directly.
9. **Rate.** One `backup` at a time; a second within ten minutes at the same recipient returns the last `Record`s instead of writing (a rooted owner side cannot fill a target). A changed recipient skips the wait.
10. **Targets the box can reach today.** A second local drive: a `backup.DirTarget` over a mounted directory, opened by the kernel process, kind `dir`. Storage the owner already has needs a kernel-component adapter (TLS ending on the core, put, get, delete and list objects, versions deleted on replace, append-only reported); none exists, so that is its own row, opened when e3 starts. It receives only sealed objects and key tables, never a key. A target whose `AppendOnly()` is true cannot drop a replaced table; the kernel reports it as a target that cannot be rewritten, as D-168 and #3188 already name.

## Lifecycle matrix (integration owner: e4, which wires the running path)

| Stage | Outcome | Slice and test |
|---|---|---|
| First boot (enroll) | the store holds the recipient; the kernel gets it | e1 |
| Box enrolled before e1 | no recipient: `backup` refuses with a fixed reason; the notice says backups cannot start, and names the fix (rotate the recovery key, REC-4) | e1, e3, e4 |
| No target | no backup is taken; notice shown on status, choice page, digest | e4 |
| Target added | anchor-signed widening logged; unsigned or wrongly signed refuses | e2, e4 |
| First backup | kernel writes to each target, reads back, marks verified; notice gone | e3, e4 |
| Restart | targets replay from the log; `Record`s and verified marks survive; the `Set` reaches `OpenBackups` | e2, e3 |
| Daily | one backup a day while a target exists | e4 |
| Write fails or read-back mismatches | no verified mark; notice stays; retried with backoff | e3 (mark), e4 (retry) |
| One target only, or a target not append-only | notice says so | e4 |
| Target removed | no new backups there; its backups stay in the `Set` | e2, e3 |
| Recovery-key rotation (REC-4) | new recipient at the next kernel start; nothing counts; backup at once | e1 (carry), e4 (trigger) |
| Restore | out of scope (#3186); a restored box has no verified backup until its first one | none |
| Erase | #3188 re-seals every backup in the `Set` e3 builds, at its kernel-held target | e3 (`Set` wiring), #3188 |

## e1: the recipient reaches the kernel (#3191)

**Scope:** `broker/cmd/agentos-enroll/main.go` (+test), `broker/cmd/agentos-unlock/main.go` (+test), `broker/clerk/handoff/handoff.go` (+test: `RecipientEntry`, a `Recipient []byte` field in `KernelKeys`, size-bounded and encoded on the wire), `broker/kernel/proc/kernelmain.go` (keeps it; no use yet), their ASSUMPTIONS rows, this brief.
**Requirement IDs:** BAK-1.
**Acceptance tests:**
- BAK-1 recipient at enroll: `cmd/agentos-enroll/main_test.go::TestEnrollStoresTheBackupRecipient`: the store holds `RecipientFor(rk)`'s encoding and no byte of `rk`. Catches a stored private half.
- BAK-1 hand-off: `clerk/handoff/handoff_test.go::TestKernelKeysCarryTheRecipient`: round trip; an oversized or malformed recipient refuses. Catches an unbounded read.
- BAK-1 unlock: `cmd/agentos-unlock/main_test.go::TestUnlockHandsTheRecipient`, and a store without the entry hands an empty one (old boxes still start).
**Guard files:** none (no new package). **Gate:** touches trusted-core files; a D-159 row cites SPEC BAK-1 as the approved design, if `trusted-base` grows.
**Estimate:** 50k tokens.

## e2: the kernel holds the backup targets (#3250)

**Scope:** `broker/kernel` only: the `TBackupTarget` and `TBackupUntarget` log kinds (`log.go`), their state and replay (`state.go`: name, kind, locator, append-only, removed), `Kernel.BackupTarget` (anchor cosign over `BackupTargetHash`, `cosign.go`) and `Kernel.Untarget` (`kernel.go`), and a `State.BackupTargets()` read. Kinds are a closed set, `dir` only for now; the adapter row adds its kind. The kernel package never imports `broker/backup` (#3254's `set.go` imports `kernel`).
**Requirement IDs:** BAK-1, HW-16, HW-17 (a declared endpoint added at tier 4).
**Acceptance tests:**
- `kernel/backuptarget_test.go::TestBackupTargetNeedsAnAnchor`: a phone passkey's, a stale-hash or a missing signature refuses; an anchor's logs it. Catches an owner side widening egress alone.
- `::TestUntargetIsANarrowingAndKeepsTheTarget`: unsigned removal logs; the target stays listed as removed.
- `::TestTargetsReplay`: targets and removals survive a replay; an unknown kind or an oversized locator refuses.
**Needs:** #3254 (it edits `kernel/kernel.go`): start after it merges (D-111, serial kernel lane). **Gate:** D-159 row.
**Estimate:** 70k tokens.

## e3: the kernel takes, writes and verifies a backup (#3251)

**Scope:** new `broker/kernel/proc/backup.go` (+test): the target constructor (kind `dir` to `backup.DirTarget`), the sealed records file, snapshot, rate, the `backup` and `backups` calls, read-back, and the `backup.Set` handed to `Kernel.OpenBackups` at start; the dispatch lines for `backup`, `backups`, `backuptarget` and `untarget` in `kernel/proc/kernelsock.go`; `broker/owner/kernelsock` client methods; `broker/cmd/agentos-kernel/main.go` (`-backup-dir`); the kernel unit's directory lines; `broker/backup` imported by `kernel/proc` (the import rule in `broker/daemon/arc2_test.go` if it lists kernel/proc's imports).
**Requirement IDs:** BAK-1, LOG-4 (the `Set` for #3188).
**Acceptance tests:**
- `kernel/proc/backup_test.go::TestBackupOpensWithTheRecoveryKeyOnly`: a backup taken through the owner socket to a `dir` target opens with `rk` (`backup.Open`, `UnwrapTable`) and holds the log prefix and the live keys.
- `::TestOneBackupPerTarget`: two targets give two `Record`s with distinct IDs, each verified on its own target only.
- `::TestSnapshotIgnoresLaterAppends`: entries appended during `Write` are not in the object and `Write` does not fail with `ErrChanged`.
- `::TestReadBackMismatchIsNeverVerified`: a target that returns other bytes leaves no mark; the next `backup` retries.
- `::TestRecordsSurviveRestartAndRefuseATamperedFile`.
- `::TestEraseResealsAKeptBackup`: after a restart, an erase re-seals a backup through the `Set` this slice builds, a removed target included (the #3188 path, end to end). Catches blocker 2 of the #3255 fix-list.
- `::TestRateAndRecipientChange`; `::TestNoRecipientRefuses`; `::TestAppendOnlyTargetReportedUnrewritable`.
**Needs:** e1, e2, #3254. #3086 edits `kernelsock.go`: start after it merges (D-111). **Gate:** D-159 row.
**Estimate:** 120k tokens.

## e4: choice page, schedule and the only-copy notice (#3252)

**Scope:** owner side only: the choice page (no backup, or a second local drive; the storage adapter row adds its kind) which gathers the anchor's signature on the local page and calls `backuptarget` or `untarget`; the daily scheduler and the at-once trigger of decision 6, with backoff after a failed or unverified backup; the notice on the status page, the choice page and the digest. Files in `broker/cmd/agentosd`, `broker/localui`, `broker/owner`; agentosd edits run serially (D-111).
**Requirement IDs:** BAK-1, BAK-2 (the notice's one-target and append-only lines).
**Acceptance tests:** the matrix rows marked e4, each a test in the touched package: notice present with no target, with no verified backup, after a recipient change, and when the kernel reports no recipient; a one-target line and a not-append-only line; gone after a verified backup on two append-only targets; one backup a day; at once after a recipient change; backoff after a failure.
**Needs:** e3. **Estimate:** 100k tokens.
**Split at build time (two sessions, D-111 serial):** e4a (#3252), the schedule and the STATUS lines, `broker/cmd/agentosd` only; e4b, the choice page with its hardware-key tap and the notice on the status and choice pages (`broker/localapi`, `broker/localsrv`, `broker/localui`, `broker/cmd/agentosd`), its own row. The daily digest is gone (DRB-1), so STATUS carries the digest's part of the notice.

## Unowned gaps (not in e1 to e4)

- **#3253:** BAK-1 says a backup carries the page CA key and the edge key with the revoked-edge record. The kernel holds none of them, so e3 writes those fields empty and records it in `kernel/proc/ASSUMPTIONS.md`. A row decides how they reach the kernel (or how the owner side adds them as a sealed section) before restore (#3186) depends on them.
- **Storage adapter (decision 10):** its own row, opened when e3 starts.

## Residual risks

1. A rooted owner side can stop triggering backups and hide the notice. It cannot add a target, mark a backup verified or remove a target's erase reach. A22's Backups and Data at home parts test the append-only target, which is what survives that attacker.
2. A second local drive is one failure domain with the box against theft and fire; the notice's one-target line says so until a second target exists.
3. A box enrolled before e1 has no recipient until the owner rotates the recovery key.
