# MIG-4-recovery-e: take backups on the running box (BAK-1), split into e1 to e4

Work item: #3191, slice e of #2865. Tier A. The row is M to L and crosses four trust zones (enrollment and unlock, the kernel process, the owner side, a storage adapter), so it splits here, as the row asked. Each slice below is its own work item (e1 #3191, e2 #3250, e3 #3251, e4 #3252) and its own session. This file is the brief for all four; each slice's builder reads the shared part and its own section.

## Shared decisions

1. **The recipient lives in the sealed store.** Only enrollment (and a later REC-4 rotation) holds the recovery key. Enrollment derives `backup.RecipientFor(rk)` and puts its encoding in the sealed store under a new `handoff.RecipientEntry` (`kernel/backup-recipient`), beside `kernel/anchors`. The unlock step reads it and hands it to the kernel on descriptor 3 in `KernelKeys`. It is public, but its integrity matters: a swapped recipient seals every later backup to someone else. The sealed store gives that integrity; a file beside the log would not. A store with no entry (enrolled before e1) hands none, and the kernel then refuses every backup with a fixed reason the owner side shows.
2. **The kernel seals; the owner side schedules, chooses and carries.** The kernel process is the only holder of the subject-key table (`proc.FileKeys`), so it calls `backup.Write`. Everything else is owner-side: the destination choice, the schedule, the upload and the notice. The issue said the choice is rebuilt "on the kernel log"; this brief puts it in the owner side instead, because the destination is a name with no secret and no authority, and a rooted owner side can already skip any upload or hide any notice, so a kernel-held choice protects nothing and would add a kernel log kind on the serial kernel lane. A reviewer who disagrees raises it at the brief, not at the build.
3. **The kernel's surface is two owner-side calls.** `backup` takes one backup now and returns its `Record`; `backups` returns the current recipient's ID and the kept `Record`s, each with its verified destinations. A third, `backup-verified {backup_id, destination, content_sha256, table_sha256}`, records that the owner side read an upload back; the kernel accepts it only when the sums match a kept `Record` sealed to the current recipient. A lying owner side can only suppress the notice, which it can do anyway by not rendering it (residual risk 1).
4. **What counts as a backup (the only-copy notice).** A backup counts only while its `Record.Recipient.ID()` equals the current recipient's ID and it has at least one verified destination. Never by timestamp. A rotation therefore brings the notice back at once, and the owner side's scheduler takes a backup at once when `backups` shows none counting and a destination is chosen (the REC-4 trigger, with no rotation hook in the kernel).
5. **Snapshot.** The log is append-only, so the `log` section is the first N bytes of the log file, N read under the kernel's handle before `Write` starts; `Write`'s second open reads the same N bytes (ASSUMPTION MIG-4-recovery-a-7). Content stores: the kernel opens none yet (`proc/kernel.go`, `OpenContent` with an empty map), so a backup holds `log` and the key table. When a content store lands, its row adds its `content/<store>` section through the same snapshot rule.
6. **Records are kept by the kernel, sealed under the log key.** One file in a kernel-only `-backup-dir`, sealed and synced like the subject-key table, so a drive edit cannot swap a `Record`'s recipient or generation before slice d (#3188) re-wraps with it. The spool is a subdirectory readable by the owner side's group only: it holds the sealed objects, nothing else. The kernel keeps the newest backup's objects in the spool and deletes older ones once a newer one is written; `Record`s outlive their spool objects, since the destination still holds them.
7. **Rate.** One `backup` at a time; a second within ten minutes at the same recipient returns the last `Record` instead of writing (a rooted owner side cannot fill the drive). A changed recipient skips the wait.

## Lifecycle matrix (integration owner: e3, which wires the running path)

| Stage | Outcome | Slice and test |
|---|---|---|
| First boot (enroll) | the store holds the recipient; the kernel gets it | e1 |
| Box enrolled before e1 | no recipient: `backup` refuses with a fixed reason; the notice says backups cannot start, and names the fix (rotate the recovery key, REC-4) | e1, e3 |
| Restart | `Record`s and verified marks survive; spool object kept | e2 |
| No destination chosen | no backup is taken; notice shown on status, choice page, digest | e3 |
| Destination chosen, first backup | kernel writes spool; owner side uploads, reads back, reports verified; notice gone | e2, e3, e4 |
| Daily | one backup a day while a destination is chosen | e3 |
| Upload fails or read-back mismatches | no verified mark; notice stays; retried with backoff | e4 |
| Recovery-key rotation (REC-4) | new recipient at the next kernel start; nothing counts; backup at once | e1 (carry), e3 (trigger) |
| Restore | out of scope (#3186); a restored box has no verified destination until its first upload | none |
| Erase | slice d re-wraps using the kept `Record` | #3188 |

## e1: the recipient reaches the kernel (#3191)

**Scope:** `broker/cmd/agentos-enroll/main.go` (+test), `broker/cmd/agentos-unlock/main.go` (+test), `broker/clerk/handoff/handoff.go` (+test: `RecipientEntry`, a `Recipient []byte` field in `KernelKeys`, size-bounded and encoded on the wire), `broker/kernel/proc/kernelmain.go` (keeps it; no use yet), their ASSUMPTIONS rows, this brief.
**Requirement IDs:** BAK-1.
**Acceptance tests:**
- BAK-1 recipient at enroll: `cmd/agentos-enroll/main_test.go::TestEnrollStoresTheBackupRecipient`: the store holds `RecipientFor(rk)`'s encoding and no byte of `rk`. Catches a stored private half.
- BAK-1 hand-off: `clerk/handoff/handoff_test.go::TestKernelKeysCarryTheRecipient`: round trip; an oversized or malformed recipient refuses. Catches an unbounded read.
- BAK-1 unlock: `cmd/agentos-unlock/main_test.go::TestUnlockHandsTheRecipient`, and a store without the entry hands an empty one (old boxes still start).
**Guard files:** none (no new package). **Gate:** touches trusted-core files; a D-159 row cites SPEC BAK-1 as the approved design, if `trusted-base` grows.
**Estimate:** 50k tokens.

## e2: the kernel takes a backup (#3250)

**Scope:** new `broker/kernel/proc/backup.go` (+test): spool, sealed records file, snapshot, rate, the three calls; the dispatch lines in `kernel/proc/kernelsock.go`; `broker/owner/kernelsock` client methods; `broker/cmd/agentos-kernel/main.go` (`-backup-dir`, `-spool-gid`); the kernel unit's directory lines; `broker/backup` imported by `kernel/proc` (the import rule in `broker/daemon/arc2_test.go` if it lists kernel/proc's imports).
**Requirement IDs:** BAK-1, LOG-4 (records for #3188).
**Acceptance tests:**
- `kernel/proc/backup_test.go::TestBackupOpensWithTheRecoveryKeyOnly`: a backup taken through the owner socket opens with `rk` (`backup.Open`, `UnwrapTable`) and holds the log prefix and the live keys.
- `::TestSnapshotIgnoresLaterAppends`: entries appended during `Write` are not in the object and `Write` does not fail with `ErrChanged`.
- `::TestRecordsSurviveRestartAndRefuseATamperedFile`.
- `::TestVerifiedNeedsMatchingSumsAndTheCurrentRecipient`: wrong sum, unknown ID, or an old recipient's backup is refused.
- `::TestRateAndRecipientChange`; `::TestNoRecipientRefuses`; `::TestSpoolKeepsOnlyTheNewestObjects`.
**Needs:** e1. #3086 edits `kernelsock.go`: start after it merges (D-111). **Gate:** D-159 row.
**Estimate:** 110k tokens.

## e3: destination choice, schedule and the only-copy notice (#3251)

**Scope:** owner side only: the choice page and its setting (no backup, a second local drive, or storage the owner already has, a name only), the daily scheduler and the at-once trigger of decision 4, the notice on the status page, the choice page and the digest. Files in `broker/cmd/agentosd`, `broker/localui`, `broker/owner`; agentosd edits run serially (D-111).
**Requirement IDs:** BAK-1.
**Acceptance tests:** the matrix rows marked e3, each a test in the touched package: notice present with no destination, with no verified backup, after a recipient change, and when the kernel reports no recipient; gone after a verified backup; one backup a day; at once after a recipient change.
**Needs:** e2. **Estimate:** 100k tokens.

## e4: upload, read-back and version deletion (#3252)

**Scope:** an uploader on the owner side that copies the spool's objects to the chosen destination, fetches each back and checks its SHA-256 against the `Record`, deletes every version of an object it replaces (slice a, residual risk 2), and reports `backup-verified`. A second local drive first (a `backup.Target` over a mounted directory). Storage the owner already has needs a storage adapter that can put, get and delete objects; none exists, so that half is its own row, opened when e4 starts.
**Requirement IDs:** BAK-1.
**Acceptance tests:** read-back mismatch is never reported verified; an upload interrupted midway leaves no verified mark and retries; a replaced object leaves no older version on a versioning fake.
**Needs:** e2 (e3 for the destination). **Estimate:** 80k tokens.

## Unowned gap (#3253, not in e1 to e4)

BAK-1 says a backup carries the page CA key and the edge key with the revoked-edge record. The kernel holds none of them, so e2 writes those fields empty and records it in `kernel/proc/ASSUMPTIONS.md`. A row decides how they reach the kernel (or how the owner side adds them as a sealed section) before restore (#3186) depends on them.

## Residual risks

1. A rooted owner side can suppress uploads and hide the notice. The kernel cannot stop it; A22's Backups and Data at home parts test the append-only target, which is what survives that attacker.
2. The spool is on the same drive as the log; it is never a backup by itself, and decision 4 never counts it.
3. A box enrolled before e1 has no recipient until the owner rotates the recovery key.
