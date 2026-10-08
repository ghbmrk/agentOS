# W3-forget-b1: Authenticated forget log checked on restore

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b (briefs/W3-forget-b.md); SPEC CAP-3, A8.

**Requirement IDs:**
- **CAP-3** (SPEC): "Deletion requests propagate: the record and everything derived from it leave recall at once." A forget must survive a restore: a backup or machine snapshot made before the forget must not bring the task back.
- **Acceptance:** none of A1–A15 names a forget across a restore. The restore path is A8 (portability and recovery: restore onto a new drive with the recovery key), and the new tests trace to CAP-3 and A8.
- **Security C3:** the lens condition carried on the W3-forget-b row since the split, extending security C2 on #160 (briefs/W3-forget.md: "its reach also covers backups made before the forget and machine snapshots"). It requires an authenticated forget log that is replayed over every restored backup and machine snapshot, with truncation and appended entries detected. A failed check keeps the restore pending and tells the owner.
- **UX F4:** once the replay exists, the done text says what happens to a restored backup in place of part a's caveat (`forgetBackups` in `broker/cmd/agentosd/forget.go`, whose comment records the intent: "a restored backup is forgotten again at once").

**Design (Mark's ruling on #317, 2026-10-08, items 1–3):**
1. **Location:** a copy of the log at every backup destination (`recovery.backupLog`) plus one in the state dir.
2. **Key:** HMAC keyed from the recovery key.
3. **Anchor:** hash-chained entries, anchored to the V6 TPM NV counter (`broker/vault/rollback.go`) where one exists.

**Restore with no anchor** (any restore to a different machine): this part fails closed. The restore stays pending, and the owner is told that the forget log could not be checked on this machine. The owner's confirmation path is W3-forget-b1-4 (ruled, D-065).

**F4 done text (the UX lens's replacement on #317, comment 6067693566, verbatim).** These replace `forgetBackups` and `forgetBackupsOnly`; they keep the older-backups fact, hold on the fail-closed path, and keep the taken-back text within one SMS segment (CH-12):
- **Agent not taken back:** `" Your agent's own files may still hold it. Older backups do too, but restoring one won't bring it back."`
- **Agent taken back:** `" Older backups may still hold it, but restoring one won't bring it back."`

**Needs:** W3-forget-a

**Gate:** tier A: strongest model, explicit threat check (log rollback by restoring an older destination copy, truncation, a forged or replayed entry, key derivation), then the lens screen with its Security section; the UX lens signs off the F4 sentences and the fail-closed text, which needs a CH-12 step: it names what still works (for example, restoring on the original PC) or says nothing can be done until an update (release point, #317).

**Scope:**
- `broker/recovery/`: `backuplog.go` and a new forget-log file, the restore path in `bundle.go`, plus a pending state between extraction and start.
- `broker/vault/rollback.go`: the anchor's counter use.
- `broker/cmd/agentosd/learn.go`: `replayForgotten` and the replay over a restored state.
- `broker/cmd/agentosd/forget.go`: appending to the log on forget, and the F4 text.
- `broker/vm/forget.go`: `restoreTarget`, the snapshots.
- The tests for these files, and the packages' ASSUMPTIONS.md.

**Estimate:** under 150k tokens, strongest model (tier A: recovery-key and vault paths). If the anchor work alone passes ~100k, stop and split it out.
