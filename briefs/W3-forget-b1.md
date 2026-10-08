# W3-forget-b1: Authenticated forget log checked on restore

Board section: Integration: wiring merged packages into the box.

Part b1 of W3-forget-b: the authenticated forget log replayed over restored backups and machine snapshots, truncation and appends detected; a failed check keeps the restore pending and tells the owner (security C3); then the done text gains its detected backups sentence, replacing part a's "Older backups and your agent's own files may still hold it" (UX F4).

**Design (Mark's ruling on #317, 2026-10-08, accepting the builder's proposal with one change):**
1. Location: a copy of the log at every backup destination (`recovery.backupLog`) plus one in the state dir.
2. Key: HMAC keyed from the recovery key.
3. Anchor: hash-chained entries, anchored to the V6 TPM NV counter (`vault/rollback.go`) where one exists.
4. No anchor (any restore to a different machine): the restore stays pending until the owner confirms by a multiple-choice text of last-forget dates, spaced far apart, exactly one correct; only dates are shown, never forgotten content.

**Open point, not yet ruled (raised on #317):** for a stale backup the owner's real last forget is not among the options, so the text also needs a "more recent than all of these" choice (and "no forgets" where the log is empty); any answer other than the restored date keeps the restore pending. Confirm the ruling's DECISIONS.md row (decision-queue PR) before building item 4.

Out of scope: the backup-delete pointer (waits on P2-2w d).

**Precondition:** W3-forget-a

**Owner:** Next build item B

**State:** queued
