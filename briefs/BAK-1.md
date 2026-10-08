# BAK-1: Backup choice and the only-copy notice

Board section: Phase 2: real hardware (cloud parts).

Backup choice and the only-copy notice: the owner chooses no backup, a second local drive, or storage they already have (tier-4, a name only, never a sign-in); until a backup verified under the current recovery key exists, the status page, the choice page and the digest (weekly, monthly after choosing none) say plainly that the drive is the only copy (BAK-1) ([assumptions](../broker/recovery/ASSUMPTIONS.md#backup-choice-bak-1)). A backup counts only while its sealed-to key matches the drive's, never by timestamp (security C1). Follow-ups: the wiring shows the choice page and notices; the upload goes through the storage adapter's grant, egress-checked to accept only a stream hashing to the receipt's sum, with the read-back fetched again by that adapter and the destination name taken from the grant (security W1); a recovery-key change starts a backup at once when a destination exists (potency PB2); a stale backup brings the notice back (L3 on #80); before release, from the #80 review: refuse letter-and-digit tokens next to a code word and JWTs in destination names, refuse look-alike scripts (NFKC or a single-script rule), count the 200-character limit in runes, and migrate or treat as unknown log entries with no key ID (they now read as old-card backups)

**Needs:** P2-8

**State on the board before the 2026-10-08 index split:** merged (#80)
