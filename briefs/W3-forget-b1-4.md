# W3-forget-b1-4: Owner confirms a restore with no anchor

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md); SPEC CAP-3, A8.

**Requirement IDs:** CAP-3 and A8, as in W3-forget-b1; security C3's "a failed check keeps the restore pending and tells the owner", for a restore with no anchor.

**Design (Mark's ruling on #317, 2026-10-08, item 4):** with no anchor (any restore to a different machine, since a new PC's TPM has no record of the old counter), the restore stays pending until the owner confirms by answering a multiple-choice text of last-forget dates, spaced far apart, with exactly one correct. The text shows only dates, never forgotten content.

**Escalated: an open point, not yet ruled (raised on #317).** The box knows only the restored log's last date. If the backup is stale, the owner's real last forget is not among the options, so the text also needs a "more recent than all of these" choice, and "no forgets" where the log is empty. Any answer other than the restored date keeps the restore pending. Build only after the ruling's DECISIONS.md row lands (decision-queue PR).

**Needs:** W3-forget-b1; the DECISIONS.md row for the open point.

**Gate:** tier A, as in W3-forget-b1; the UX lens signs off the confirmation text.

**Scope:** the pending-restore state from W3-forget-b1 in `broker/recovery/`; the owner text and reply handling in `broker/cmd/agentosd/`; their tests and ASSUMPTIONS.md.

**Estimate:** under 100k tokens, strongest model (tier A).
