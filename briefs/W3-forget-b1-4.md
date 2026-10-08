# W3-forget-b1-4: Owner confirms a restore with no anchor

Board section: Integration: wiring merged packages into the box. Part of W3-forget-b1 (briefs/W3-forget-b1.md); SPEC CAP-3, A8.

**Requirement IDs:** CAP-3 and A8, as in W3-forget-b1; security C3's "a failed check keeps the restore pending and tells the owner", for a restore with no anchor.

**Design (Mark's ruling on #317, 2026-10-08, item 4, and comment 6067625766; ruled, D-065):** with no anchor (any restore to a different machine, since a new PC's TPM has no record of the old counter), the restore stays pending until the owner answers a multiple-choice text. Its choices:
- the restored log's last-forget date (the correct answer);
- decoy dates, spaced far apart;
- "later than all of these";
- "never" (no forgets).

Every date uses the same format and precision as the real date, so the correct option can't be picked out by how it looks. The text shows only dates, never forgotten content. Any answer other than the restored log's own date keeps the restore pending: the owner is told the backup predates the last forget and is offered a newer backup if one exists. A same-machine restore with a TPM anchor needs no text.

**Needs:** W3-forget-b1; D-065 (#406). Must land before A8 and gate G3 (the first release): between b1 and this package, a restore onto a new PC with the recovery key stays pending with no way forward, so b1 does not ship alone.

**Gate:** tier A, as in W3-forget-b1; the UX lens signs off the confirmation text.

**Scope:** the pending-restore state from W3-forget-b1 in `broker/recovery/`; the owner text and reply handling in `broker/cmd/agentosd/`; their tests and ASSUMPTIONS.md.

**Estimate:** under 100k tokens, strongest model (tier A).
