# W5-Dc-r9: Dead digest batches cannot fill the queue (CH-15, OP-9, CAP-3)

Release finding on #592 (W5-Dc, merged a818e20), the builder's own. BOARD row W5-Dc-r9. Builds on W5-Dc-r7 (#612, merged da7ee11), which made a forget redact an Unknown batch whole and keep it.

SPEC rows: CH-15 (the daily digest is always sent), OP-9 (STATUS and the digest name a lost capability while it lasts), CAP-3 (a forgotten record leaves at once and is never revived).

**Today.** `Enqueue` returns `ErrFull` once `len(Batches) >= MaxBatches` (agentosd: 128) or the saved state passes `MaxBytes` (8 MiB). Two kinds of batch never leave the queue:
- **Unknown.** `begin` refuses it, nothing resends it (OP-2), `Compact` keeps it (not terminal), and `Forget` only redacts it (W5-Dc-r7).
- **Held after late.** A Ready batch with every source acknowledged that `Late` re-armed once and that passed its new expiry again: `begin` refuses it (expired), `Late` refuses it (already late), `Expire` keeps it (sources consumed), `Compact` keeps it (not terminal). Only a `Forget` of one of its references removes it.

Neither can ever be sent again; each is kept only so agentosd can name it (`digestUnknownStatus`/`digestHeldStatus` on STATUS, `digestUnknownLine`/`digestHeldLine` in a later digest). With one such batch a day (a modem that times out every day), the 129th day's `Collect` gets `ErrFull`, agentosd marks the day owed and retries for ever, and no digest goes again: CH-15 broken, and the outage looks like an owed collection.

**Decision: `Enqueue` evicts the oldest dead batch when, and only when, the new batch would not otherwise fit.** Record it as an assumption in digestqueue ASSUMPTIONS.
- *Dead* = `Unknown` (redacted or not), or `Ready && Late && !created.Before(Expires)` with `created` the new batch's creation time (the caller's now; `Collector.Collect` passes it). Nothing else: Ready, Sending, terminal and Held-not-yet-late batches are never evicted here (terminal ones are `Compact`'s).
- Eviction runs on the new state: while it holds more than `MaxBatches` batches or its JSON passes `MaxBytes`, remove the lowest-ID dead batch. If none is left and it still does not fit: `ErrFull`, nothing changed (as today). The eviction and the admission commit in one save.
- `Seq` and every `Latest` entry stay, so an evicted batch is never revived: a re-offer of its exact generation is `ErrRetired` (ledger points at a missing batch), an older one `ErrConflict`. Its sources are all acknowledged (validate requires it for Unknown; `Late` requires it), so no source is wedged.
- Why this rule (CH-15 > keeping an old notice): the queue keeps every dead batch as long as it possibly can, so its STATUS line and digest line stay true while it exists (OP-9), and drops one only when the alternative is refusing today's digest. Oldest first: its line is the one most likely already carried, and STATUS still reads true while any other dead batch remains.
- CAP-3: eviction removes text, never adds or resends it. A redacted Unknown batch is evicted like any other.
- Rejected:
  - Age-based retention in `Compact(now)`: needs a clock in `Compact`, an agentosd change, and a horizon SPEC does not give; and more than `MaxBatches` dead batches within the horizon would still fill the queue.
  - A caller `Retire(id)` once the line is carried (agentosd `Done`): needs agentosd wiring in a file two other packages are editing, and a carrier that keeps going Unknown never makes `Done`, so the queue still fills.
  - Moving dead batches to `Cancelled`: claims not sent (CH-12), loses the status line (rejected in W5-Dc-r7 too).

**Requirements** (local IDs):
- **QC-1 (CH-15), a full queue of dead batches still admits.** With `MaxBatches` batches all Unknown, or all held after late, or a mix, `Enqueue` admits the new batch and removes exactly the oldest dead one; the rest stay with their state. Full-queue test at agentosd's 128.
- **QC-2 (OP-9), eviction only when needed and only of dead batches.** With room, no batch is removed. A full queue of live batches (Ready not past expiry, Sending, Ready late but not yet past its new expiry, late and Sending past it) is `ErrFull` with the store bytes unchanged. Among dead batches the lowest ID goes first.
- **QC-3 (CAP-3), an evicted batch is never revived or resent.** Its text is gone from the store; `Seq` and `Latest` are kept; a re-offer of its exact snapshot is refused (`ErrRetired`); a redacted Unknown batch is evicted the same way.
- **QC-4 (CH-15), the byte bound too.** When the new batch fits the count but not `MaxBytes`, dead batches are evicted until it fits; if none remain, `ErrFull` unchanged.
- **QC-5 (CH-15, OP-9), agentosd end to end.** In the digest rig, with every send Unknown for 130 days, a digest goes every day, the queue never passes 128 batches, and STATUS reads `digestUnknownStatus` throughout.

**Tests first.** Queue tests in a new `broker/digestqueue/capacity_test.go`; agentosd test in a new `broker/cmd/agentosd/digest_capacity_test.go` (new file, so no conflict with #617 or W5-Dc-r12). Each red at main, markers `REQ: CH-15 (W5-Dc-r9 QC-1)` and so on. Mutants to kill: no eviction; eviction of any batch; newest-first; held-late without the expiry check; eviction with room; no byte loop.

**Out of scope.** `Compact` blocked by `owesFailed` (agentosd) while an exhausted batch's line is uncarried; Failed batches; retention of terminal batches; W5-Dc-r1a/r1b/r12, W3-forget-*.

**Scope:**
- `broker/digestqueue/queue.go` (`Enqueue` and one helper), `broker/digestqueue/capacity_test.go`, `broker/digestqueue/ASSUMPTIONS.md`.
- `broker/cmd/agentosd/digest_capacity_test.go` (new). No `digest.go` change is needed.
- `briefs/W5-Dc-r9.md`, `BOARD.md` row W5-Dc-r9 (and a new row for any release finding).

**Needs:** W5-Dc (#592), W5-Dc-r7 (#612).

**Done:** CI green; QC-1 to QC-5 covered by passing tests with markers; risk tier A expected (`broker/digestqueue`, `broker/cmd`).

## Delivery

Builder model: the session's model. Estimate/checkpoint: about 60k tokens, not a ceiling. Review: L3 on the strongest model with a threat check (no path revives or resends an evicted batch; eviction cannot drop a sendable batch; the admission and eviction are one save).
