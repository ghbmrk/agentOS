# PROJ-read: one journal read per projection sync

Board section: SIM (row PROJ-read). Seed brief from the 2026-10-12 waste review (point 7, approved by Mark). Release finding: it serves the SIM-proj invariant that projections are cheap rebuilds of the one journal (SPEC §9, D-095). Failure path: with P views and a journal of H records, one `Sync` decodes the whole journal P times, so its cost grows as P×H. Each owner-facing view that SIM-owner-hold and SIM-pull add raises P, and the cost lands on the STATUS path.

**Tier:** A (`broker/journal`, the core). Strongest model. About 40k tokens. Run `tools/risk_tier.py` before opening the PR.

**Needs:** SIM-proj (merged, #722). Build it before SIM-owner-hold wires `Sync` into agentosd, because nothing calls `Projector.Sync` in production yet.

## Today (main at the time of the waste review)

- `Projector.Sync` (broker/projection/projection.go, ~l.187-199) calls `src.RecordsAfter(v.offset)` once per view.
- `Engine.RecordsAfter` (broker/journal/engine.go, ~l.770-785) calls `readJournal`, which reads the whole store and decodes it (`decodeJournal`), then slices it at `seq`.
- `Boot` and `restore` (projection.go ~l.118-175) also call `RecordsAfter` once per view, so a boot costs P full decodes too.

## Requirements (local IDs)

- **PROJ-read-1.** A `Sync` over P views reads and decodes the journal at most once. It reads from the lowest offset among the views, and each view applies its own tail of that one read.
- **PROJ-read-2.** `Boot` does the same: at most one full decode for all views without a usable snapshot, plus at most one for those restored from snapshots.
- **PROJ-read-3.** The error behaviour is unchanged: if the journal cannot be read, every view stays at its offset and `Sync` returns the error (the existing tests keep passing).

## Tests (`broker/projection/projection_test.go`, written first)

- A counting `Source` with three views: one `Sync` makes one `RecordsAfter` call, and each view ends with the same state as today.
- Views at different offsets each apply exactly their own tail. No record is applied twice and none is skipped.
- `Boot` with a mix of snapshotted and fresh views stays within the PROJ-read-2 bound.

## Scope

`broker/projection/projection.go` and its tests. Touch `broker/journal` only if a cheaper tail read needs it. Changing the `Source` interface is allowed only if every implementation in the tree changes in the same PR.

## Integration owner and lifecycle

This package owns the read path from journal to views. Its outcomes are: one read, applied to every view; a read failure leaves every view at its offset; a boot works from a mixed set of snapshots. Each outcome has one test in the matrix above. A finding on another lifecycle stage goes back to this package, not to a new row.
