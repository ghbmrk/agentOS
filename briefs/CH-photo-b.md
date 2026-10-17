# CH-photo-b: photo content store

Board section: Backlog refill (2026-10-17). Part of CH-photo-upload (briefs/CH-photo-upload.md), work item #2146; SPEC CH-23, CH-26, OP-11, CAP-3, RES-4. Tier A.

**Needs:** CH-photo-a. **Gate:** as CH-photo-a (the package is `broker/photo`); lenses L3 and Security.

## Change

In `broker/photo` (store files beside a's `decode.go`):

1. **Content store.** Re-encoded photo and thumbnail kept under the state directory by SHA-256 of the image bytes, written to a temporary name, synced and renamed, so a photo is kept whole or not at all. A record per photo: ID (short, shown to the owner, e.g. `P` plus a counter), hash, source (`upload` now, `mms` later), received time, pixel size, caption's task reference, the machines it was delivered to, and expiry. Listed in `broker/durable/stores.txt` as `photo content`.
2. **Journal.** Receipt, delivery and deletion are journal records. Register a `journal.Lifecycle` with Kind prefix `photo.` (keep, deliver, delete; deletes `journal.Irreversible`) and DailyCap 200, the first production use of `journal/lifecycle.go`; if the lifecycle does not fit, journal plain records and enforce the cap in the store, and say why in ASSUMPTIONS.md.
3. **Limits.** At most 10 photos per upload and 200 a day (counted on the box's day, across all sources). RES-4: the store asks the storage reserve before writing and refuses a photo it cannot fully keep.
4. **Expiry.** Owner-set days (default 30, as CH-19), enforced by a sweep at boot and then periodically, only on a trusted clock (`clock`); never early.
5. **Erase.** `Delete(id)` and `DeleteAll()` are a CAP-3 erase: remove the bytes and thumbnail, `journal.Engine.Erase` the photo's records' content, and propagate to derived content through the recall source-deletion path (`recalltool/reach.go`), returning a confirmation that names any backup still holding it and any running machine it was delivered to (CH-26). `recalltool` is `frozen-import` under G1, which is a second reason this package waits on freeze-off.

**Acceptance tests:**
- CH-26 (content store, journal): `TestStoreKeepsByHash`, `TestStoreJournalsReceiptDeliveryDeletion` (`broker/photo/store_test.go`), and the existing `broker/durable` `lifecycle_guard_test.go` passing with the new `stores.txt` row.
- CH-23 (limits): `TestStoreDailyCap200`, `TestStoreTenPerUpload`.
- RES-4 / CH-26 (no partial keep): `TestStoreRefusesWhenReserveShort`, `TestStoreCrashLeavesNoPartial` (kill between write and rename; boot finds no record and no stray file).
- CH-26 (expiry): `TestExpiryAfterDays`, `TestExpiryWaitsForTrustedClock`.
- CAP-3 / CH-26 (erase): `TestDeleteErasesBytesAndJournalContent`, `TestDeleteConfirmationNamesRunningMachine`, `TestDeleteReachesRecall`.

Failure path: a photo the owner deleted, or one past its days, is still readable from the store, the journal or recall.

**Guard files:** none new beyond CH-photo-a's (`photo` is classed there); `broker/durable/stores.txt` gains the row.

## Scope

`broker/photo/` store files and tests, `broker/photo/ASSUMPTIONS.md`, `broker/durable/stores.txt`, `broker/recalltool/reach.go` (the photo source kind only) and its test.

## Estimate

One session, about 120k tokens, strongest model.
