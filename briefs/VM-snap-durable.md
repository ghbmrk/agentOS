# VM-snap-durable: a snapshot is published only once all of it is durable, and retired only once its unlink is

Board section: Security and architecture review. Work item: #1240 (with its amendment on the issue).

**Goal.** `captureAs` and `mergeLocked` (`broker/vm/vm.go`) make the snapshot directory under its final name, copy the layer and memory image into it and write `meta.json` last, with no fsync of the copied files or directories. load takes any snapshot directory holding a matching `meta.json`, so after a power cut a snapshot can come back with `meta.json` present and its layer or memory image short or empty: a restore point that restores the wrong state (CAP-3). On the other side, `removeSnapshot` (`broker/vm/forget.go`) unlinks `meta.json` without syncing the directory, so ForgetSince can report a reset done while a power cut could bring the deleted snapshot back.

Fix:
1. `durable.PublishDir(dir, perm, fill)`: fill writes into a stage beside dir (`StageDir`, `TempPrefix` plus the name); every regular file is fsynced, every directory bottom-up, the stage renamed to dir, the parent fsynced. Before the rename a failure leaves no dir and no stage; a failed parent sync after it returns `ErrDirSync` with dir complete. Reflinks, holes, hard links and xattrs stay as `overlay.Copy` writes them, since the copy is the fill.
2. captureAs and mergeLocked publish through it (`publishSnap`, which also removes a directory whose parent sync failed). `measure` bounds paths under the stage's longer root.
3. removeSnapshot syncs the snapshot directory after the unlink, so the removal of the `meta.json` entry is durable, and returns a failed sync: ForgetSince fails and its caller retries before marking the reset. (The amendment says "the snapshot dir's parent"; the entry removed is in the snapshot directory itself, so that is the directory synced.)

**Requirement IDs:** CAP-3, OP-4.

**Acceptance tests:**
- `broker/durable/publish_test.go`: `TestCAP3PublishDirOrder` (mkdir stage, fill, file fsyncs, directory syncs deepest first, rename, parent sync), `TestCAP3PublishDirFailures` (each step failed in turn: no dir and no stage before the rename; `ErrDirSync` with dir whole after it), `TestCAP3PublishDirRefusesExisting`.
- `broker/vm/snapdurable_test.go`: `TestCAP3SnapshotPublishedOnlyWhole` (no snapshot directory while it is written; a failed publish before or after the rename leaves nothing listed, on disk or after a restart), `TestCAP3CrashedStageNotLoaded`, `TestCAP3SnapshotKeepsLinksHolesXattrs`, `TestCAP3RetiredSnapshotStaysGone` (a failed sync fails ForgetSince; the disk state at the crash point after the synced unlink is not loaded after a restart).

**Scope:** `broker/durable/durable.go`, `broker/durable/publish_test.go` (new), `broker/durable/ASSUMPTIONS.md`, `broker/vm/vm.go`, `broker/vm/forget.go`, `broker/vm/snapdurable_test.go` (new), `broker/vm/ASSUMPTIONS.md`, this brief. Tier A. Avoids the lines #2136 (#1130) changes in vm.go and its test files.

**Dependencies:** none. **Usage estimate:** medium (one helper, two call sites, one sync, seven tests).
