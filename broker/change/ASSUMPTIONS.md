# Change store: assumptions

Covers `broker/change`, which now holds only `store.go`: the file store the deleted change pipeline used, still used by `claim`, `firstboot`, `apply`, `localui` and `cmd/agentosd`. The pipeline's rows (C1 to C44 and the rows after them) went with it (#2785 c3) and stay in git history; docs/migration/cases.md §7 lists its cases for the rebuild on the kernel. c4 moves the store to its own package and deletes this one.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-4-untrusted-change-c3-1 | **A save is atomic.** `FileStore.Save` and `DirContent.Put` write with `durable.WriteFile` (write, fsync, rename, fsync the directory), so after a crash `Load` and `Get` return the old content or the new. A missing file reads as nil, nil. `MemStore` and `MemContent` are for tests. Test: `TestFileStoreKeepsOldOrNew`, `TestDirContentRoundTrip`. | OP-4 | If c4 moves the store onto another atomic write, the same tests carry over (brief c4). |
| MIG-4-untrusted-change-c3-2 | **`Executor` stays until c4.** `const Executor = "change"` remains only because `cmd/agentosd` registers it as retired, so a recorded intent naming it is refused; `grants` denies every `meta.change.*` intent with "the change pipeline is not running". | OP-5 | c4 removes both. |
