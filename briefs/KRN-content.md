# KRN-content: sealed content in the running kernel (LOG-4, D-169)

Work item: #3550, from the gap noted on #3515 (comment 6458131269). Tier A. Unblocks VIS-core part (c), face enrolment (#3544, #3515).

## The gap

`proc.OpenKernel` (`broker/kernel/proc/kernel.go`) calls `OpenContent` with an empty store map, so `Seal` has nowhere to write. The only `kernel.ContentStore` is `MemContent` (tests, sim). The kernel socket has `erase`, `erasedreads` and `unerased`, but no `OpenSubject`, `Seal` or `ReadFor`, though all three exist in `broker/kernel/erase.go`.

## Decisions

1. **A file store beside the key table.** `FileContent` keeps one store per directory under `KernelConfig.ContentDir` (`-content-dir`, required by `RunKernel` and `cmd/agentos-kernel` like `-keys-dir`): one file per item, named by its ciphertext's SHA-256, written with `privfile.WriteAtomic`, the directory 0700 and this uid's alone (`privfile.Check`). Items arrive sealed under the subject key, so the store holds ciphertext only. `Delete` unlinks and syncs the directory and succeeds for an absent item.
2. **Every store on the drive opens.** `OpenContentStores` opens each configured store and every store directory already present, so a store dropped from the config still has its items erased. A store missing from the drive leaves its erase in `Unerased` (fail closed). A temporary from a torn write is removed at start: `Seal` puts before it logs, so that item was never named. Store names are `[a-z][a-z0-9-]{0,31}` and never the key table, so a name is a safe directory name.
3. **One socket per content clerk, bound to its own store.** `ContentSide(store)` serves `opensubject`, `seal` (into `store` only) and `readfor` (of `store`'s items only; another store's item is `ErrItem`). `MainConfig.Content` and `-content store=/abs/socket,uid` (repeatable) name them. Each socket admits one uid, refused if it is the owner side's, the model clerk's, the link's or another content clerk's; a clerk the kernel calls (`-clerk`) may share it. Erase, recall and named stay the owner side's. `readfor` logs `content.read` under the caller's lineage before it answers (D-169). The kernel gains one read, `State.ItemStore`.
4. **Bounds.** An item is at most `MaxItem` (1 MiB) of plaintext, so a `seal` call and a `readfor` answer fit the socket's 4 MiB bounds. The kernel's content errors (`ErrStore`, `ErrSubjectKey`, `ErrItem`, `ErrLineage`) cross the wire as sentinels.
5. **Not this row.** Backups still carry no `content/<store>` sections (MIG-4-recovery-e3-a); that is a release follow-up. Which uid the vision path uses for its content socket is VIS-core's (parts c and f): its enrolment step seals through that clerk, not from the owner side.

## Lifecycle (integration owner: this package)

| Stage | Outcome |
|---|---|
| First start | `content/` and each configured store made 0700 |
| Seal, then restart | the item reads back through `readfor` |
| Torn write, then restart | temporary removed; logged items read |
| Erase | key gone, item file gone, `readfor` refused, the lineage listed in `ErasedReads` |
| Store dropped from config, then erase | store still opened from disk, erase confirmed |
| Store missing from the drive | erase stays in `Unerased`, retried by Tick |
| No `KeyDir` (tests only) | `opensubject` and `seal` are `ErrContentClosed` |
| Setup not done | content calls are `ErrSetupOnly` |

## Scope

`broker/kernel/erase.go` (`State.ItemStore`), `broker/kernel/proc/` (`content.go`, `kernel.go`, `kernelmain.go`, `kernelsock.go`, `backup.go`'s target guard, tests, `ASSUMPTIONS.md`), `broker/cmd/agentos-kernel/` (flags and tests), `broker/cmd/agentos-unlock/main_test.go` (its rig's `ContentDir`), `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-keeper-kernel.service` (`-content-dir`), `docs/LANES.md` (the seam list, word-neutral), this brief.

**Requirement IDs:** LOG-4, LOG-1, CLK-1.

**Guard files:** none (no new package). **Gate:** `docs/LANES.md` is a gate file, so a separate Security accept (D-137); `broker/kernel` and `broker/cmd/agentos-kernel` are trusted core, so the build PR names a one-row D-159 decision in its `Trusted-core:` line.

## Acceptance tests

- LOG-4: `kernel/proc/contentstore_test.go::TestASealedItemLivesUntilItsErase`: seal through the socket, restart, `readfor` returns it; after erase `readfor` is `ErrErased`, the file is gone, the lineage is in `ErasedReads`, and no file under the box's directory ever held the plaintext canary. *Mutants:* `OpenKernel` passing an empty store map; `Delete` not unlinking.
- LOG-4: `TestATornWriteLeavesAWholeStore`: a write stopped after its temporary leaves a store that opens and reads. *Mutant:* no temporary removal.
- CLK-1: `TestOnlyAContentClerkSealsAndReads`: the owner, meter and link sockets have no content call, a socket for another uid takes nothing, another store's item reads as `ErrItem`, and none of it logs. *Mutant:* drop the `ItemStore` check.
- LOG-4: `TestNoKeyTableRefusesSeal`: with no `KeyDir`, `seal` is `ErrContentClosed`.
- LOG-4: `TestAStoreDroppedFromTheConfigIsStillErased`. *Mutant:* open only configured stores.
- LOG-4: `TestContentRefusalsCrossTheSocket`, `TestALooseContentStoreStopsTheStart`, `TestRunKernelNeedsAContentDir`, `TestTheKernelServesTheContentSockets` (non-root; *mutant:* the `Content` loop in `RunKernel` dropped).
- CLK-1: `cmd/agentos-kernel/main_test.go::TestEachContentSocketIsItsClerksAlone`. *Mutants:* drop the shared-uid check or the store-name check.
- `kernelsock_test.go::TestNoSideReadsSealedContent` now covers every side: only a content side has `readfor`.
