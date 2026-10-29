# INFER-retrieve: the local retrieve pass, the embedding service's consumer

Board row: issue #3783 (section Model routes and the Codex lane). Class: later. Tier: A (`tools/risk_tier.py` prints A for `broker/clerk/retrieve/`, an unclassed broker package; this brief is tier C). Builder: strongest model. Two slices, one session each: **R1** (startable now) and **R2** (after the home archive's mail store, TN-archive, and in the `cmd/agentosd` serial slot). Usage estimate: R1 70k, R2 90k.

**Acceptance tests:** each slice's tests are named under its slice below.

## Why (facts, verified at main d273d6c)

- The service exists and ships disk-only: `broker/infer` (client `Client{Path}` with `Embed(ctx, texts) ([][]float32, Info, error)`, bounds `MaxTexts` 64 and `MaxText` 8 KiB), `broker/infer/supervise`, `broker/cmd/agentos-infer` with the llama.cpp adapter, and the image's Qwen3-Embedding-0.6B Q8_0 (1024 dims, Apache-2.0, D-230). `agentosd.service` passes the model and its pin but not `-infer` (`tests/test_image_infer.py::test_the_unit_names_the_pinned_model_and_leaves_infer_off`), "until a retrieve row consumes the service" (`broker/infer/ASSUMPTIONS.md` INFER-A16).
- The socket is unreachable by any clerk: `supervise` makes its directory 0700 to agentosd. #3657's G3 (closed unmerged; its text is in that PR's diff) designed peer access: a `Peer` uid admitted through a group on a 0710 directory and a 0660 socket.
- SPEC v1.0 places retrieve among PLN-7's local passes ("retrieve (recall and embedding search, LOG-4)"); CAP-13 is retired into PLN-7 (`tests/test_image_infer.py` cites PLN-7 since #3784). PLN-3 labels embeddings private. LOG-1 makes search indexes projections, droppable and rebuilt from the log. LOG-4: erase makes content unreadable everywhere and "indexes built from the item are rebuilt without it". KRN-3 (D-153): a learned part only proposes; an exact rule decides. RES-4 reserves storage for "the recall index".
- What there is to search: the new core keeps sealed content per subject in content stores (`broker/kernel/erase.go`, `kernel/proc` `ContentSide`, KRN-content, D-211). Today the only content clerk is face enrolment (`vision/faces`, wrap keys); mail is not kept on the box. BAK-2 makes the home archive "the log's content store" and says "tasks read archived mail and files only from the archive"; that is TN-archive (BOARD, queued after A21). So the archive is the corpus this pass exists for, and it does not exist yet. Recall by name (`kernel.Named`) matches labels exactly after folding case and spaces; its comment and `briefs/KRN-forget.md` defer fuzzier matching to this pass.

## Design decisions (this brief's; option A was taken as an engineering call under D-230, "embeddings only", so none is pending with Mark)

1. **Corpus: the home archive's text items** (mail first, then files), not subject names. Names are short and mostly proper nouns, where an embedding adds little over spelling rules and would hold about 1 GB of service memory for it. Fuzzier name matching stays deferred and, when built, starts from deterministic folding (confusables, edit distance), not this pass.
2. **Dialling clerk: the content clerk that sealed the items** (the archive's clerk). Under KRN-content, sealed plaintext crosses to the clerk that sealed it and to no one else; that clerk already holds each item's text at seal time, so it embeds before sealing and reads nothing back to do so. The text it sends to the inference service stays on the box: that service has no network, no store and no credentials (INF-6), and its logs carry no text (INF-8). Not the kernel (KRN-3, and no model call in trusted core), not agentosd (ARC-2: it holds no inference client), not the model clerk (it never holds archive plaintext), not a planner (it reaches only the model clerk, PLN-5).
3. **Index: sealed vectors, an in-memory projection.**
   - At seal, the clerk embeds the item's text in chunks and seals one item of class `retrieve-vectors` under the **same subject** as the source item, in its own store. Erase destroys the subject key, so the vectors die with the content (LOG-4) with no extra erase path, and backups carry them like any item.
   - The searchable index is in the clerk's memory only, rebuilt at start from the `retrieve-vectors` items read through `ReadFor` under one service lineage, `svc-retrieve` (the `svc-vision` pattern in `vision/faces`, D-169). A rebuild after a crash equals one from empty (LOG-1). Nothing unsealed is written to disk.
   - Shape: chunks of at most 2,048 bytes on paragraph, then sentence, then UTF-8 boundaries; at most 64 chunks per item (the first 128 KiB; the rest is counted as unindexed); vectors truncated to 256 dims and renormalised (Matryoshka, which Qwen3-Embedding is trained for), quantised to int8 with one float32 scale per vector, so about 260 bytes a chunk. The item records the model's SHA-256 and the dim. Default cap 200,000 chunks (about 52 MB); past it, new items stay unindexed and `Stats` says so. [Inference: MRL truncation quality and the cap are unmeasured; R2 measures recall on a synthetic set and the N95 figures.]
   - Query: the model's query instruction prefix is a constant tied to the pinned model hash; documents carry none. Search is a brute-force int8 dot product over the projection, top k at most 50.
4. **What a hit is and is not (KRN-3).** A hit is a ranking proposal: subject, source item hash, score. It never decides a label, key, step or route (PLN-7). Reading the item stays the caller's `ReadFor` under the agent's own lineage, which the kernel refuses for an erased item, so a stale vector can at worst rank a hit that then cannot be read. When the service is off, missing, corrupt or unavailable, `Search` returns `ErrUnavailable`, never an empty list, and the task proceeds on the archive's exact lookups unaided (PLN-7; `docs/conv-5-uncovered.md` CAP-13a).
5. **Erase reaches memory at once.** `Rewind(subject)` drops the subject's entries from the projection immediately (the `faces.Rewind` seam, told by the same erase notice); a periodic reconcile (default 15 minutes) re-reads and drops anything `ReadFor` reports gone, bounding the window if a notice is lost.
6. **Model change.** Vector items whose model hash differs from the service's are ignored; the clerk re-embeds their source items (read under `svc-retrieve`) and seals new vector items. Old ones stay until the subject's erase; their cost is counted in `Stats`.
7. **Peer access.** `infer/supervise` gains G3's `Peer` uid; agentosd's `-infer-peer-uid` names the archive clerk's uid and refuses root, its own uid and `-infer-uid`. `vision/supervise` leaves it unset, so the vision jail is unchanged (VIS-A6).

## R1 INFER-retrieve-index (startable now; issue #3783)

The index library against seams, with no process, socket, wiring or image change, so `-infer` stays off. Precedent: `vision/faces` merged ahead of its wiring the same way.

- New package `broker/clerk/retrieve`: `Embedder` (`Embed(ctx, texts) ([][]float32, Info, error)`, which `infer.Client` satisfies; R1 does not import `infer`) and `Content` (`Seal`, `ReadFor`, as `faces.Content`) as interfaces; `Index` with `Add(ctx, subject, source Hash, text)`, `Search(ctx, query, k)`, `Rebuild(ctx, items)`, `Rewind(subject)`, `Reconcile(ctx)`, `Stats()`; the chunker; the vector item's binary format with its parser. A failed `Add` (service unavailable) keeps the source pending in memory and `Retry` indexes it later; the caller also passes unindexed sources to `Rebuild` at start.
- The library checks every vector itself, beyond the client: the dim equals the pinned dim, values are finite, the count equals the chunk count, and the model hash equals the one the index was built for; otherwise nothing is sealed and the source stays pending.
- Standard library only: no `net`, `os/exec`, `syscall`, `unsafe`, `plugin` or `C`, held by a package-local `imports_test.go`. No log line carries text, a query or a vector.

**Acceptance tests (R1)**, in `broker/clerk/retrieve/retrieve_test.go` against a fake embedder (a fixed concept-table vector per text, with unavailable, wrong-dim, NaN and wrong-count switches) and an in-memory `Content`:
- LOG-4: `TestAddSealsVectorsUnderSourceSubject` (one `retrieve-vectors` item, under the source's subject, recording model hash and dim); `TestRewindDropsSubjectAtOnce` (no hit names it afterwards); `TestReconcileDropsGoneItems` (`ReadFor` reporting gone removes the entries). Catches vectors that outlive an erase.
- LOG-1: `TestRebuildEqualsLiveIndex` (a projection rebuilt from the sealed items ranks every query as the live one did, and every read was under `svc-retrieve`). Catches an index that is not a projection.
- PLN-7: `TestSearchRanksByMeaning` (the concept-table match comes first); `TestUnavailableIsNotEmpty` (`ErrUnavailable`, never an empty list; `Add` stays pending and `Retry` indexes it). Catches a silent "no results" when the service is down.
- PLN-3 and the untrusted service: `TestUntrustedVectorsRejected` (table: wrong dim, NaN, Inf, wrong count, other model hash: nothing sealed); `TestMalformedVectorItemSkipped` (a truncated or foreign item is counted and skipped at rebuild, never a panic).
- Bounds: `TestChunkBounds` (no chunk over 2,048 bytes, none splitting a UTF-8 sequence, at most 64 per item and per `Embed` call, the overflow counted); `TestIndexFullLeavesItemsUnindexed`; `TestModelChangeReembeds` (other-hash items ignored, sources re-embedded).
- `TestLogsCarryNoText`: a synthetic canary in a text and in a query never appears in log output. `TestImportsStandardLibraryOnly` (`imports_test.go`).

**Scope (R1):** `broker/clerk/retrieve/**` (new), `briefs/INFER-RETRIEVE.md` (findings only). No open PR touches it.

**Guard files (R1):** none. The package is unclassed, so tier A; it needs no `arc2_test.go` entry since nothing in a guarded plane imports it, and its own import test holds it to the standard library. Leaving `arc2_test.go` alone keeps R1 disjoint from #3746, which holds that file.

## R2 INFER-retrieve-wire (after TN-archive's mail store; `cmd/agentosd` slot)

- `broker/infer/supervise`: `Peer` (G3 of #3657): a 0710 directory group-owned by a group admitting exactly that uid, a 0660 socket; unset, unchanged.
- `broker/cmd/agentosd/infer.go`: `-infer-peer-uid`, with the refusals above.
- The archive clerk: holds an `Index` over `infer.Client` at `-infer-socket`, embeds at seal, rebuilds at start, takes the erase notice, and serves the archive's read step a ranked mode (query in, item handles out), which TN-archive's read step defines.
- Image: `agentosd.service` gains `-infer` and `-infer-peer-uid @uid:<archive clerk>`; `tests/test_image_infer.py` flips its unit test to require them; the `agentos-setup.conf` group line if the peer group is static.
- Floor (HW-4): on the N95, rebuild time and RSS at 200,000 chunks, search p95, and the embed p95 from INFER-floor (#3656); R2 sets the search latency limit from them.

**Acceptance tests (R2):** `TestPeerUIDReachesSocket`, `TestOtherUIDRefused` (`supervise_test.go`, as root in the machines job); `TestVisionSocketUnchanged`; `TestInferPeerFlagRefusals` (agentosd); in the archive clerk, `TestArchiveIndexesSealedMail` and `TestRankedReadReturnsReadableHandles` (an erased item's handle is refused by `ReadFor`); `tests/test_image_infer.py::test_the_unit_turns_infer_on_for_its_peer`; the N95 figures in the PR body.

**Scope (R2):** `broker/infer/supervise/**`, `broker/infer/ASSUMPTIONS.md`, `broker/cmd/agentosd/infer.go` and its test, the archive clerk's files TN-archive creates, `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service`, `image/mkosi/mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf`, `tests/test_image_infer.py`.

**Guard files (R2):** `broker/daemon/inference_test.go` `netOK["infer/supervise"]` gains only the names the peer group needs (for example `syscall.Chown`; a name beyond those is a review point); `broker/daemon/arc2_test.go` and `tools/trusted_base.py` or `broker/core/core.txt` lines for `clerk/retrieve` as linked into the archive clerk's process, as TN-archive classes that process. Pre-approved here; tier A, with the separate Security accept wherever `premerge.py --needs-mark` prints `mark`.

## Lifecycle (OPERATING §5)

Integration owner: R2, through the archive clerk, which owns this matrix.

| Stage | Outcome | Test |
|---|---|---|
| First boot, service on | archive items embedded at seal; search answers | `TestArchiveIndexesSealedMail` |
| First boot or any time, service off or failing | archive syncs and seals; items pending; search `unavailable`; broker unaffected (DEP-1) | `TestUnavailableIsNotEmpty`, INF-4 tests |
| Clerk restart or crash | projection rebuilt from sealed vectors, equal to the live one | `TestRebuildEqualsLiveIndex` |
| Update with a new model | old vectors ignored, sources re-embedded | `TestModelChangeReembeds` |
| Erase | entries dropped at once; vectors unreadable with the key; stale hit unreadable | `TestRewindDropsSubjectAtOnce`, `TestReconcileDropsGoneItems`, `TestRankedReadReturnsReadableHandles` |
| Restore | vectors restored with their subjects; held erases re-applied first (LOG-4) | covered by the kernel's restore tests; none added |
| Removal (`-infer` off) | as service off | as above |

## Assumptions (R1 records them in `broker/clerk/retrieve/ASSUMPTIONS.md`, new)

- RET-A1: the archive is a KRN-content store whose clerk holds each item's text at seal (BAK-2). If TN-archive builds it otherwise, R2 adapts the seams; R1's library does not change.
- RET-A2 [Inference]: 256-dim int8 Matryoshka vectors keep enough recall for mail search; R2 measures on a synthetic set against full 1024-dim float vectors and raises the dim if recall drops more than 5 points.
- RET-A3: sending item text to the no-network inference service is within KRN-content's "sealed plaintext crosses to the clerk that sealed it": the text is the clerk's before sealing, and the service keeps nothing.
- RET-A4: reading every vector item under `svc-retrieve` at each start costs one `content.read` entry per item; R2 measures the log growth at 200,000 chunks and, if it is too large, proposes a per-subject wrap key (the `faces` pattern) instead.

## Out of scope

Name recall by meaning; the planner-facing plan step beyond the archive's read step; reduce, extract, triage, check and draft passes; pipelines and cascades (HLD-4); accelerator leases (RES-3); compute hosts; STATUS lines beyond `Stats`.
