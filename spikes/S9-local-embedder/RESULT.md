# S9 result

Status: see "Outcome" at the end.

## Pre-declared adoption threshold (written and committed before any comparison was run)

Metric: the corpus in `corpus.json` (316 documents, 128 queries, seven categories), scored through `recall.Index.Lookup` exactly as the index fuses BM25, facts and vectors today (`eval/`). The baseline is the current default (`HashEmbedder`, 512-d). Per-category scores are means over that category's queries; the overall figure is the unweighted mean of the seven category means.

Adopt a neural embedder only if all of these hold:
1. Overall correct-source recall@10 rises by at least **0.10** absolute over the hash baseline, and overall MRR rises by at least **0.10**.
2. No category's recall@10 falls by more than **0.02**.
3. The gain survives the cheaper alternatives: it also exceeds what BM25 alone (no embedder) gets by at least 0.10 overall recall@10, so the vectors, not the fusion, earn it.
4. Resource gates on 4 CPU cores: p95 single-query embed latency <= 150 ms; added resident memory <= 600 MB for the service (the local-inference cgroup is 2048 MB at the floor and S3 already measured 2.0 GB for small model, speech and embeddings, so anything larger needs a budget decision); throughput >= 5 items/s so a 100k backfill finishes in under six hours.
5. The chosen dimension (768, 256 or 128) is the smallest one that keeps 1 to 3 true; int8 top-10 overlap with float >= 0.85 for that embedder (`TestInt8RankingAccuracy` method).

Caveat recorded before the run: the corpus is authored by the builder, and the paraphrase and other-language categories are where a neural model is expected to win by construction. The threshold is therefore on the overall mean with a no-regression rule, and the result must be read with that bias in view.

## What ran

Network check first: `huggingface.co` (EmbeddingGemma 2, original EmbeddingGemma), `hf-mirror.com`, `cdn-lfs.huggingface.co`, `ollama.com`, `kaggle.com`, `modelscope.cn` and `ai.google.dev` all fail the session proxy's CONNECT (403 or no route). PyPI and GitHub release assets are reachable, but PyPI packages that bundle weights (checked: `wordllama`) fetch them from Hugging Face at first use and fail the same way; `fastembed`'s Google Storage mirror returned 403. No embedding weights could be obtained, so **no neural embedder was run, and none of the resource gates (4) or the int8 floor (5) was measured**. Nothing in this PR is a measurement of EmbeddingGemma, and the coordinator's figures for it remain unverified.

Baselines, on the frozen corpus, through the real index (`go run ./eval -emb none|hash`, 316 docs, 128 queries):

| category (n) | BM25 + facts only: recall@10 / MRR | + HashEmbedder 512-d: recall@10 / MRR |
|---|---|---|
| plain (24) | 0.958 / 0.757 | 0.958 / 0.764 |
| misspelled (24) | 0.375 / 0.189 | 0.500 / 0.253 |
| paraphrase (24) | 0.375 / 0.156 | 0.375 / 0.146 |
| other-language (24) | 0.125 / 0.019 | 0.125 / 0.018 |
| quoted-dup (8) | 0.875 / 0.812 | 0.875 / 0.812 |
| versions (8) | 1.000 / 0.458 | 1.000 / 0.479 |
| two-accounts (16) | 1.000 / 1.000 | 1.000 / 1.000 |
| **overall** | **0.673 / 0.485** | **0.690 / 0.496** |

Reading: the room a neural model could take is real and concentrated where expected (paraphrase 0.375, other-language 0.125, misspelled 0.500); hash gives +0.017 overall over BM25 alone, almost all in misspellings. Under the pre-declared threshold a neural embedder needs overall recall@10 >= 0.79 and MRR >= 0.60 to be adopted. Because paraphrase and other-language make up two of seven equally weighted categories and are the model's home ground by construction, clearing that bar needs about +0.35 on each of them with no loss elsewhere; that is plausible but not assured, and is what the run must show.

## Integration analysis (reasoning, not measurement; for whoever runs the model)

- **The broker cannot call the embedder.** ARC-2 forbids inference in the control path and `TestAgentosdLinksNoInference` admits a socket-capable import only by named review. A recall-side vector client in the agentosd graph would be a new embedder dial from the broker at ingest, and the test's own list shows the one allowed dial (`modelroute`, to the vault's socket). Adding a second needs a reviewed allow-list entry with its reason, and it still makes the broker invoke inference when mail arrives. Not recommended.
- **Prefer service-side embedding (CAP-13 "retrieve").** SPEC CAP-13 already puts embedding search in the local inference service, called by the guest, never by the broker. Design: the service reads items it is allowed (local, no egress), computes vectors, and hands them to the broker over the narrow recall socket as `Item.Vector` with its `VecID`; for a query it embeds in the service and passes the query vector in `Query` (a new field). The broker only compares same-`VecID` vectors, so a wrong or hostile vector can change ranking and nothing else (CAP-3: results are already untrusted content). Absent service: no vectors, `Reembed` later, BM25 and facts answer meanwhile (DEP-1, OP-9: the digest says "memory search is on text only"). This needs no SPEC change if a recall write path that accepts a vector from the service is judged an existing tool (CAP-13); if L1 reads it otherwise, the diff is one sentence in CAP-13. No `SPEC-DIFF.md` is drafted because the question is not yet earning one.
- **REV-5.** Vector ranking is a cosine between the query vector and each item's own vector, with no corpus-level statistic, so a public-only search stays independent of private data; BM25's statistics are already restricted to public items for `PublicOnly`. A service-side query vector must be computed from the query text only.
- **Memory.** Local inference has 2048 MB at the floor and S3 measured 2.0 GB for small model, speech and embeddings together, so a 270M-parameter backbone (about 0.3 to 0.6 GB in int8 to fp16) fits only if it replaces the embedding model S3 already counted, not on top of it. Recall's 100k ceiling at 512-d int8 is about 50 MB of vectors, so 256-d or 128-d costs the broker less, not more.

## Outcome

**No decision. The question stays open.** Step 1 failed at the network: the weights cannot be fetched from this sandbox, so the threshold could not be tested and the adopt / don't-adopt call is not made. No `S9b` brief is written. What this PR leaves ready: the frozen corpus, a harness that scores any embedder through the real index (`eval/`, `-emb file`), `embed_st.py` (untested, since there are no weights to run it on) which also reports RSS, items/s and p95 latency, the pre-declared threshold, hash and BM25 baselines, and the integration analysis above. To finish: a session with Hugging Face reachable (or the weights placed on disk, never committed) runs `embed_st.py` for 768/256/128 fp and int8, then `go run ./eval -emb file -vectors out.json`, fills the table above, and decides. Until then, potency P4 (metadata filters and byte budgets first) stands.

Model usage: about 0.1M tokens, Sonnet-class builder.
