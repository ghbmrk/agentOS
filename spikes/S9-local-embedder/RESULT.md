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
