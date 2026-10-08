# S9 spike assumptions

- The corpus is synthetic and builder-authored (`make_corpus.py`, seed 9, frozen as `corpus.json`); paraphrases and Spanish queries are hand-written, so category results show direction, not production accuracy.
- `eval/` imports `broker/recall` through a `replace` directive in its own module, so it is outside the broker module and not built by broker CI; it calls only the exported `Open`, `Ingest`, `Lookup`.
- Item order and ranking ties are deterministic for a given corpus; the harness uses recall's default minimum cosine for each embedder (`CosineFloor`, else 0.3 for a file embedder).
- "Correct source" is one ref per query. Quoted-duplicate and version categories measure whether the original or newest document outranks its copies and predecessors; embeddings are not expected to settle these (metadata is), and they are kept so a gain elsewhere cannot hide a loss here.
- Vectors from `embed_st.py` are keyed by exact text, so the harness sees what an out-of-process embedder would return; nothing neural runs inside the harness.
