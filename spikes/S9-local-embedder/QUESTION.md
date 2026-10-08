# S9: local neural embedder for recall

**Question.** Does a small open neural embedder (EmbeddingGemma 2 text backbone, else the original EmbeddingGemma or a comparable open model) beat `HashEmbedder` on a frozen synthetic corpus by the threshold in RESULT.md, within the box's memory and latency budget, enough to justify a local-inference service for recall?

**Kill/pivot rule.** Gain below the threshold, or a resource gate missed: do not adopt; recall stays on hash + BM25 + facts and metadata filters (potency P4). No weights measured: no decision (the question stays open).

**Time box.** One session. Not release-critical (`later`); started on the owner's request 2026-10-08.
