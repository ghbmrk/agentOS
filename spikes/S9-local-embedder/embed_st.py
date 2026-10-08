#!/usr/bin/env python3
"""Embed corpus.json with a sentence-transformers model and write vectors for eval -emb file.

NOT RUN in the S9 session: huggingface.co was blocked by the session proxy, so no weights could
be fetched. Written so the next session with the weights runs it unchanged.

  python3 -I embed_st.py MODEL_DIR_OR_ID DIM OUT.json     (DIM = 768, 256 or 128; Matryoshka truncation)
Also reports RSS and per-query latency (p95 over the query texts, single-threaded batch of 1).
"""
import json, sys, time, resource, numpy as np
from sentence_transformers import SentenceTransformer

model_id, dim, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
c = json.load(open("corpus.json"))
m = SentenceTransformer(model_id, truncate_dim=dim, device="cpu")
def prep(v):
    v = np.asarray(v, dtype=np.float32); return (v / np.linalg.norm(v)).tolist()
texts = sorted({d["text"] for d in c["docs"]} | {q["text"] for q in c["queries"]})
t0 = time.time(); vecs = m.encode([t for t in texts], batch_size=16); dt = time.time() - t0
lat = []
for q in c["queries"]:
    t = time.time(); m.encode([q["text"]]); lat.append(time.time() - t)
print(f"items/s={len(texts)/dt:.1f} p95_query_ms={np.percentile(lat,95)*1000:.0f} "
      f"maxrss_mb={resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024:.0f}")
json.dump({"id": f"{model_id}/{dim}", "vecs": {t: prep(v) for t, v in zip(texts, vecs)}}, open(out, "w"))
