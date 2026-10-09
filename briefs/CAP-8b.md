# CAP-8b: Worker follow-ups (#146): file offsets, tar over exec

Board section: Backlog refill (2026-10-05).

Worker follow-ups from the #146 lenses: `worker_read_file` offset and length, and tar over exec stdin documented for trees (potency R3); a toolchain base image and a package cache for workers (potency R4); STOP and PAUSE end worker commands in flight (security R2); the SR2-3 and SR2-4 disk rows cover `wk-` machines, with a per-worker layer cap meanwhile (security R3) Built here (#150): read offset and length, base64 input and output, STOP ends and holds worker commands (the broker has no PAUSE state yet; PAUSE joins when it does), the per-worker layer cap `-worker-layer-mb`. Not here: the toolchain image and package cache (potency R4, with the image build) and the SR2-3/SR2-4 rows themselves

**Needs:** CAP-8 merged

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** in review (#150, Next build item D)
