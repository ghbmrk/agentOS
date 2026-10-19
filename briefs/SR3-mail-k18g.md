# SR3-mail-k18g: egress proxy body check memory and slot hold time

Board section: SR3 mail. Work item: #2296. Follow-up of SR3-mail-k18f (#1771, PR #2294); release findings of that PR's reviews. **Tier A** (`broker/egress`, `broker/cmd/*`): Security plus combined review; strongest model.

**Before starting:** re-read `broker/egress/proxy.go` (`admit`, `bodyCost`, `checkApart`, `BodyRule.apply`) and K18 in `broker/egress/ASSUMPTIONS.md`. k18f already added the per-machine concurrency limit (`DefaultMaxConcurrent`, 4) and `bodyCost`; confirm each item below still fails on main before changing code, and drop any that no longer does (say so in the PR).

**Two parts, in this order; part 1 may ship alone if part 2 passes the checkpoint.**

1. **Streaming body check (CRED-8).** `apply` decodes the whole body into `map[string]any`; an 8 MiB body `{"a":[{},{},…]}` holds about 171 MiB live (Security repro on #2294). Failure path: hostile-shape bodies from a few machines push the vault process past `GOMEMLIMIT`/`MemoryMax`. Walk tokens instead (top-level keys as `json.RawMessage`; `remoteSource` and the tools check over the walk), so live memory is about twice the body, and lower `bodyCost` to match.
2. **Slot hold time (CRED-8, K18).** The egress model socket's `http.Server` (`cmd/agentos-egress/server.go`, `newServer`) and the guest server (`guest/plane.go`) set no `WriteTimeout`, so a guest that stops reading a streamed reply holds its slots as long as it likes (inferred from the code, not run). Failure path: a few compromised machines hold every slot and the rest get 429. Add a per-write deadline on the proxy's response copy (`http.ResponseController.SetWriteDeadline`), and cap one machine's share of the in-flight budget (e.g. no machine above half) so N-1 machines at their share leave the last admitted.

**Requirements:**
- K18g-1: the check's live memory per body byte stays under 3 for the costliest shapes in `TestBodyCostBoundsApply`.
- K18g-2: the check accepts and refuses exactly what the decoder did (differential test on the existing corpus).
- K18g-3: a stalled reader's slot is released within the write deadline.
- K18g-4: one machine cannot hold more than its share of the budget.

**Acceptance tests (REQ: K18g-1 … K18g-4), written first:** a measured-memory test on the 8 MiB shape (mutant: revert to full decode); a differential test of old versus new decisions; a stalled-reader test with a short deadline (mutant: no deadline); an admit test where machines at their share leave one admitted (mutant: no share cap). `tests/test_egress_memory.py` still reads its figures from the code.

**Out of scope.** The mail calls' own bounds (k18b), changes to `DefaultMaxConcurrent`.

**Scope:** `broker/egress/proxy.go`, `broker/egress/*_test.go`, `broker/cmd/agentos-egress/server.go`, `broker/guest/plane.go` (the deadline only), `broker/egress/ASSUMPTIONS.md` (K18), `tests/test_egress_memory.py`, this brief. D-111: no build while another open PR touches these files.

**Usage estimate:** 120k tokens; checkpoint at 90k (ship part 1 alone there).
