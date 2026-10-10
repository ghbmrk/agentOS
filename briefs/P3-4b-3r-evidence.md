# P3-4b-3r-evidence: a fuzz finding clears only on evidence the target cannot forge

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC LOOP-7, LOOP-9. Written 2026-10-10 from LATER.md P3-4b-3r-confine l6 (#588 Security L1), promoted on Mark's request (project thread "Fuzz evidence store"). It also closes l2, whose evidence-loss half is the same flaw.

**Tier A** (`broker/loop7`, `broker/loops`): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section.

**Dependencies, all merged:** P3-4b-3r-confine (#588), P3-4b-3h-r2's producer on the record (`loops.Record.Producer`, `CloseTarget`).

**Where the root tests run.** A new test that needs root or a jail skips without root and runs in the `machines` job's "Machine tests as root" step, which already runs `./loop7`.

## Today

`replay` runs a target's corpus with `-test.v` and resolves each open crash finding whose stored input printed its own `--- PASS: Fuzz…/<file>` line. Both halves are the target's:
- the PASS line is the child's own output, and so is its exit status. An input that runs code in the decoder prints the line and exits 0, and its finding clears on the same binary that crashed;
- the corpus (`testdata/fuzz/<Name>`) is the fuzz user's. An exploited child can delete or rewrite its own crash input, and a child of one target can delete another's (l2). The evidence LOOP-9 says to preserve is then gone, and a fixed build has nothing to replay.

Hang findings already close only on a different binary (F13, S30). Crash findings do not.

## Requirements (each with a failing test first)

**IDs:** LOOP-9 (a finding's evidence is preserved, and its regression is replayed), LOOP-7 (a fuzz child has no more authority than any guest, so it cannot clear its own finding). Tests carry `REQ: LOOP-9, LOOP-7`.

1. **Nothing the target prints clears a finding on the binary that produced it.** Every fuzz finding but the oversize one is reported with its producing binary's SHA-256 (`Finding.Producer`). `loops.Resolve` clears one only on a replay from a different binary (`Replay.Binary`), and records the producer on the replay. A record with no producer is refused, so loop7 first re-reports such a finding with the current binary (adoption).
   - Test: a target that crashes, then on the same binary prints `--- PASS` for every input and exits 0 without running the regression, is not cleared, whether or not it also deletes its stored input.
2. **A root-owned evidence store.** `Config.Evidence` is a root-owned directory outside the jail's tree (`New` refuses one inside it, or inside a target or cache directory). Each failing input, and each corpus input an open finding names, is copied to `Evidence/<pkg>/<Name>/<sha256>` (0400, written whole then renamed) when root reads it. A stored file is read back only if its digest matches its name.
   - Test: a target that deletes its crash input from its corpus still has it replayed from the store; with a jail, the child can write neither the store nor the directory it is replayed from.
3. **The clearing replay is root's.** For each open crash finding whose producer is not the current binary and whose input is in the store, root copies the input alone into a fresh root-owned directory (0755, file 0444) and runs `-test.run=^<Name>$/^<sha256>$` there. It passes only on exit 0 with that input's own PASS line and no FAIL line; a failure re-reports the finding with the current binary.
   - Test: a fixed release clears it; a new release that still fails keeps it open and becomes its producer.
4. **Records.** loop7 ASSUMPTIONS (the store, the clearing rule, and the residual: a still-vulnerable new build whose exploit forges exit 0 can clear, never unpause); loops ASSUMPTIONS for `Resolve`'s rule; agentosd's wiring row for the store's path; LATER.md l2 and l6 removed.

**Threat check:**
- A target forging its own pass on the binary that crashed (requirement 1).
- A target destroying or rewriting its evidence, or another target's (requirement 2).
- A target writing the input it is about to be judged on (requirement 3: root-owned copy).
- Root following a link while writing the store or the replay directory (os.Root only, the leaf emptied first).
- A legacy finding with no producer clearing without one (adoption, requirement 1).

**Scope:** `broker/loop7/loop7.go`, its tests and ASSUMPTIONS.md; `broker/loops/report.go`, `secure.go` (field docs), the loops tests that resolve fuzz findings, and ASSUMPTIONS.md; `broker/cmd/agentosd/learn.go` (the store path) and its ASSUMPTIONS.md; BOARD.md; LATER.md.

**Estimate:** ~120k. Checkpoint at 70k: requirement 1 green in loops and loop7.
