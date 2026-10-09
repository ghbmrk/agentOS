# P3-4b-3r-confine-r5 and -r6: the jail's defences are tested and its reads, output and kill are bounded

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC LOOP-1, LOOP-7, ARC-2. Written 2026-10-09 from the #588 (P3-4b-3r-confine) review records.

**What this brief covers.** BOARD row P3-4b-3r-confine-r5 lists eight points. They split by function into two packages, each sized for one session:

| Package (BOARD row) | Points of row r5 | Main functions in `broker/loop7/loop7.go` | Estimate |
|---|---|---|---|
| [P3-4b-3r-confine-r5](#p3-4b-3r-confine-r5) | 1, 2, 3, 4 (corpus half), 5 | root's path operations (`input`, `seed`, `ownPath`, `prune`), `run`'s output | ~95k |
| [P3-4b-3r-confine-r6](#p3-4b-3r-confine-r6) | 6, 7, 8 | `Jail.empty` | ~80k |

The `hang.json` parts of points 1 and 4 are not here. P3-4b-3h-r2 removes the file, and the row says those parts then go away.

**Tier A for both** (`broker/loop7`): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section.

**Dependencies, all merged:** P3-4b-3r-confine (#588, bba009a).

**Where the root tests run.** Every new test that needs root or cgroup v2 skips without `AGENTOS_CGROUP_PARENT` and runs in the `machines` job's "Machine tests as root" step. That step already runs `./loop7`, from #588. The PR shows each new root test as RUN then PASS there.

**Parallel work.** The two packages edit different functions of `loop7.go` and can run in parallel; the second to merge rebases. P3-4b-3h-r2 edits `Fuzz`, `hang` and `closeHangs`, and P3-4b-3r-confine-r2 edits `Jail` and `run`'s `SysProcAttr`. A conflict is a rebase, not a redesign.

## P3-4b-3r-confine-r5

**Goal:** each of F16's defences fails a test when reverted, and nothing the fuzz user can grow lands unbounded in broker memory.

**IDs:** ARC-2 (the child cannot reach outside its tree through root), LOOP-1 (a child cannot exhaust the broker). Tests carry `REQ: ARC-2, LOOP-1`.

**Sources:** BOARD P3-4b-3r-confine-r5 points 1 to 5. #588 Security, comments 6081240541, 6080932863 and 6080853844; L3, comments 6080174845 (point 3) and 6080932863; loop7 F16.

### Requirements (each with a failing test first)

1. **A link out of `State` is never followed** (r5 point 1, without `hang.json`). Make `t.Dir` (`targets/<pkg>`) a link to a directory outside `State` that holds a corpus file and a seed name. Then drive `Load`'s seeding, a replay (which reads inputs through `input`) and a fuzz step. Assert:
   - no file outside is read, replaced or created;
   - the run fails as the runner's error, never as a finding.

   Show the test catches reverts: with `input` reverted to `os.ReadFile` and `seed` to `os.OpenFile` on a joined path, it must fail. Note the mutation in the PR.
2. **`ownPath` and `prune` never act through a swapped link** (r5 point 2; L3 point 3 on 6080174845).
   - `ownPath`: with a symlink at `rel` pointing outside `State`, the outside target's owner is unchanged.
   - `prune`: with a package cache directory swapped for a link to an outside directory after the walk and before the removals, nothing outside is removed. Use a hook in the test build, or a walk callback seam.

   Each test fails with the path-based `os.Lchown` or `os.Remove` the row names. Today the root-based calls are in place but no test pins them.
3. **Jailed variants** (r5 point 3). Every hang test runs unjailed today. Add a jailed run of `TestARepeatedHangRecordsTheNewerBuild`, or of its successor if P3-4b-3h-r2 has renamed it. Add a test that a jailed child still starts after the leaf has been emptied twice in a row, which guards against the `cgroup.kill` regression F16 records.
4. **The corpus read is bounded** (r5 point 4, corpus half). The row calls it `corpusFile`; in the tree it is `Source.input`. `input` and `seed`'s reads use `ReadFile` on files the fuzz user can grow.
   - Refuse a file whose `Lstat` size is above a cap, before any read. Suggested cap: 1 MiB per input; Go's fuzz inputs are small, and the builder records the figure in F16.
   - Read through a `LimitReader` of cap+1, so a file that grows between the stat and the read is refused too.
   - A refused input is reported as the target finding "a stored test input is too large to replay". This holds the target open and is visible, never silent. The builder confirms the wording with the owner-text rule (P3-4b-3c lens test) and adds it to the lens clause.
   - Tests: an oversize input is refused with no `ReadFile` of it (a read counter, or a FIFO that would block); a file at the cap is read.
5. **`run`'s collected output is capped** (r5 point 5). `cmd.CombinedOutput()` buffers all child output in broker memory, outside the leaf's `memory.max`. Collect at most a cap and discard the rest while still draining the pipe, so the child never blocks. Suggested cap: 1 MiB; a 30 s step's progress lines are a few KiB. Keep the tail, not the head: `progressOf` and `tail` read the end. Use a ring buffer, or keep the first 64 KiB plus the last cap.
   - Tests: a fake child that writes past the cap leaves the broker's buffer at the cap, and the step still reports, with its last progress lines parsed; a normal step's output is unchanged.
   - F12's "Only the last count is read" depends on the tail, so state the cap there.
6. **Records.** F16: the reads are bounded, and the tests that pin each defence are named. F12: the output cap.

**Threat check:**
- Root following a planted link out of the fuzz tree for read, chown or removal (requirements 1 and 2).
- A fuzz-written file or output stream exhausting broker memory (requirements 4 and 5).
- A refused input becoming a silent pass (requirement 4 makes it a finding).
- A cap that cuts the progress lines the stall rule reads (requirement 5 keeps the tail).

**Scope:** `broker/loop7/loop7.go` (`input`, `seed`, `ownPath`, `prune`, `run`'s output collection, and a test seam if needed); `broker/loop7/confine_test.go`, `runner_test.go` and `loop7_test.go`; `broker/loop7/ASSUMPTIONS.md` (F12, F16); `broker/loops/secure.go`, only if the new target detail needs its text there (the `CheckFuzz` case and its constant).

**Estimate:** ~95k. Checkpoint at 50k: requirements 1, 2 and 5 green.

## P3-4b-3r-confine-r6

**Goal:** emptying the fuzz leaf always ends with no fuzz process alive, and within LOOP-1's preemption target.

**IDs:** LOOP-1 (the agent gets the box back within 2 s), ARC-2. Tests carry `REQ: LOOP-1, ARC-2`.

**Sources:** BOARD P3-4b-3r-confine-r5 points 6 to 8: #588 Security 4a L-a and L-b (comment 6080212450), and the tier-A containment gap confirmed in `loop7.go` (L3, comment 6080174845 point 1).

### Today

`Jail.empty` freezes the leaf within `killWait` (5 s), SIGKILLs each pid in `cgroup.procs`, thaws, and waits for `populated 0`. When `Freeze` fails, it thaws and returns the error without any SIGKILL. A fuzz-uid process that slows the freeze therefore survives every later round, and keeps the leaf's CPU and memory while machines start. The wait can also block up to 5 s after cancel, past LOOP-1's 2 s.

### Requirements (each with a failing test first)

1. **A failed freeze still kills** (r5 point 7). When `Freeze` does not reach `frozen 1` within its bound:
   - SIGKILL every pid in `cgroup.procs` anyway;
   - re-read and repeat until the leaf reports `populated 0` or the deadline passes;
   - return an error naming the survivors only if any remain.

   A fork race without the freeze is bounded by `pids.max` (256), so each pass shrinks the set. Optionally use pidfds (`pidfd_open` then `pidfd_send_signal`), so a pid freed and reused by another process is never signalled. If not, record in F16 why a reused pid cannot belong to another user's process inside this leaf. Test (root): a leaf whose freeze cannot complete, made with a test seam that makes `Freeze` fail, still ends empty. It fails on main, where the child survives.
2. **The wait is bounded by the preemption target** (r5 point 6). Bound `empty()`'s whole run so that a cancelled job returns within LOOP-1's 2 s. Suggested split: 1.5 s for freeze and kill, then the wait, all under one deadline passed in from the caller's context plus a floor.
   - When the deadline passes with survivors, return the error. Root then does not work in the tree (F16), and the next run's first `empty()` tries again.
   - Test: a leaf that never freezes, through the seam, still returns within the target, measured in the test with a margin.
   - Record the figure in F16 and agentosd L7-3.
3. **The freeze is shown to matter** (r5 point 8). Add a tight fork-loop test (root): a child that forks as fast as it can, inside the leaf's `pids.max`. The test fails with `Freeze` mutated out of `empty()` and passes with it. Today, with `Freeze` mutated out, the fork-chain stress test still passes, so nothing shows the freeze is needed. If no fork loop on CI's kernel outruns a kill pass without the freeze, say so in the PR with the run's numbers, and record in F16 that the freeze is defence in depth.
4. **Records.** F16 (what `empty()` guarantees on a failed freeze, and its bound); agentosd L7-3 or L7-6, whichever states the preemption figure.

**Threat check:**
- A fuzz-uid process surviving a failed freeze and racing root's next path operation (requirement 1).
- `empty()` holding back a machine start past LOOP-1's target (requirement 2).
- Signalling a recycled pid (requirement 1's pidfd option, or the recorded reason).
- A test suite that passes with the freeze removed (requirement 3).

**Scope:** `broker/loop7/loop7.go` (`Jail.empty`, `killWait`, and a freeze seam for tests); `broker/loop7/confine_test.go`; `broker/loop7/ASSUMPTIONS.md` (F16); `broker/cgroup/` only if `Freeze` needs a variant with a deadline (with its test); `broker/cmd/agentosd/ASSUMPTIONS.md` (one row).

**Estimate:** ~80k. Checkpoint at 45k: requirements 1 and 2 green.
