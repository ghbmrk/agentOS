# MIG-4-untrusted-change (b): the change pipeline, split into c1 to c4

Work item #2785, part (b). Part (a), deleting the skill compiler, merged as #2807. Tier A. Written 2026-10-27 against main at dbd714e.

## What main shows

- **Nothing in production runs the change pipeline.** Outside tests and the A11 harness below, nothing calls `change.New`, `loops.New` or builds a `maintain.Loop3`. `cmd/agentosd` registers `change.Executor` only as a retired executor (`learnstate.go`, `registerRetired`). `grants.Config.Changes` is never set, so the gate already denies every `meta.change.*` intent (`grants/gate.go`, "Nil: they are denied"). #2776 unhooked the learning plane, and the pipeline went with it.
- **What production still uses from `change` is the file store.** `store.go` (`Store`, `MemStore`, `FileStore`, `Content`, `DirContent`) is used by `claim`, `firstboot`, `apply`, `localui`, `e2e/boxe2e`, `cmd/agentosd` (`evidence.go`) and `cmd/agentos-{ap,egress,seller,localui}`. It has nothing to do with changes.
- **The code that still names the engine is all unwired or in tests:**
  - `loops`: the scheduler and its loops (#2786);
  - `maintain`: `Loop3` (sub A; built only in `maintain` and its tests; `follow` uses only `maintain.FollowAlert`);
  - the A11 loop 2 qualification harness, outside the broker module: `assurance/loop2/` (`rig.go` calls `change.New`; it also imports `loops`), its seeds `assurance/loop2-seeds/`, `tests/test_loop2_harness.py`, `assurance/README.md`'s Loop 2 section, and the two "Loop 2 qualification (A11)" steps in `.github/workflows/assurance.yml`. `go vet ./...` in broker/ does not see it, so deleting `change` or `loops` first would turn that workflow red;
  - dated review evidence, `reviews/potency/evidence/2026-10-08/{replay_grader,attention_cohorts}.go`, which nothing builds. It is a record and stays;
  - `grants`: `gate.go`'s `Changes` branch, plus `change_test.go`, `guestreason_test.go`, `pageresult_test.go`, `noticeclass_test.go` and `loops_test.go`;
  - `apply`: comments, and `WhySecurity` and `ErrNotStaged` in `rig_test.go` and `settle_test.go`;
  - `cmd/agentosd`: `change.Executor` in `registerRetired`.
- **The port's targets still do not exist** (unchanged since the issue comment of 2026-10-22). The kernel's entry set (`kernel/state.go`, `schema`) has no goal-outcome or verdict entry (KRN-9, LOG-6). `kernel/sim` has only the seeded fuzz `Run`, with no replay of recorded tasks (HLD-2). The kernel has no HLD-4 standing-key adoption check.

## Decision this brief needs: delete, not port

Mark approved (b) on 2026-10-22 as a port that waits on kernel-lane work. Main now shows that the port would rebuild an engine nothing calls, onto interfaces that do not exist. **Recommendation: delete the pipeline and keep the store.** HLD-2 to HLD-4 are then rebuilt as a new row on the kernel's interfaces once those exist (an outcome entry with a `State()` view, a sim replay of recorded tasks, and the HLD-4 adoption check). This is the reasoning Mark approved for 2785a (`compile`) and for #2776, and it is what docs/OPERATING.md §5 step 4 asks of a port: delete what it replaces.

- **What gets worse:** nothing that runs. HLD-3 and HLD-4 already have no running implementation.
- **What is lost:** about 15k lines (with tests) of reference design. It stays in git history, and docs/migration/cases.md §7 already lists its cases (#1929, #1963, #2099 and others) for the rebuild.
- **The alternative, port:** it keeps waiting on three kernel-lane rows that no one has filed. Until then, `change` keeps `journal` and `verb` alive (#2577, #2572).

The slices below assume delete. If Mark chooses port instead, c1 and c2 still hold, since their code is unwired either way (though the A11 harness would be rebuilt with the port rather than deleted), c3 is replaced by the port, and c4 is unchanged.

## Slices

Deletion runs leaves first, so every PR compiles and every workflow stays green. c1 goes first, because the A11 harness imports both `change` and `loops`. Then c2, then c3, then c4.

**(c1) MIG-4-untrusted-change-c1: delete `maintain`'s update loop and the A11 loop 2 harness.** No `cmd/agentosd`. `maintain` is a sub A directory, unclaimed. The workflow edit makes this a gate-file PR, so it needs a Security accept.
- Delete `maintain.Loop3`, its `Config`, its state and its tests. Keep `FollowAlert` and anything else `follow` uses, along with its tests. `maintain` then imports neither `change` nor `loops`.
- Delete `assurance/loop2/`, `assurance/loop2-seeds/`, `tests/test_loop2_harness.py`, `assurance/README.md`'s Loop 2 section and its H-rows, and the two Loop 2 steps (and their report upload, if it uploads only those) in `.github/workflows/assurance.yml`. A11's loop 2 clause loses an unwired harness; its rebuild belongs with HLD-4's. The PR names this.
- Update `maintain/ASSUMPTIONS.md`: rows for the deleted loop are struck with "deleted (#2785 c1)".
- UPD-4 and UPD-5 lose an unwired implementation. Their real home is the update path on the kernel (#2579 or a successor). The PR names this.

**(c2) the loops side: #2786.** That row's brief adds one acceptance item: `loops` imports no `change` name (direct or test), `grants/loops_test.go` goes with whatever of `loops` it tests, and `broker/daemon/arc2_test.go`'s `loops` entry drops `change`. #3310 holds `loops/plainname.go`, so c2 starts when #3310 lands.

**(c3) MIG-4-untrusted-change-c3: delete the engine.** No `cmd/agentosd`. Gate files likely (`grants` is in core.txt), so a Security accept is needed.
- `broker/change/`: delete every file except `store.go`, `doc.go` and `ASSUMPTIONS.md`. Keep `const Executor = "change"` in `doc.go` until c4, because `cmd/agentosd` names it. `store.go` keeps its `durable` import until c4. `doc.go` and `ASSUMPTIONS.md` shrink to the store. The package then imports neither `journal` nor `verb`.
- `broker/grants`: delete `Config.Changes`, the `Changes` interface, `evaluateChange`, and the `Decided` call. `meta.change.*` intents fall to the gate's default deny, with the fixed reason they get today when `Changes` is nil. Delete `change_test.go`. In `guestreason_test.go`, `pageresult_test.go` and `noticeclass_test.go`, delete only the cases that build a pipeline.
- `broker/apply`: tests use local constants or strings for `WhySecurity` and `ErrNotStaged`; the comments drop the `change.` names.
- `broker/daemon/arc2_test.go`: `change`'s allowed imports shrink to what `store.go` needs (`durable` is not listed there, so `change` probably goes to `nil`). `tools/g1_scope_g2.txt` keeps `allow broker/change/`, since the package remains.

**(c4) MIG-4-untrusted-change-c4: the store leaves `change`, and `change` is deleted.** Needs the `cmd/agentosd` slot.
- Move `store.go` into a new leaf package, `broker/filestore` (`Store`, `Mem`, `File`, `Content`, `MemContent`, `DirContent`), and update every importer listed above. Its atomic write is the one #2577 keeps:
  - if #2577 has merged, the store uses what replaced `durable`;
  - otherwise it uses `kernel/privfile.WriteAtomic` (same steps: write, fsync, rename, fsync the directory), and callers that test `durable.ErrDirSync` on a store save switch to `privfile.ErrUnsynced`. With `loops` gone, that is only `localui`.
- Delete `broker/change` and `registerRetired`'s `change.Executor` entry. Replace `change` with `filestore` in the guard files: `broker/daemon/arc2_test.go` (the `change` entry, and `cmd/agentosd`'s list) and `tools/g1_scope_g2.txt`.

## Requirements and acceptance tests

**Acceptance tests:** none new for c1, c3 and c4. They delete unwired code and move a store; no SPEC ID gains or loses running behaviour. Each PR proves it with:
- **c1:** `go vet ./...`; `go test ./maintain/... ./follow/...`; `go list -deps -test ./maintain` names neither `broker/change` nor `broker/loops`; `grep -rl 'broker/\(change\|loops\)"' assurance tests` is empty; the assurance workflow's YAML still parses (`python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' .github/workflows/assurance.yml`).
- **c3:** `go vet ./...`; `go test ./change/... ./grants/... ./apply/... ./cmd/agentosd/ -run 'Learn|Retired'` (`learnstate_test.go` names `change.Executor`, kept in `doc.go`); `go list -deps -test ./change` names none of `journal`, `durable` or `verb` except through `store.go`'s `durable` import. Also one new test, `grants/gate_test.go::TestChangeIntentDenied`: a `meta.change.*` intent is denied with today's reason. No test pins that reason now, and the test catches a gate whose deleted branch falls through to allow.
- **c4:** `go vet ./...`; `go test ./filestore/... ./claim/... ./firstboot/... ./localui/... ./cmd/...`; `filestore/store_test.go` carries `store.go`'s existing tests over (OP-4: a crash leaves the old or the new content).
- **All:** `tools/trace.py --ratchet` passes. The PR body lists the packages taken off the old core (for #2577's count) and the docs/migration/cases.md §7 rows it retires.

**Guard files:** c1 `.github/workflows/assurance.yml` (a gate file). c3 changes `broker/daemon/arc2_test.go`'s `change` entry. c4 adds `broker/filestore`: its `g1_scope_g2.txt` line and its `arc2_test.go` entry (standard library and `kernel/privfile` or `durable`'s successor only). `tools/risk_tier.py` names neither `change` nor the new package, so leave it unless `risk_tier.py` asks. All of these are pre-approved in each slice's scope.

**Usage:** c1 about 60k, c3 about 100k (mostly deletion; the grants edits need care), c4 about 80k.

## Done when (#2785)

`broker/change` no longer exists (c4), so it imports none of `journal`, `durable` or `verb`. `go vet ./...` passes. `tools/trace.py --ratchet` passes.
