# SR3-8-f: quarantine by directory name; tests pin the fsyncs (SR3-8-f1, SR3-8-f2)

Release findings from Security 4a on #432 (SR3-8), S1 and S2 (`reviews/security/2026-10-08-pr432.md`, recorded by #452), filed as BOARD rows SR3-8-f1 and SR3-8-f2. Anchors: OSS-2, C7, C8, C10, A12.

**Why one package.** Both rows are in `broker/cleanroom`'s store (`store.go`, `intake.go`, `builder.go`), and both are tested from `durable_test.go`. Every tier-A PR costs a full L3 plus Security cycle. Together they come to about 200 lines of code and tests. Split rule: if SR3-8-f2's seam is still red at the checkpoint, ship SR3-8-f1 alone and move f2 to its own brief.

**Requirements** (local IDs):

- **SR3-8-f1a (identity from the directory):** `openStore` treats an artifact directory whose manifest ID differs from the directory name as unreadable. It reports `Manifest{ID: e.Name()}` and never `a.m`, so the damaged list holds only directory names that `ReadDir` returned.
  - `get(id)` also refuses a manifest whose `ID` is not `id`. Today it checks only that `id` matches `segment`.
- **SR3-8-f1b (quarantine validates):** `Store.quarantine(id)` refuses an `id` that fails `segment` or starts with `.`. It returns an error and renames nothing.
  - This covers every caller: `New`'s damaged loop (`builder.go:158`) and the outcome path (`builder.go:457`, `o.Artifact`).
  - A refused quarantine in `New` is reported and skipped. It never fails `New`. Today `m.ID == ""` makes `New` fail, which is a denial of service by one file.
- **SR3-8-f2 (pin the syscalls):** the durability tests observe the fsyncs themselves, not just the fault hook.
  - Route every durable call in the package through one seam the hook wraps: each `f.Sync()` and each `syncDir`, in `writeSynced`, `fill`, `quarantine`, `builder.go`'s queue, park and job writes, and `intake.go:149`. The fault hook then runs inside the seam, immediately before the real call. A test can record calls that happened, not calls that were announced.
  - One shape: package vars `syncFile = (*os.File).Sync` and `syncDirFn = syncDir`, which a test replaces with a recorder that also calls the original.
  - Removing the real call must fail a test while the hook stays.

**Failing-test-first controls.** Show each one failing at main and cite the message in the PR, then show it passing at the head. Use only temporary directories, and keep every path inside `t.TempDir()`, including the "outside" directory.

| ID | Test | Why it fails on main |
|---|---|---|
| SR3-8-f1a | Commit two artifacts, A (healthy) and B. Rewrite B's manifest so its `ID` names A and its digest no longer verifies, then reopen with `New`. A is still served by `Get`, and B is in `.quarantine/` with the `B-` prefix. | `openStore` returns `a.m` (ID A), so `New` quarantines the healthy A. |
| SR3-8-f1b | Under `t.TempDir()`, make `artifacts/` and a sibling `victim/`. Give a damaged artifact the manifest `ID` `"../victim"` and reopen: `victim/` is still in place, and nothing named `victim-*` is under `artifacts/.quarantine/`. | `quarantine("../victim")` renames the sibling into the store. |
| SR3-8-f1b empty | Same, with manifest `ID: ""`. `New` succeeds and quarantines the damaged directory by its own name. | `New` fails. |
| SR3-8-f1b direct | `quarantine` called with `".."`, `".x"`, `"a/b"` and `""` returns an error, and the directory tree is unchanged. | No validation. |
| SR3-8-f2 | Replace the seam with a recorder. Commit an artifact: the recorder shows a real file sync for each written file, and a real directory sync for each directory `fill` created and for the store directory after the rename. Mutants: delete `syncDir(dirs[i])` in `fill`, or delete `f.Sync()` in `writeSynced`, keeping each `fault.hit`. Each mutant fails this test. Quote both runs in the PR. | Both mutants survive today (S2): the tests see only `fault.hit`. |

**Controls that must keep passing.** All of `durable_test.go`: the crash points, the fault injection at every op, and a staged directory removed on reopen. Also `cleanroom_test.go`, `integration_test.go` and `oss11_test.go`. A healthy store reopens with nothing quarantined.

**Threat check for the reviewer.**
- Can any input still reach `os.Rename`'s source or destination outside the store? Consider the manifest `ID`, a journaled `o.Artifact`, symlinked directories (does `ReadDir` plus `IsDir` follow them?), and names with a trailing `.`.
- Can a damaged manifest still cause a healthy artifact to be quarantined, or `New` to fail?
- Does the seam leave any production path that skips the real sync when no test hook is set?

**Out of scope.**
- LATER `CR-quarantine-prune` (bounding `.quarantine/`).
- Rewriting the store's layout.
- Fsync semantics on filesystems other than the one CI runs.

**Scope:**
- `broker/cleanroom/{store.go, intake.go, builder.go}`.
- `broker/cleanroom/durable_test.go`, or a new `broker/cleanroom/*_test.go`.
- `broker/cleanroom/ASSUMPTIONS.md`: C14 (identity is the directory name; quarantine validates; the tests pin the syscalls).
- `briefs/SR3-8-f.md` (Delivery notes only) and `BOARD.md` rows SR3-8-f1 and SR3-8-f2.

**Needs:** SR3-8 (merged, #432 6ec0328).

**Done:**
- CI is green.
- SR3-8-f1a/b and SR3-8-f2 are each covered by a passing test.
- Both mutant runs are quoted.
- Risk tier A.

## Delivery

- **Builder model:** strongest model (risk tier A: `broker/cleanroom`).
- **Order of work:** tests first. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR.
- **Review:** L3 on the strongest model with the threat check above, then the Potency lens (it raised the mutant class) and a Security section (OPERATING §3–4).
- **Estimate and checkpoint:** about 80k tokens. This is a checkpoint, not a ceiling (OPERATING §5).
- **Delivery notes (#578):** Identity is checked in `get` (an `ID` mismatch returns `errDamaged`), so `settle` also quarantines a mismatched artifact at completion. `openStore` and `list` skip names that fail `validID`, so a stray non-segment directory is now ignored rather than quarantined. Builder and intake syncs go through the seam with a nil hook, so existing fault traces are unchanged. `TestSyncsOnlyThroughSeam` pins the routing in the source.
