# P3-4b-4c-nofollow: the tamper verdict's host digest follows no guest link and cannot wedge

Board section: Phase 3: the agentic loops. Part of P3-4b-4c ([P3-4b-4c.md](P3-4b-4c.md#p3-4b-4c-tamper)); SPEC LOOP-7. Written 2026-10-09 from the #584 (P3-4b-4c-tamper) Security records.

**Package:** P3-4b-4c-nofollow, carrying P3-4b-4c-symlink. Both change how `Run` in `broker/loops/machine.go` stats, digests and cleans a tamper target or the control. The symlink row says it comes after nofollow; built together, they share one set of path helpers and one test rig.

**Tier A** (`broker/loops`; the verdict that closes a tamper finding): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. Runs on CI in the `broker` job; no root needed.

**Dependencies, all merged:** P3-4b-4c-tamper (#584, 522fe80).

**Parallel work.** P3-4b-4c-control, -machineid and -quiesce also edit `machine.go`, but they are built with box row P3-4b-4c, which is not ready. Whoever merges second rebases.

## Goal

A guest that controls a writable target or the control can neither wedge the round, with `Quiesce` held, nor turn a link into a false refusal that deletes the evidence. A host-side event that removes the control fails the round instead of passing it.

## IDs

LOOP-7 (the probe's verdict is the broker's, from what it reads itself). Tests carry `REQ: LOOP-7`.

## Sources

- nofollow: #584 Security 2 (comment 6079573945). `treeDigest` walks with `Lstat`-based entries, but it opens each regular file with plain `os.Open`, without a ctx. A file swapped for a FIFO, or for a link to `/dev/zero`, between the walk's stat and the open blocks the round forever, with the broker's writers held by `Quiesce`.
- symlink: #584 Security points 1 and 2 (comment 6080039732).
  - A target or control `Path` that is a symlink to a directory is followed by `machprobe.Tamper` and by `targetDigest`'s `os.Stat`, while `treeDigest` hashes only the link text. The round then reads as a refusal, and `removeSiblings` (also `os.Stat`) deletes the sibling inside the referent. Reproduced: `Found=[]` plus one journaled refusal.
  - ENOENT on the control after the round counts as "changed" (`machine.go`, "Removed from inside the machine is changed"), so the round passes. A teardown or a cleaner on the host can cause that, so it is not proof the script ran.
- Code today: `Run`, `targetDigest`, `treeDigest` and `removeSiblings` in `broker/loops/machine.go`; `TestAnUnreadableControlFailsTheRound` in `machine_test.go`, whose second half asserts a removed control passes; loops S33.

## Requirements (each with a failing test first)

1. **The digest opens only a regular file, without following, and is bounded** (nofollow).
   - Open each file to be hashed with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, through `os.OpenFile` with the `syscall` flags. Do not add a module to `go.mod`.
   - Then `Fstat` it. The round fails if the opened file is not regular, or if its device and inode differ from the walk's `Lstat`. Either case means the tree changed under the walk; it is never a pass.
   - Bound the read by the round's ctx: check `ctx.Err()` between chunks, and keep the copy in chunks so a cancel is seen within one.
   - Tests use a seam between the walk's stat and the open: a package-level hook in the test build, or a field on the digester. Each case swaps a regular file. The round must return an error within the test's ctx, with `resume` called and nothing journaled as a finding:
     - swapped for a FIFO (`syscall.Mkfifo`): fails on main, where the round blocks; run it with a timeout;
     - swapped for a symlink to a file outside the target: on main, the outside file's content is hashed;
     - swapped for a symlink to `/dev/zero`.
2. **`Attempt`'s contract is written down** (nofollow). The row rests on "`Attempt` returns only after its machine has stopped". S33 does not say so today, and the gVisor test helper `tamperIn` waits only for its exec.
   - Add the sentence to S33 as a contract on whoever wires `Attempt`.
   - Make `Run` not depend on it for liveness: requirement 1's bound holds even while the guest still runs.
   - The wiring that guarantees it belongs to box row P3-4b-4c. List it on the PR's Findings line as a release item for that row's acceptance.
3. **A symlinked `Path` is refused before the round** (symlink).
   - `Run` checks each target's and the control's `Path` with `os.Lstat` before `Quiesce`. If one is a symlink, it returns an error naming which, journals nothing and writes nothing.
   - `targetDigest` and `removeSiblings` use `Lstat` for their directory test, so neither acts through a link even if one appears mid-round. In that case `removeSiblings` removes nothing and the round fails.
   - Tests:
     - a control whose `Path` is a symlink to a directory: `Run` errors, and the referent's sibling, planted by the test, is still there (fails on main);
     - the same for a target;
     - a target replaced by a link to a directory after the before-digest, through the rig's `Attempt`: the round fails, and nothing in the referent is removed.
   - Wiring that passes `filepath.EvalSymlinks` paths is the other route the row allows. Refusal is the one chosen here: it fails closed when the wiring changes. Say so in S33.
4. **A missing control fails the round** (symlink point 2).
   - ENOENT on the control's after-digest is a failed round with an error, not "changed".
   - Flip the second half of `TestAnUnreadableControlFailsTheRound` to expect an error, and fix the doc comment above it.
   - A target's ENOENT still counts as changed, because the guest can remove a target it can write. Record why the two differ in S33.
5. **Records.** loops S33 states:
   - how files are opened (no follow, regular only, ctx-bounded);
   - that a symlinked `Path` is refused;
   - `Attempt`'s stop contract;
   - that a missing control fails the round.

   `machprobe` M4 changes only if the guest side changes, and this package does not expect it to.

## Threat check

- A guest wedging the round, and with it the broker's writers, through a FIFO or device link (requirement 1).
- A guest steering the host's read outside the target through a planted link (requirement 1's `O_NOFOLLOW` and inode check).
- A false refusal that also deletes the evidence of a real tamper (requirement 3).
- A host-side removal closing a tamper finding as "the probe ran" (requirement 4).
- A fix that only moves the race: the inode check makes a swap between stat and open a failed round, never a pass.

## Scope

`broker/loops/machine.go` (`Run`'s path checks, `targetDigest`, `treeDigest`, `removeSiblings`, and a test seam), `broker/loops/machine_test.go`, and `broker/loops/ASSUMPTIONS.md` (S33).

**Not here:**
- the guest side, `broker/machprobe`;
- the box wiring of `Attempt` (P3-4b-4c);
- P3-4b-4c-control, -machineid and -quiesce.

**Estimate:** ~70k. Checkpoint at 40k: requirements 1 and 3 green.
