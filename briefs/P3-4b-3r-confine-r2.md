# P3-4b-3r-confine-r2: the fuzz user's file system reach is its own tree, bounded

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC LOOP-1, LOOP-7, ARC-2, RES-4. Written 2026-10-09 from the #588 (P3-4b-3r-confine) review records.

**Package:** P3-4b-3r-confine-r2, carrying P3-4b-3r-confine-r4. Both are about where the fuzz user can write and how much, and both change the image's tmpfiles, `fuzzJail` in agentosd and the jail's start attributes.

**Tier A** (`broker/loop7`, `broker/cmd/agentosd`, image): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. Runs on CI: root tests in the `machines` job, image checks in `tests/test_image.py`.

**Dependencies, all merged:** P3-4b-3r-confine (#588, bba009a).

**Parallel work.** P3-4b-3r-confine-r3 edits `agentosd.service` and `fuzzLimits`, and confine-r5 and -r6 edit other `loop7.go` functions. Shared files: `learn.go`, `loop7.go`, and agentosd and loop7 `ASSUMPTIONS.md`. Whoever merges second rebases.

## Goal

A fuzz child can read and write only its own tree, plus what the engine needs. Its writes are bounded by a quota, not just by the honest engine's caps, and it leaves nothing behind after its leaf is emptied.

## IDs

ARC-2 (the child holds none of the broker's authority), LOOP-1 (it cannot starve the broker: disk, memory), RES-4 (disk reserve). Tests carry `REQ: ARC-2, LOOP-1`.

## Sources

- r2: #588 L3 point 3 and Security R3. The search-only ACL `u:agentos-fuzz:--x` on the broker's 0700 `/var/lib/agentos` stops that directory being the boundary. Any file below it at a known path whose own mode lets others read it is open to a fuzz child; `modem/roles.json` is 0644.
- r4: #588 Security R2 and loop7 F15. During a 30 s step the fuzz uid can write without limit to its `testdata`, the cache, its scratch directory and world-writable `/var/tmp`, all on the root ext4 that holds the journal. `/tmp` is in the same position unless it is a tmpfs. The prune only runs before the next step.
- r4: Security 4a R-b, comment 6080212450. The child has no IPC namespace, so SysV shm, POSIX mqueues and files in `/dev/shm` outlive `empty()`. They stay charged to the leaf's memcg, up to its 1 GiB, which can trip `memory.max` in later steps. F12 then reports that as a false input finding.

## Requirements (each with a failing test first)

1. **The fuzz state leaves the broker's tree** (r2). Move LOOP-7's state from `/var/lib/agentos/loop7` to a directory of its own beside it. Suggested: `/var/lib/agentos-fuzz`, mode 0700, owned by `agentos-fuzz`, with root-owned `/var/lib` above it, so F16's parent rule holds.
   - Drop the `a+ /var/lib/agentos … u:agentos-fuzz:--x` line from `tmpfiles.d/agentos.conf`.
   - agentosd creates the directory as root and `Jail.Own`s it, as today. No tmpfiles line creates it, because the image's `/var/lib` must not carry it (`mkosi.finalize`, as in L7-6).
   - The state path is a constant in agentosd, never a flag.
   - Migration: none. No box runs LOOP-7 yet (box row P3-4b-4c is queued). A dev box's old `/var/lib/agentos/loop7` is left as is, and the PR says so.
   - Tests:
     - `tests/test_image.py`: no tmpfiles line grants `agentos-fuzz` anything under `/var/lib/agentos`, and the image does not ship the new directory;
     - agentosd: `fuzzJail`'s `State` is the new path, and its parent is not writable by the user;
     - root, `machines` job: a jailed child cannot open `/var/lib/agentos/modem/roles.json`, planted 0644 by the test (fails on main through the ACL).
2. **A disk quota bounds the fuzz user's tree** (r4). Reuse `broker/quota`, the project quotas RES-4 already uses for machines (`machineQuota`, `-disk-quota`):
   - Tag the fuzz state tree with its own project ID, distinct from every machine's; record the ID in agentosd ASSUMPTIONS.
   - Limit it. Suggested: 1 GiB of blocks, covering the caches' 512 MiB plus targets and scratch, and an inode cap; record both against RES-4's reserve.
   - `fuzzJail` applies it before `Own`.
   - With `-disk-quota=off`, or a file system without project quotas, agentosd logs why and runs no fuzz targets. This matches L7-6's rule that no confinement means no fuzzing, not unconfined fuzzing; the guard still runs.
   - Tests:
     - unit: `fuzzJail` with quotas off returns no jail and a reason;
     - root, `machines` job, with a prjquota loop mount as `quota`'s tests make one (`quota/quotatest`): a jailed child writing past the limit gets `EDQUOT` and the broker is unaffected.

     That job already sets `AGENTOS_REQUIRE_QUOTA=1`, so the test must run there, not skip.
3. **No write outside the tree** (r4). Project quotas cover only the tagged tree. Deny the fuzz user the shared writable directories:
   - Add a named-user ACL entry `u:agentos-fuzz:---` on `/tmp`, `/var/tmp` and `/dev/shm` through tmpfiles (`a+`). A named-user entry overrides the other bits of a 1777 directory for that user only.
   - The engine's temporary files go to `TMPDIR`, the per-run scratch directory (L7-2). Go's fuzz shared memory uses `os.CreateTemp("", …)`, so it lands there too. The builder confirms against Go 1.26's `internal/fuzz`.
   - Tests:
     - `tests/test_image.py` checks the three lines;
     - root: a jailed child cannot create a file in `/var/tmp` or `/tmp` with the ACL set by the test (fails on main);
     - the existing jailed fuzz-step tests stay green.
4. **IPC is private and dies with the run** (r4, R-b). Add `CLONE_NEWIPC` to the jail's `Cloneflags`, beside `CLONE_NEWNET`. SysV segments and POSIX mqueues then die with the namespace when its last process exits, which `empty()` ensures.
   - `/dev/shm` is a file system, not IPC; requirement 3 closes it.
   - Test (root): a jailed child that creates a SysV shm segment (`shmget` via `syscall.Syscall`, or `ipcmk` if it is in the CI image) leaves none visible in the host namespace after the run (fails on main).
5. **Records.**
   - loop7 F2 and F7 (the IPC namespace), F9 and F16 (the new `State`, its parent), F15 (the quota bounds a hostile child; the caps keep the honest engine within it).
   - agentosd L7-6: the new path, the ACL removed, the quota and its ID, the `/tmp`, `/var/tmp` and `/dev/shm` denials, fuzzing off without quotas.

## Threat check

- A fuzz child reading broker state through others-readable files (requirement 1).
- Filling the disk the journal shares during one step (requirements 2 and 3).
- Leaving memory charged to the leaf after it is emptied (requirement 4, and requirement 3 for `/dev/shm`).
- Turning confinement off silently when quotas are unavailable (requirement 2 fails closed to no fuzzing).
- An ACL that also denies another user (requirement 3 names only `agentos-fuzz`; the image test checks the exact line).

## Scope

- `broker/cmd/agentosd/learn.go` (`fuzzJail`, the state constant, the quota), `main.go` only to pass the quota mode, their tests, and `ASSUMPTIONS.md` (L7-6).
- `broker/loop7/loop7.go` (`Jail`: `Cloneflags`, and a quota hook if the jail applies it), `confine_test.go`, and `ASSUMPTIONS.md` (F2, F7, F9, F15, F16).
- `image/mkosi/mkosi.extra/usr/lib/tmpfiles.d/agentos.conf`, `image/mkosi/mkosi.finalize` (only if it must assert the new directory's absence), and `tests/test_image.py`.
- `.github/workflows/ci.yml`: the `machines` job's root step, only to add a package or `-run`.

**Not here:** `no_new_privs` and the leaf's memory cap (P3-4b-3r-confine-r3).

**Estimate:** ~120k. Checkpoint at 60k: requirements 1 and 4 green. If requirement 2 is not green by 100k, land requirements 1, 3 and 4 and split requirement 2 into a new row.
