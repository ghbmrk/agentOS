# P3-4b-3r-confine-r3: fuzz children cannot gain privileges; the fuzz leaf's memory cap is measured

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC LOOP-1, LOOP-7, ARC-2, RES-2. Written 2026-10-09 from the #588 (P3-4b-3r-confine) review records.

**Package:** P3-4b-3r-confine-r3, carrying P3-4b-3r-confine-r1. Both are small changes to how agentosd starts and sizes the jail:
- r3 adds one systemd line or one prctl and a root test;
- r1 adds one CI measurement and one constant.

**Tier A** (`broker/loop7`, `broker/cmd/agentosd`, image): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section.

**Dependencies, all merged:** P3-4b-3r-confine (#588, bba009a).

**Parallel work.** P3-4b-3r-confine-r2 edits `fuzzJail`, `Jail`'s `Cloneflags` and the tmpfiles. This package edits `agentosd.service` and `fuzzLimits`, and the jail's start path in `loop7.go`. Whoever merges second rebases.

## Goal

A fuzz child can never gain privileges through a setuid or file-capability binary. The fuzz leaf's 1 GiB memory cap is replaced by a measured figure, or this package stops with the evidence for a budget decision.

## IDs

ARC-2 (the child holds none of the broker's authority), LOOP-1 (fuzzing never starves the agent), RES-2 (memory budget). Tests carry `REQ: ARC-2, LOOP-1`.

## Sources

- r3: #588 Security R1. Fuzz children run without `no_new_privs`, so the bounding set stays full. The image's setuid-root binaries (`su`, `mount`, `passwd`, the dbus helper) turn a decoder exploit plus one local setuid bug into root.
- r1: agentosd L7-6's "If it changes" column, and #588 L3 point 2 and Security R4. The leaf's 1 GiB `memory.max` sits outside the RES-2 budget sum. It fits the HW-4 floor only because fuzzing runs in spare capacity and is preempted within 2 s. Measure, then lower it to 512 MiB or count the leaf in the budget.

## Requirements (each with a failing test first)

1. **`no_new_privs` on every fuzz child** (r3). Do it in two layers.
   - **In the code, always.** Set the flag in the jail's start path, so the guarantee holds whatever unit starts agentosd:
     - start the child from a goroutine locked with `runtime.LockOSThread`, after `prctl(PR_SET_NO_NEW_PRIVS, 1)` on that thread;
     - let the goroutine exit still locked, so the thread is discarded.

     The flag is per thread and is inherited across clone. Write down why Go's `forkExec` clones from the calling thread. If that cannot be shown, wrap the child in a tiny root-owned exec shim in the release that sets the flag and execs the target; record the choice in F2.
   - **On the unit, if the audit passes.** Add `NoNewPrivileges=yes` to `agentosd.service`.
     - First, audit every binary agentosd starts. `daemon` `TestEveryChildGetsAnExplicitEnvironment` enumerates the call sites: runsc, chronyc, arecord and aplay, the guest bridge, the fuzz children, and `probecmd`'s.
     - For each one, confirm it needs no setuid bit and no file capability as agentosd runs it, as root. List the results in the PR.
     - If any child needs privileges, leave the unit as it is and say why in L7-6.
   - Tests:
     - root, `machines` job: a jailed fuzz child's `/proc/<pid>/status` shows `NoNewPrivs:\t1`. A fake child that dumps its own status is enough. The test fails on main.
     - A child the daemon starts outside the jail, afterwards and from another goroutine, does not carry the flag. This shows the flag did not leak into the daemon's other threads (only without the unit line; with it, every child carries the flag and this test is moot).
     - `tests/test_image.py` checks the unit line, if added.
2. **The leaf's memory cap is measured** (r1). The floor box is not on CI, so measure what CI can show and decide from it.
   - In the `machines` job, as root: run each target in the image's fuzz manifest for one fuzz step (`FuzzTime` 30 s, one worker, as wired) in a fresh leaf, and read the leaf's `memory.peak` after each.
     - A test or a small tool under `broker/loop7` prints a table of target and peak. CI keeps it as the step summary or a job artifact.
     - If `memory.peak` is missing (kernels before 5.19), poll `memory.current` once every 100 ms instead.
   - **Decision rule.**
     - If the largest peak is at most 384 MiB, a quarter of headroom under 512, set `fuzzLimits` to 512 MiB for both `MaxBytes` and `HighBytes`, and record the table in L7-6.
     - Otherwise, keep 1 GiB, write the table into the PR, and stop. Counting the leaf in the RES-2 budget changes SPEC RES-2's table, which needs an L1 spec-diff that Mark approves. The coordinator takes that.
   - Test: `fuzzLimits.MaxBytes` equals the value L7-6 states (a pin). The measurement must have run on this PR's CI; link the run.
   - The floor-box measurement of a fuzz worker beside a starting machine stays owed to the box. Name it in L7-6's "If it changes" column, and in box row P3-4b-4c's acceptance through the PR's Findings line as a release item.
3. **Records.** agentosd L7-6: `no_new_privs` and the route taken, the audit list, the measured peaks and the cap. loop7 F2: the child's privileges.

## Threat check

- A decoder exploit chaining into a setuid binary (requirement 1).
- `NoNewPrivileges=yes` breaking a production child (requirement 1's audit; the existing chrony, runsc, modem and OpenClaw tests in the `machines` job stay green).
- A per-thread flag leaking to the daemon's other children (requirement 1's leak test).
- A memory cap lowered below what an honest target needs, which would turn every step into a false OOM finding under F12 (requirement 2's decision rule needs 25% headroom over the measured peak).

## Scope

- `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service` (one line) and `tests/test_image.py`.
- `broker/loop7/loop7.go` (`Jail.attr` or the start path, for the prctl), `confine_test.go`, a measurement test or tool under `broker/loop7/`, and `ASSUMPTIONS.md` (F2).
- `broker/cmd/agentosd/learn.go` (`fuzzLimits`), its test, and `ASSUMPTIONS.md` (L7-6).
- `.github/workflows/ci.yml`: the `machines` job, to run the measurement and publish its table.

**Estimate:** ~80k. Checkpoint at 45k: requirement 1 green.
