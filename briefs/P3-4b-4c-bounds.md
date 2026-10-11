# P3-4b-4c-bounds: the exhaustion round claims only what it checks, and its parsers fail closed

Board section: Phase 3: the agentic loops. Part of P3-4b-4c ([P3-4b-4c.md](P3-4b-4c.md#p3-4b-4c-exhaust)); SPEC LOOP-7, RES-1, RES-2. Written 2026-10-09 from the #599 (P3-4b-4c-exhaust) review records.

**Package:** P3-4b-4c-bounds, carrying P3-4b-4c-pids. Both correct what `ExhaustProbe.Run` in `broker/loops/machine.go` reads and claims:
- pids changes the `processes` claim;
- bounds changes the counters the round reads.

Both edit `Run`, `limited`, the counter parsers and S35.

**Tier A** (`broker/loops`, `broker/machprobe`): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. Unit tests run in CI's `broker` job; the real-guest test (`broker/vm/gvisor/machprobe_test.go`) runs as root in the `machines` job.

**Dependencies, all merged:** P3-4b-4c-exhaust (#599, d3e3e3c).

**Parallel work.** P3-4b-4c-nofollow edits the tamper half of `machine.go` (`Run` for `TamperProbe`, `treeDigest`). This package edits only the exhaustion half. Whoever merges second rebases.

## Goal

A clean exhaustion round lists in `Checked` only limits that bound the guest. No counter value the parsers accept can make a limit or a rise look met when it is not.

## IDs

- LOOP-7: exhaustion probes from inside the sandbox.
- RES-2: each machine's memory, CPU, I/O and process-count limits are enforced, and each machine has a process cap. The `processes` claim and the limit checks rest on it.
- RES-1: admission classes, and experiments frozen or killed when foreground needs resources. This is the round's response half; its hold and CPU count are what requirement 2 bounds.

Requirement 1's tests carry `REQ: LOOP-7, RES-2`. The tests of requirements 2 and 3 carry `REQ: LOOP-7, RES-1, RES-2`, because a counter feeds both a limit check and the round's rise.

## Sources

- pids: the builder's own finding on #599, and #599 Security R2 (comment 6080976185).
  - Under gVisor, a guest process is a task inside the sentry, not a host task. The machine cgroup's `pids.max` therefore bounds the sentry's host threads, not guest processes.
  - Today `Run`'s limit loop checks every entry of `pressureKinds`, `processes` included, through `limited`'s `pids.max` case. A clean round then appends all of `pressureKinds` to `Checked`.
  - `usage()` already skips processes for the rise check, and its comment and S35 say why.
- bounds: #599 Security L1 and L2 (comment 6081667338).
  - `cpuCount` sums `cpuset.cpus.effective` ranges with no cap. Four `0-4611686018427387903` ranges plus `0-1` wrap to 2, and `p.Hold*time.Duration(cpus)/2` can also wrap.
  - `cgroupCounter` accepts a negative value, so a negative baseline inflates the rise.
  - Both are kernel-written and not reachable by the guest. A security finding is still not "later" (OPERATING §2).
- Security README row "A guard fails open on a missing, invalid or out-of-range value". It names this package as owner of its check: a table-driven test beside each parser or guard.
- Records: loops S35 to S38; `machprobe` M2.

## Requirements (each with a failing test first)

1. **`processes` is claimed only if it is bounded** (pids). This brief takes it out of the claims:
   - remove `processes` from what a clean round appends to `Checked`, so an open `processes` finding is never closed by a round that cannot see guest processes;
   - keep the `pids.max` check, but report it under a subject that says what it bounds: the sandbox's host threads. Suggested subject `"sandbox threads"`, with a plain name and a step in `findingText`'s `CheckExhaust` case. A host thread limit that is unset or above budget is still a real RES-1 risk, and stays a High finding;
   - the guest still presses processes (`machprobe.Press`). Its result is logged, per M1, and never a verdict.

   Making the bound real needs a gVisor guest task limit that this repository does not use or document today. It is not in this package: BOARD row P3-4b-4c-pids-r1 owns it. Name that row on the PR's Findings line.

   The lens test (`ownertext_test.go`) covers the new subject's text only. The rest of LATER P3-4b-4c-exhaust l2 (adding `CheckExhaust` and `CheckTamper` with hostile subjects to the identifier scan) stays in LATER.

   Tests:
   - a clean round's `Checked` has no `processes` (fails on main);
   - an open `processes` finding stays open after a clean round;
   - `pids.max` above budget gives the new subject's finding;
   - the real-guest test's expectations at the `pids.max` cases follow the new subject.

   Record in S35 and the LOOP-7 coverage claim that guest processes are not checked yet.
2. **Counters reject values the kernel never writes** (bounds).
   - `cpuCount` fails closed when the count exceeds a cap. Suggested `1<<16`, checked while summing, so the sum cannot wrap first.
   - The `Hold*cpus` product is computed so it cannot overflow; for example, compare against `math.MaxInt64` before multiplying.
   - `cgroupCounter` rejects `n < 0`, and `cgroupInt` keeps rejecting zero and "max" as it does.

   Tests:
   - the wrapping list from the source fails the round (fails on main);
   - a negative counter fails the round (fails on main);
   - a count at the cap passes.
3. **One table-driven fail-closed test per parser or guard** (Security README row).
   - Beside each of these, a table feeds nil, missing, negative, wrapping or overflowing, non-numeric and under-minimum inputs, and asserts the round fails closed: an error, `Checked` empty, nothing closed.
   - In `loops`: `cpusEffective` and `cpuCount`, `cgroupCounter`, `cgroupInt`, `limited`, `usage`'s nil `DiskUsed`, and `ExhaustProbe.Run`'s configuration guard. The guard covers an unset `Budget`, a `Script` at or below its minimums (S35's "1-byte minimums" check, which BOARD P3-4b-4c owes), and a `Hold` under `cpuFloor`.
   - In `machprobe`: `Press`'s unknown kind and its `Procs` and `Child` checks, and `fill`'s size.
   - Where a row of a table passes on main (the guard already holds), keep it as a pin.
   - List the guards that were open on main as blockers this check found.
   - Do not cover the tamper-side guards here; P3-4b-4c-nofollow owns them.
4. **Records.**
   - S35: the `processes` claim, the new subject, the caps and the negative rule, and the `Script` minimums check if requirement 3 adds it.
   - S38, if the new subject's urgency needs a line.
   - `machprobe` M2: unchanged unless `Press` changes.
   - The Security README row: its check now exists for `loops` exhaustion and `machprobe`. Owner: the next package touching the tamper side, which is P3-4b-4c-nofollow.

## Threat check

- A round claiming a guest-process bound it cannot see, closing a real finding (requirement 1).
- A wrapped or negative counter turning a failed press into a met rise, or an unlimited host into a bounded one (requirement 2).
- A parser that later regresses to failing open without a test noticing (requirement 3).
- A finding text with no step or with an identifier (the lens test covers the new subject).

## Scope

- `broker/loops/machine.go` (the exhaustion half only), `machine_test.go`, `secure.go` (the `CheckExhaust` text case only), `ownertext_test.go` and `ASSUMPTIONS.md` (S35, S38).
- `broker/machprobe/machprobe.go` (guards only, if a table finds one open), `machprobe_test.go` and `ASSUMPTIONS.md`.
- `broker/vm/gvisor/machprobe_test.go` (the expectations only).
- `reviews/security/README.md` (one row).

**Estimate:** ~80k. Checkpoint at 45k: requirements 1 and 2 green.
