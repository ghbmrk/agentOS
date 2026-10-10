# DEP-2: depaudit evidence out of the tracee's reach

Release finding from the reviews of #401 (HK-1): Security lens point 2, L3 R1, Potency point 2 (counts folded in). It predates HK-1: `_inner` is unchanged there.

**Problem:** the verdict is built from `work/net.strace`, `work/stderr` (strace's own messages share it) and `work/result.json`. A traced process can write all three, since opens are untraced and `TMPDIR`/`HOME` reveal the work dir. L3 probe: a scenario connects to `93.184.216.34:443`, then truncates `$TMPDIR/../net.strace`, and the run ends `pass` with no violations. The same channel can erase a real strace fault message (HK-1b). The kept paths (`ROOT`, `sys.prefix`, a target's `keep`) are writable from the sandbox and persist across attempts and targets, so a faulted attempt can rewrite `tools/depaudit.py` before the rerun executes `_inner` from it.

**Direction** (from the L3; the builder confirms it):
- strace's `-o` output and its own stderr go to pipes or file descriptors `_inner` holds, outside every bind-mounted path, so a tracee can at most append a line and never erase one.
- `ROOT`, `sys.prefix` and the keep entries are mounted read-only (`mount -o remount,bind,ro`) unless a target declares that it writes there.
- The report and the PASS line show attempts, strace faults and cleanup retries per target, so the HK-1 assumptions (tools/ASSUMPTIONS.md D1, D3) can be observed.

**Requirements** (local IDs; no SPEC row, this is a defect in tooling):
- DEP-2a: a scenario that truncates or rewrites the trace file, strace's stderr or the result file after a planted connect still ends `violation`; a planted control does this.
- DEP-2b: a scenario cannot write `ROOT`, `sys.prefix` or a keep entry unless its target declares it; a planted control tries.
- DEP-2c: the report gives each target's attempt count, fault count and cleanup retries.

**Scope:** `tools/depaudit.py`, `tests/test_depaudit.py`, `tools/ASSUMPTIONS.md`, `briefs/DEP-2.md`, `BOARD.md` row.

**Done:** CI green; DEP-2a–c covered; the existing planted-leak controls still pass in `depaudit run`. Risk tier A.

**Estimate:** about 80k tokens.
