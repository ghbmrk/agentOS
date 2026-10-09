# HK-1: depaudit self-test flake fix

Defect in merged harness code (P1-6, `tools/depaudit.py`). Not a product package.

**Goal:** the `dependency-audit` job stops failing on harness flakes, without weakening what it detects.

**Evidence** (job logs, tail only):
- #391 run 37824851327 (head 7e81122): `test_shipped_registry_passes` → `OSError: [Errno 39] Directory not empty: 'go-build2650989805'` from `TemporaryDirectory.__exit__` in `run_target`. A process still wrote into the work dir while rmtree ran.
- #372: same OSError in the harness self-tests (reported; the failing attempt's log was replaced by a green re-run and could not be fetched).
- #378: `strace` PTRACE_LISTEN EIO in the recovery-offline scenario (reported; log likewise not retrievable). Inferred mechanism: strace exits non-zero with its own message, the harness reads that as `scenario-failed`, and tracees it let go of keep running untraced.

**Requirements** (local IDs; no SPEC row, this is a defect in tooling):
- HK-1a: removing the work dir outlasts a straggler writing into it (retry on ENOTEMPTY only, bounded, still raises); the sandbox's process group is killed after each run.
- HK-1b: a strace fault (`strace: …Input/output error` / `PTRACE_*` on the scenario's stderr with non-zero exit) is rerun, up to 3 attempts; all faulting is outcome `error`, never `pass`. A scenario failing on its own is not rerun.
- HK-1c: violations seen in a faulted attempt are carried into the final result, so a fault cannot hide a leak.

**Scope:** `tools/depaudit.py`, `tests/test_depaudit.py`, `briefs/HK-1.md`, `BOARD.md` row. Nothing else.

**Done:** CI green; HK-1a–c covered; the planted-leak controls (phones-home, host-socket variants, symlink) still pass in `depaudit run`.

**Estimate:** about 60k tokens.
