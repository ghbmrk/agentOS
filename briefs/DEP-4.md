# DEP-4: depaudit fails closed on its own preconditions (recursive read-only, strace names)

Release findings from the reviews of #437 (DEP-2): L3 point 3 (tools/ASSUMPTIONS.md D10) and Security point 2, which was BOARD row DEP-5 and is folded in here. Needed for A9.

**Why one package.** Both are small fail-closed checks on the sandbox's own preconditions, in `tools/depaudit.py` and `tests/test_depaudit.py`. Every tier-A PR costs a full L3, lens and Security cycle, so one PR saves a cycle, and Security on #437 suggested folding point 2 into DEP-4. DEP-3 stays separate: it changes the sandbox's identity model, needs a CI precondition probe first, and carries its own Potency risk.

**Problem.**
- **Writable submounts (D10).** `_mask_host_sockets` binds each kept path with `--rbind`, then `remount,bind,ro`. The remount applies to the top mount only, so a submount under `ROOT`, `sys.prefix` or a keep entry stays writable, which breaks DEP-2b (kept paths cannot carry state between attempts or targets). None exist under the kept paths on CI today, so it is latent. Verified locally (util-linux 2.39.3, kernel 6.18): `mount --rbind -o ro=recursive` and `mount -o remount,bind,ro=recursive` both leave a tmpfs submount `rw` and writable, so do not rely on them. `mount_setattr(AT_FDCWD, path, AT_RECURSIVE, {attr_set=MOUNT_ATTR_RDONLY})` (syscall 442, the same ctypes route `_clear_read_only` uses) made the submount `ro` and a write failed with EROFS.
- **Unknown strace names (old DEP-5).** `TRACED` prefixes every link and mount name with `?`, so an strace that does not know one skips it silently and that syscall goes unseen; the run still says `pass`. strace 6.8 knows them all on x86_64 (checked: an unknown name without `?` fails with "invalid system call"). This predates DEP-2.

**Requirements** (local IDs; no SPEC row, a defect in tooling):
- **DEP-4a:** every mount at or under each read-only kept path is read-only inside the sandbox before the command runs. Set it recursively with `mount_setattr` and `AT_RECURSIVE`, then verify from `/proc/self/mountinfo`: if any mount at or under a read-only kept path is `rw` and is not a declared `writes` path (or under one), the attempt fails as a sandbox error, never runs the command. `writes` paths inside a read-only parent are bound after the recursive set and stay writable, as today. If `mount_setattr` is missing (ENOSYS, kernel before 5.12), prefer failing closed: a fallback remount path would be a tier-A branch CI never runs (L3 on #545 point 3). Never run with an unchecked submount.
- **DEP-4b:** `sandbox_available()` is false, so `depaudit run` fails loudly (exit 2), if the strace on PATH cannot name every syscall in `TRACED` that exists on the running architecture. Probe without the `?` prefix. Names the architecture does not have (`symlink` and `link` on aarch64's generic table) are allowed by an explicit per-architecture list, not by `?`: the `?` stays in `TRACED` only for those.

**Failing-test-first controls.** Each must be shown failing at main (cite the failing message in the PR), then passing at the head.

| ID | Control | Why it fails on main |
|---|---|---|
| DEP-4a | A test (in `EvidenceTest` or a new class) runs a target whose `keep` entry has a tmpfs submount, created before the sandbox inside `unshare -r -m` in the test process or a helper, and a scenario that writes a file into the submount. Expect the write to fail with EROFS, or the attempt to be a sandbox error; never `pass` with the file written. Also extend `control-kept-read-only` to read `/proc/self/mountinfo` and fail on any `rw` mount at or under a read-only kept path. | The write lands: `remount,bind,ro` left the submount `rw`. |
| DEP-4a | A unit test feeds the mountinfo check a synthetic mountinfo text (a `ro` kept path with an `rw` child, a `writes` child, an octal-escaped path such as `\040`) and checks the verdict for each. | No such check exists. |
| DEP-4b | A test puts a stub `strace` first on PATH that execs the real one but exits 1 with "invalid system call" when `-e trace=` names one chosen `TRACED` name without `?`, and expects `sandbox_available()` false (reset `_SANDBOX` first). A second case with the real strace expects true. | `sandbox_available()` runs `strace -o /dev/null true` with no `-e`, so it returns true. |

**Controls that must keep passing.** All 11 built-in controls, in particular `control-kept-read-only` (both halves), `control-own-user-namespace` and `control-no-ptrace-ancestors`. A `writes` path under a read-only parent stays writable (the existing write-kept control).

**Also in scope (record accuracy, LATER DEP-2-sum).** tools/ASSUMPTIONS.md D11 says the counts are summed on the `depaudit run` line; they are printed per target only. Either fix D11's wording or print the total, and remove the LATER line.

**Out of scope.**
- The uid boundary for the evidence (DEP-3).
- `DEP-2-join`, `DEP-2-otattr` and `DEP-2-nestns` (LATER, later).

**Scope:**
- `tools/depaudit.py`, `tests/test_depaudit.py`.
- `tools/ASSUMPTIONS.md`: close D10 as checked; add a row for DEP-4b and the per-architecture list; fix D11.
- `LATER.md`: remove DEP-2-sum, and the DEP-4 and DEP-5 release lines once closed.
- `briefs/DEP-4.md` (Delivery notes only), `BOARD.md` rows DEP-4 and DEP-5.

**Needs:** DEP-2 (merged). Build before DEP-3: both change `control-kept-read-only`, `sandbox_available()`, `_control` and `control_targets`, and DEP-3 builds on this package's mountinfo check (L3 on #545).

**Done:**
- CI green; `dependency-audit` runs the new tests unskipped (grep its log for the test names and `PASS control-kept-read-only`, and quote them).
- DEP-4a–b covered.
- `depaudit run` on `assurance/dep-targets.json` passes.
- Risk tier A.

## Delivery

Builder model: strongest model (risk tier A: `tools/depaudit*`). One package per session, tests first: land each control red at main before the fix, and keep the message for the PR. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR. Review: L3 on the strongest model with a threat check, then the UX and Potency lens and a separate Security section (OPERATING §3–4). Estimate/checkpoint: about 90k tokens, not a ceiling (OPERATING §5).
