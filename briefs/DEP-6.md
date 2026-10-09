# DEP-6: depaudit test potency and failure messages (DEP-6a–e)

Release findings from the UX and Potency lens on #552 (DEP-4): Potency 2 and 3, UX 5, 6 and 7, filed as BOARD rows DEP-6a–e. Needed for A9 (the dependency audit's evidence and its fail-loud preconditions).

**Why one package.** All five are small changes to `tools/depaudit.py` and `tests/test_depaudit.py`, around the same three places: `TRACED`, `sandbox_available()` with its exit-2 FAIL line, and `control-kept-read-only`. Every tier-A PR costs a full L3, lens and Security cycle, so one PR saves four cycles. Together they are about 150 lines of code and tests, well inside one session. Split only if the checkpoint below is passed with DEP-6b still red: then ship DEP-6a, c, d and e, and move DEP-6b to its own brief.

**Build after DEP-3.** DEP-3 (building now) changes `sandbox_available()` (a uid-map precondition), its FAIL line and `control-kept-read-only` (it must keep proving `ro` as a non-root uid). Building DEP-6 in parallel would make the second merge a tier-A delta needing another Security re-sign. Start from main after DEP-3 merges, and reread those three places there: the line references below are from main at 958fa35.

**Requirements** (local IDs; no SPEC row, a defect in tooling and its tests):
- **DEP-6a:** `TRACED` is built by a function `_traced(machine)`, and `TRACED = _traced(os.uname().machine)`. `?` appears exactly on the names in `_ABSENT[machine]`; an unlisted machine gets no `?`. Tests call `_traced` for `"aarch64"` and `"x86_64"` directly, so the aarch64 branch runs on x86_64 CI. Replaces `test_only_the_architecture_list_carries_a_question_mark`, which derives both sides from `_ABSENT` and the running machine.
- **DEP-6b:** `control-kept-read-only`'s mount check shares no code with `writable_mounts`, `_reaches_rw` or `_OCTAL`. It reads another source: `/proc/self/mounts` (field 2 is the octal-escaped mount point; field 4 shows `ro` if the mount or its superblock is read-only), then `os.statvfs` on each mount point at or under a read-only kept path. It fails on any mount there that is `rw` in both, unless a `writes` path at or under it covers it. A mount point that gives ENOENT is hidden (as D10); any other error counts as writable. Put the check in its own pure function (mounts text, read-only paths, writes paths, an injectable statvfs) so a unit test can drive it. A bug in `writable_mounts` must no longer blind both `_inner`'s check and this control.
- **DEP-6c:** `sandbox_available()` probes `mount_setattr` once, with no side effect (for example syscall `_SYS_MOUNT_SETATTR` with an invalid fd: any errno but ENOSYS means the call exists). ENOSYS makes it false, so `depaudit run` exits 2 up front, naming `mount_setattr` and Linux 5.12. `_inner` also catches the `OSError` from `_set_read_only` and exits with one line naming the path and errno, not a traceback. Never a fallback remount (DEP-4a).
- **DEP-6d:** when `sandbox_available()` is false, it keeps why: the missing binary, the ENOSYS of DEP-6c, DEP-3's uid-map reason, or the probe's stderr tail (last 5 lines, at most 500 characters). `cmd_run` prints that reason on the exit-2 FAIL line, so a rejected strace name (`invalid system call 'mount'`) or a failing `unshare`/`setpriv` shows.
- **DEP-6e:** `_inner`'s rw-mount error gives a next step: `depaudit: sandbox not run, rw mount under a read-only kept path: <paths>; bind it read-only, or drop the keep entry (tools/ASSUMPTIONS.md D10)`.

**Failing-test-first controls.** Each must be shown failing at main (after DEP-3), with the failing message cited in the PR, then passing at the head.

| ID | Test | Why it fails on main |
|---|---|---|
| DEP-6a | `_traced("aarch64").split(",")` has exactly `?symlink` and `?link` with a `?`; `_traced("x86_64")` and `_traced("riscv64")` have none, and each lists every name in `_LINKS`, `_MOUNTS` and the four socket calls once. Show that dropping the `"?"` from the comprehension, or deleting the `_ABSENT` entry, now fails it. | `_traced` does not exist; the current test passes with either mutant. |
| DEP-6b | Unit: the new function, fed synthetic `/proc/self/mounts` text (a `ro` kept path with an `rw` child, a `writes` child, a `\040`-escaped path, an `rw` child whose statvfs gives ENOENT, one whose statvfs gives EACCES), returns the expected violations. A second case patches `depaudit.writable_mounts` to return `[]` and expects the function to still report the `rw` child. Keep `SubmountTest` passing. | No such function; the control calls `writable_mounts`, so the patched case reports nothing. |
| DEP-6c | Patch `depaudit._SYS_MOUNT_SETATTR` to an unassigned number (for example 1000; the kernel returns a real ENOSYS) and reset `_SANDBOX`. Expect `sandbox_available()` false, and `cmd_run` to return 2 with stderr naming `mount_setattr` and `5.12`, before any target runs. | `sandbox_available()` never looks at `mount_setattr`, so it returns true. |
| DEP-6d | With the stub `strace` from `StraceNamesTest` first on PATH, `cmd_run` returns 2 and its stderr contains `invalid system call 'mount'`. With `unshare` absent from PATH, the line names `unshare`. | The probe's stderr is discarded; the FAIL line lists `TRACED` only. |
| DEP-6e | Extend the `/etc` test in `SubmountTest` (`keep: ["/etc"]`): `detail` matches `bind it read-only, or drop the keep entry`. | The message stops after the paths. |

**Controls that must keep passing.** All built-in controls, in particular both halves of `control-kept-read-only` (DEP-6b changes only how its mount half reads), `control-own-user-namespace`, `control-no-ptrace-ancestors` and DEP-3's new controls. `StraceNamesTest`'s real-strace case stays true on CI. `MountinfoTest` stays as is: `writable_mounts` and `_reaches_rw` are unchanged.

**Threat check for the reviewer.** None of the five may make the sandbox run where main refuses:
- DEP-6c's probe may only turn `sandbox_available()` false, never true.
- DEP-6c's catch in `_inner` must still exit before the command runs.
- DEP-6b must not narrow `_inner`'s check, which stays authoritative.

**Out of scope.**
- `DEP-4-ctl` (the control's kept-path list vs `_inner`'s), `DEP-4-strace1`, `DEP-4-erofs`, `DEP-4-prop`, `DEP-4-topo` and `DEP-4-compat`: LATER, later. If DEP-6b's rewrite makes `DEP-4-ctl` moot, say so on the Findings line; do not widen the list on purpose.
- The uid boundary itself (DEP-3).

**Scope:**
- `tools/depaudit.py`, `tests/test_depaudit.py`.
- `tools/ASSUMPTIONS.md`: D10 (the control's independent source, DEP-6b), D12 (`_traced`, DEP-6a), and a row for the `mount_setattr` probe (DEP-6c).
- `briefs/DEP-6.md` (Delivery notes only), `BOARD.md` rows DEP-6a–e.

**Needs:** DEP-4 (merged, #552) and DEP-3 (must merge first; see above).

**Done:**
- CI green; `dependency-audit` runs the new tests unskipped (grep its log for the test names and `PASS control-kept-read-only`, and quote them).
- DEP-6a–e covered.
- `depaudit run` on `assurance/dep-targets.json` passes.
- Risk tier A.

## Delivery

Builder model: strongest model (risk tier A: `tools/depaudit*`). One package per session, tests first: land each test red at main before the fix, and keep the message for the PR. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR. Review: L3 on the strongest model with the threat check above, then the UX and Potency lens and a separate Security section (OPERATING §3–4). Estimate/checkpoint: about 80k tokens, not a ceiling (OPERATING §5).

## Delivery notes

- DEP-6a–e built on #568 from 82817bb. Local IDs have no SPEC row, so tests carry the "local ID, no REQ marker" docstring (trace.py rejects unknown IDs).
- Locally there is no newuidmap or subuid range (installing them needs a permission prompt), so the sandbox tests (6d strace stub, 6d subrange, 6e, `control-kept-read-only`) run red and green on CI only.
- One test was corrected after the red commit: the DEP-6c stub's message now uses `_set_read_only`'s new wording (errno before path), which the assertion expects.
