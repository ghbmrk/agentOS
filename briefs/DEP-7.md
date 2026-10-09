# DEP-7: depaudit uid boundary, coverage and mutant-kill follow-ups (DEP-3-r1 to r7)

Release findings from the reviews of #562 (DEP-3, merged at 82817bb): L3 point 1 (comment 6077030291) and Security 4a points 1–6 (comment 6077043337). Needed for A9 (evidence integrity). BOARD rows DEP-3-r1 to DEP-3-r7 link here.

**Why one package.** All seven are test or control additions around the uid boundary DEP-3 built. None changes what the sandbox allows: every channel they probe is already closed, and the findings are that no check goes red if it reopens. Every tier-A PR costs a full L3, lens and Security cycle, so one PR saves six. About 120 lines of tests and control code. Split only at the checkpoint below, with r2 and r3 still red: ship r1 and r4–r7, and move r2 and r3 to their own brief.

**Build after DEP-6.** DEP-6 (building now) edits the same `tools/depaudit.py` and `tests/test_depaudit.py`: `sandbox_available()`, `_inner`'s error paths, `control-kept-read-only` and the `IdMapTest` neighbourhood. Building in parallel makes the second merge a tier-A delta needing another Security re-sign (OPERATING §3). Start from main after DEP-6 merges and reread the places named below; line numbers in this brief are not given for that reason (names are from main at 82817bb). The BOARD rows read "queued (after DEP-6)".

**What "red first" means here.** The channels are closed at main, so a test cannot fail at main for want of a fix. Each requirement instead gets a named **mutant** that reopens the property, and the PR cites the failing message with the mutant applied, then the pass at the head. The sandbox does not run in a root container (no subordinate range), so mutants of the sandbox controls (r2, r3, r4) run on CI: push the mutant as a throwaway commit on the branch, cite the failing job line, revert it. Unit-level ones (r1 stub aside, r5, r6, r7) run locally.

**Requirements** (local IDs, as DEP-3's: no SPEC row, a defect in tooling; trace to A9 through DEP-3a–c):

| ID | Row, source | Requirement |
|---|---|---|
| DEP-7a | DEP-3-r1, L3 #562 point 1 | `test_the_evidence_channels_are_closed_by_uid_alone` also asserts the count of connect events in `res`: both connects of `evidence-channels` (before and after the channels) are logged. Use `res["events"]` if no other traced call appears in that run; otherwise count the connect entries. A lost second connect fails a named assertion, not only the control's exit code. Do the same in the with-capability-drop test. |
| DEP-7b | DEP-3-r2, Security point 1 | `_evidence_channels` also tries to reopen strace's stderr: `/proc/<ppid>/fd/2`, `O_RDONLY | O_NONBLOCK`, read, and add "opened … to read" to `wrong` if the open succeeds. Use the strace parent's pid: the probe must go through the tracer's `/proc` entry so it exercises the `ptrace_may_access` gate on strace as well as the pipe inode's DAC (0600, owned by ns uid 0). `/proc/self/fd/2` is not a substitute: it is the same pipe, which the scenario uid is also refused by DAC, but it skips the gate on strace. The `mode == "evidence-channels"` caller keeps the connect before and after. |
| DEP-7c | DEP-3-r3, Security point 2 | `_evidence_channels` also signals the tracer from the tracee: `os.kill` of the strace pid and of pid 1, and adds each that succeeds to `wrong`. Probe with signal 0 (same `kill_ok_by_cred` check as SIGSTOP, no effect if it is allowed); use `SIGSTOP` only with a reason in the PR, since a success would hang the run until the runner's timeout. `ProcessLookupError` is a failure of the control (the pid is wrong), not a refusal: only `PermissionError` counts as refused. |
| DEP-7d | DEP-3-r4, Security point 3 | `distinct-uid` also reads `/proc/self/status` and exits nonzero unless it has the line `NoNewPrivs:\t1`. Removing `prctl(PR_SET_NO_NEW_PRIVS)` from `AS_SCENARIO` makes `control-distinct-uid` fail. |
| DEP-7e | DEP-3-r5, Security point 4 | `IdMapTest` case: a `/etc/subuid` range for the runner with no matching subgid range (separate files, as `ranges` patches both to one file today; give `SUBGID` its own file) makes `_id_maps()` raise `OSError` and `sandbox_available()` false. The raise comes from the explicit `uid is None or gid is None` guard, not from `None` reaching a format string. Add the mirror case (subgid only). The test asserts `assertRaises(OSError)` on `_id_maps()` itself, not only that `sandbox_available()` is false: under Security's `or` → `and` mutant `_id_maps()` raises nothing and `sandbox_available()` fails by an uncaught `TypeError` in `_map_text`, which is not a named assertion. |
| DEP-7f | DEP-3-r6, Security point 5 | Unit test: `_refused_read_only` with `errno.EACCES` and `os.statvfs` stubbed to report `f_flag` without `ST_RDONLY` returns false; with `ST_RDONLY` it returns true; `errno.EROFS` returns true without calling `statvfs`; any other errno returns false. Removing the statvfs guard fails it. |
| DEP-7g | DEP-3-r7, Security point 6 | A test pins the order `_inner` actually uses: `_end_namespace` (kill and reap) completes before any `_chown_tree(path, 0)`. Smallest seam: move the two steps into one helper (for example `_hand_back(paths)`) that `_inner` calls, with no change of behaviour, and test it with `_end_namespace` and `_chown_tree` replaced by recorders (swapping the two calls, or removing `_end_namespace`, fails it). A second check pins `_inner` itself, with `ast` on its source: it calls the helper, and the only `_chown_tree(…, 0)` reachable from `_inner` is inside the helper. A direct chown to 0 in `_inner`, or `_inner` skipping the helper, fails it. If a seam is not wanted, assert the order from the source with `ast`, and say why in the PR. |

**Mutants** (each must turn the named test or control red; cite the message):

| ID | Mutant | Fails |
|---|---|---|
| DEP-7a | `_control("evidence-channels")` skips the second connect (both connects are in that branch, not in `_evidence_channels`), or `parse_strace` drops one line | the new count assertion, by name |
| DEP-7b | `AS_SCENARIO` made a no-op (tracee keeps uid 0) with `drop_caps=False` | `control-evidence-channels`, naming the strace stderr path |
| DEP-7c | same mutant | `control-evidence-channels`, naming the kill target |
| DEP-7d | delete the `prctl(38, 1, …)` line in `AS_SCENARIO` | `control-distinct-uid` |
| DEP-7e | `uid is None or gid is None` → `and` in `_id_maps` (Security's surviving mutant); and a second: `_id_maps` treats a missing gid range as the uid range | the new `IdMapTest` case, by `assertRaises(OSError)` on `_id_maps()` |
| DEP-7f | `_refused_read_only` returns true on any EACCES | the new unit test |
| DEP-7g | `_hand_back` chowns before `_end_namespace`; `_end_namespace` removed; `_inner` chowns to 0 outside the helper or skips it | the helper's ordering test, or the `ast` check on `_inner` |

**Reuse.** Everything extends what DEP-3 built: `_evidence_channels`, `_ids` and the `distinct-uid` control, `UidBoundaryTest.judged(..., drop_caps=False)` (the test-only parameter, never an env var), `IdMapTest.ranges`, `_subordinate`, `_id_maps`, `_refused_read_only`, `_end_namespace`, `_chown_tree`. No new component, no new control name, no new `_control` mode.

**Controls that must keep passing.** All built-in controls on `assurance/dep-targets.json`, in particular `control-own-user-namespace`, `control-evidence-tamper`, `control-no-ptrace-ancestors` and both halves of `control-kept-read-only`. Whatever DEP-6 merged (its tests and the FAIL line wording) is unchanged by this package.

**Threat check for the reviewer.**
- DEP-7b and 7c add probes that run as the tracee. None may change a verdict toward `pass`: an allowed open or signal must end the control `scenario-failed`, never be swallowed. `ProcessLookupError` and `FileNotFoundError` on the probe path must fail the control (the target was not found, so nothing was denied by the uid).
- DEP-7c: a signal that is allowed must not leave `_inner` or strace stopped. Signal 0 meets that; any other signal needs the PR to show why the run still ends.
- DEP-7g's helper must not reorder the steps, add a caller, or move the chown ahead of the reap. Behaviour of `_inner` is otherwise unchanged.
- No change to `AS_SCENARIO`, `DROP_CAPS`, the maps, `_LINE` or `sandbox_available()`. A diff there is out of scope.

**Out of scope.** Each stays on LATER.md (DEP-3's later points) or with DEP-6:
- Hard-link `lchown` DoS of the verdict (L3 point 2), unparsed trace lines failing closed (L3 point 3, PR's own finding), the subordinate-count-0 case (L3 point 4; add it only if DEP-7e's case is a one-line sibling, and say so on the Findings line).
- Security later points 7–9, and lens points 3–8.
- The no-range and missing-`newuidmap` operator wording (lens UX 1–2): DEP-6d/e.
- A positive control proving the blind fd list can open the pipes (lens 7), `/proc/1/mem`, `process_vm_writev` and `pidfd_getfd` probes (lens 6): later.

**Scope:**
- `tools/depaudit.py` (`_evidence_channels`, the `distinct-uid` mode, and for DEP-7g the helper in `_inner`), `tests/test_depaudit.py`.
- `tools/ASSUMPTIONS.md`: extend D9 with the strace-stderr, signal and NNP checks, one line each.
- `briefs/DEP-7.md` (Delivery notes only), `BOARD.md` rows DEP-3-r1 to DEP-3-r7.

**Needs:** DEP-3 (merged, #562) and DEP-6 (must merge first; see above).

**Done:**
- CI green; `dependency-audit` runs the changed controls and new tests unskipped (grep its log for `PASS control-evidence-channels`, `PASS control-distinct-uid` and the new test names, and quote them).
- DEP-7a–g covered, each mutant shown red with its message in the PR.
- `depaudit run` on `assurance/dep-targets.json` passes.
- Risk tier A (`python3 tools/risk_tier.py --git origin/main HEAD`).

## Delivery

Builder model: strongest model (risk tier A: `tools/depaudit*`). One package per session, tests first: write each test or control change, show its mutant red, then the head green; keep the messages for the PR. Review: L3 on the strongest model with the threat check above, then the UX and Potency lens and a separate Security section (OPERATING §3–4); Security re-signs any later tier-A delta. Estimate/checkpoint: about 70k tokens, not a ceiling (OPERATING §5). Checkpoint: if DEP-7b or DEP-7c is still red after two fix attempts, or the CI mutant runs cost more than two rounds, ship the rest and move those two to their own brief.
