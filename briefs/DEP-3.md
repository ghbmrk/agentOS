# DEP-3: depaudit evidence out of the tracee's uid

Release finding from the reviews of #437 (DEP-2): L3 point 2, Security point 3, Security re-sign 3 N1; tools/ASSUMPTIONS.md D9. Needed for A9 (evidence integrity).

**Problem.** DEP-2a's invariant (a tracee can at most append a line, never erase one) rests on a capability gap, not a boundary. The scenario runs as uid 0 of the sandbox's user namespace, the same uid as `_inner` (PID 1) and strace. Today only `DROP_CAPS` (no CAP_SYS_PTRACE, so `ptrace_may_access` refuses an ancestor holding caps the tracee lacks) stops three untraced channels:
- **Drain:** `open("/proc/1/fd/<trace_r or err_r>")` and read, erasing connect lines or a strace fault line.
- **Freeze or forge:** `PTRACE_SEIZE` on `_inner`, then drain deterministically or rewrite the result in its memory.
- **Partial line:** `open("/proc/1/fd/<trace_w>", O_WRONLY)` and write bytes with no newline just before a connect. `_LINE` is anchored, so strace's next line (`x123 connect(…`) no longer parses and the connect is lost without draining anything (inferred, Security on #437 point 3).

Anything that gives the tracee CAP_SYS_PTRACE back, or drops `_inner` to the tracee's capabilities, reopens all three.

**Direction** (recommended; the builder confirms or argues the alternative in the PR):
- Run the scenario under a uid and gid distinct from `_inner` and strace. Map a range wider than `-r`'s single uid, for example `0 <outer euid> 1` plus `<scenario uid> <subordinate start> <count>`. Use `unshare --map-users`/`--map-groups` or `newuidmap`/`newgidmap` with a subordinate range, or, if CI runs depaudit under `sudo`, write the map directly. `-r` is unconditional since DEP-2 (Security re-sign 2, B2), so a root run is safe.
- After strace, drop to that uid before the command: `setpriv --reuid=<u> --regid=<g> --clear-groups`, then `DROP_CAPS` stays as a second layer. A non-root uid keeps no capabilities across exec, and `/proc/1/*` of another uid is closed by `ptrace_may_access` without any cap.
- Give the work directory (`tmp/`, `home/`, `stdout`) to the scenario uid; kept paths stay root-owned and read-only.
- **Alternative** (only with a reason in the PR): hold the read ends in a process outside the PID namespace and deny `ptrace`, `process_vm_writev` and `pidfd_getfd` to the tracee by seccomp. This is a new component; the uid route reuses kernel DAC (CLAUDE.md: reuse first).

**Unverified preconditions; check these first, on CI, before writing code:**
- Whether the `ubuntu-latest` runner user has an `/etc/subuid` and `/etc/subgid` range and `newuidmap` installed. Locally (root container) `newuidmap` is absent. If CI lacks them, either `apt-get install uidmap` plus a range in `assurance.yml`, or run depaudit under `sudo` there. Record the choice in ASSUMPTIONS.
- Whether every target in `assurance/dep-targets.json` still passes without userns root (Potency question: a scenario that needed root in the namespace now fails). If one breaks, say which and why in the PR; do not widen the scenario's privileges to fix it.

**Requirements** (local IDs; no SPEC row, a defect in tooling):
- **DEP-3a:** the scenario's uid and gid differ from `_inner`'s and strace's. If the wider map cannot be set up, `sandbox_available()` is false and `depaudit run` fails loudly (`FAIL sandbox unavailable`, exit 2), never runs with the old single-uid map.
- **DEP-3b:** each of the three channels, tried after a connect, still ends `violation` with the connect counted, **even with `DROP_CAPS` emptied**. The boundary must hold on the uid alone.
- **DEP-3c:** the scenario's `uid_map` and `gid_map` match the exact shape `_inner` intends, not merely "not the initial identity map" (Security re-sign 3, N1: under a runtime that already nests the runner in a user namespace, today's check passes without `-r`).

**Failing-test-first controls.** Each must be shown failing at main (cite the failing message in the PR), then passing at the head.

| ID | Control | Why it fails on main |
|---|---|---|
| DEP-3a | New built-in `control-distinct-uid`: reads `Uid:`/`Gid:` of `/proc/self/status` and `/proc/1/status` and of its strace parent, sends the loopback datagram `must_log` needs, exits nonzero if any pair is equal. A test fakes a missing `newuidmap`/subordinate range (PATH or a stub) and expects `sandbox_available()` false. | All three are uid 0 today; `sandbox_available()` does not look at the map. |
| DEP-3b | New `_control` mode `evidence-channels` (`expect: violation`, `expect_kinds: ["ipv4"]`, `must_log` the connect). For each `/proc/1/fd` pipe it tries: open write-only and write a partial line, open read-only and read non-blocking, then `PTRACE_SEIZE` on PID 1. Then it connects to 192.0.2.10:443. The test runs it twice: as shipped, and with `DROP_CAPS` reduced to `[]` through a test-only parameter of `run_target`/`_inner`, not an env var a scenario could set. Both must end `violation` with the connect logged. | With `DROP_CAPS=[]` the tracee is uid 0 with CAP_SYS_PTRACE, so the partial-line write succeeds and the connect line no longer parses: `pass`, no violations. The write is deterministic and does not race the reader. |
| DEP-3c | `control-own-user-namespace` compares the whole `uid_map` and `gid_map` to the lines `_inner` intends (the harness passes the expected text; a control may trust it). | On main the map is `0 <euid> 1`, without the scenario's range, so the exact comparison fails. |

**Controls that must keep passing.** `control-kept-read-only` currently counts any errno but EROFS as "not read-only". As a non-root uid, a write to a root-owned kept path may fail with EACCES first and never reach the `ro` check. Keep the control proving `ro` with the mountinfo check DEP-4 adds to it (DEP-4a, merged before this package starts). Do not accept EACCES as proof. `control-no-ptrace-ancestors` and `control-evidence-tamper` keep passing unchanged.

**Out of scope.**
- Recursive read-only and strace name checks (DEP-4).
- `DEP-2-join` (LATER, later).
- Parsing changes to `_LINE`. A fail-closed rule for unparsed trace lines is a fair second layer, but it is a `release` or `later` finding, not this package.

**Scope:**
- `tools/depaudit.py`, `tests/test_depaudit.py`, `tools/ASSUMPTIONS.md` (rewrite D9 as a boundary; add a row for the map and its CI precondition; correct D8's "uid 0" wording).
- `.github/workflows/assurance.yml` only if the CI precondition needs it.
- `briefs/DEP-3.md` (Delivery notes only), `BOARD.md` row.

**Needs:** DEP-2 (merged) and DEP-4 (merged first). Both change `control-kept-read-only`, `sandbox_available()`, `_control` and `control_targets`, so building them in parallel would make the second merge a tier-A delta needing another Security re-sign (L3 on #545). The CI precondition probe touches no repo code and may run while DEP-4 builds.

**Done:**
- CI green; `dependency-audit` runs every new control unskipped (grep its log for each `PASS control-…` line and the test names, and quote them).
- DEP-3a–c covered.
- `depaudit run` on `assurance/dep-targets.json` passes.
- Risk tier A.

## Delivery

Builder model: strongest model (risk tier A: `tools/depaudit*`). One package per session, tests first: land each control red at main before the fix, and keep the message for the PR. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR. Review: L3 on the strongest model with a threat check, then the UX and Potency lens and a separate Security section (OPERATING §3–4); later tier-A deltas need a Security re-sign. Estimate/checkpoint: about 120k tokens, not a ceiling (OPERATING §5). If the CI precondition check shows neither a subordinate range nor `sudo` is workable, stop and escalate with the probe output instead of choosing the seccomp route alone.
