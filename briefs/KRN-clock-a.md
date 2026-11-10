# KRN-clock-a: take broker/clock off broker/durable

Board section: Migration to the capability kernel (D-139). Work item #5147, part a (its **Needs:** line: "the guard moves off it first"). Part b, the kernel reading time through the guard, waits on the serial kernel lane (#5156) and is not in this package.

**Problem:** the TIM-1 guard (`broker/clock`) imports `broker/durable`, old core (`tools/old_core.txt`), for one call: `saveLocked`'s atomic write of `StatePath`. Part b cannot wire the guard into `cmd/agentos-kernel` while it does, and `durable` cannot be deleted while any kept directory imports it (docs/LANES.md, the `durable` row).

**Requirements:** TIM-1 (K4: the restriction, owner text, hold anchor and floor survive a restart, written so a crash leaves the old or the new file whole). Reuse `broker/kernel/privfile.WriteAtomic`, the new core's crash-safe write (#2643 c, hardened in #3954), already used by `broker/update` and `broker/question`; no new component. Its directory rule (owned by this uid or root, no group or other write bit; opened with `O_NOFOLLOW`) is stricter than `durable`'s: a save into a directory another uid can write is refused and logged (`Logf`), as any failed save is today. Its fixed temporary name (`clock.json.tmp`) is removed and replaced by the next save, so a crash leaves no growing residue. Nothing else changes: same file, mode 0600, same JSON, same readers (`BootEstimate`, `agentos-clock-boot`).

**Scope:** `broker/clock/clock.go`, `broker/clock/store_test.go` (new), `broker/clock/ASSUMPTIONS.md` (K4), `broker/durable/stores.txt` (its `clock` line goes: `lifecycle_guard_test.go` requires it once the package no longer calls `durable`), this brief.

**Guard files:** `broker/durable/stores.txt` (line removed), and the privfile crash-path lint (`crashtest_lint_test.go`): the save passes a test-set stop field (`Guard.saveStop`) that a test drives through every step.

**Acceptance tests:** `broker/clock/store_test.go`: `TestTIM1ClockImportsNoOldCore` (no non-test file of the package imports a directory listed in `tools/old_core.txt`), `TestTIM1StaleTempReplaced` (a temporary left by a crash is replaced and the restriction still survives a restart), `TestTIM1SaveRefusesSharedDir` (a state directory other uids can write gets no state file, and the failure is logged), `TestTIM1SaveCrashLeavesOneWholeForm` (a save stopped after any write step leaves the old or the new state whole, and the next save lands). Existing restart tests (`TestTIM1RestrictionSurvivesRestart`, `TestTIM1UnreadableStateFailsClosed` and the K11 floor tests) pass unchanged.

**Out of scope:** the kernel's clock (#5147 b), LANES' import table (process doc; the `durable` deletion row updates it), `broker/durable` itself.

**Tier / gate:** tier A (`broker/clock`, `tools/risk_tier.py`): L3 on the strongest model, the tier's lens screen and a separate Security accept.

**Usage estimate:** one session, well under 150k.
