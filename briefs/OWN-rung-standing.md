# OWN-rung-standing: standing-key steps, task approvals and metered calls carry their deriving event's rung

Board section: Defects and later findings on surviving packages. Work item #5005 (release items of OWN-rung-caveat, #4940, D-311 row 4). Item 4 (live floors) is carried by the owner-page row (D-311 row 5) and is out of this brief.

**Problem:** `State.Rung` (`broker/kernel/task.go`) returns P0 when a step has no task, so a standing-key step is checked at P0 and a standing key with a rung caveat above P0 runs nothing. A passkey task approval (P3) raises no rung for the requests it covers. `Verified.Spend` does not check the rung, so a rung caveat does not bind metered model or API calls. `assurance/keycheck` has no `rung` kind, so `broker/test/keydiff` plants no rung mutant. All four fail closed except item 3 (Spend), which fails open.

**Requirements:** CH-3, KEY-2 (rung clause), KRN-5, CLK-3, D-147, LOG-7.
1. A step under a standing key is checked at the rung of the owner event that derived the key (recorded on the key's derivation, not inferred from the step).
2. A task approval for a site raises the rung of the requests it covers to that approval's rung.
3. `Verified.Spend` checks the key's rung caveat like a step does.
4. `assurance/keycheck` gains a `rung` kind and `broker/test/keydiff` plants the `if s.Rung < l.Rung` mutant, which the differential test kills.

**Parts:** (a) items 1 to 3 in `broker/kernel`; (b) item 4 in `assurance/keycheck` and `broker/test/keydiff`, after (a), as its own PR.

**Scope:** (a) `broker/kernel/task.go`, `kernel.go`, `state.go`, `broker/kernel/key/` (`key.go`, `authorize.go`, `worth.go` as needed) and their tests, `broker/kernel/ASSUMPTIONS.md`; (b) `assurance/keycheck/`, `broker/test/keydiff/`. Not `broker/kernel/forget.go` or `erase_test.go` (open PR #5937) or `broker/kernel/proc/` (open PRs).

**Acceptance tests:**
- `broker/kernel/key/rung_test.go`: `TestStandingKeyStepRunsAtItsDerivingRung` (KEY-5 first-approval standing key with a P3 rung caveat runs its later step); catches the P0 fallback.
- `broker/kernel`: `TestTaskApprovalRaisesCoveredRequestRung` (a covered submit in a P1 task under a P3 caveat passes after the passkey approval); catches the missing raise.
- `broker/kernel`: `TestSpendRefusesBelowTheKeyRung` (a P3-rung key funding a metered call in a P1 task is refused); catches the open Spend path.
- (b) `broker/test/keydiff`: the planted rung mutant is reported by the differential test; catches a dropped Go rung check.

**Guard files:** none.

**Dependencies:** #4940 done. None open.

**Tier / gate:** tier A (kernel, `assurance/`): L3 on the strongest model, lens screen, separate Security accept on each part.

**Usage estimate:** (a) one session, about 120k; (b) one session, under 100k.
