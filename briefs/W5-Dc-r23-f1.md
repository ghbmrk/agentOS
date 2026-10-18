# W5-Dc-r23-f1: the held-install notice names no step that cannot work

Work item: #2066 (release, tier A). Source: UX lens screen on PR #2045 (W5-Dc-r23) at head 30cb9d1.

## Scope

`broker/grants/gate.go` (the held-install notice in `Authorize`, now the exported constant `HeldInstallNotice`), `broker/grants/noticeclass_test.go` and `broker/grants/change_test.go` (the two tests that assert the notice), `broker/cmd/agentosd/held_test.go` (the CH-12 held-text check), and rows GR17 and GR37 of `broker/grants/ASSUMPTIONS.md`. Tier A: grants and owner pacing.

**Guard files:** none (no new package).

## Problem

The gate holds an install (a release adoption) only when `Config.LocalUI` is false, and agentosd never sets it; no non-test code calls `Gate.ConfirmLocal`, and no build has a recovery-key flow. Yet the hold texts the owner "Waiting for your confirmation on my Wi-Fi page, or your recovery key.", and since #2045 it goes out approval class, so an owner with urgent approvals gets it at once in quiet hours and looks for a page that does not exist (CH-12: a text names only steps that work). The CH-12 held-text check covers held-restore texts only, so nothing caught it.

## Change

The notice becomes `HeldInstallNotice`: "A software update is waiting. I can install it once my Wi-Fi page is set up; nothing to do now." It names no step and asks nothing, so it is posted as `owner.ClassUpdate`, as the issue's fix sketch says: quiet hours may hold it, and the held request stays pending and is never denied (GR17), so nothing expires on the owner. The CH-12 check gains two steps, `confirm-page` and `recovery-key`, and checks `HeldInstallNotice` with neither allowed. There is no branch that restores the old wording when `LocalUI` is wired: with a page the gate does not hold installs at all, so the notice is never sent then.

**Acceptance tests:** CH-12, CH-15: `TestHeldInstallNoticeNamesNoStep` (`broker/grants/noticeclass_test.go`) proposes a release with no local UI, flushes, and checks the one notice is `HeldInstallNotice`, posted as `owner.ClassUpdate`, naming no confirm step, recovery key or reply; `TestHeldOwnerTextsNameOnlyStepsThatWork/held-install` (`broker/cmd/agentosd/held_test.go`) runs the CH-12 check on it. Both fail on the old notice (class approval; names `confirm-page` and `recovery-key`).

Failure path: in quiet hours an owner with urgent approvals is texted to confirm on a Wi-Fi page that no build has, or with a recovery key no flow accepts.

## Handoff and estimate

One session, under 40k tokens. L3 and Security reviews on the strongest model.
