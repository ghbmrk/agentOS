# CLK-run-signin-ctx: a sign-in's contexts end with it

Board row: #5317 (tier A, release, from #5290's review fix-list 2 and #5356's review comments 6780945301 and 6780960922). Depends on #5290, #5323, #5324, #5325, #5326 (all merged). Usage estimate: 60k tokens.

**Why (facts).** `PlanHost.end` cancels the sign-in's `bg` (`broker/clerk/run/plansignin.go:351`, `s.cancel()`), and `Begin` cancels the start context it hands to `Workers.Start` and to `awaitCode`'s `w.Read` (`plansignin.go:248`, `defer lcancel()`). No test observes either: `fakeCLI` drops the contexts it is handed, so both lines survive deletion and carried tree-wide `Mutant-equivalent:` waivers. `SignInWorker.Read`'s doc does not say its ctx is bounded by the call or that a sign-in's contexts end with it.

## Requirements
- **SIC-1 Read's contract.** `SignInWorker.Read`'s doc states that ctx bounds only the call and ends no later than the sign-in, and agrees with `SignInWorkers.Start`'s ("ctx is cancelled when Begin returns"). Not in this PR: any non-test line in the diff would narrow mutgate's targets to that hunk (#5753), so the doc line lands in a separate one-hunk PR after this one merges.
- **SIC-2 The start context ends with Begin.** The context handed to `Workers.Start` (and so to `awaitCode`'s reads) is cancelled once `Begin` returns, even while the sign-in still waits for the owner (kills `:248` deleted).
- **SIC-3 The sign-in's context ends with it.** The context handed to `await`'s reads is cancelled once the sign-in has ended by the owner's approval, with no Remove (kills `:351` deleted).

## Design
- `fakeCLI` records the context of its last `Start` and its last `Read`, under `f.mu`.
- SIC-2: a new test begins a sign-in with Link and Wall of an hour, so neither timer ends the context, and checks the recorded start context's `Err()` right after `Begin` returns, before the code exchange (the exchange would end `bg` and mask the line).
- SIC-3: in `TestPlanRemoveKeepsLastWithTheLogin`, subtest "after a signed-in sign-in", after the "sign-in to end" wait, the last `Read` context (`await`'s, which is `bg`) is non-nil and ended. No Remove has run there, so only `end` can have cancelled it.
- Each assertion fails when only its own line is deleted. The PR carries no `Mutant-equivalent:` line for either.
- The diff is test-only (plus this brief), and the fake's change sits outside a test function, so mutgate targets every covered line of `broker/clerk/run`; the survivor rows above cleared those.

## Scope (files)
- `broker/clerk/run/plansignin_test.go`, this brief. `broker/clerk/run/plansignin.go`'s doc line (SIC-1) follows in its own PR.
- **Guard files:** none.

## Acceptance tests
**Acceptance tests:** `broker/clerk/run/plansignin_test.go::TestPlanSignInStartContextEndsWithBegin` (SIC-2: fails with `plansignin.go:248` deleted); `broker/clerk/run/plansignin_test.go::TestPlanRemoveKeepsLastWithTheLogin/after_a_signed-in_sign-in` (SIC-3: fails with `plansignin.go:351` deleted); SIC-1 is a doc line, checked by review in its own PR. `mutgate` on `broker/clerk/run` reports 0 unwaived survivors.
