# W3-forget-b2c-f1: A carried take-back is bounded and visible, a restored one is told, and the done-text lint sees every call

Board section: Integration: wiring merged packages into the box. Follows W3-forget-b2c (#427), W3-forget-b2c-2 (#541) and W3-forget-reach; SPEC CAP-3. Last of three packages that edit `broker/cmd/agentosd/forget.go` in turn (see Order). **Folds W3-forget-b2c-f2** (the `ErrNotOpen` test guard): it is test-only, in the same file and function as F1-1, and L3 on #427 said it could ride the same push.

**Sources:**
- L3 on #427, release 1: `carryAgent` retries an owed take-back for the whole boot, bounded in rate and not in count, and on a permanent error the owner hears nothing after the first text. Keep the in-boot retry; after a bound, send one text or show a STATUS line.
- UX on #427, release 1 (bound the silence) and release 2 (the restore path must send the done text, with a test); Security on #427 r2, later 2 (a take-back replayed after a restore runs silently). Together they are this row's "folds the UX point f4".
- L3 on #427, release 2 (this row's f2): the edit to `TestForgetItem2LeavesAFailedTakeBackToRecall` (forget_agent_test.go:200) dropped the "recall not open" row and its `f.sleep → t.Fatalf("retried")` guard, so a change that retries on `ErrNotOpen` is no longer caught.
- Security 4a on #541, P1 ([record](../reviews/security/2026-10-09-pr541.md)): the CH-12 done-text lint (`forget_inform_lint_test.go`) matches identifiers in `inform`'s argument only. It misses `f.inform(recalltool.TakenBack)`, a done text passed through a local variable, and one sent through `promise` or `say` (mutant M2).

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): the owner is told when the agent no longer holds a forgotten task, and is not left waiting on a promise that will not be kept silently.
- **UX-182-3** (UX lens on #182; not a SPEC ID): a text promised or owed is sent, after a restart too; a text that reports a done take-back is sent through the owed path (`done`).
- **CH-12** (SPEC.md:178): every owner text keeps the message format and names the state and a next step; F1-2's line follows CH-12's STATUS exception lines.
- **F1-1** (bounded silence): a take-back `carryAgent` is still carrying after a bound (the builder picks it, about 1h of retries; a constant, testable with the fake clock) sends **one** owner text that names the state (still not taken back, the agent still holds the task) and a next step, and the take-back stays owed and keeps being retried. At most one such text per take-back per boot. A permanent error (one that retry cannot fix) gets the text at once rather than at the bound; the builder records which errors count as permanent in ASSUMPTIONS.md. Tests with the fake clock: (a) a transient error sends no text before the bound, one at it, none after, and the done text still once if a later retry succeeds; (b) one permanent error sends the text before the bound, and only once over later retries and past the bound.
- **F1-2** (visible state): while any take-back is owed and carried, the box's STATUS shows one line saying so (count only, no task words), wired as the other notes are (`cfg.Notes`, learn.go:262). It disappears when none is owed. Test: the line appears for an owed take-back and goes when it is done.
- **F1-3** (restore path told): `resumeRestored` (forget.go:841) sends the done text for a take-back it replays from a restored log, owed as `agentDone` owes it, and only when `Reach` reports it done (the W3-forget-reach state, not `TakeBack == nil`). A replay that is carried follows `carryAgent` (F1-1 applies). A take-back recall already holds (`Handled`) is not re-run and gets no second text if one was already told. Test: a restored log entry with recall open is taken back and told once; a crash after the take-back and before the send is told after restart; a restored entry already told is not told again.
- **F1-4** (f2's guard): `TestForgetItem2LeavesAFailedTakeBackToRecall` regains its "recall not open" row (`ResultSucceeded, forgetAgentNotOpen`) with the `f.sleep → t.Fatalf("retried")` guard. Test: mutating the code to retry on `ErrNotOpen` fails it.
- **F1-5** (CH-12-lint): the lint flags a done text (`forgetAgentDone`, `recalltool.TakenBack`, and every other done text the lint names now) in any call but `done`: `inform`, `promise`, `say`, through a selector, and through a local variable assigned from one. Add the three #541 mutants (selector, local variable, `promise`/`say`) as lint test cases that must fail, and keep the current ones passing.

**Design constraints:**
- New texts (F1-1, F1-2's line) go through the UX lens and keep to CH-12: state, next step, no task words, no jargon. Keep them to one text each.
- Nothing here decides "done" on its own: use the state W3-forget-reach exposes. If that state is missing at the merge base, stop and escalate (the order was not kept).
- `carryAgent`'s retry is not stopped by the bound; only the owner's silence is.

**Not in this package:** recall's done state itself and saving before `takeBack` (W3-forget-reach); item 1's log timing (W3-forget-b2c-f3); the forget log's wiring and restore command (W3-forget-b1-5, b1-6); L1 of #541 (uncorroborated `Agent` entries, LATER); a STATUS line for item 1 forgets still retrying (raise as a finding if seen).

**Tests (write first, each with a `REQ:` marker):** F1-1 to F1-5 as above; the existing done-text and owed tests still pass; `-race` over the carry and restore tests.

**Scope:** `broker/cmd/agentosd/forget.go` (`carryAgent`, `resumeRestored`, `resumeAgent` only as F1-3 needs, the texts block), `broker/cmd/agentosd/learn.go` (the `cfg.Notes` line for F1-2 only), their tests (`forget_agent_test.go`, `forget_owed_test.go`, `forget_inform_lint_test.go`, or a new `forget_carry_test.go`), and `broker/cmd/agentosd/ASSUMPTIONS.md`. Nothing else. Do not touch `Execute`, `retry`, `logForget` (f3) or `broker/recalltool` (reach).

**Order and parallelism:** **W3-forget-b2c-f3, then W3-forget-reach, then this.** It starts only once W3-forget-reach has merged: F1-1's and F1-3's "done" rest on the state reach exposes, and on `takeBack == nil` they would be wrong (Security #541 P2). F1-4 and F1-5 are test-only and could go earlier, but they edit the same test files reach edits, so they wait too. Needs: W3-forget-b2c-2 merged (d63322a), W3-forget-reach merged.

**Gate:** tier A (`python3 tools/risk_tier.py broker/cmd/agentosd/forget.go broker/cmd/agentosd/learn.go` prints A): L3 on the strongest model with a threat check, Security re-sign at the final head (OPERATING §3-4). Lenses: Security and UX (new owner texts).

**Threat check to answer in the PR:** can a restore replay a take-back and tell the owner done while a reset is unfinished; can the bound text or STATUS line leak task words; can one take-back produce two done texts across the carry, the restore replay and a restart; does the lint still catch every mutant?

**PR:** carries `Defect: W3-forget-b2c` (the silence, the restore path and the lost test guard are in its merged code). Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 120k tokens (checkpoint 100k). If F1-1 and F1-2 together pass 60k, ship F1-3 to F1-5 first and split the bound and STATUS into a new row, escalated on BOARD.md.
