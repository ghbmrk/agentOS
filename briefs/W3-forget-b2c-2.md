# W3-forget-b2c-2: Item 2's texts are owed until they send

Board section: Integration: wiring merged packages into the box. Follows W3-forget-b2c (#427) and W3-forget-b3 (#425); SPEC CAP-3, CH-12.

**Sources:** L3 on #425, second PR with this kind of finding (UX-182-3 / CH-12): item 2's texts go out with `f.inform`, which sends and forgets, so a text lost to a down modem or a restart is never sent. W3-forget-b3 fixed that for item 1 only.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): the item 2 take-back this package tells about ("an agent that read it is rolled back to before the read … Actions already taken stay done"). It adds no CAP-3 behavior.
- **UX-182-3** (UX lens on #182; not a SPEC ID): a text promised or owed is sent after a restart; a lost send is not lost for good.
- **CH-12** (SPEC): every text that reports a wait says what the owner can do or that nothing is needed; texts keep their wording (UX screen only if a text changes, and none should).
- **CH-12-lint** (this package): no done text in `ownerForget` reaches `inform` directly (Work 4).
- **Spec gap:** no SPEC.md ID says the owner is told when a take-back is done. The duty rests on UX-182-3 and #182. Raised to Mark through the L1 coordinator; SPEC.md is not edited here.

**Needs:** W3-forget-b2c (#427) and W3-forget-b3 (#425), both merged; **W3-forget-b4 merged first** (see Order).

**Work:**
1. **Which texts.** Done: `forgetAgentDone` (`agentBack` and `carryAgent`, forget.go:671, 733). Promises (`forgetAgentNotYet`, `NoAgent`, `NotTaken`, `NotOpen`, `WhenOpen`): sent through `say` once, a failed send logged; they are not owed, because the done text that follows is. The builder may argue otherwise in the PR with a sentence each.
2. **Owed only when done.** The take-back is judged by `takeBack`'s own result, so no recall state is read on restart. At the two `err == nil` sites the entry (key `grants.ForgetAgentGoal(id)`, new `Agent` flag on `owedForget`, no task words) is saved **after** `takeBack` returned nil and **before** the text is sent, and cleared only after the send reports success (`done`/`paid`). On `recalltool.ErrCarried` no entry is made or kept: recall's `Retry` owns that text (`TakenBack`, reach.go:223), and the entry, if any, is dropped. The only signal available is `takeBack`'s result; `Reach.Handled` means "recorded, owed or done" (reach.go:258) and is **not** used to decide that anything is done. No done-versus-owed signal exists on `forgetAgent.work`; adding one touches `broker/recalltool` and is out of scope.
3. **Restart.** An `Agent` entry on disk exists only after a take-back returned nil, so `finishOwed` (run in `learning.attach`, before `forgetOwner.agent` is set and before recall opens, main.go:654, 691) needs neither: it sends `forgetAgentDone` for each `Agent` entry through `done`, once the owner channel is up, and clears it on send. It does not read `f.agent` or `Handled`. The existing item 1 branch (`f.forgotten(g)`) is unchanged; an `Agent` entry is matched first and never reaches it.
4. **No direct inform.** A Go test parses `forget.go` (`go/ast`) and fails if any call `f.inform(x)` has `x` naming a done text (`forgetDone`, `forgetDoneRest`/`doneLater` results, `forgetAgentDone`, `forgetOwedLost`); done texts go only through `done`/`say`. Pin it with a mutant: change one site back to `f.inform` and the test fails.

**Residual risks to record in ASSUMPTIONS.md (the cost of not reading recall state):** a crash after `takeBack` returns nil and before the entry is saved leaves item 2 done and the owner untold; a text recall's own `Retry` owes on `ErrCarried` is not owed across a restart (a `recalltool` change, `later` or `release` row to raise).

**Not in this package:** bounding the in-boot retry or its STATUS line (W3-forget-b2c-f1); the `ErrNotOpen` test guard (f2); the restore-while-owed privacy point (f3); the local Wi-Fi page (W3-forget-b3r); any change to item 1's owed logic.

**Tests (write first, each with a `REQ:` marker):**
- A send failure on item 2's done text leaves it owed on disk, and a later send clears it (as W3-forget-b3's tests do for item 1).
- A restart with an `Agent` entry on disk (`f.agent` nil, recall closed) texts `forgetAgentDone` once and clears it.
- `ErrCarried` leaves no entry, and `forgetAgentDone` is not sent by this path (recall's `Retry` sends it): no doubled text.
- A `Handled`-true, not-done take-back (owed in recall) is never told done by this package.
- The owed entry is on disk at the moment the done text is sent (the b4 test pattern, for item 2).
- The owed file holds goal IDs, times and counts only (synthetic canary in a task body never appears).
- The no-direct-inform check (Work 4) and its mutant.
- `-race` over the new tests with `Text` and `resumeAgent` running.

**Scope:** `broker/cmd/agentosd/forget.go` (`agentBack`, `carryAgent`, `finishOwed`, the owed entry type), `broker/cmd/agentosd/learn.go` only if `finishOwed` needs its inputs wired there, their tests (`forget_agent_test.go`, `forget_owed_test.go`, a new lint test), and `broker/cmd/agentosd/ASSUMPTIONS.md`. Nothing else. It must not touch the methods W3-forget-b3r adds to `forget.go`.

**Order and parallelism:** not parallel with W3-forget-b4. Both edit `forget.go` and the owed tests in `broker/cmd/agentosd`, so parallel branches conflict, and b2c-2 relies on b4's save-first rule and order test. Run b4, then b2c-2 (start it after b4 merges). W3-forget-b3r adds only new methods and can run beside either. The b2c-f1..f3 rows also edit this area; none starts before b2c-2 merges.

**Gate:** tier A (`broker/cmd/agentosd`, and it touches a deletion path): L3 on the strongest model with a threat check, UX lens (texts), Security re-sign (OPERATING §3-4).

**Threat check to answer in the PR:** can the owner be told "taken back" when recall did not record it; does any owed file, log or text hold task words; what a replayed or tampered owed entry can do (only a repeated or missing text).

**PR:** carries `Defect: W3-forget-b2c`. Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 110k tokens (checkpoint 110k); simpler than a recall-state design (no `Handled`, no OnOpen hook). If the diff passes the checkpoint, split Work 4 into its own row.
