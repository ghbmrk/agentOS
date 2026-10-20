# CAP3-held-forget-scope: a forget tells the owner about held agent texts it drops

Board section: Human-native texting. Work item: #2391. Follow-up of O44, O45 (PR #2385); combined reviews, comments 6252859131 and 6253004220. **Tier A** (`broker/owner`, `broker/cmd/agentosd`). Edits `reaction.go`: do not run beside CH11-reaction-quote-gaps, and open #2355 also touches `reaction.go`: start after it lands or closes (D-111).

**Why / failure path.** `Channel.ForgetRecent` (`reaction.go:450`, `:469-475`; it returns nothing today) drops every `Agent: true` `HeldText` because a held text could quote a forgotten reply. `HeldText` (`pacer.go:114-124`) has no task, so task B's held text is lost when the owner forgets task A, with no notice and no `HeldDropped` count.

**Requirements:**
- CAP3-F1: after a forget, the owner is told how many held agent texts were dropped (a count, never their text), as its own broker text (`A deletion dropped N held agent texts.`) after any forget reply, so a later forget cannot drop it (#2516). The count's path: `ForgetRecent` returns it, `keptReplies.forget` and `forgetFan` (`evidence.go:887-903`, `forgetOwnerLocked` at `:777-782`) carry it, and `broker/recalltool/reach.go` words it (`:1050`) after discarding `ForgetTasks`' count today (`:888`, `:897`). The drop is not counted in `HeldDropped`, so no released notice speaks of it.
- CAP3-F2: `HeldText` records its task, and a forget drops only the deleted task's held texts; the reaction window keys by task too (O44). Another task's held text is released after quiet hours.
- CAP3-F3: O44 says "starts with `Agent:` (after a leading ellipsis)" (`normQuote` trims it; the 24 h check uses `normQuote`, `reaction.go:145`).

**Acceptance tests:** (REQ: CAP3-F1..F3)
- `broker/owner/reaction_forget_test.go::TestForgetDropsOnlyTheDeletedTasksHeldTexts` (F2; mutant: drop all).
- `::TestForgetReplyCountsDroppedHeldTexts` (F1; reply shows N and none of the text; mutant: omit the count).
- `::TestForgetDropIsNotInHeldDropped` (F1; mutant: add to `HeldDropped`).
- F3 has no test (`tests/test_owner_assumptions.py` does not exist): it is a stated review point, checked by reading O44.

**Order.** F1 and F3 ship first and are useful alone; F2 follows if the diff stays small, else it becomes a new row (note it in the PR).

**Out of scope.** Reaction quote shapes (CH11-reaction-quote-gaps).

**Scope:** `broker/owner/reaction.go`, `pacer.go`, `reaction_forget_test.go`, `broker/owner/ASSUMPTIONS.md` (O44, O45), `broker/cmd/agentosd/evidence.go` and its test, `broker/recalltool/reach.go` and its test, this brief.

**Usage estimate:** 80k tokens; checkpoint at 60k.
