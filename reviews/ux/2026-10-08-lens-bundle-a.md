# UX lens screen: bundle 2026-10-08a (#300, #319, #323, #327)

Record: PRs #300 #319 #323 #327 · packages CRED-4b, OSS-6e, OSS-10w, W3-forget-b2b · heads e000ecc, abe4598, 72a8693, fc62903 · main be5a80c

**Stage:** OPERATING §4 stage 4, batched lens screen, UX section. All four PRs are tier A and have an L3 accept on the head named below. Security is a separate session (`reviews/security/`); Potency is in [`../potency/2026-10-08-lens-bundle-a.md`](../potency/2026-10-08-lens-bundle-a.md).
**Read:** each diff against `origin/main` (owner-facing strings, notices, owner flows), the cited IDs in SPEC.md, the L3 accept comments (findings only), DECISIONS.md (CAP-3 deletion reach, 2026-10-05; OSS-6 clock), and CH-12 (SPEC.md:178).
**Labels:** [Fact] checked in the diff or spec · [Inference] reasoned, untested.

## Verdicts

| PR | Head | Verdict | Findings |
|---|---|---|---|
| #300 CRED-4b part 1 | e000ecc | **accept** | none |
| #319 OSS-6e | abe4598 | **accept** | none |
| #323 OSS-10w | 72a8693 | **accept** | 1 release (into OSS-10w2), 1 later |
| #327 W3-forget-b2b | fc62903 | **fix-list** | 2 blockers, release rows as on its Findings line, 1 later |

---

## #300 CRED-4b part 1: broker gate for the credentialed browser executor (e000ecc)
**Verdict: accept.**
- [Fact] There is no owner-facing text. The new strings are `Result.Error`/`Detail` values that go to the agent (`withheld`, `off_origin`, `confinement`, `timeout`). Each one says what happened and, where the agent can act, what to do instead ("not a declared origin; use an uncredentialed context").
- [Inference] When the executor stops (off-origin, malformed reply, timeout), the owner hears about it through CRED-4b part 2's session and sandbox wiring, not here. Nothing to add to K1–K13.

## #319 OSS-6e: the 20h floor holds across broker restarts (abe4598)
**Verdict: accept.**
- [Fact] The change is internal to `broker/pubid`. It adds no owner text, prompt or setting. A malformed stored count refuses the outbox, which is the existing rule (MUST 2 on #163). The owner sees nothing new.

## #323 OSS-10w: follow-fork executor, WF1–WF3 (72a8693)
**Verdict: accept.** The builder asked the UX lens to check the switch-back wording and the gate/executor split.
- [Fact] **Wording: passes.** The request object for an empty name is "get updates from the AgentOS project again" (`grants/grant.go`). It is plain, it names the source, and "again" tells the owner this is a return. The alert uses `ProjectName` ("the AgentOS project") instead of an empty name: "Updates now come from the AgentOS project, set on my Wi-Fi page at 15:04. …". It follows the first-person voice and the single name for the Wi-Fi page (UX run 2, finding 2).
- **release (fold into the existing OSS-10w2 row; no new row): run WF1 when the page describes the root, before any code is asked.** [Fact] Under the split, the gate admits an empty name and the executor enforces WF1. A switch-back to a root whose root keys differ from the shipped ones is asked with the owner's code, approved, and only then refused with NotApplied ("switching back needs the project's own root keys…"). [Inference] The owner spends a code approval on a request that could never succeed, and the reason ends up only in the journal evidence. Proposal for OSS-10w2: `page_follow_root` (describe) already parses the root, so it should apply the same key-material comparison and show a fixed refusal before the follow form offers a switch-back. The executor keeps WF1 as the gate. The page check only moves the predicate earlier, so the owner does not see a dead end (arbitration lever: make the safe path the shortest path). OSS-10w2 also owns the page wording for `not a root to follow`. Under CH-12 that wording must say what the owner can do ("check the file you were given, or ask the fork's maintainers for theirs").
- **later:** after a switch back to the project, the alert's "Not you? Switch back there and change your codes." reads oddly, because "back" now points away from the project. "Not you? Change it there and change your codes." works for both directions. One line in LATER.md.

## #327 W3-forget-b2b: FORGET takes the agent's work back as item 2 (fc62903)
**Verdict: fix-list.** Both blockers are small text and detail changes inside the PR's own files.

**Blocker 1 (CAP-3; DECISIONS 2026-10-05 "Deletion reach into agent work"): item 2 does not state the work so far, and its texts claim more than CAP-3 allows.**
- [Fact] CAP-3: "If the agent has done work since, the owner is asked first, with the restore point and the work so far … Actions already taken stay done." Mark's decision fixes the form of the ask: "a text naming the restore point and the work so far ("forget a mail you deleted from agent, back to 08:12 Oct 5; 2 actions stay done")". Recall's own ask follows it: `Reach` detail tails at `recalltool/reach.go:739–750` read "; N actions so far stay done".
- [Fact] #327's `ownerForget.AgentItem` returns the object "your agent's work since <time>" with an **empty detail** (`forget.go`, `AgentItem`). `Reach.Work` returns only a bool, so the count never reaches the ask.
- [Fact] The texts around it claim a full undo. The notice says "item 2 takes that work back", and the done text `recalltool.TakenBack` says "Your agent's work since that task is undone". Neither says that its actions stay done.
- [Inference] Effect on the owner: they approve, with a code, an irreversible reset without knowing how much work it covers. They may also believe that mails or other actions the agent already took were reversed. That is the misunderstanding CAP-3's "actions already taken stay done" exists to prevent.
- **Fix (reuse, no new path):**
  - Have `Reach.Work` also return the action count that `r.actions(lineage, since, time.Time{})` already computes.
  - Render item 2's detail with the same tails recall uses ("; N actions so far stay done" … "", within `fieldCap`).
  - Change the notice's first sentence to "Your agent has worked since that task, so item 2 resets it to before then; its actions stay done." The second sentence is the BOARD row's own text and stays as it is.
  - `TakenBack` gains the count, as recall's done text does ("Its N actions since stay done.").
  - Add a test that asserts the count appears in the item-2 detail and in the done text.

**Blocker 2 (CH-12, SPEC.md:178): three failure texts tell the owner to "Send FORGET to ask again", which cannot work once item 1 has run.**
- [Fact] CH-12: "Every text that reports a problem or a wait says what the owner can do, or that nothing is needed; it never suggests a step that cannot fix the cause." `forgetAgentNoAgent`, `forgetAgentNotTaken` and `forgetAgentNotOpen` are sent from `agentBack`, which runs only when item 1 was approved (`siblingApproved`). Item 1 deletes the task (the PR body says so: "item 1 deletes the task before item 2 can read it"). FORGET then lists recent kept tasks (`f.tasks.recent`), and the forgotten task is no longer among them, so a new FORGET cannot ask item 2 for it again.
- [Inference] Effect on the owner: they follow the instruction, the task is missing from the list, and the agent still holds the forgotten task with no route offered.
- Class: CH-12 is not among the PR's cited IDs, but these texts are new in this PR and the fix is wording inside its scope. Per OPERATING §2 ("when unsure, pick the stricter"), this is a blocker.
- **Fix:** where item 1 was approved, say what remains true and drop the dead step. For example: "Forgotten, but your agent's work since it is not undone: your agent is not running. It still holds that task." (similarly for "couldn't save" and "memory is not open"). `forgetAgentAlone` keeps "Send FORGET to ask again": item 1 was not approved, so the task is still listed and the step works.
- [Inference] A route that carries these three cases (an owed take-back that recall finishes later, as `ErrCarried` already does) would remove the dead end itself. It changes the take-back's recovery semantics, so it belongs in a **release** row next to the OP-4 reconcile row the PR already proposes. The PR's Findings line should name it.

**Release (agree with the PR's Findings line, no change in class):** the contradicting texts (item 1 NotApplied while item 2 says "no longer holds"; item 1's "your agent's own files may still hold it" next to item 2's done text). Blocker 1's fix to `TakenBack` should be written with that row in mind, but it does not close it.

**later (agree):** "until that work is undone" in the BOARD-mandated notice. The owner keeps the work when approving only item 1, so the sentence names no event the owner can expect. Revisit with the contradictory-texts row.

---

## Recurring kind
"A problem text names a step that cannot work" has now appeared on #124, #126, #132, #133 (UX run 2) and #327. CH-12 states the rule, but no check enforces it. Per CLAUDE.md, the next package that touches owner texts should add a test or lint that flags any text ending "Send X to …" whose command's precondition the failing path has already removed. It can start as a table test over the forget texts. Noted in README.

---

## Re-check 2026-10-08 at 14ee01c (#327 W3-forget-b2b)
Verdict: accept

Read: `git diff fc62903 db120d6` (non-merge content; SPEC/TRACE/DECISIONS changes in that range come from main merges, not the PR) and `14ee01c^1..14ee01c` (BOARD/LATER only). Files: `forget.go`, `main.go`, `grants/gate.go`, `grants/grant.go`, `recalltool/{reach,provenance,service}.go`. [Fact] = in the diff.
- **Blocker 1 (CAP-3) resolved.** [Fact] Item 2's detail is now "N actions so far stay done" (`ForgetAgentActions`, from the count `Reach.Actions` takes when the ask is made; fixed in params so a re-issue asks what was asked, "no actions yet" at 0, nothing named if unknown). The notice reads "item 2 takes it back to before the task; actions it took stay done." and `TakenBack` reads "…no longer holds it. Actions it took stay done." The full-undo claim and "undone" are gone.
  - **later (one LATER.md line):** the done text says actions stay done but not how many; the count is in the ask, which is what CAP-3 requires.
- **Blocker 2 (CH-12) resolved as asked.** [Fact] No text sent after item 1 has run says "Send FORGET to ask again" (only `forgetAgentAlone`, where item 1 was not approved, keeps it). The not-saved and not-open texts say what remains true ("Your agent's own files may still hold that task").
  - **later (fold into the existing contradicting-texts / carried-take-back release row):** [Inference] those two texts and `forgetAgentNoAgent` ("it holds nothing new. Nothing is needed.") don't agree on whether the agent's files hold the task, and the first two give neither a step nor "nothing needed". The carried take-back row removes the cause.
- **New owner text in the later deltas:** `forgetAgentWhenOpen` ("Not taken back yet: memory is not open. I will do it when it opens and text you.") states the wait and what happens next; `forgetAgentNotYet` likewise. Both are CH-12-compliant, and scope is intact. [Fact] Approved items 2 queue until recall opens and run once (serialized, `Handled` check), so the owner is not texted twice.
- **Release rows** on the PR's Findings line stand; no new row from this re-check.
- **Potency:** the deltas add capability (item 2 waits for recall rather than failing); nothing is capped.
