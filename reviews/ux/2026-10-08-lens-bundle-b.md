# UX lens screen: bundle 2026-10-08b (#320, #321, #322, #324, #329)

Record: PRs #320 #321 #322 #324 #329 · packages P2-2w c1, W3-forget-b2, P2-2w d, SR2-3g, P2-2a f1 · heads 35febcd, 24f3d9d, 11fa1f2, cee016a, 3a79399 · main be5a80c

**Stage:** OPERATING §4 stage 4, batched lens screen, UX section. #320, #322, #324 and #329 are tier A; #321 is tier B, so its combined pass includes a short Security paragraph here. Each PR has an L3 accept on the head named below, and no head had moved when this screen ran. Security for the tier-A PRs is a separate session (`reviews/security/`). Potency is in [`../potency/2026-10-08-lens-bundle-b.md`](../potency/2026-10-08-lens-bundle-b.md).
**Read:** each diff against `origin/main` (owner-facing strings, notices, owner flows), the cited IDs in SPEC.md (CH-3, CH-6, CH-12, CH-20, ONB-3, ONB-6, CRED-8, LOOP-3), the L3 accept comments (findings only), and DECISIONS.md.
**Labels:** [Fact] checked in the diff or spec, or reproduced · [Inference] reasoned, untested.

## Verdicts

| PR | Head | Verdict | Findings |
|---|---|---|---|
| #320 P2-2w c1 | 35febcd | **accept** | 1 release (into the P2-2w c2 row), 2 later |
| #321 W3-forget-b2 | 24f3d9d | **accept** (UX and Security) | agree with the builder's later item |
| #322 P2-2w d | 11fa1f2 | **fix-list** | 2 blockers |
| #324 SR2-3g | cee016a | **accept** | 1 later |
| #329 P2-2a f1 | 3a79399 | **fix-list** | 1 blocker, 1 later |

---

## #320 P2-2w c1: code-generator enrollment at setup (35febcd)
**Verdict: accept.**
- [Fact] The flow matches ONB-3 and ONB-6. `POST /enroll` returns the seed's otpauth link and the typed fallback. `POST /enroll/confirm` takes one code, seals, closes setup and sends the owner `noteEnrolled`. Wrong codes share the channel's counted bucket (`MaxWrongCounted`), and a 429 carries `HeaderPausedUntil`, so the page can say when to try again.
- [Fact] After sealing, the agent and page errors say what to do: "the code generator is already enrolled; a new one needs the recovery key" (CH-12 ✔).
- **release (fold into the existing P2-2w c2 page row; no new row): a re-fetch of `/enroll` silently replaces the seed the owner already scanned.**
  - [Fact] Each `POST /enroll` before confirmation mints a new seed and replaces the pending one.
  - [Inference] A page reload, a second tab or a back-and-forward after scanning leaves the owner's authenticator on the old seed. Each confirm then fails, uses counted tries, and can end in a pause the owner can't explain. The owner's only fix is to delete that entry and scan again, and nothing tells them so.
  - Proposal for c2: keep one link per page session (show the same pending seed until it is confirmed or the session ends), or, if a new seed is minted, say "Scan this new code; delete the older AgentOS entry." Show the pause time from `HeaderPausedUntil` in plain words (CH-12: what the owner can do).
- **later:** two wording items, one LATER.md line each.
  1. [Fact] `noteEnrolled` says "codes from any earlier one no longer work". At a first setup there was no earlier one. [Inference] An owner can read that as a warning about something they didn't do. "A code generator was enrolled at setup." is enough at first setup; keep the second clause for re-enrollment (REC-3).
  2. [Fact] `init -setup` prints "Setup shows the code generator. Keep the passphrase offline. It is shown once." "It" can mean either the generator or the passphrase. Say "The passphrase is shown once."
  - [Inference, not raised] The otpauth label "AgentOS:box" is the same on every box. An owner with two boxes can't tell the entries apart. This matters only once multi-box exists, so it is not raised as a row.

## #321 W3-forget-b2: FORGET cancels a build that read the goal (24f3d9d), tier B
**Verdict: accept.**
- **UX:** [Fact] There is no new owner text. The cancelled build ends with `ErrRequeued` and logs nothing to the owner. I agree with the builder's **later** item (LATER.md already holds it): a rebuild after the requeue could ask a duplicate question. [Fact] C23(c) already drops proposals built from a forgotten goal, so a YES to the earlier ask adopts nothing. The harm is one extra text, not a wrong effect.
- **Security (tier B combined pass):** no new exposure.
  - [Fact] Cancelling reaches the builder: `loopbuild` returns on `ctx.Done()` (builder.go:160, 232) and destroys its machine (builder.go:275), so a cancelled build leaves no machine holding the goal.
  - [Fact] The forgets counter and `forgotAt` are read and written under the same lock as the build's start and end, which closes the forget-before-start and forget-after-end windows.
  - [Fact] A proposal that already reached the pipeline is still covered by C23 (c) and (d): it is dropped, and later candidates from that goal are refused.
  - [Fact] There are no credentials or personal data in code or tests; the fixtures are synthetic.

## #322 P2-2w d: texts name the Wi-Fi page and say when it isn't served (11fa1f2)
**Verdict: fix-list.** Both blockers are in `broker/cmd/agentosd/evidence.go`, inside the PR's own scope.

**Blocker 1 (L3 SHOULD 4 on #148; a regression): when the page isn't served, "Email replies to <someone else>" is swallowed instead of going to the agent.**
- [Fact] In `evidence.settings` the new `if !e.page { return evidenceNoPage, true }` (evidence.go:413) runs **before** the address check. That check (`e.mail.Owns(addr)`, with the `alias` form) is what returns `"", false` for "Email replies to bob@corp.example", so that text goes to the agent as a task.
- [Fact] Reproduced with a scratch test in a worktree at 11fa1f2 (not committed). With the page off, "Email replies to bob@corp.example" returned `taken from the agent: "Not changed: turning this on needs my Wi-Fi page, which isn't running."`.
- [Inference] `-localui-uid` is opt-in, so this hits every box that doesn't serve the page. The owner's request to the agent is dropped and they get a reply about a setting they didn't ask for.
- **Fix:** move the page check below the address block, just before `id := "owner/evidence/" …`. Add a test: page off, alias form for a non-owned address → `"", false`.

**Blocker 2 (CH-12): `evidenceNoPage` gives no owner step and does not say nothing is needed.**
- [Fact] The text is "Not changed: turning this on needs my Wi-Fi page, which isn't running." CH-12: "Every text that reports a problem or a wait says what the owner can do, or that nothing is needed; it never suggests a step that cannot fix the cause."
- [Inference] "isn't running" suggests a restart, and a restart can't fix a page that is off by configuration (no `-localui-uid`). That is CH-12's own example of a step that can't fix the cause.
- **Fix (suggested, GSM-7, one segment):** "Not changed: turning this on needs my Wi-Fi page, which this box isn't serving. Private replies still come by text." If there is a real owner step (for example, whoever installed the box turns the page on), name that step instead of the second sentence.
- [Fact] The agent-facing `NoPage*` reasons in gate.go are fine: they name the page and say it isn't served.
- [Fact] I agree with the builder's LATER f3 and the carries to d2 and W7. `pagewording_test.go` (an AST lint against "local page" and "does not have yet") is the kind of check the recurring-kind note below asks for.

## #324 SR2-3g: guest-visible error filter (cee016a)
**Verdict: accept.**
- [Fact] There is no owner text. `guesterr.Filter` passes only `Safe` errors as written. Anything else becomes "<tool> failed (ref xxxxxxxx); the broker's log has the detail". Every agent-facing message that told the agent what to do (question, recalltool, mcp.go, tree.go, workers) was converted to `Safe` text, so that guidance still reaches the agent. The ones left as refs are internal faults (for example, the machine label at question.go:880, outside-namespace at tree.go:87).
- **later:** [Inference] When the agent relays a ref to the owner ("the broker's log has the detail"), the owner has no way to look it up. A ref lookup on the Wi-Fi page would close this. One LATER.md line; it is not CH-12-blocking, because the text goes to the agent, not the owner.
- SR2-3j and SR2-3k are security rows; they are left to the Security section.

## #329 P2-2a f1: a page approval of a changed item does not run (3a79399)
**Verdict: fix-list.**

**Blocker (CH-12): the "did not run" text tells every owner to ask the agent again, but some page-confirmed items can't be made by the agent.**
- [Fact] gate.go:1887 texts "<request> did not run: it changed after my Wi-Fi page showed it. Ask your agent again if still needed." for any local item whose `ItemSum` changed.
- [Fact] Local, page-confirmed items come from several origins: grant changes made by the agent (gate.go:877), the evidence destination (OriginOwner or originLocal only: "only the owner sets where private replies go", gate.go:936), follow (originLocal only, gate.go:966) and sharing (gate.go:1139).
- [Fact] For evidence and follow the agent is refused by origin. So "Ask your agent again" names a step that can't work: CH-12 "never suggests a step that cannot fix the cause".
- **Fix:** choose the step by the intent's origin. For the agent: "Ask your agent again if still needed." For evidence: "Send EMAIL REPLIES ON again if still needed." For a page-made follow or sharing change: "Set it again on my Wi-Fi page if still needed." If the origin isn't available at that point, use one neutral step that is always true: "Make the request again if still needed." Add one test per origin.
- **later:** [Inference, unverified] a page decision with an empty `d.Request` would make a text that starts " did not run". If the request can be empty, fall back to "A request".

---

## Recurring kind
"A problem text names a step that cannot work, or none" (CH-12) has now appeared on UX run 2 (#124, #126, #132, #133), #327 (bundle a), and here on #329 (a wrong step) and #322 (no step). Bundle a asked the next package that touches owner texts to add a check. That hasn't landed, and both PRs here add owner texts. #322's `pagewording_test.go` shows the pattern works.

Proposal: the next package that touches owner texts adds a table test over its problem texts. Each problem text maps to the step it names (or "nothing needed"), and the test checks that the step is open on the failing path, or for the origin.

Cross-lens results for the fixes above are in the Potency file's arbitration table.

---

## Re-check 2026-10-08 at a579274 (#322 P2-2w d)
Verdict: accept

Read: `git diff 11fa1f2 a579274` (8a2e3d0, 9def31c, and the main merge, which adds only BOARD/LATER rows); `evidence.go`, `evidence_test.go`. [Fact] = in the diff.
- **Blocker 1 resolved as asked.** [Fact] `settings` now runs the address block (`e.mail.Owns`, the `alias` form → `"", false`) before the `!e.page` check. The test "Email replies to bob@corp.example" with the page off returns `ok=false` and submits no intent.
- **Blocker 2 resolved as asked.** [Fact] `evidenceNoPage` is now "…which this box isn't serving. Private replies still come by text." (my suggested wording; "isn't running" is gone and the test forbids it). 9def31c adds `evidenceNoPageSet` for when replies already go to an address ("Private replies still go to o***@…"), so the text isn't false on that path; it is masked and tested. A non-owned address in the EVIDENCE form gets the no-page refusal, not a step that then fails (CH-12).
- **New owner text:** [Fact] only `evidenceNoPageSet`. It is first person, names the Wi-Fi page, and says what is true. Scope intact; no new flow.
- **later (one LATER.md line):** [Inference] neither text names an owner step for turning the page on. That is a deployment setting (`-localui-uid`), not an owner step, so "nothing needed" is acceptable under CH-12; revisit if setup gains a page toggle.
- **Potency:** no new cap (see the potency record).

## Re-check 2026-10-08 at 8a02c52 (#329 P2-2a f1)
Verdict: accept

Read: `git diff 3a79399 8a02c52` (f982c0c, 6449b3b, 8a02c52): `gate.go`, `pageresult_test.go`.
- **Blocker (CH-12) resolved via the neutral step I allowed.** [Fact] The text is now "<request> did not run: it changed after my Wi-Fi page showed it. Make the request again if still needed." No origin is named, and no step it names fails for evidence, follow or sharing. A test per origin asserts the exact text, no "agent", and ≤160 characters. The comment states why agent/guest origins never get a page-confirmed item (`evaluateBroker` denies them every broker action), and the test submits agent evidence/follow/grant-change intents and expects `Denied`.
- **later (one LATER.md line):** [Fact] the per-origin test covers agent, evidence and follow, not sharing. The neutral text holds for it by construction, so no blocker. The empty-`d.Request` fallback from the first pass stays a `later`.
- No new owner flow; scope intact. **Potency:** neutral (text only).
