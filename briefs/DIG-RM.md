# DIG-RM: remove the daily digest that D-097 retired, from SPEC and from agentosd

Board section: Integration. Decision D-097 (Mark, Decisions cards 2026-10-10): "STATUS is the owner's primary view, only urgent classes pushed, daily digest removed, weekly liveness line (CH-15)". CH-15 already says "There is no digest." Class: release (failure path below). Four packages, run in order: **DIG-RM-spec** (L1 spec-diff, SPEC.md only, Mark approves), **DIG-RM-a** (every digest line reaches STATUS instead), **DIG-RM-b** (delete the digest code), **DIG-RM-c** (no comment or log line still describes the digest, enforced by a lint test).

**Failure path (checked at main aa1a1c9):** SPEC still sends the owner to a digest in ten places (table below), so a builder working from OP-2, CH-11, CRED-5 or DEV-10 builds or keeps digest behaviour CH-15 forbids. agentosd still runs it: `main.go:652` builds `newDigestBox`, `main.go:851` runs `go dg.run(ctx)`, and `digest.go` pushes "Daily digest: %s; reply STATUS for more." at `digestHour = 8`. That is an unasked text of a non-urgent class every day, which CH-15 forbids.

**Conflict settled (Q1).** D-116 (2026-10-14, after D-097) parks unclear effects "in the daily digest without interrupting the owner", lets RETRY act on digest items, and lists a refused resend "in the next digest"; Mark approved that wording of OP-2, OP-4 and CH-11 the same day. Both decisions hold if the parked list moves to STATUS. The owner is still never interrupted (D-116's point) and never texted it unasked (D-097's point). Mark confirmed that reading on 2026-10-17 (Q1 below).

## Reference map

Each live digest reference, where D-097 puts it, and the recommended wording. Change-log rows (lines 721, 746, 748, 760) are history and stay as written. "Marked" means D-097 alone did not settle the reference; Mark settled each on 2026-10-17 (Decisions below).

| # | SPEC line, ID | Today | D-097 home | Recommended wording |
|---|---|---|---|---|
| 1 | 387, OP-2 step 3 | "the item goes in the daily digest (e.g. "Invoice 42: unclear if paid; not retried.")" | STATUS line (marked, Q1) | "the item is listed in STATUS until a check or a retry settles it (e.g. "Invoice 42: unclear if paid; not retried."), and is never texted unasked (CH-15)." |
| 2 | 389, OP-2 | "The owner MAY ask to retry a digest item (RETRY, CH-11)." | STATUS line (marked, Q1) | "The owner MAY ask to retry an item STATUS lists as unclear (RETRY, CH-11)." A refused resend stays listed in STATUS (D-116's "next digest"). |
| 3 | 393, OP-4 | "is parked for the digest (OP-2)" | STATUS line (marked, Q1) | "is parked and listed in STATUS (OP-2)" |
| 4 | 230, CH-11 | "`RETRY` asks about each effect the daily digest marks unclear and not retried (OP-2)" | STATUS line (marked, Q1) | "`RETRY` asks about each effect STATUS lists as unclear and not retried (OP-2)" |
| 5 | 283, CRED-5 | "the owner gets one digest line naming the plan and the choice ("ChatGPT plan paused until you say yes; …"), and ONB-9's line for that plan says the same" | STATUS line (marked, Q2) | "STATUS and ONB-9's line for that plan name the plan and the choice ("ChatGPT plan paused until you say yes; using your other routes meanwhile.") until they answer". No push: work continues on the other routes, so nothing is blocked (CH-15's first urgent class does not apply). |
| 6 | 503, DEV-5 | "counted in the digest" | STATUS line | "counted in STATUS" (one line per device that acted today, e.g. "Thermostat: 4 changes today."). Dropping the count is the alternative; it is the owner's only view of the cap. |
| 7 | 510, DEV-9 | "the digest names a cut-off device that reports outdated firmware" | STATUS line | "STATUS names a cut-off device that reports outdated firmware, for as long as it does (OP-9)" |
| 8 | 523, DEV-10 | "Discovery results reach the owner as one digest line ("Found a printer and 3 lights. …") and on the local page." | STATUS line | "Discovery results appear as one STATUS line ("Found a printer and 3 lights. Connect them on my Wi-Fi page.") and on the local page." |
| 9 | 523, DEV-10 | "gets its own digest line, … with an ID unique among open requests (CH-12) that stays open until the next digest" | STATUS line; new ID lifetime (marked, Q3) | "gets its own STATUS line, … with an ID unique among open requests (CH-12) that stays open while discovery still finds the device and it is neither connected nor dismissed, with no time cap" |
| 10 | 523, DEV-10 | "A grant unused for 60 days (owner-set) appears in the digest with `REVOKE <id>`." | STATUS line | "… appears in STATUS with `REVOKE <id>` until it is used or revoked." |
| 11 | 216, CH-3 table | "in reply to the digest line" | STATUS line | "in reply to its STATUS line" |
| 12 | 516, DEV-10 table | "Code-generator code in reply to its digest line (`CONNECT <id> <code>`)" | STATUS line | "… in reply to its STATUS line (`CONNECT <id> <code>`)" |

No reference maps to an urgent text: none blocks work, carries a deadline, holds work, or is a security alert. Nothing is dropped outright; row 6 is the one candidate, with the alternative noted in its row.

## DIG-RM-spec: SPEC.md loses the digest (L1 spec-diff, Mark approves)

**Requirement IDs:** OP-2, OP-4, CH-11, CH-3 (table), CRED-5, DEV-5, DEV-9, DEV-10, as amended per the map; CH-15 unchanged. **Change:** the twelve edits in the map, worded as there (Mark's answers to Q1 to Q3 match); one change-log row citing D-097 and this brief. No other SPEC text moves.

**Acceptance tests:** none: a SPEC-only PR has no code; the check is `grep -n -i digest SPEC.md` printing only change-log rows and CH-15's "There is no digest", plus `python3 tools/doclint.py` clean. Mark's approval of the PR at its head is the acceptance.

**Guard files:** none (no package added). **Scope:** `SPEC.md`. **Tier and model:** per `tools/risk_tier.py` (SPEC.md is L1; Mark merges). **Usage estimate:** 30k tokens, checkpoint 20k. **Dependencies:** this brief merged; none left (Q1 to Q3 answered 2026-10-17).

## DIG-RM-a: every digest line is shown in STATUS (tier A)

**Requirement IDs** (the builder writes the failing test first):
- **DRA-1 (sources move to STATUS):** each source that feeds the digest today is a STATUS note (`daemon.Config.Notes`, `[]func() string`) or part of an existing STATUS line. The sources are `maintain.Loop3`, `loops.Learn`, `loops.Guard`, `loops.Scheduler`, `question.Book`, `loop7.Source`, `apply.Applier`, `events.Attention`, `change.Pipeline`, `owner.Channel` (`TakeDigestNotes`: ignored-code and code-flood counts, and local notes via `owner/local.go`), and agentosd's `secondLine`, `capLines`, `qualitySource`, `sleepSource`, `unclearSource`, `mailSource`. A line stays in STATUS while its condition holds (OP-9), never only until it was sent once.
- **DRA-2 (draining sources):** a source whose read drains it (`question.Book.TakeDigest`, `events.Attention.TakeDigest`, `owner.Channel.TakeDigestNotes`) gets a read that does not drain, or its items already show in STATUS through the open-question view. The builder checks which, and STATUS does not list one item twice.
- **DRA-3 (unclear list, OP-2/OP-4 per Q1):** STATUS lists `Daemon.RetryWaiting()` in the existing unclear wording (`unclear.go`), capped as `unclearLineMax` caps it today. A refused retry stays listed. Comments that send a reader to the digest say STATUS: `daemon.go:246,251,516`, `retry.go:108`, `journal/engine.go:668,677,729,877` ("parked for the daily digest"), `owner/channel.go:109,186,617`. `events.Attention`'s route named "digest" is renamed in DIG-RM-b (DRB-2), not here.
- **DRA-4 (forget holds, CAP-3):** a forgotten subject never appears in a STATUS line moved here. The digest's forget filter (`forgetOwner.wireDigest`) has a STATUS equivalent, or each moved source already filters.
- **DRA-6 (owner text that names the digest):** `broker/owner/local.go:222`, the Wi-Fi wrong-code alert, ends "More wrong tries today go in the digest." Once DRA-1 makes the local notes a STATUS line, it ends "Text STATUS for more wrong tries today." (fixed broker wording, CH-12). A scan of `broker/**/*.go` string literals at aa1a1c9 finds no other owner-facing text naming the digest outside code DIG-RM-b deletes (`digest.go`, and `plainname.go:23`, a guard file there).
- **DRA-5 (nothing new is pushed):** moving a line to STATUS sends no text; the daily digest still runs until DIG-RM-b deletes it (this package only adds STATUS lines).

**Acceptance tests:**
- DRA-1: `broker/cmd/agentosd/status_sources_test.go::TestEveryDigestSourceIsAStatusNote`. It reads `newDigestSources` and the box's registered sources and fails while any is not wired to STATUS. It is the inverse of DIG-1's "no `Digest()` goes unwired" check, and it outlives DIG-RM-b by checking `Notes` against every method whose name contains `Digest` left in the tree outside `broker/vendor` and tests (`git grep -n 'func (.*) .*Digest.*('`, which today also finds `TakeDigestNotes`; `change.Pipeline.Digests` and `wireDigest` are listed as not sources). A mutant that unwires `TakeDigestNotes` must fail it.
- DRA-1: `::TestStatusLineStaysWhileConditionHolds`.
- DRA-2: `::TestStatusReadDoesNotDrainQuestionsOrAttention`.
- DRA-2: `::TestStatusListsAnOpenQuestionOnce`.
- DRA-2: `::TestStatusShowsCodeFloodCountsWithoutDraining`. Synthetic code texts without the current challenge; two STATUS reads show the same count.
- DRA-3: `::TestStatusListsUnclearEffects`.
- DRA-3: `::TestRefusedRetryStaysInStatus`.
- DRA-4: `::TestForgottenSubjectNotInStatus`. It uses a synthetic canary subject.
- DRA-5: `::TestMovingLinesSendsNoText`. A fake link sees no send.
- DRA-6: `broker/owner/local_test.go::TestWrongCodeAlertPointsToStatus`. A synthetic wrong code; the alert names STATUS and not the digest.
- Mutants:
  - drop one source from `Notes`;
  - make the STATUS read drain;
  - skip the forget filter.

**Guard files:** none (no package added, no import added to `cmd/agentosd` beyond its arc2 allowlist). **Scope:** `broker/cmd/agentosd/{main.go,capoff.go,unclear.go,mail.go,forget.go,secondline.go,qualitywire.go,sleepwire.go}`, `broker/cmd/agentosd/status_sources_test.go` (new), `broker/daemon/{daemon.go,retry.go}` (comments and, if needed, a STATUS note hook), a non-draining read in `broker/question/question.go` and `broker/events/attention.go` only if DRA-2 needs one, `broker/owner/{channel.go,local.go}` and a test beside them (the non-draining read for DRA-2, comments for DRA-3), and `broker/journal/engine.go` (comments only). Not `broker/digestqueue`, not `digest.go` (DIG-RM-b deletes them). **Guards:** `digestgate2_test.go`'s `bootOrder` stays green (the digest still runs here); the source-scanning lint tests in `cmd/agentosd` stay green; STATUS lines are fixed broker wording (CH-12), no agent text.

**Tier and model:** A (`broker/cmd/agentosd`): strongest model. **Usage estimate:** 110k tokens, checkpoint 80k. **Dependencies:** DIG-RM-spec merged; no open PR touches the scope files (D-111, check at start).

## DIG-RM-b: delete the digest (tier A, Mark merges)

**Requirement IDs:**
- **DRB-1 (no digest send):** agentosd starts no digest. `newDigestBox`, `dg.register`, `newDigestTransport`, `wireDigest`, `go dg.run` and the `newDigestSources` log are gone from `main.go`, and no owner text is sent on a daily timer. The `-digest` flag goes too. Its directory holds `queue.json`, `digest-sources.json`, `unclear-digest.json` and `mail-digest.json`, which record what the digest already sent and when to list it again; STATUS shows a line while its condition holds, so none of that state has a successor and nothing migrates. Log lines about the digest go with the code that writes them (`main.go:182,949,1007`, `mail.go:507,519`, `learn.go:1332`, `forget.go:1502`): each is deleted or says what the code now does. The builder confirms the state point at start; any field STATUS does need moves under the daemon's state dir in DIG-RM-a. A box upgraded with the old directory still on disk starts cleanly and ignores it (`::TestStartsWithOldDigestDir`).
- **DRB-2 (code gone):** the following are deleted:
  - `broker/digestqueue` in whole;
  - `broker/cmd/agentosd/digest.go` and its tests (`digest_test.go`, `digestgate_test.go`, `digestgate2_test.go`, `digestforget_test.go`, `digestwire_test.go`, `digest_capacity_test.go`, `digest_learning_off_test.go` if W3-forget-b2c-f1-r4 merged it);
  - the digest halves of `unclear.go` and `mail.go` (`Peek`/`Ack`, `digestqueue` imports).

  Each `Digest()`/`TakeDigest()`/`TakeDigestNotes()` method that DIG-RM-a left with no caller is removed or renamed to its STATUS role, and `events.Route`'s "digest" name says what the route now does.
- **DRB-3 (one dispatch path, CH-15):** a call-site test proves owner texts leave only through the urgent push path and conversation replies; the digest gate's "`Send` only in `sendReady`" rule retires with it.

**Acceptance tests:**
- DRB-1: `broker/cmd/agentosd/nodigest_test.go::TestNoDailyOwnerText`. A fake clock runs past 08:00 for two days, and a fake link sees no send while nothing is urgent.
- DRB-1: `::TestMainStartsNoDigest`. A source scan of `main.go`.
- DRB-1: `::TestStartsWithOldDigestDir`.
- DRB-1: `::TestNoDigestWhileLearningIsDown`. This is Mark's "Skip it" on #974: the learn dir is unopenable and a restored log names a synthetic canary goal; the fake link sees no send.
- DRB-3: `::TestOwnerTextsLeaveOnlyByPushOrConversation`.
- DRB-2: `go build ./... && go vet ./...` with `broker/digestqueue` absent.
- Mutants:
  - restore `go dg.run`;
  - route a STATUS line to the link.

**Guard files:** these are pre-approved scope.
- `tools/risk_tier.py`: drop `"digestqueue"` from the tier A set (line 93).
- `tools/g1_scope.txt:117` and `tools/g1_scope_g2.txt:112`: drop `allow broker/digestqueue/`.
- `broker/daemon/arc2_test.go`: drop the `digestqueue` entry and its comment at lines 99 and 208 to 210, and `"digestqueue"` from the `cmd/agentosd` allowlist.
- `broker/loops/plainname.go:23`: drop the fuzz name.

Touching risk_tier.py and the g1 lists makes `premerge.py --needs-mark` print `mark`: Mark merges (D-125). **Scope:** the files above; `broker/cmd/agentosd/{main.go,unclear.go,mail.go,forget.go,capoff.go,secondline.go,qualitywire.go,sleepwire.go}` and their tests; for DRB-2's removals and renames, the files holding a `Digest` method and their callers and tests in the eight packages that have one: `broker/apply/apply.go`, `broker/change/digest.go`, `broker/loops/{loop1.go,scheduler.go,secure.go}`, `broker/loop7/loop7.go`, `broker/maintain/maintain.go`, `broker/question/question.go`, `broker/events/attention.go`, `broker/owner/channel.go` (re-check with `git grep -n 'func (.*) .*Digest.*('` at start); `broker/cmd/agentosd/nodigest_test.go` (new) and `broker/cmd/agentosd/ASSUMPTIONS.md` (close the digest rows). If that list makes the package exceed 150k, move the renames into DIG-RM-a rather than widening further. **Guards:** net lines go down. No test is skipped or quarantined: a digest test is deleted with the code it tests, and each deleted case is listed in the PR as retired with the digest or met by a DRB test.

**Tier and model:** A: strongest model. **Usage estimate:** 80k tokens, checkpoint 60k (mostly deletion). **Dependencies:** DIG-RM-a merged.

## DIG-RM-c: no comment still describes the digest (tier per `risk_tier.py`, mechanical)

**Requirement IDs:**
- **DRC-1 (wording):** no comment, log line or owner-facing string in `broker/**/*.go` outside `broker/vendor` describes the removed digest as a place a line goes ("the daily digest", "the next digest", "in the digest", "digest line/source/queue/item", "STATUS and the digest", "the owner's digest"). Each says STATUS, the urgent push, or is deleted with what it described. Uses of "digest" meaning a hash stay.
- **DRC-2 (lint, FIRST-PASS):** this is the second PR to find leftover digest wording (L3 rounds 1 and 2 on #2249), so it becomes a check. `broker/cmd/agentosd/digestwording_test.go::TestNoDigestFeatureWording` walks `broker` and fails on the phrases above. Its allowlist names the files that use the hash sense: `broker/{sipsign,tpmseal,update,recovery,modem}/`, `cmd/agentos-egress`, `loops/machine.go`, `follow/follow.go`, `grants/grant.go`, `localui/follow.go`, `journal/{answer.go,check/check.go}`, `corpus/embed.go`, `checker/checker.go`, `mail/watch.go`. Mutant: restore "More wrong tries today go in the digest." and the test fails. The PR's Findings line names the check so the L3 lens README lists it (records are bot-written).

**Files the scan finds at aa1a1c9** (comment lines, from `git grep -n -i -E '//.*\b(the|next|daily|a|its|one|owner.s) digest\b|//.*digest (line|source|item|note|pacing|queue|gate)'` with the hash-sense files removed). The builder re-runs the scan at start; the test, not this list, is the acceptance:
- `apply/apply.go` 160,202,1238,1280; `attention/attention.go` 477; `change/{digest.go 300,303; effect.go 596,950; pipeline.go 242,341,345,369,381,1411}`; `clock/clock.go` 139.
- `cmd/agentosd/`: `capoff.go` 23,79,332,334; `evidence.go` 89,90,505,507; `forget.go` 190,230,593,601,1496,1497,1524,1541; `learn.go` 973,1072,1086,1103,1106,1285,1293,1424; `loop2.go` 24,38; `mail.go` 97,300,307,423,499; `main.go` 127,143,147,163,165,642,673,674,830,1004,1339,1459; `qualitywire.go` 27; `secondline.go` 13,27; `sleepwire.go` 31,84; `unclear.go` 19,22,29,68,121. Lines DIG-RM-b already deleted are skipped.
- `daemon/{daemon.go 246,251,516; retry.go 108}` and `journal/engine.go` 668,677,729,877 (if DRA-3 has not already reworded them); `journal/engine.go` 1050,1093; `journal/{intent.go 245; store.go 176}`.
- `events/{attention.go 38,41,56,117,120; bus.go 168,185; doc.go 18}`; `grants/gate.go` 2858 (1491, 1518 and 1520 are the hash sense); `loop7/loop7.go` 377,651,906; `loops/{loop1.go 179,208,243,369,490; probe.go 62; scheduler.go 86,654; secure.go 31,95,99,217,220,227,324,854,866,944,1169,1211,1292,1650,1682,1755,1758}`.
- `mail/{exec.go 41; undo.go 13,109,149}`; `maintain/maintain.go` 188,193,208,1069; `modemlink/modemlink.go` 297; `owner/{approvals.go 19,686,724; autoreply.go 249; boot.go 24; channel.go 109,186,324,617,626,718; local.go 41,210,258,345,429; render.go 221}`; `question/question.go` 24,149,284,285,1097,1111,1112,1119,1273,1294; `recalltool/reach.go` 630; `route/route.go` 164.

**Acceptance tests:** DRC-1, DRC-2: `broker/cmd/agentosd/digestwording_test.go::TestNoDigestFeatureWording` (and its mutant). **Guard files:** none. **Scope:** comment and log-string lines only in the files listed above (no code or behaviour change), plus the new test. **Tier and model:** whatever `risk_tier.py` prints (it touches tier-A paths, so A expected); the sweep itself suits a `haiku` subagent under the builder. **Usage estimate:** 60k tokens, checkpoint 40k. **Dependencies:** DIG-RM-b merged (so the deleted code's comments are already gone).

## SIM-pull and board dispositions

SIM-pull (briefs/SIM.md) already plans the same deletion, but it waits on SIM-owner-hold, SIM-sd and SIM-cases, so the daily push CH-15 forbids would keep running until that chain lands. **Decided (Q4, Mark 2026-10-17):** run DIG-RM-a/b standalone now and narrow SIM-pull's Change to the STATUS projection and urgent push, dropping "`broker/digestqueue` in whole … the digest gate" once DIG-RM-b merges. SIM-cases' digest cases are retired by DIG-RM-b's list.

Rows to change on their work-item issues once this brief merges (the coordinator or the next builder applies them; BOARD.md is never hand-edited):

| Row | Disposition |
|---|---|
| DIG-1 (digest sender) | Close: contradicts D-097; its "no `Digest()` unwired" check lives on as DRA-1. |
| W5-Dc-r2 (digest time, withdrawn) | Close: rests on the removed feature. Its items re-home: the send hour has no successor; quiet-hours and pacing items go to CH-15's push path (UX-INV covers counting them). |
| W3-forget-b2c-f1-r4 (brief merged in #2233) | Mark chose "Skip it" on #974 (2026-10-17 19:44Z): no digest runs while learning is down. DIG-RM-b carries this by deleting the digest; DRB-1's tests run once with the learn dir unopenable. Build r4 on its own only if DIG-RM-b is not started first; otherwise close it as done by DIG-RM-b. |
| W5-Dc-r3 (outage line when the digest can't be built) | Close: moot under D-097, which removes the digest (Decisions 6 withdrew its card). "Is the box alive?" is answered by CH-15's weekly "Still running." line, the release finding below. |
| W5-Dc-r5 (source-side forget, built in SIM-erase) | Keep; its STATUS half is DRA-4. |
| P3-6d "Change digest" | Re-word to a change's STATUS line. |
| UX-41-2 "Health result in STATUS and the digest" | Re-word to STATUS only. |
| SR3-4f-3-f1, SR3-4f-r3, SR3-4f-2-r1-f2, P3-4b-4c-dedupe, P3-4b-3r-text, SR3-mail-w2-f1, SR3-mail-w2-r1 | Re-word each "digest line" to "STATUS line". The row's builder checks whether DRA-1 already covers it. |
| UX-INV | Replace "digest sources (DIG-1)" with "STATUS lines (DIG-RM-a)". |
| SIM-pull | Narrow as above (Q4). |
| SPEC-residue (queued, release) | Its middle third, "replace post-D-097 digest leftovers with STATUS", is DIG-RM-spec: narrow the row to the portable-drive leftovers (HW-9/D-102) and CH-3's 30 days to CH-14's 7. Both edit SPEC.md, so whichever opens first goes first and the other waits (D-111); neither carries the other's lines. |
| W5-Dc-r14 (L1 for SG-r1-1 to -6) | Separate PR: Mark accepted all six rules on 2026-10-17 and another thread writes that spec diff. DIG-RM-spec does not edit its lines (the urgent classes, quiet hours, QUIET/TEXTS/URGENT, the allowance); if r14 drops SG-r1's digest rule, DIG-RM-spec cites it rather than repeating it. The two SPEC PRs run in sequence (D-111). |
| W5-Dc-r13 (mail security alerts) | Re-word "outside digest pacing" to "as an urgent `security` text (CH-15)"; the work itself is unchanged and stays with SIM-owner-hold. |
| DIGEST-skew-daygen (later) | Close as done by DIG-RM-b: the digest's day counters are deleted with it. |
| PAYCAP-1, PAYCAP-2 (stubs) | Re-word "declines reach the owner as a digest line" and "failures are digest lines" to STATUS lines; a decline that blocks a purchase the owner is waiting on is the conversation's reply, not a push. Their briefs (`briefs/PAYCAP-1.md`, `briefs/PAYCAP-2.md`) change with the row, outside this PR. |

**Finding (release):** CH-15's weekly liveness line has no code at aa1a1c9. With the digest gone, an owner who rarely pulls has no sign the box is up. This needs a new work-item row, not part of DIG-RM.

## Decisions (Mark, 2026-10-17, via the coordinator's cards)

- **Q1. Where parked unclear effects go.** STATUS lists them, and RETRY acts on that list (map rows 1 to 4). It reconciles D-116 with D-097.
- **Q2. CRED-5 mid-life pause.** STATUS and ONB-9 only, no push (row 5).
- **Q3. CONNECT ID lifetime.** It is listed in STATUS while discovery still finds the device and it is neither connected nor dismissed, with no time cap (row 9). Mark: "Fine to have a passive list of devices to connect, as long as device still there".
- **Q4. Order.** DIG-RM-a/b run standalone now, and SIM-pull narrows.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | D-116's intent is "park without interrupting", not "use the digest". | Mark's Q1 answer, 2026-10-17. | Settled. |
| 2 | `daemon.Config.Notes` is the STATUS note hook, and STATUS has room for the moved lines. | `daemon.go:163-165`. STATUS is pulled, so length costs one MORE page (CH-12). | If STATUS must stay short, DIG-RM-a adds a summary line with MORE. |
| 3 | CH-15's liveness line is not built yet, so deleting the digest removes no liveness behaviour. | `grep -rn "Still running" broker` finds nothing at aa1a1c9. | If the digest turns out to carry it, DIG-RM-b keeps it on its own timer. Building it is a separate `class:release` row (finding below). |
| 4 | No live SPEC requirement other than the twelve mapped names the digest. | `grep -n -i digest SPEC.md` at aa1a1c9 (change log aside). | DIG-RM-spec adds the row. |
