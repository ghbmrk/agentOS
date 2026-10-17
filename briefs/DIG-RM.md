# DIG-RM: remove the daily digest that D-097 retired, from SPEC and from agentosd

Board section: Integration. Decision D-097 (Mark, Decisions cards 2026-10-10): "STATUS is the owner's primary view, only urgent classes pushed, daily digest removed, weekly liveness line (CH-15)". CH-15 already says "There is no digest." Class: release (failure path below). Three packages, run in order: **DIG-RM-spec** (L1 spec-diff, SPEC.md only, Mark approves), **DIG-RM-a** (every digest line reaches STATUS instead), **DIG-RM-b** (delete the digest code).

**Failure path (checked at main aa1a1c9):** SPEC still sends the owner to a digest in ten places (table below), so a builder working from OP-2, CH-11, CRED-5 or DEV-10 builds or keeps digest behaviour CH-15 forbids. agentosd still runs it: `main.go:652` builds `newDigestBox`, `main.go:851` runs `go dg.run(ctx)`, and `digest.go` pushes "Daily digest: %s; reply STATUS for more." at `digestHour = 8`. That is an unasked text of a non-urgent class every day, which CH-15 forbids.

**Conflict to settle first (Q1).** D-116 (2026-10-14, after D-097) parks unclear effects "in the daily digest without interrupting the owner", lets RETRY act on digest items, and lists a refused resend "in the next digest"; Mark approved that wording of OP-2, OP-4 and CH-11 the same day. Both decisions hold if the parked list moves to STATUS. The owner is still never interrupted (D-116's point) and never texted it unasked (D-097's point). This brief takes that reading; Q1 asks Mark to confirm it.

## Reference map

Each live digest reference, where D-097 puts it, and the recommended wording. Change-log rows (lines 721, 746, 748, 760) are history and stay as written. "Marked" means D-097 does not settle the reference; the brief takes the reading closest to D-097 and lists the reference under Questions.

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
| 9 | 523, DEV-10 | "gets its own digest line, … with an ID unique among open requests (CH-12) that stays open until the next digest" | STATUS line; new ID lifetime (marked, Q3) | "gets its own STATUS line, … with an ID unique among open requests (CH-12) that stays open while discovery still finds the device and it is neither connected nor dismissed, and for at most 7 days (owner-set)" |
| 10 | 523, DEV-10 | "A grant unused for 60 days (owner-set) appears in the digest with `REVOKE <id>`." | STATUS line | "… appears in STATUS with `REVOKE <id>` until it is used or revoked." |
| 11 | 216, CH-3 table | "in reply to the digest line" | STATUS line | "in reply to its STATUS line" |
| 12 | 516, DEV-10 table | "Code-generator code in reply to its digest line (`CONNECT <id> <code>`)" | STATUS line | "… in reply to its STATUS line (`CONNECT <id> <code>`)" |

No reference maps to an urgent text: none blocks work, carries a deadline, holds work, or is a security alert. Nothing is dropped outright; row 6 is the one candidate, with the alternative noted in its row.

## DIG-RM-spec: SPEC.md loses the digest (L1 spec-diff, Mark approves)

**Requirement IDs:** OP-2, OP-4, CH-11, CH-3 (table), CRED-5, DEV-5, DEV-9, DEV-10, as amended per the map; CH-15 unchanged. **Change:** the twelve edits in the map, worded as there unless Mark answers Q1 to Q3 otherwise; one change-log row citing D-097 and this brief. No other SPEC text moves.

**Acceptance tests:** none: a SPEC-only PR has no code; the check is `grep -n -i digest SPEC.md` printing only change-log rows and CH-15's "There is no digest", plus `python3 tools/doclint.py` clean. Mark's approval of the PR at its head is the acceptance.

**Guard files:** none (no package added). **Scope:** `SPEC.md`. **Tier and model:** per `tools/risk_tier.py` (SPEC.md is L1; Mark merges). **Usage estimate:** 30k tokens, checkpoint 20k. **Dependencies:** this brief merged; Q1 to Q3 answered or the recommended readings accepted.

## DIG-RM-a: every digest line is shown in STATUS (tier A)

**Requirement IDs** (the builder writes the failing test first):
- **DRA-1 (sources move to STATUS):** each source that feeds the digest today is a STATUS note (`daemon.Config.Notes`, `[]func() string`) or part of an existing STATUS line. The sources are `maintain.Loop3`, `loops.Learn`, `loops.Guard`, `loops.Scheduler`, `question.Book`, `loop7.Source`, `apply.Applier`, `events.Attention`, `change.Pipeline`, and agentosd's `secondLine`, `capLines`, `qualitySource`, `sleepSource`, `unclearSource`, `mailSource`. A line stays in STATUS while its condition holds (OP-9), never only until it was sent once.
- **DRA-2 (draining sources):** a source whose read drains it (`question.Book.TakeDigest`, `events.Attention.TakeDigest`) gets a read that does not drain, or its items already show in STATUS through the open-question view. The builder checks which, and STATUS does not list one item twice.
- **DRA-3 (unclear list, OP-2/OP-4 per Q1):** STATUS lists `Daemon.RetryWaiting()` in the existing unclear wording (`unclear.go`), capped as `unclearLineMax` caps it today. A refused retry stays listed. `daemon.go:246,251,516` and `retry.go:108` comments say STATUS, not digest.
- **DRA-4 (forget holds, CAP-3):** a forgotten subject never appears in a STATUS line moved here. The digest's forget filter (`forgetOwner.wireDigest`) has a STATUS equivalent, or each moved source already filters.
- **DRA-5 (nothing new is pushed):** moving a line to STATUS sends no text; the daily digest still runs until DIG-RM-b deletes it (this package only adds STATUS lines).

**Acceptance tests:**
- DRA-1: `broker/cmd/agentosd/status_sources_test.go::TestEveryDigestSourceIsAStatusNote`. It reads `newDigestSources` and the box's registered sources and fails while any is not wired to STATUS. It is the inverse of DIG-1's "no `Digest()` goes unwired" check, and it outlives DIG-RM-b by checking `Notes` against the `Digest()`/`TakeDigest()` implementors left in the tree.
- DRA-1: `::TestStatusLineStaysWhileConditionHolds`.
- DRA-2: `::TestStatusReadDoesNotDrainQuestionsOrAttention`.
- DRA-2: `::TestStatusListsAnOpenQuestionOnce`.
- DRA-3: `::TestStatusListsUnclearEffects`.
- DRA-3: `::TestRefusedRetryStaysInStatus`.
- DRA-4: `::TestForgottenSubjectNotInStatus`. It uses a synthetic canary subject.
- DRA-5: `::TestMovingLinesSendsNoText`. A fake link sees no send.
- Mutants:
  - drop one source from `Notes`;
  - make the STATUS read drain;
  - skip the forget filter.

**Guard files:** none (no package added, no import added to `cmd/agentosd` beyond its arc2 allowlist). **Scope:** `broker/cmd/agentosd/{main.go,capoff.go,unclear.go,mail.go,forget.go,secondline.go,qualitywire.go,sleepwire.go}`, `broker/cmd/agentosd/status_sources_test.go` (new), `broker/daemon/{daemon.go,retry.go}` (comments and, if needed, a STATUS note hook), and a non-draining read in `broker/question/question.go` and `broker/events/attention.go` only if DRA-2 needs one. Not `broker/digestqueue`, not `digest.go` (DIG-RM-b deletes them). **Guards:** `digestgate2_test.go`'s `bootOrder` stays green (the digest still runs here); the source-scanning lint tests in `cmd/agentosd` stay green; STATUS lines are fixed broker wording (CH-12), no agent text.

**Tier and model:** A (`broker/cmd/agentosd`): strongest model. **Usage estimate:** 110k tokens, checkpoint 80k. **Dependencies:** DIG-RM-spec merged (or Q1 answered); no open PR touches the scope files (D-111, check at start).

## DIG-RM-b: delete the digest (tier A, Mark merges)

**Requirement IDs:**
- **DRB-1 (no digest send):** agentosd starts no digest. `newDigestBox`, `dg.register`, `newDigestTransport`, `wireDigest`, `go dg.run` and the `newDigestSources` log are gone from `main.go`, and no owner text is sent on a daily timer.
- **DRB-2 (code gone):** the following are deleted:
  - `broker/digestqueue` in whole;
  - `broker/cmd/agentosd/digest.go` and its tests (`digest_test.go`, `digestgate_test.go`, `digestgate2_test.go`, `digestforget_test.go`, `digestwire_test.go`, `digest_capacity_test.go`, `digest_learning_off_test.go` if W3-forget-b2c-f1-r4 merged it);
  - the digest halves of `unclear.go` and `mail.go` (`Peek`/`Ack`, `digestqueue` imports).

  Each `Digest()`/`TakeDigest()` method that DIG-RM-a left with no caller is removed or renamed to its STATUS role.
- **DRB-3 (one dispatch path, CH-15):** a call-site test proves owner texts leave only through the urgent push path and conversation replies; the digest gate's "`Send` only in `sendReady`" rule retires with it.

**Acceptance tests:**
- DRB-1: `broker/cmd/agentosd/nodigest_test.go::TestNoDailyOwnerText`. A fake clock runs past 08:00 for two days, and a fake link sees no send while nothing is urgent.
- DRB-1: `::TestMainStartsNoDigest`. A source scan of `main.go`.
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

Touching risk_tier.py and the g1 lists makes `premerge.py --needs-mark` print `mark`: Mark merges (D-125). **Scope:** the files above, plus `broker/cmd/agentosd/nodigest_test.go` (new) and `broker/cmd/agentosd/ASSUMPTIONS.md` (close the digest rows). **Guards:** net lines go down. No test is skipped or quarantined: a digest test is deleted with the code it tests, and each deleted case is listed in the PR as retired with the digest or met by a DRB test.

**Tier and model:** A: strongest model. **Usage estimate:** 80k tokens, checkpoint 60k (mostly deletion). **Dependencies:** DIG-RM-a merged.

## SIM-pull and board dispositions

SIM-pull (briefs/SIM.md) already plans the same deletion, but it waits on SIM-owner-hold, SIM-sd and SIM-cases, so the daily push CH-15 forbids would keep running until that chain lands. **Recommended (Q4):** run DIG-RM-a/b standalone now and narrow SIM-pull's Change to the STATUS projection and urgent push, dropping "`broker/digestqueue` in whole … the digest gate" once DIG-RM-b merges. SIM-cases' digest cases are retired by DIG-RM-b's list.

Rows to change on their work-item issues once this brief merges (the coordinator or the next builder applies them; BOARD.md is never hand-edited):

| Row | Disposition |
|---|---|
| DIG-1 (digest sender) | Close: contradicts D-097; its "no `Digest()` unwired" check lives on as DRA-1. |
| W5-Dc-r2 (digest time, withdrawn) | Close: rests on the removed feature. Its items re-home: the send hour has no successor; quiet-hours and pacing items go to CH-15's push path (UX-INV covers counting them). |
| W3-forget-b2c-f1-r4 (brief merged in #2233) | Close as moot once DIG-RM-b merges; build it only if it lands first. |
| W5-Dc-r5 (source-side forget, built in SIM-erase) | Keep; its STATUS half is DRA-4. |
| P3-6d "Change digest" | Re-word to a change's STATUS line. |
| UX-41-2 "Health result in STATUS and the digest" | Re-word to STATUS only. |
| SR3-4f-3-f1, SR3-4f-r3, SR3-4f-2-r1-f2, P3-4b-4c-dedupe, P3-4b-3r-text, SR3-mail-w2-f1, SR3-mail-w2-r1 | Re-word each "digest line" to "STATUS line". The row's builder checks whether DRA-1 already covers it. |
| UX-INV | Replace "digest sources (DIG-1)" with "STATUS lines (DIG-RM-a)". |
| SIM-pull | Narrow as above (Q4). |

**Finding (release):** CH-15's weekly liveness line has no code at aa1a1c9. With the digest gone, an owner who rarely pulls has no sign the box is up. This needs a new work-item row, not part of DIG-RM.

## Questions for Mark

- **Q1. Where parked unclear effects go (D-116 vs D-097).**
  - (a) STATUS lists them, and RETRY acts on that list. **Recommended:** it keeps both decisions and never texts unasked.
  - (b) One urgent text when an effect is parked. This makes parking an urgent class.
  - (c) Keep D-116's digest for this one class. This contradicts CH-15.
- **Q2. CRED-5 mid-life pause.**
  - (a) STATUS and ONB-9 only. **Recommended:** work goes on by other routes, so nothing is blocked.
  - (b) One urgent text, because which plan does the work changed.
- **Q3. How long a CONNECT ID stays open.**
  - (a) While discovery finds the device and it is not connected or dismissed, at most 7 days, owner-set. **Recommended.**
  - (b) Until connected or dismissed, with no time cap.
  - (c) A fixed 24 hours.
- **Q4. Order of work.**
  - (a) DIG-RM-a/b standalone now, and narrow SIM-pull. **Recommended:** the forbidden daily push stops sooner.
  - (b) Fold the deletion into SIM-pull and wait for its chain.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | D-116's intent is "park without interrupting", not "use the digest". | decisions/D-116.md; D-097 predates it and was not mentioned there. | If Mark meant the digest, Q1(c), and CH-15 needs an exception. |
| 2 | `daemon.Config.Notes` is the STATUS note hook, and STATUS has room for the moved lines. | `daemon.go:163-165`. STATUS is pulled, so length costs one MORE page (CH-12). | If STATUS must stay short, DIG-RM-a adds a summary line with MORE. |
| 3 | CH-15's liveness line is not built yet, so deleting the digest removes no liveness behaviour. | `grep -rn "Still running" broker` finds nothing at aa1a1c9. | If the digest turns out to carry it, DIG-RM-b keeps it on its own timer. Building it is a separate `class:release` row (finding below). |
| 4 | No live SPEC requirement other than the twelve mapped names the digest. | `grep -n -i digest SPEC.md` at aa1a1c9 (change log aside). | DIG-RM-spec adds the row. |
