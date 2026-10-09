# W5-Dc-r1: Owner quiet hours and unsolicited-text pacing (CH-15)

Release finding L3 1 on #565 (W5-Dc, merged a818e20 as #592). LATER.md W5-Db l3 records that W5-Dc built only CH-15's "the daily digest is always sent"; the rest of CH-15 is this row. BOARD row W5-Dc-r1.

SPEC rows: CH-15 ("Unsolicited texts are rate-limited (default 3 per hour, owner-set); everything non-urgent waits for the digest. The owner defines the urgent classes. Quiet hours hold every text except STOP/RESUME confirmations and those classes."), CH-11 (STOP always works), CH-12 (texts say what is true), CH-3 (unlocked session), OP-9 (no silent loss), onboarding (SPEC line 269: quiet hours and digest time are set at onboarding), the mail security alert line (SPEC line 396: security alerts reach the owner "at once, outside digest pacing"), UPD-9 (a held security fix is put to the owner "once, paced (CH-15)"). Note that the BOARD row's summary leaves out "and those classes": owner-defined urgent classes also pass quiet hours.

**Why two packages under one row.** The pacer core (state, gate, hold and release, settings) lives in `broker/owner`; making every sender use it lives in `broker/cmd/agentosd` and `broker/grants`. Built as one, the package passes 150k. Split:
- **W5-Dc-r1a**, the owner pacer: about 400 lines with tests, about 120k tokens.
- **W5-Dc-r1b**, the wiring: about 250 lines with tests, about 90k tokens. It starts from main after r1a merges.

Each is its own session and PR; the PR title starts with `W5-Dc-r1a` or `W5-Dc-r1b`. BOARD row W5-Dc-r1 is built as these two PRs, in order: its status names the part in build (for example `building (r1a)`), and it becomes `merged` only when r1b merges.

**Order.** r1a, then r1b. Independent of W5-Dc-r7. W5-Dc-r2 (digest time) and W5-Dc-r11 (gate tightening, `go dg.run` boot order) touch `broker/cmd/agentosd/digest.go` and the boot order near r1b's lines: whichever merges second merges main first. Line references are from main at a818e20; reread them there.

**Conflict risk with held Codex drafts (CODEX-1).** Open, unmerged W5-D PRs held as Codex drafts (#333, #335, #338, #347 to #361, #397, #413 and others) also pace owner texts. #335 (branch `pkg/w5-d37-durable-shared-pacing-codex-20261008`) edits `broker/owner/channel.go`, `state.go`, `local.go`, `autoreply.go`, `approvals.go` and `codes.go`, and adds `broker/owner/digest_outbox.go` and `broker/grants/pacing.go`. All of them sit on a base older than #555. Build from main only; do not read, copy or depend on those branches. Do not create files with those names. Put the new code in a new file (`broker/owner/pacer.go`) and keep edits to the shared files to the call sites named here, so either side's later merge stays small.

**Today.**
- `broker/owner` has no quiet hours and no hourly cap on unsolicited texts. `Notify` (channel.go:899) and `Inform` (channel.go:913) do Disclose, then `control.Fit`, then `Modem.Send` at once. So do `alert` (local.go:389, local sign-in alerts), `Boot` (boot.go:114, the "Box restarted" text with re-sent requests) and `sendRequest`/`QueueAutoReply` (autoreply.go:87, 145).
- The only caps: `DefaultReplyLimit = 6` (replies to number-only messages) and `resumeTextsPerHour = 3` (RESUME code texts), both in channel.go.
- `broker/grants` already paces approval requests: `RequestsPerHour` (default `DefaultRequestsPerHour = 3`, gate.go:37), coalescing, and the hooks `Urgent func(owner.Item) bool` and `Quiet func(time.Time) bool` (gate.go:240 to 248, used at gate.go:1784 and 2697). agentosd sets neither `Quiet` nor `Urgent`, and grants counts only its own texts.
- The digest goes through its own transport (`newDigestTransport`, digest.go:718; `d.snd.Send`, digest.go:423) with no quiet-hours check.
- Other callers of `Notify`/`Inform`: `recalltool/reach.go:756`, loops `report.go` and `probe.go` (`Notify(text, false)`), loops `secure.go:585` and `683` (`Notify(text, urgent)`), `clock/clock.go:476` (not wired in agentosd: `questions.go:117`), `meter/meter.go:370` (agentosd's meter configs journal only, `main.go:1087`), and in agentosd `loop2.go:157`, `evidence.go:514` (agent replies), `questions.go:133` (agent questions), `main.go:688` (recall take-back notices, `Reach.tell`), `sleepwire.go:158`, `follow.go:115`, `digest.go:406` (outage line), plus grants' `own.Inform` calls.

**Spec gaps.** SPEC does not settle these. Each has a provisional choice the builder follows; record each in owner ASSUMPTIONS as provisional, and Mark rules on them through an L1 spec-diff PR, tracked as BOARD row W5-Dc-r14 (it also covers the new QUIET, TEXTS and URGENT words, which extend CH-11's closed set). Do not edit SPEC.md.
- **SG-r1-1, default quiet hours.** The onboarding line names quiet hours but gives no default value. Provisional: off (no window) until the owner sets one.
- **SG-r1-2, the urgent classes and their default.** SPEC says the owner defines urgent classes but names no class list and no default. The security alert line says security alerts go "at once, outside digest pacing". Provisional: a closed set of four classes, `security`, `approval`, `agent` and `update`. `agent` is what the agent itself texts the owner: replies from a machine (`evidence.go:514`) and its questions (`questions.go:133`). `security` is always urgent: it cannot be cleared, since SPEC line 396 already requires it at once. The owner may add `approval` and `agent`. `update` is never urgent.
- **SG-r1-3, where a paced text waits.** CH-15 says non-urgent texts wait "for the digest", but the digest is built from queue sources, not from owner texts. Provisional: a held text waits in a durable, bounded hold in owner state. When quiet hours end and the allowance returns, the hold is released as few combined texts as fit `control.MaxText`, each counting as one text. Folding held texts into the digest itself is a later question for DIG-1.
- **SG-r1-4, replies during quiet hours.** "Quiet hours hold every text except STOP/RESUME confirmations" could include replies to the owner's own messages. Provisional: only unsolicited texts are paced or held. A reply to an owner message on the `Run` path (HELP, STATUS, YES, a code request) goes at once, because the owner just wrote and so is reachable. STOP and RESUME confirmations are such replies, so they pass as CH-15 requires.
- **SG-r1-5, the owner's setting words.** The onboarding line says the defaults are "changeable any time by text", but CH-11's control words are a closed set and name no pacing setting, and CH-11 sends natural-language configuration through fixed-wording render-back. Provisional: whole-message forms `QUIET <from>-<to>` (box-local hours, for example `QUIET 22-7`), `QUIET OFF`, `TEXTS <n>` (1 to 20 an hour) and `URGENT <class> ON|OFF`. They are handled before the agent sees the message, as `LOOPS OFF` is today, and take effect only in an unlocked session (CH-3). Narrowing is not cheaper here: fewer texts or longer quiet hours could hide activity from the owner, so every change needs the unlock. Each change is confirmed in fixed wording.
- **SG-r1-6, the digest and the allowance.** Provisional: the daily digest is held by quiet hours but does not count against, and is not held by, the hourly allowance ("always sent").

**Findings to raise (not in either package):** held texts are not indexed by forget reference, so a CAP-3 forget does not reach a text held overnight. Raise it as **release** with the r1a PR, and record it in owner ASSUMPTIONS.

## W5-Dc-r1a: the owner pacer

**Requirements** (local IDs under CH-15):
- **QH-1, pacing settings.**
  - Owner `State` gains a pacing setting: quiet window start and end (minutes of the box-local day, read through `Config.Location`; equal means off), texts per hour (default 3), and the urgent classes beyond `security`.
  - An absent or zero setting reads as the defaults (SG-r1-1, SG-r1-2), so a state file from main loads unchanged.
  - The settings are validated on load: a bad value fails closed to the defaults and is logged, never to "no pacing".
- **QH-2, one gate for unsolicited texts.**
  - Add `func (c *Channel) Post(class Class, text string) error` in `owner/pacer.go`. It applies Disclose and `control.Fit` as `Inform` does today, then:
    - An urgent class sends at once, in quiet hours too, and counts toward the hour.
    - Any other class is held when it is quiet hours or the last hour's unsolicited sends have reached the allowance. Otherwise it sends and is counted.
  - `Inform` keeps its signature and becomes `Post(ClassUpdate, …)`. `Notify` keeps its signature, its Disclose and its `AgentPrefix`, and posts as `ClassAgent`: its callers on main are the agent reply and question paths and the recall closure (QH-9).
  - Add `NotifyAs(class Class, text string) error`: `Notify`'s Disclose and `AgentPrefix` with a caller-chosen class, for agent-derived text that belongs to another class (r1b's recall closure).
  - `alert` becomes `Post(ClassSecurity, …)`. Agent text (`Notify`, `NotifyAs`) is never packed with another text on release, so a " / " inside it cannot forge a broker segment (CH-19).
  - The `Boot` text is not paced (round 1 on #617, lens 1): it carries the new codes and explains them, so a held copy could be released after its codes died, or arrive after the codes it explains. It goes at once, like security, and counts toward the hour.
  - `sendRequest` and `QueueAutoReply` are not held by the owner, because grants paces them (r1b), but they are counted, so the allowance is one budget across all unsolicited texts.
  - Replies on `Run`'s `send` (channel.go:936) and the RESUME code text are never held or counted (SG-r1-4).
- **QH-3, a durable, bounded hold.**
  - A held text is saved in owner state before `Post` returns nil. A save failure returns the error and sends nothing.
  - The hold keeps at most 32 texts. Past that it drops the oldest and counts the drops. The next released text starts "N earlier texts were dropped while paced." (CH-12, OP-9).
- **QH-4, release.**
  - `func (c *Channel) Release() error` sends the hold when it is not quiet hours and the allowance has room. It packs held texts, oldest first, into as few texts as fit `control.MaxText`, one text per allowance unit. Each is removed from state only after `Modem.Send` returns nil; a send error keeps it.
  - `Post` calls `Release` first, so held texts never fall behind newer ones.
  - r1b calls `Release` from agentosd's minute tick. A test drives it directly.
- **QH-5, read-only hooks for the wiring.** `Quiet(t time.Time) bool`, `Urgent(class Class) bool`, and `Allowance(now time.Time) int` (unsolicited texts left this hour, counting `sendRequest` and `QueueAutoReply` sends). They read the same setting, under `c.mu`, with no I/O.
- **QH-6, owner settings.**
  - Run parses SG-r1-5's forms as whole messages, ignoring case and punctuation as CH-11 does.
  - In an unlocked session it saves the setting, then replies in fixed wording. For example: "Quiet hours set: 22:00 to 07:00. Texts wait until then, except security alerts. Reply QUIET OFF to end them." The wording names what still gets through.
  - Locked, it replies with the existing unlock prompt and changes nothing.
  - A malformed form (`QUIET 25-7`, `TEXTS 0`, `URGENT update ON`) gets one fixed line naming the valid forms and changes nothing.
  - HELP lists the forms if they fit its one text. Otherwise say why in the PR.

**Failing-test-first controls** (r1a). Tests go in `broker/owner/pacer_test.go`, with the existing channel fakes. Markers: `REQ: CH-15 (W5-Dc-r1a QH-2)` and so on.

| ID | Test | Why it fails on main |
|---|---|---|
| QH-1 | `TestPacingDefaultsFromAnOldState`: a state file from main loads with 3 an hour, no quiet window, `security` urgent; a corrupt setting loads as the defaults. | No setting. |
| QH-2 | `TestFourthUpdateInAnHourIsHeld`: three `Inform` texts send, the fourth is held, and the modem fake shows three. At hour plus one minute, `Release` sends it. | All four send. |
| QH-2 | `TestQuietHoursHoldUpdatesButNotSecurity`: quiet 22 to 7, 23:00 box-local time (a non-UTC `Location`). `Inform` is held; `alert` (a local sign-in) sends; with `URGENT approval ON`, the `Boot` text sends; `Notify` is held unless `URGENT agent ON`, and `NotifyAs(ClassApproval, …)` follows `URGENT approval`, both keeping `AgentPrefix`. | Everything sends. |
| QH-2 | `TestRepliesAreNeverHeld`: in quiet hours with the allowance spent, the owner texts STOP, then RESUME with its code, then HELP and STATUS; each reply goes at once and none counts. | Passes on main. It pins SG-r1-4; show the mutant "Run's send goes through Post" failing it. |
| QH-2 | `TestRequestsShareTheAllowance`: two `sendRequest` texts, then two `Inform` texts; the second `Inform` is held. | No shared count. |
| QH-3 | `TestHeldTextSurvivesARestart`: hold one, rebuild the channel from saved state, `Release` after quiet hours; it is sent once. A save failure on hold returns an error and sends nothing. | No hold. |
| QH-3 | `TestHoldIsBounded`: hold 40; 32 are kept, and the first released text starts "8 earlier texts were dropped while paced." | No hold. |
| QH-4 | `TestReleasePacksAndKeepsOrder`: five short held texts go out as one text in order; a send error keeps them all; a newer `Inform` never goes before an older held one. | No release. |
| QH-6 | `TestPacingSettingsNeedUnlock`: locked `QUIET 22-7` changes nothing and prompts the unlock; unlocked, it saves and replies in fixed wording; `TEXTS 0` and `URGENT update ON` are refused with the forms line; `URGENT security OFF` is refused. | No such forms: the message goes to the agent. |

**Controls that must keep passing.** All of `broker/owner` tests, in particular the reply-limit and RESUME-text caps, `settings_test.go` (`LOOPS OFF`/`LOOPS ON`), the Boot and autoreply tests, and the local sign-in alert tests.

**Scope (r1a):**
- New `broker/owner/pacer.go` and `broker/owner/pacer_test.go`.
- `broker/owner/channel.go`: `Notify`, `Inform`, and Run's settings dispatch; HELP if it fits.
- `broker/owner/state.go`: the setting, the hold, and the send times.
- `broker/owner/local.go` (`alert`), `broker/owner/boot.go` (the send line), `broker/owner/autoreply.go` (count only).
- `broker/owner/ASSUMPTIONS.md`: new rows for SG-r1-1 to SG-r1-6 (provisional) and for the hold's forget gap.
- `briefs/W5-Dc-r1.md` (Delivery notes only), `BOARD.md` row W5-Dc-r1, `LATER.md` only if a finding is classed later.

## W5-Dc-r1b: every sender through the pacer

**Requirements** (local IDs under CH-15):
- **QH-7, the digest waits for quiet hours.**
  - In `sendReady` (digest.go, before `d.snd.Send` at line 423), a digest due in quiet hours is not sent. The batch stays `Ready` and goes at the first tick after quiet hours end.
  - It does not use or wait on the hourly allowance (SG-r1-6).
  - If the wait can pass the batch's `Expires`, show in a test that the existing Late/Held path still sends that day's digest once, and record it in digestqueue ASSUMPTIONS. If it cannot, say why in the PR.
  - The outage line (digest.go:406) goes through `Inform` and so is paced as an update.
- **QH-8, grants uses the owner's setting.** agentosd sets the grants `Config` as follows. Use one budget, not two: approval requests count toward the owner's allowance once, not also against grants' own count. The change in `broker/grants/gate.go` is limited to the budget line (gate.go:1780) and the new field. Do not add `grants/pacing.go`.
  - `Quiet: own.Quiet`.
  - `Urgent: func(owner.Item) bool { return own.Urgent(owner.ClassApproval) }`.
  - A new `Allowance func(time.Time) int` that, when set, replaces grants' own `textsLocked` count.
- **QH-9, each caller names its class.** Re-point each caller to `Post` with its class. The table is provisional; the builder confirms each one against the call site and lists the final table in the PR.
  - Loops security texts: `security` when `urgent`, else `update`. `loops/secure.go:585` and `683` pass `urgent` to `Notify(text, urgent)`, which agentosd wires to `loop2Notify.send` (`loop2.go:145`, via `learn.go:262`); `send` drops the flag today. Map it there; `secure.go` needs no change. Loops report and probe (`Notify(text, false)`) and forget done texts (`forget.go:183`) through the same `send` are `update`.
  - Fork-switch alert (`follow.go:109`, `maintain.FollowAlert`: "Not you? Switch back there and change your codes"): `security`.
  - Agent replies (`evidence.go:514`, `e.notify` used by `evidence.send`) and agent questions (`questions.go:133`, `question.Config.Send`): `agent`. Both call `Notify`, which posts as `agent` after r1a, so neither changes; the test pins it.
  - Recall take-back notices (`main.go:686` to `691`, the recalltool `Notify` closure used by `Reach.tell`, `recalltool/reach.go:752`; texts at `reach.go:263` `TakenBack`, `729`, `736` and `801`): `approval`. Each closes a take-back the owner approved (CAP-3: the owner is asked first), so it follows the owner's approval class. Re-point the `main.go` closure from `ch.Notify` to `ch.NotifyAs(owner.ClassApproval, text)` (the texts name the agent, so they keep Disclose and the prefix); `recalltool` does not change.
  - Provider mail security alerts (SPEC line 396): no sender exists on main. `broker/mail` only flags a message (`guard.go:378` `isAlert`, `guard.go:394` `AlertWording`) so that hiding it must be asked (ADP-2), and `undo.go:130` counts guard hits; nothing texts the owner. Sending them at once is BOARD row W5-Dc-r13, which uses the `security` class from this package. Do not edit `broker/mail`.
  - Everything else: `update`. That covers `sleepwire.go:158` (the holding line), `digest.go:406` (the outage line) and grants' `Inform` notices (`gate.go` 1651, 2127, 2150, 2269, 2323, 2362 and 2532). Grants' notices about a change the owner must act on before expiry are `approval`.
  - Not callers: agentosd's meter configs only journal (`main.go:1087`), and `clock` has no `Notify` wired in agentosd (`questions.go:117`). If the builder finds either wired, class it `update` and say so in the PR.
  - A caller outside `owner`, `grants` and `cmd/agentosd` that needs only a class change keeps calling `Notify`/`Inform` (as `update`) unless the table says otherwise. List it in the PR rather than widening the scope.
- **QH-10, release and status.**
  - agentosd's minute tick calls `own.Release()`.
  - While any text is held, STATUS shows one line: "N texts held until 07:00 (quiet hours)" or "N texts held: 3 an hour". Over the cap it shows the drop count (OP-9).

**Failing-test-first controls** (r1b). Tests go in `broker/cmd/agentosd/digest_test.go`, a new `broker/cmd/agentosd/pacing_test.go`, and `broker/grants/gate_test.go` (or the grants test file that covers `Quiet`). Markers: `REQ: CH-15 (W5-Dc-r1b QH-7)` and so on.

| ID | Test | Why it fails on main |
|---|---|---|
| QH-7 | `TestDigestWaitsForQuietHoursToEnd`: digest time 06:30, quiet 22 to 7. Nothing is sent at 06:30; at 07:00 one digest is sent; the batch was `Ready` in between. Past the batch's expiry, the Late path sends it once. | Sent at 06:30. |
| QH-7 | `TestDigestIgnoresTheHourlyAllowance`: the allowance is spent; the digest still goes at its time. | Passes on main; it pins SG-r1-6. Show the mutant "digest waits for the allowance" failing it. |
| QH-8 | `TestGrantsUseOwnerQuietAndAllowance`: with the agentosd wiring, an approval request in quiet hours waits until they end. With the owner allowance spent by updates, a request waits for the next hour; with `URGENT approval ON`, it goes at once. | `Quiet` is nil and the count is grants' own. |
| QH-9 | `TestCallersUseTheirClass`: a loops urgent security text in quiet hours goes at once; a fork-switch alert in quiet hours goes at once; a loops report is held; an agent reply from `evidence.send` is held unless `URGENT agent ON`; a recall take-back notice is held unless `URGENT approval ON`. | Everything sends. |
| QH-10 | `TestTickReleasesAndStatusSaysHeld`: in quiet hours, two updates are held and STATUS shows the held line; at 07:00, the tick sends them as one text and the line is gone. | No release; no line. |

**Controls that must keep passing.** All `broker/cmd/agentosd`, `broker/grants` and `broker/owner` tests, in particular W5-Dc's digest tests (always sent, Unknown line, outage line once a day), grants' coalescing and re-issue-past-budget tests (`reissued` still goes past the allowance), and grants' auto-reply release in quiet hours (gate.go:2697).

**Scope (r1b):**
- `broker/cmd/agentosd/digest.go` (`sendReady` and the tick only), `broker/cmd/agentosd/main.go` (wiring and the class in the recalltool `Notify` closure, lines 686 to 691), the agentosd call sites in QH-9 that change class (`loop2.go`, `follow.go`), new `broker/cmd/agentosd/pacing_test.go`, `broker/cmd/agentosd/digest_test.go`.
- `broker/grants/gate.go` (the `Allowance` field and the budget line), its test.
- Not `broker/loops`, `broker/recalltool` or `broker/mail`: their classes are set at the agentosd wiring (QH-9).
- `broker/cmd/agentosd/ASSUMPTIONS.md`, `broker/grants/ASSUMPTIONS.md` (one row on the shared budget), and the digestqueue ASSUMPTIONS line from QH-7.
- `briefs/W5-Dc-r1.md` (Delivery notes only), `BOARD.md` row W5-Dc-r1.

**Threat check for the reviewer (both packages).**
- No security text can be held. That covers `security` class texts (loops urgent security texts and the fork-switch alert) and local sign-in alerts; provider mail security alerts join once W5-Dc-r13 sends them. The owner cannot make `security` non-urgent, and a spoofed sender cannot change any pacing setting without an unlocked session.
- STOP and RESUME confirmations, and every reply to an owner message, go at once in quiet hours and with the allowance spent (CH-11, CH-15).
- No silent loss: a held text is saved before `Post` returns. It leaves the hold only after a successful send, and is released at least once across a crash (O23: a repeat is preferred to a loss). A dropped text is counted and said (OP-9, CH-12).
- One budget: no path sends unsolicited texts past the allowance except urgent classes, re-issued approvals (grants' existing rule) and the digest.
- The digest is still sent every day (CH-15's last clause): quiet hours delay it and never drop it.
- Nothing in a held text reaches logs. Held text sits in owner state, as approval items do today; its forget gap is the release finding above.

**Out of scope.** Digest time (W5-Dc-r2). Update windows (UPD-6 reads quiet hours later; not here). Folding held texts into the digest (SG-r1-3, later, DIG-1). Onboarding's prompt for the quiet hours value (the onboarding package). Grants' coalescing rules. CAP-3 reach into the hold (the release finding above).

**Needs:** W5-Dc (merged, #592). r1b needs r1a merged.

**Done (each package):**
- CI green.
- The package's QH IDs covered by passing tests with markers.
- Risk tier A (`broker/owner`; r1b also `broker/cmd`, `broker/grants`).
- The PR lists the spec gaps SG-r1-1 to SG-r1-6 as provisional, for Mark.

## Delivery

Builder model: strongest model for both (risk tier A; the Sonnet pilot covers tiers B and C only). One package per session, tests first: land each test red at main before the fix, and keep the message for the PR. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening each PR. Review: L3 on the strongest model with the threat check above, then the UX lens (every new text) and a separate Security section (OPERATING §3–4). Estimate/checkpoint: r1a about 120k tokens, r1b about 90k, not ceilings (OPERATING §5). If r1a nears 150k with QH-6 red, ship QH-1 to QH-5 and move QH-6 into r1b's session, saying so in both PRs.

**r1b delivery notes.** Built on the strongest model (tier A). Three widenings, declared as brief gaps on the PR: grants' one budget (`Config.Allowance`) also replaces grants' own count in `take` and `Reserve`, not only the `flushDue` line, or requests and questions would still have two budgets (grants GR34); `owner.Channel.HeldNote` is added in `broker/owner` because the owner exposes no held count for QH-10's STATUS line; the digest sends at 08:00 (`digestHour`), not 06:30, so the QH-7 test runs quiet hours past 08:00. Assumptions: `broker/cmd/agentosd/ASSUMPTIONS.md` PW1 to PW4, `broker/grants/ASSUMPTIONS.md` GR34, and the QH-7 bullet in `broker/digestqueue/ASSUMPTIONS.md`.
