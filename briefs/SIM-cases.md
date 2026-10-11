# SIM-cases: the W5-D drafts' crash, acknowledgement and forget cases

Package anchor: [SIM.md](SIM.md#sim-cases-w5-d-cases-become-tests-against-main-tier-a). Source: the 67 open W5-D draft PRs (#263 to #435, one stack on `0c97632`), plus the POT, UX and other W5 codex drafts where they test the same kinds of case. Each line gives the draft, the case, what the owner sees, and where the case lives now:

- **main**: a passing test on main already states it (named).
- **here**: a new test in this PR (named; `broker/owner/simcases_test.go`).
- **SIM-owner-hold**, **SIM-pull** or **SIM-erase**: main fails the case or lacks the surface, and that package's acceptance includes it.
- **retired with the digest**: the case exists only because of the daily digest, which SIM-pull deletes outright (`broker/digestqueue` in whole, the agentosd digest box, the digest gate). SIM-pull's acceptance lists these cases as retired. Each case's owner-visible residue is named once, in the residue section below.

Cases are written against what the owner sees (a text sent or not, after a restart or a forget), not the drafts' types. "No owner-visible case" means the draft tests only internal storage, wiring or tooling behaviour that no owner text, STATUS line or page shows.

## Owner-visible cases that survive the digest

| Draft | Case | Owner sees | Where |
|---|---|---|---|
| #271 W5-D7 | Send cancelled before the bridge admits it | Nothing sent; the text is not counted as possibly sent | main: `modemlink` `TestSendReceiptRefusedBeforeQueueIsNotSent`, `TestSendReceiptTimeoutBeforeHandIsNotSent` |
| #271 W5-D7 | Send cancelled after hand-off to the modem, late receipt arrives | The text stays "may have been sent"; the late receipt does not resend or flip it | main: `TestSendReceiptTimeoutAfterHandIsUnknown`, `TestSendReceiptTimeoutRacingHandIsUnknown`, `TestSentIDsAreSingleUse` |
| #272 W5-D8 | A failed send to the owner's line | The local page shows the line failure | main: `modemlink` `TestOwnerLineNoteForTheLocalPage` |
| #280 W5-D14 | Local STOP while the owner state is busy | STOP takes effect at once | main: `owner` `TestStopIsNotQueuedBehindAHungVerifier`, `TestSlowAgentNeverDelaysStop` |
| #280 W5-D14 | STOP after an older RESUME code was issued | The older RESUME code no longer resumes | main: `TestResumeNeedsATextedCodeAndStopVoidsIt` |
| #280 W5-D14 | STOP during a RESUME code check | The system stays stopped | main: `TestStopDuringAResumeCheckIsNotLifted` |
| #304 W5-D22 | A strong code used, then a restart | The same code is refused after restart | main: `TestGridCellsAndGeneratorStepsAreSingleUseAcrossRestarts`, `TestACodeIsSpentAcrossThePageAndTexts` |
| #304 W5-D22 | Code check whose state save fails | No unlock, the code is not spent, the owner gets the state-error reply | main: `TestFailedSaveLeavesNothingLiveInMemory` |
| #305 W5-D23 | Wrong codes on the local page | Counted once each; the lock and challenge are texted once | main: `TestLocalWrongCodesCountAndAlertTheOwner`, `TestManyWrongPageCodesTellTheLockAndChallengeOnce` |
| #307 W5-D25 | Sign-in alert whose send fails | The held alert is still delivered, once, after restart | main: `TestLocalSignInAlertsSurviveRestartAndFailedSend` |
| #307 W5-D25 | Sign-in whose record save fails | The sign-in stands and is texted at once, once (main's semantics; the draft's "no authority without the record" is not carried) | here: `TestSignInWhoseRecordSaveFailsIsTextedAtOnce` |
| #306 W5-D24 | Owner state unreadable at startup | The channel refuses to start and writes nothing over the state | here: `TestUnreadableStateRefusesToStartAndWritesNothing` |
| #306 W5-D24 | STOP while owner state is unreadable | STOP still takes effect | SIM-owner-hold (STOP must not depend on owner state loading) |
| #335 W5-D37, #336 W5-D38, #337 W5-D39 | Hourly allowance spent and saved, then a restart | The fourth update in the hour is held, not sent; it goes once the hour passes, across restarts | here: `TestSpentAllowanceSurvivesARestart` (stamp saves succeed) |
| #335 W5-D37, #336 W5-D38, #337 W5-D39 | A crash or failed stamp save after a text goes out | The restart does not refill the hourly allowance | SIM-owner-hold: main sends before it saves the stamp and ignores the save error (`pacer.go` `sendCounted`, `countSent`), so the allowance refills; draft tests #336 `TestLedgerFailureDuringActualBeginPreventsOwnerHandoff`, #337 `TestFiveStoreLedgerCutRecoversExactDebtBeforeBridgeRetry`, `…StopDuringLedgerSave` |
| #335 W5-D37 | An aged request's priority turn, then a restart | The aged request still goes first after restart | SIM-owner-hold: main's `grants` `Gate.Reserve` keeps the aged turn in memory only; draft test `TestDurablePacingAgedPrioritySurvivesRestart` |
| #335 W5-D37 | A pacing storage fault on any request path | The request is requeued, never sent uncounted or dropped | SIM-owner-hold: main has no reserve before hand-off; draft test `TestDurablePacingFaultRequeuesEveryRequestPath` |
| #335 W5-D37 | Concurrent sends against the allowance | Never more than the allowance in the hour | main: `TestReleaseSendsExactlyTheAllowance`, `TestRequestsShareTheAllowance` |
| #335 W5-D37 | A blocked pacing save | STOP and urgent texts are not delayed by it | SIM-owner-hold (the hold becomes a projection; no pacing write sits in front of STOP) |
| #336 W5-D38 | Pacing save fails before a text goes out | The text is not sent; the error is returned | SIM-owner-hold: main's `TestHeldTextSurvivesARestart` covers only the hold save, and main sends before the stamp save |
| #333 W5-D35 | Questions and other updates share one allowance | One hourly budget across kinds | main: `TestRequestsShareTheAllowance`; the digest half is retired with the digest |
| #385 W5-D60 | Accounting state missing at daemon start | Owner STOP still works | SIM-owner-hold (STOP must not depend on any pacing state) |
| #287 W5-sid | A short request ID lent, then a restart before the pipeline saves it | Two open requests never share one short ID | SIM-owner-hold (request IDs come from the journal; main has no lending API) |
| #390 POT-P5 | A declined suggestion, then a reload | It is not offered again | main: `attention` `TestDeclineAndRestart` (the draft's `TestDeclineSurvivesNewShapesExpiryAndReload`) |
| #390 POT-P5 | Account suggestion pacing, then a reload | The pacing is kept across reload | Not carried: main has no account suggestion pacing to keep (draft `TestAccountPacingSurvivesReloadAndDecline`); LATER.md |

Cases main already fails, from the W5-Dc reviews these drafts answered: a forget drops a held text, and the hold is rebuilt from owner-text intents (r13, r15, r16, r17), are SIM-owner-hold's acceptance; a forget reaching every projection once is SIM-erase's.

STOP and urgent texts never wait behind blocked storage (the pattern in #282, #303, #305, #309, #331, #347, #348, #353 and #373) rides with SIM-owner-hold's "no pacing write sits in front of STOP" row above; LATER.md `SIM-cases-stop` keeps it, tagged recheck, until SIM-owner-hold's review confirms it.

## Retired with the digest

Every case in these drafts exists only because a digest is collected, queued, acknowledged and sent. Each line names the case families.

| Draft | Cases (crash cut, acknowledgement, forget) |
|---|---|
| #263 W5-D1 | No tests (digest contract text); no owner-visible case |
| #266 W5-D2 | Restart while sending is Unknown and never resent; Unknown needs explicit not-sent evidence before retry; accepted is terminal; forget purges the pending payload; forget fails before touching in-flight references; save failure never admits |
| #267 W5-D3 | Collection queued durably before the source is acknowledged; restart after source ack before the queue bit; partial ack recovered before a new peek; expired batch does not consume its source |
| #268 W5-D4 | Change-digest peek survives restart; ack keeps notices added after peek; ack idempotent after restart; forget invalidates the pending goal snapshot |
| #269 W5-D5 | Change source reopen after partial ack; later notice survives an old ack |
| #270 W5-D6 | Question-digest peek without consumption; failed ack restores pending counters |
| #274 W5-D9 | Bridge attempt: ambiguous transport never retries; accepted-but-finish-save-failure stays quarantined; attempt survives queue reopen |
| #276 W5-D10 | Digest recovery across every durable boundary |
| #277 W5-D11 | Fuzzed receipts cannot consume later notices (fuzz only) |
| #279 W5-D13, #285 W5-D17, #286 W5-D18, #301 W5-D19 | Digest-note snapshot reopens with its receipt; ack keeps later counts; failed save quarantines until reopen; ordered replay survives ack and reopen; producer claim survives reopen |
| #282 W5-D15 | Owner notes survive source and channel reopen; note failure never falls back to a destructive digest |
| #284 W5-D16, #308 W5-D26 | Owner source reopen after source ack before queue bit; queue consumption before uncertain owner retirement does not resurrect |
| #302 W5-D20, #303 W5-D21 | Guard and note share one transaction; source/outbox ack cuts recover without duplicate counts; digest ack before uncertain outbox retirement does not resurrect a note |
| #306 W5-D24 | Source outage keeps the digest outbox (load-failure and STOP halves: the owner-visible table above) |
| #309 W5-D27, #310 W5-D28 | STOP during begin prevents the bridge call; STOP after hand-off persists Unknown and ignores the late receipt |
| #311 W5-D29, #313 W5-D31 | Daily alive line due/ack survive reopen; no double issue across DST |
| #312 W5-D30 | Expiry or heartbeat rollover during begin never calls transport |
| #314 W5-D32, #332 W5-D34 | Daily cadence reopens on the same identity; ambiguous delivery never creates a replacement; maintenance never hides Unknown outcomes |
| #331 W5-D33, #334 W5-D36 | Host STOP after hand-off persists Unknown and rejects the late receipt; four-file reopen |
| #336 W5-D38, #337 W5-D39 | Digest allowance survives reopen (question half: the owner-visible table above); Unknown reopen keeps debt and rejects late acceptance |
| #348 W5-D42 | Provisioned host with missing ledger keeps recovery controls |

What the owner keeps from these after SIM-pull: an urgent text is never sent twice after a crash and an uncertain send is reported as such (the modemlink rows above), STATUS after a crash shows the same open items (SIM-pull acceptance), and a forgotten subject never appears in STATUS (SIM-pull, SIM-erase).

## No owner-visible case

These drafts test pacing-file storage, leases, manifests, ancestors, drain order, daemon wiring or offline reconciliation tooling. D-095 makes the journal the only durable state, so none of these files survive as owner-facing surfaces.

| Draft | What it tests |
|---|---|
| #278 W5-D12 | Context error classification on owner sends |
| #338 W5-D40, #347 W5-D41 | Required pacing ledger, latency and health |
| #349 W5-D43 to #354 W5-D48 | Pacing file bounds, lease, retirement, session, startup, startup slot |
| #359 W5-D49 to #361 W5-D51 | Manifest, anchored IO, parent links |
| #368 W5-D52 | Consumer drain order |
| #369 W5-D53, #375 W5-D57 | Reconciliation checkpoints and offline Git transport (tooling) |
| #371 W5-D54, #373 W5-D55, #374 W5-D56 | Duplicate recovery, owned recovery, manifest startup |
| #376 W5-D58, #382 W5-D59 | Daemon wait and close errors |
| #385 W5-D60 | Provisioned daemon config refusals (its STOP case is above) |
| #395 W5-D61 | Owner factory assembly |
| #397 W5-D62 to #435 W5-D67 | Inspection, protected lease and manifest, close results, constructor cleanup, protected recovery |
| #388 POT-P6 | Router candidate evidence per task class (in memory, reset on restart); no crash, acknowledgement or forget case |
| #252 W5-sl, #387, #399, #405, #417 | Digest wording, replay fixtures, UX reviews: no crash, acknowledgement or forget case |
