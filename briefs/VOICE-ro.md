# VOICE-ro: the read-only voice assistant

Board section: Owner channel (SPEC CH-5, CH-17, CH-21). Mark chose this as the next slice on 2026-11-03 (Decisions 8, item 2) and full read-aloud on token calls, as a natural conversation rather than menus (item 7). Design: the flip-phone note §2.2 to §2.5 and the rearchitecture note §2.3 (project files, `answers/2026-11-01-*`). Tier A: it parses owner-channel input (OPERATING §3, criterion c).

## What it is

The owner calls the box's number and asks, in plain speech, what is in the mail and the calendar, what is due and what the box is doing; the box answers in speech. It moves no money, grants nothing and approves nothing: no kernel window opens on these calls, so no key means yes. The speed-dial token (item 5) is part of the slice, so a call from the handset gets full read-aloud (Mark, 2026-11-03: "make sure speed dial works", no stopgaps). Approvals by voice (item 6) are not built here.

- **Failure path to test first:** text a model wrote (the answerer, or a mail it quotes) is spoken although it asks for a code or tells the owner to press a key, or the box keeps speaking after the owner pressed 0 or hung up.

## Rules this slice holds (flip-phone note §2.2)

1. **Models emit text; the box speaks.** Every sentence of an answer passes the CH-21 check (`owner.AgentVoice`) alone and joined with everything the answer has already spoken, plus the spoken prompt grammar ("press", "key", "dial", "enter", "push" followed by a digit or key name), before it reaches the synthesizer. A held sentence ends that answer and the box plays its fixed held clip instead.
2. **A transcript is a claim.** Recognized text goes to the answerer as text and nowhere else; nothing in it is a verified field, and no key on these calls approves anything.
3. **0 is STOP.** Pressing 0 stops the answer being spoken at once. Talking over the box (barge-in) does the same and starts a new turn, as on a call with a person.
4. **The rung is the call's, not the transcript's.** The handset's speed-dial contact holds the box's number, a pause and the token, so the phone keys the token once the call is up (flip-phone note §2.1). The box reads keys up to `#`, 32 keys or 6 s, has the kernel check them once, and runs the call at P2 if they check, with full read-aloud. Any other call from the owner's number (dialled by hand, or a spoofed caller ID) is P0: a call's audio goes back to whoever called, so the answerer reads only the box's status there. Token keys reach nothing but the check, and none of them is STOP. The box listens from the start; what the owner says while the token is read is answered once the rung is known. A static token can be replayed by anyone who sees the call's key events; VOICE-ro-t answers that threat (L3 on #4944). A call from any other number is not answered here.
5. **Turn timing is measured.** Per turn: end of the owner's speech to the first audio, and to the first content audio, reported as median, 95th and 99th percentiles. Targets (flip-phone note §2.4): an acknowledgement within 300 ms and first content within 1.5 s with a warm planner; a fixed "one moment" clip covers any gap over a second, counted from the end of the owner's speech, and a fixed failed clip means a failure is never silence.

## Packages, in order

| ID | Scope | What | Waits on |
|---|---|---|---|
| VOICE-ro-a | `broker/call/**`, its line in `tools/risk_tier.py` (tier A, criterion c), C18 in `broker/modem/at/S2-CONFIRM.md` | The call loop: line, recognizer, answerer and synthesizer as interfaces; sentence cut and check; barge-in; 0 is STOP; reading the speed-dial token and the call's rung; turn timing | nothing |
| VOICE-ro-t | `broker/kernel/**` (token slot), the owner page | The token: made at home on the owner page with the passkey, held sealed by the kernel, checked in constant time with tries limited across calls, and answers replay of a static token seen in the call's key events (rotation from the owner page, or a counter part); the page shows the contact to save on the handset (number, pause, token, `#`) | a; S2's C18 on a real call |
| VOICE-ro-b | `broker/speech/**`, `broker/cmd/agentos-speech/**` | The recognizer and synthesizer as one sandboxed untrusted process (a small streaming recognizer and a local synthesizer, both public weights, tuned on telephone audio, never the owner's calls), timed on the M6 Ultra | a |
| VOICE-ro-c | `broker/call/answer/**`, `broker/cmd/agentosd/**` (serial, D-111) | The answerer: the planner's reads of mail, calendar, due items and STATUS, labels checked against the call's rung (the label gate is part p0, #4948) | a, the planner's read path |
| VOICE-ro-d | `broker/cmd/agentos-modem/**`, `broker/modem/bridge/**` | Wiring: owner calls reach the loop in the modem bridge; text to the answerer over the bridge socket | a, b, c, t; live run on S2 |

**Acceptance tests:** VOICE-ro-a, `go test ./broker/call/...`:
- `TestCodeAskIsNeverSpoken`, `TestKeyPromptIsNeverSpoken`, `TestCheckSpansTheSentenceCut` (rule 1)
- `TestKeysApproveNothing` (rule 2)
- `TestZeroStopsSpeech`, `TestBargeInStopsAndStartsANewTurn`, `TestHangupEndsTheLoop` (rule 3)
- `TestSpeedDialTokenRaisesTheCallToP2`, `TestWrongTokenStaysP0AndIsTriedOnce`, `TestTokenWindowAndLimit`, `TestTokenWaitEnds`, `TestOwnerCallRunsAtP0`, `TestOtherCallerIsNotAnswered` (rule 4)
- `TestOneMomentCoversASlowAnswer`, `TestOneMomentCoversEverySlowPart`, `TestClipWaitCountsFromTheEndOfSpeech`, `TestClipIsNotContent`, `TestTurnTimesArePercentiles` (rule 5)
- `TestSpeechDuringTheTokenIsAnswered`, `TestTokenWaitTurnCarriesAcrossBargeIn`, `TestCarryIsAskedOnce`, `TestZeroDropsTheCarry`, `TestStopWordDropsTheCarry`, `TestEmptyFinalAsksNothing` (rule 4)
- `TestOneClipDeadlineCoversEveryWait` (rule 5, on a moving clock)

## VOICE-ro-c, part p0: the answerer holds P0 by data labels (#4948)

`broker/call/answer` is a `call.Answerer`: its reads return facts with their data labels (PLN-3), and the writer (the model that words the answer) is given only the facts the ask's rung may hear. P2 hears every fact; any other rung hears only facts labelled `status` alone, so an unlabelled or mixed fact is private. `broker/clerk/plan` was named here before: it is the plan-login clerk, not the planner.

**Acceptance tests:** VOICE-ro-c-p0, `go test ./broker/call/answer/...`: `TestP0AskForMailOrCalendarGetsNoPrivateContent`, `TestOnlyP2IsFull`, `TestUnlabelledAndMixedFactsArePrivate`, `TestP2HearsMailAndCalendar`, `TestReadsSeeTheAsk`, `TestFailedReadFailsTheTurn` (rule 4)

## VOICE-ro-b, part b1: the speech process's wire and the box-side client (#5171)

The process is untrusted (a model runs in it), so the box-side client treats every frame it sends as a claim, like the transcript itself. Part b1 builds the wire (`broker/speech/wire`), the client (`broker/speech`, implementing `call.Recognizer` and `call.Synthesizer`), and the program's serve loop behind an engine interface (`broker/cmd/agentos-speech`). Part b2 (the pinned public-weight recognizer and synthesizer, tuned on telephone audio, timed on the M6 Ultra) needs the hardware and is its own row.

1. **A bad frame ends the session.** An unknown type, an oversize frame, text that is not UTF-8 or carries a control character, odd-length PCM, a reply to a sentence not asked, or an end of speech past the audio sent closes the transcript channel and fails every pending and later `Speak`, so the loop plays its failed clip. Nothing is repaired or skipped.
2. **End of speech is on the box's clock.** The process names the sample at which speech ended; the client maps it to when the box forwarded that audio and never later than when the transcript arrived, so a slow or lying recognizer cannot hold back the one-moment clip.
3. **Audio is bounded by its text.** A sentence's audio is at most 1 s plus 250 ms per rune (40 s in all), whole samples; longer audio fails that sentence rather than being cut.
4. **A cancelled sentence stays cancelled.** A `Speak` whose context ends returns at once, and its late audio is dropped, never played as the next sentence.
5. **The process sees only audio and checked sentences.** The wire carries nothing else to it; an untagged build has no engine and exits non-zero, failing closed.

**Acceptance tests:** VOICE-ro-b, `go test ./broker/speech/... ./broker/cmd/agentos-speech/...`:
- `TestBadFrameEndsTheSession`, `TestControlCharacterEndsTheSession`, `TestUnaskedReplyEndsTheSession`, `FuzzClient` (rule 1)
- `TestEndIsTheBoxClock`, `TestEndPastTheAudioEndsTheSession` (rule 2)
- `TestAudioBoundedByText`, `TestOddAudioEndsTheSession` (rule 3)
- `TestCancelledSentenceIsDropped` (rule 4)
- `TestServeRoundTrip`, `TestNoEngineFailsClosed` (rule 5)
