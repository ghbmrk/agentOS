# VOICE-ro: the read-only voice assistant

Board section: Owner channel (SPEC CH-5, CH-17, CH-21). Mark chose this as the next slice on 2026-11-03 (Decisions 8, item 2) and full read-aloud on token calls, as a natural conversation rather than menus (item 7). Design: the flip-phone note §2.2 to §2.5 and the rearchitecture note §2.3 (project files, `answers/2026-11-01-*`). Tier A: it parses owner-channel input (OPERATING §3, criterion c).

## What it is

The owner calls the box's number and asks, in plain speech, what is in the mail and the calendar, what is due and what the box is doing; the box answers in speech. It moves no money, grants nothing and approves nothing: no kernel window opens on these calls, so no key means yes. Items 5 and 6 (the speed-dial token and capped approvals away) wait on S2 and are not built here.

- **Failure path to test first:** text a model wrote (the answerer, or a mail it quotes) is spoken although it asks for a code or tells the owner to press a key, or the box keeps speaking after the owner pressed 0 or hung up.

## Rules this slice holds (flip-phone note §2.2)

1. **Models emit text; the box speaks.** Every sentence of an answer passes the CH-21 check (`owner.AgentVoice`) alone and joined with everything the answer has already spoken, plus the spoken prompt grammar ("press", "key", "dial", "enter", "push" followed by a digit or key name), before it reaches the synthesizer. A held sentence ends that answer and the box plays its fixed held clip instead.
2. **A transcript is a claim.** Recognized text goes to the answerer as text and nowhere else; nothing in it is a verified field, and no key on these calls approves anything.
3. **0 is STOP.** Pressing 0 stops the answer being spoken at once. Talking over the box (barge-in) does the same and starts a new turn, as on a call with a person.
4. **The rung is the call's, not the transcript's.** A call the owner placed is P0 (caller ID only), and a spoofed caller ID hears whatever the answer says, because a call's audio goes back to whoever called. So until the speed-dial token (S2) makes it P2, the answerer gets P0 and reads only the box's status, never mail or calendar (Decisions 8 card on #4934; the loop passes the rung, so the token changes one value). A call from any other number is not answered here.
5. **Turn timing is measured.** Per turn: end of the owner's speech to the first audio, and to the first content audio, reported as median, 95th and 99th percentiles. Targets (flip-phone note §2.4): an acknowledgement within 300 ms and first content within 1.5 s with a warm planner; a fixed "one moment" clip covers any gap over a second.

## Packages, in order

| ID | Scope | What | Waits on |
|---|---|---|---|
| VOICE-ro-a | `broker/call/**` and its line in `tools/risk_tier.py` (tier A, criterion c) | The call loop: line, recognizer, answerer and synthesizer as interfaces; sentence cut and check; barge-in; 0 is STOP; the call's rung; turn timing | nothing |
| VOICE-ro-b | `broker/speech/**`, `broker/cmd/agentos-speech/**` | The recognizer and synthesizer as one sandboxed untrusted process (a small streaming recognizer and a local synthesizer, both public weights, tuned on telephone audio, never the owner's calls), timed on the M6 Ultra | a |
| VOICE-ro-c | `broker/clerk/plan/**` read side, `broker/cmd/agentosd/**` (serial, D-111) | The answerer: the planner's reads of mail, calendar, due items and STATUS, labels checked against the call's rung | a, the planner's read path |
| VOICE-ro-d | `broker/cmd/agentos-modem/**`, `broker/modem/bridge/**` | Wiring: owner calls reach the loop in the modem bridge; text to the answerer over the bridge socket | a, b, c; live run on S2 |

**Acceptance tests:** VOICE-ro-a, `go test ./broker/call/...`:
- `TestCodeAskIsNeverSpoken`, `TestKeyPromptIsNeverSpoken`, `TestCheckSpansTheSentenceCut` (rule 1)
- `TestKeysApproveNothing` (rule 2)
- `TestZeroStopsSpeech`, `TestBargeInStopsAndStartsANewTurn`, `TestHangupEndsTheLoop` (rule 3)
- `TestOwnerCallRunsAtP0`, `TestOtherCallerIsNotAnswered` (rule 4)
- `TestOneMomentCoversASlowAnswer`, `TestTurnTimesArePercentiles` (rule 5)
