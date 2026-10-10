# PACE-1: A held "Cleared" text never follows the alert that superseded it (OWN-4, CH-15)

Architecture review finding 3 (Mark's thread, 2026-10-10): security alerts go out urgent, but loops "Cleared" texts are queued non-urgent (`broker/loops/report.go`, `broker/cmd/agentosd/loop2.go`), so a finding can clear, return, and the stale "Cleared" reaches the owner after the new alert. Tier A (owner channel, security notice path).

SPEC rows: OWN-4 (notify when knowing changes what the owner would believe; a security alert), CH-15 (pacing and quiet hours never reorder what the owner believes).

**Today.**
- `Guard.closeTextLocked` decides the "Cleared: X." lines; `Pass`, `Resolve`, `CloseTarget` and `runProbe` send them with `Notify(text, false)`.
- agentosd's `loop2Notify.send` posts a non-urgent loops text as `ClassUpdate`, which the owner pacer holds in quiet hours or past the hourly allowance (W5-Dc-r1a O23).
- A return within `ReText` is texted "It is back: …" urgent (`ClassSecurity`), which skips the hold.
- So: alert (urgent) at 23:00, clear at 23:30 (held), return at 00:10 (urgent, sent), release at 07:01 sends "Cleared". The owner's last text says all clear while the finding is open. This breaks loops S39's invariant ("the owner's last text never says it is back after it closed") once pacing is on.

**Decision: a held text names the cleared keys it speaks for, and the pacer revalidates them against the guard's live state at send.**
- `owner.HeldText.Subjects` (saved). `Channel.PostAbout(class, text, subjects)` posts it. `Channel.SetCurrent(hook)` sets the check; `hook(subjects)` is true when the text is still true.
- Revalidation runs on every send path of a text with subjects: urgent, send-now, and `releasePaced`. A text that fails is dropped from the hold and not counted against the allowance.
- Fail closed: a text with subjects and no hook is dropped. The owner then stays on the alert, which is the safe side.
- `loops.Guard.Current(keys)` uses `clearedLinesLocked`'s predicate: false when any open record that is `Texted || Again` has one of the keys.
- `Pass` sends cleared lines in their own text through `GuardConfig.NotifyClear(text, keys)` when the pass is not urgent, so a held "Cleared" never shares a text with an unrelated notice it would take down when dropped. An urgent pass keeps one text, sent at once (as before).
- Why keys and not a revision counter: the question at send is "is this statement still true", which the guard answers from live state. A revision counter answers "has anything changed", which drops true clears after an unrelated change and needs a new saved counter per key. Keys need no new guard state and match the predicate that decided the line.

**Requirements** (local IDs under OWN-4 and CH-15):
- **PC-1, subjects survive a restart.** A held text's subjects are saved with the hold and read back.
- **PC-2, a superseded held text is dropped at release.** At release, a held text whose hook says false is removed and not sent, and does not spend the allowance; the other held texts are sent as before.
- **PC-3, fail closed.** With no hook, a text with subjects is not sent on any path: a paced one stays held, the rest of the hold going past it, until a hook is set and confirms it (so a restart before agentosd wires the hook cannot delete a true clear; L3 on #708); an urgent one is dropped. With a hook, only the texts it accepts are sent.
- **PC-4, ordering.** Through a real guard and a real owner pacer wired as agentosd wires them: alert, clear (held in quiet hours), return ("It is back", sent). At the release no "Cleared" is sent, and the owner's last text is the return.
- **PC-5, a later true clear is sent.** After PC-4, the finding clears again; that "Cleared" is sent and is the owner's last text.
- **PC-6, agentosd wires it.** Loops cleared texts reach the owner channel through `PostAbout` with their keys, and the guard's `Current` is the channel's hook. An agentosd test through `openLearning` and `attach` fails if either wiring line is deleted (L3 on #708).
- **PC-7, cleared lines go apart.** A non-urgent pass that closes one finding and texts another sends the cleared line in its own text, with its key; `Current` is true while the key is closed and false once it reopens.

**Scope.** `broker/owner/{pacer.go,channel.go}`, `broker/loops/{secure.go,report.go,probe.go}`, `broker/cmd/agentosd/{loop2.go,learn.go}`, their tests and ASSUMPTIONS. Not W5-Dc-r17 (forget reach into the hold), not MORE lines.

**Estimate.** About 250 lines with tests; one session.
