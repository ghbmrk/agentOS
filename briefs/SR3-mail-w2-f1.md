# SR3-mail-w2-f1: mail organize can run unasked in production, and its refusals speak to the owner

Board section: Security and architecture review (2026-10-08). Source: #655 reviews (UX/Potency 6087962017 points 2-5, L3 6088269153 points 1-2); redactor row from SR3-mail-w2 l5. Class release, tier A. Six parts; run as two PRs (below).

**Why it matters.** agentosd sets no `Redactor`, so `daemon.Run` journals free text as `[redacted]`, `evidenceReadable` fails, and every mail organize is asked, with the digest line and UNDO dormant (agentosd `ASSUMPTIONS.md` MW4). The words an owner sees for a refused organize are the gate's internals ("the adapter's guard refuses this effect (ADP-2)", `grants/gate.go:963`), and four UNDO and MORE paths give the owner wrong or no answer.

**Requirements:** CRED-7 (redact by default; nothing secret in the journal), CH-12 (words the owner can act on), CH-19, ADP-2, OWN-8. Anchor: agentosd MW4, SR3-mail-w2 l5 (`docs/LATER-HISTORY.md`).

**Acceptance tests:** (REQ: CRED-7, CH-12, CH-19, ADP-2, OWN-8)
- PR 1: T1 `TestRedactorKeepsOnlyMailChangeFields`, T2 `TestOrganizeRunsUnaskedWithRedactor`, T3 `TestUndoIDCollisionDetected`, T4 `TestMailDaysTwoAccountTrail` (each described under PR 1 below).
- PR 2: the gate ask/deny text test for (a), the unreachable-adapter `UndoReport` test for (b), the forced-ask `Reason` reaching the ask text for (c), and the `MORE <id>` test through `owner/channel.go` for (d).

**Status of each part on main (all six open; re-check at start).**
- Redactor: none set; MW4 describes the effect.
- (a) `gate.go:963` still returns the ADP-2 wording; no state-specific words.
- (b) `mail.UndoReport` has `Restored` and `Skipped` only (`undo.go:28`), so an unreachable vault reads as "changed since".
- (c) the forced-ask `Reason` at `gate.go:981` is "no guard for this account". agentosd registers the mail loop as an Escalator (`agentosd/mail.go:91`), so the forced ask an owner sees today is `mail.go:221` ("no UNDO yet ..."), and PR 1 turns that path off in production. The builder confirms which site the words belong to; `agentosd/mail.go` is in PR 2's scope.
- (d) `MORE` is handled in `broker/owner/channel.go:494`; no route for a mail UNDO ID.
- (e) `mailDays.undo` (`agentosd/mail.go:402`) takes the first day whose `undoID` matches; two days colliding inside `undoLookback` (8) restore the wrong one.
- (f) `mailDays.changes()` (`mail.go:352`) filters by account; no test has two accounts in one trail.

**PR 1: redactor, (e), (f).** Privacy decision first: the redactor keeps only `mail.Change` fields (record ID, folders, sender domain at most; SR3-mail-w2 l5), removes vault values and CH-19 patterns from them, and `[redacted]`s everything else. State the kept field list in MW4 and flag it for the Security lens; a field not on the list is not kept. The redactor is for `daemon.Run` only: do not set `valueStore.redact` from it (`values.go:331` treats any value the journal redactor changes as a secret, so every non-Change value would become the placeholder). Reuse `owner.SecretShaped` / `credentialShaped` for the CH-19 patterns, not new ones.
- T1 `TestRedactorKeepsOnlyMailChangeFields` (`broker/cmd/agentosd/`): a journaled `mail.Change` round-trips through `ParseChange` after redaction; a canary vault value and a CH-19 pattern placed in each kept field are gone; a non-Change free text is `[redacted]`.
- T2 `TestOrganizeRunsUnaskedWithRedactor`: with the redactor wired, `evidenceReadable` is true and an in-bounds organize is allowed without an ask; without it (control), asked.
- T3 (e) `TestUndoIDCollisionDetected`: a fixed key and two days with equal `undoID` within the look-back; `undo` answers that the ID is ambiguous and restores nothing. Find a colliding pair by search over days with a fixed key.
- T4 (f) `TestMailDaysTwoAccountTrail`: two accounts' organize records interleaved in one trail; each `mailDays` returns only its own.

**PR 2: (a), (b), (c), (d)** (owner-voice words; depends on PR 1 merged).
- (a) Gate `Reason`s for the unbound, locked and unconnected states, in the owner's and agent's words: agent: "the mail account changed since this was asked; ask again"; owner: "did not run: the mail account was replaced". Replaces the ADP-2 string and the SR3-5-f2 l6 wording; the test asserts the ask/deny text.
- (b) `UndoReport` gains `Unreachable`; `Text()` says "could not reach the mail account; nothing restored" apart from "changed since"; a test with an adapter whose calls fail.
- (c) forced-ask `Reason`: "I can't undo this yet, so I'm asking first", with a test that it reaches the ask text.
- (d) `MORE <id>` on a mail UNDO ID lists what the undo would restore (hook beside `UndoHook`); a test through `owner/channel.go`.

**Out of scope.** The wire codes `signin` and `unreachable` (SR3-mail-w2-r1), the scanner fence, and new mail operations.

**Scope:** PR 1: `broker/cmd/agentosd/` (wiring, `mail.go`, ASSUMPTIONS MW4, new tests). PR 2: `broker/grants/gate.go`, `broker/mail/undo.go`, `broker/owner/channel.go` and `approvals.go`, `broker/cmd/agentosd/mail.go`, their tests. This brief.

**Dependencies:** SR3-mail-w2 (merged, #655). SR3-5-f4 touches `broker/mail` too: not in parallel. D-111: check overlap at start.

**Usage estimate:** PR 1: 70k, PR 2: 70k tokens, checkpoint at the PR boundary. Builder model: strongest (tier A: `broker/grants`, `broker/mail`, journal redaction).
