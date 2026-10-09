# W3-forget-b4: Owed-text order and failed saves in W3-forget-b3

Board section: Integration: wiring merged packages into the box. Fixes the three release points of Security 4a on #425 (W3-forget-b3); SPEC CAP-3.

**Sources:** [reviews/security/2026-10-09-pr425-sec4a.md](../reviews/security/2026-10-09-pr425-sec4a.md), points S1-S3 (all `release`; none breaks CAP-3 at the #425 head without a double fault). Read the note first: it names the lines and the mutant (M4) that survived.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): "Deletion requests propagate: the record and everything derived from it leave recall at once" (and the agent is rolled back, asking first). This package keeps that path from ending silently; it adds no CAP-3 behavior.
- **UX-182-3** (UX lens on #182; not a SPEC ID): a forget cut off by a restart texts its done text after the replay, and a forget never finishes with no text owed unless the owner was already told.
- **Spec gap:** no SPEC.md ID says the owner is told when a forget is done (CAP-3 and CH-12 do not; CH-12 covers only texts that report a wait or problem). The duty rests on UX-182-3 and #182. Raised to Mark through the L1 coordinator; SPEC.md is not edited here (CLAUDE.md).
- **S1:** `learn.go` (about line 253) renames an unreadable `forget-owed.json` to `.bad` before `lostForgetOwed` saves the file that owes `forgetOwedLost`. A crash between the two leaves no file, so the owner is never told the owed texts were lost. The fresh file and the bad one share one path (`FileStore.Save` writes a temp file and renames it over the path), so "save first, then rename" would move the fresh file aside. Order to build: (1) keep the bad file aside without removing it, by hard link or a 0600 copy to `forget-owed.json.bad` (the `.bad` copy keeps 0600; M5 pins the aside); (2) `Save` the `!lost` file over the path (atomic: the path holds the bad file or the fresh one, never nothing); (3) only then log. If step 1 fails, still do step 2 and owe the notice; the unreadable file is then replaced, and that is logged. A crash after step 1 leaves the bad file in place, so the next start repeats the sequence. Test by a store whose `Save` fails or a crash hook between the steps.
- **S2:** in `Execute`, a failed `owed.owe` is only logged. After a `retry` and a crash, the tombstone holds, the replay finishes the forget, and no text is owed, though the owner may have been told "Not forgotten yet… I'll text you when it's done." Retry the owed save inside `retry` (each pass, until it holds or the forget finishes), so the entry reaches disk before the forget can end; the retry stops on shutdown like the forget's own. If a save cannot be made to hold by the time `done` runs, `done` keeps the text owed in memory as it does now. Record in ASSUMPTIONS.md what a failed owed save plus a crash still risks, and that `forgetNotSaved` has been said.
- **S3:** no test pins F4's order (tell the owner, then drop the entry); mutant M4 (drop before the send) passes every test. Add a test whose owner send (`tell`) records the owed file's content at the moment of the send and asserts the entry is present then and gone after. Run M4 again; the new test must kill it. Add a second for S2 (owed save fails, then `retry` finishes, then the file holds the entry before the done text is told).

**Needs:** W3-forget-b3 (merged, #425)

**Work:** tests first (S3's order test fails on no code change only if M4 is applied; confirm it kills M4 and passes on the current code, then S1 and S2 tests fail before their fix). Then the smallest change that passes each.

**Not in this package:** the new methods W3-forget-b3r adds to `forget.go` (a task lister and `ask` wrapper; leave them untouched and unreformatted); item 2's owed texts (W3-forget-b2c-2); folding the owed stores (LATER W3-forget-b3 rr2); any change to the owed file's format.

**Scope:** `broker/cmd/agentosd/learn.go` (the owed-file open in `openLearning`), `Execute` and `retry` in `broker/cmd/agentosd/forget.go`, their tests (`forget_owed_test.go`, `forgetowed_test.go`, `learn_test.go`), and `broker/cmd/agentosd/ASSUMPTIONS.md`. Nothing else.

**Order with other rows:** runs before W3-forget-b2c-2 (both edit `forget.go` and the owed tests; b2c-2 builds on b4's order test and its save-first rule). W3-forget-b3r adds new methods only and lands in either order. Do not start b2c-2 until b4 has merged.

**Gate:** tier A (`tools/risk_tier.py` prints A for `broker/cmd/agentosd`): L3 on the strongest model with a threat check, Security re-sign at the final head (OPERATING §3-4). Lenses: Security only; no owner-visible wording changes, so no UX screen unless a text changes.

**Threat check to answer in the PR:** after each of the three fixes, which crash point still loses a text, and does any file or log now hold task words (it must hold goal IDs, times and counts only)?

**PR:** carries `Defect: W3-forget-b3`. Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 90k tokens (checkpoint 90k). Builder model: strongest.
