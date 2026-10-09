# SR3-2-f: scope bound asks name queued places, and erasure keeps the record bound (SR3-2-f2, SR3-2-f3)

These are release findings on #428 (SR3-2): UX point 1 ([note](../reviews/ux/2026-10-08-pr428.md)) and Security point 3 ([note](../reviews/security/2026-10-08-pr428.md)), filed as BOARD rows SR3-2-f2 and SR3-2-f3. Anchors: ADP-9, CH-12, CAP-3, A12, A4.

**Why one package.** Both rows are about how `Gate.matches` counts places under a pre-allowance's scope bound (`broker/grants/gate.go`, the `day`/`perRec` counts over `g.inUse`). Both need the same small change to `journal.Use`, which must carry more than `{Intent, Started}`. Together they are about 150 lines of code and tests. Split only at the checkpoint, if one is still red: ship the other.

**Requirements** (local IDs):

- **SR3-2-f2 (name the queued places):** a rule fails to match only on its scope bound (`PerDay` or `PerRecord`), and at least one of the places it counted is an intent not yet started. In that case the owner's ask names them in the item's `Detail`, for example `2 earlier sends still queued`, or `1 earlier send still queued`.
  - The intent's action supplies the verb, through the existing action-noun wording if there is one; otherwise use `earlier actions`.
  - Fit within the 40-character `Detail` field (`owner/render.go`), with no truncation mid-word.
  - When `Escalate` also sets a reason, keep `Escalate`'s reason and append the queued count only if both fit; otherwise `Escalate`'s reason wins.
  - The decision is unchanged: the ask is still made, and nothing is denied or passed differently.
- **SR3-2-f3 (erased intents still bound per record):** an intent erased under CAP-3 (`RecErased`: `Params` and `Preconditions` set to nil) still counts toward `PerDay` as today. It also counts toward `PerRecord`, for every record key. The recommended conservative fix keeps no deleted content.
  - Add `Erased bool` to `journal.Use`, set from the entry's erased flag (`engine.go` RecErased apply).
  - In `matches`, an erased use counts against `perRec` whatever the record.
  - **Alternative:** keep `ParamRecord` among the fields erasure keeps. This retains an identifier of deleted content. Take it only if the builder shows the record key is not content under CAP-3; record the reason in journal ASSUMPTIONS.

**Failing-test-first controls.** Show each test failing at main and cite the message in the PR, then show it passing at the head.

| ID | Test | Why it fails on main |
|---|---|---|
| SR3-2-f2 | Use a pre-allowance with `PerDay: 2`. Authorize two sends that stay queued (STOP, or `Started: false`), then submit a third. The owner item's `Detail` is `2 earlier sends still queued`. With one queued and one started, it reads `1 earlier send still queued`. With both started, `Detail` stays as main produces it. | `Detail` is `esc.Reason` only, which is empty here. |
| SR3-2-f2 fit | A long `Escalate` reason plus the count stays within 40 characters and keeps the reason. | New behavior. |
| SR3-2-f3 | Use `PerRecord: 1` on record R. Authorize and succeed one intent on R, `Erase` it, then submit a second intent on R: it is asked, not passed. Mutant: count the erased use per record only when `Params` match, and the test fails. | Erasure nils `Params`, so `x.Params[ParamRecord]` is missing and `perRec` misses it; the second intent passes. |
| SR3-2-f3 journal | `Engine.InUse` reports `Erased: true` for an erased Succeeded intent within the window, and `false` otherwise. Replay gives the same result. | `Use` has no such field. |

**Controls that must keep passing:**
- `broker/grants/scopebound_test.go` (SR3-2's dispatch recheck and over-ask).
- `broker/journal` erasure and replay tests (CAP-3 keeps no params; OP-1 still recognizes the resubmission by fingerprint).
- `pagewording_test.go` for the owner item's layout.

**Threat check for the reviewer:**
- Does the new `Detail` text carry any parameter of the queued intents (a recipient, a subject or a record)? It must carry only a count and a verb.
- Can an erased use ever count *less* than before?
- Does `Erased` survive replay and `Rewrite`?

**Out of scope:**
- The mail adapter's own bound (SR3-mail-f).
- LATER `SR3-2 l1` and `SR3-2 l2`.
- A per-intent list in the ask; a count is enough for ADP-9.

**Scope:**
- `broker/grants/gate.go` (`matches`, `evaluateEffect`'s `Detail`), plus new or extended `broker/grants/*_test.go`.
- `broker/journal/engine.go` (`Use`, `InUse`), plus `broker/journal/*_test.go`.
- `broker/grants/ASSUMPTIONS.md` (GR7/GR31 notes) and `broker/journal/ASSUMPTIONS.md` (an erased use counts per record).
- `briefs/SR3-2-f.md` (Delivery notes only), and `BOARD.md` rows SR3-2-f2 and SR3-2-f3.

**Needs:** SR3-2 (merged, #428 75a97c7).

**Done:**
- CI green.
- SR3-2-f2 and SR3-2-f3 covered by passing tests.
- The red-at-main messages quoted in the PR.
- Risk tier A (`broker/grants`, `broker/journal`).

## Delivery

- **Builder model:** strongest model (risk tier A). Tests first.
- **Before the PR:** run `python3 tools/risk_tier.py --git origin/main HEAD`.
- **Review:** L3 on the strongest model with the threat check above, then the UX lens (for the `Detail` wording) and a Security section (OPERATING §3–4).
- **Estimate/checkpoint:** about 70k tokens. This is not a ceiling (OPERATING §5).
- **Delivery note (builder):** the note is shown with `Detail` but kept out of what an approval binds (`wait.base`; restart re-issue matches the carried digest over counts up to 1000). Adding it to the approved item would have refused every approved bound ask at dispatch (count 0 there) and closed it at restart; `TestQueuedNoteIsNotWhatIsApproved` covers both. The record key is not kept after erasure (alternative not taken; journal A16).
