# CLK-3-f5d: browser task approvals, round 2 (site split, covered reads, secret mark, word precision, STATUS lines)

Board row: #2714 (tier A, lane:primary). Source: #2714 items 1 to 3, comment 6328020885, item 8 (#2705, after #2723), and the coordinator's housekeeping: #2689's live wording items and #2609 K8. Usage estimate: 80k tokens.

**Why (facts).** At ed6a1f3: a submit on a second site under a task's tap failed a bare `unapproved` with no Approval, the same as no tap at all; a read under a live tap still said it needed the owner's exact approval; an Approval on a secret screen carried no mark, so a card could offer the task tap again and loop; "2-Step Verification", "Update email address", "Revoke sessions" and "Authorize application" marked no screen; the clerk never set `kernel.Result.Covered`, so STATUS listed no covered submit; and a driver that stopped reading could block a step with the gate's lock held (K8).

## Requirements (from SPEC.md)
- **CLK-3 "One approval per task"**: what asks again (another site), covered requests listed in STATUS.
- **VRB-1, CLK-5 "Secret screens"**: the word lists, how texts are split and compared.
- **KRN-5**: which owner messages open a task (#2689 item 6).

## Design
- The clerk reads the task's approvals through one function (`covers`) that the gate calls under its lock with the site it computes: the approval for that site, else another live one of the task. A post or read on another site then gets `approval_required` with that request's Approval and the reason, so sub B's card offers the tap for `Approval.Site`. With no approval in the task, a post stays `unapproved`.
- A read the task's tap covers answers `task_approved` with its Approval; one it does not cover says why.
- `Approval.Secret` is the listed word that marks the screen. `asksAgain` reads it, so a task tap never covers such a request and the card asks for the exact approval.
- New pairs (update email, edit email, revoke session, revoke access, active session, connected app, authorize app, authorize application) and `2-step`, in SPEC and code together. No single word is narrowed: every context signal is page text, a false match costs one tap and loses nothing, and the structural fix for a site's checkout is its recipe (VRB-2).
- `kernel.Result.Covered` carries `coveredLine`, cut to `kernel.MaxShown`, which drops a longer line.
- K8: the request write shares the reply's deadline.

## Package IDs
- **BRS-22 Site split.** A submit on another site than the task's approval asks again with its own Approval, naming its site and the reason; once that site is tapped, it is sent.
- **BRS-23 Covered reads.** A read under the task's tap says `task_approved`; on another site or a secret screen it says why it needs a tap.
- **BRS-24 Secret mark.** An Approval on a secret screen carries its word, and no task tap covers it.
- **BRS-25 Corpus.** Every line of the synthetic corpus keeps its pinned mark: ordinary checkout texts do not mark, the measured false positives and known misses are listed, and the secret texts mark.
- **BRS-26 STATUS lines.** A covered submit's line reaches the kernel's `Result.Covered` and fits `MaxShown`.
- **BRS-27 Write deadline.** A driver that stops reading is stopped within the timeout (K8).

## Scope (files)
- In scope: `broker/browser/` (code, tests, `testdata/secret_screens.txt`, ASSUMPTIONS.md), SPEC.md CLK-5 "Secret screens" and one clause of KRN-5, this brief.
- Out of scope: sub B's card (noted on #2578); K9 request ids (the executor, #2609); scheme and port (#2714 item 4, later).

## Acceptance tests
**Acceptance tests:** in `broker/browser/task_test.go`: `TestASiteSplitAsksForTheOtherSitesTap` (BRS-22), `TestAReadSaysWhetherTheTasksTapCoversIt` (BRS-23, BRS-24), `TestOneTapCoversTheTasksSubmits` and `TestCoveredLineFitsStatus` (BRS-26); in `site_test.go`: `TestSecretScreenCorpus` (BRS-25), `TestSecretListsAreTheSpecs`; in `gate_test.go`: `TestADriverThatStopsReadingIsStopped` (BRS-27). `REQ: CLK-3, VRB-1`.
