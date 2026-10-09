# UX review loop

A recurring review of the owner-facing experience (onboarding and everyday use) against the spec. Purely advisory: findings become proposals here, and spec changes go through an L1 spec-diff PR that Mark merges.

**Yardstick:** owner effort as SPEC §1 defines it (attention, time, decisions, memory, checking, and recovery, counted across failed tasks as well as accepted ones), judged against OWN-1–6 and OWN-17–18 and measured by OWN-19's journey components.

**Scope:** setup, the text/voice channel, approvals and codes, notifications and digests, the local Wi-Fi UI, moving PCs, recovery as the owner experiences it. Security properties are fixed inputs; a UX proposal that touches one states the tradeoff.

**Output of a spec-wide run** (only when Mark or L1 asks for one): `YYYY-MM-DD-ux-review.md` with findings (severity, owner effect, proposal), a decisions list for Mark, and, when warranted, SPEC.md edits in the same PR.

## In the lens screen

Tier A PRs get a UX pass in the lens screen; tier B PRs get UX as part of the combined pass. Each run applies the scope below to the PR's diff. Verdicts go to `reviews/ux/YYYY-MM-DD-pr<N>.md` (combined passes to `reviews/combined/`), in the L3 format of docs/OPERATING.md §4.

Before raising a finding on text shown to the guest, check that a guest can reach it: trace the path from a guest tool call to the text, through the MCP guard and the gate. #461 (SR2-3o) was built for refusals that no guest could reach.

## Checks that replaced findings

Finding kinds CI now catches; the screen no longer looks for them by hand (OPERATING §4).

| Finding kind | Check | Since |
|---|---|---|
| CH-12 "a problem text names a step that cannot work" (UX run 2, #327, #423; #409 U6), for the held-restore texts only | `TestHeldOwnerTextsNameOnlyStepsThatWork` (broker/cmd/agentosd/held_test.go): each text a held box can send names only steps that work in its state, is GSM-7 within three segments, and lists exactly the replies taken. Other owner texts are still screened by hand. | W3-forget-b1-7 |
| "Finding text names an identifier, or alarms with no step" (#523, #515) | `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` (broker/loops/ownertext_test.go): every check's owner line and cleared line, in each containment state, is GSM-7 within three segments; an urgent line names a pause or a reply and a line naming one is urgent; LOOP-7 lines built from hostile subjects show no Go identifier, path or hex run. `TestThePlainNameMapCoversEveryLoop7Subject` keeps the plain-name map complete. | P3-4b-3c |

## Spec-wide runs

Weekly runs over all of `main` until 2026-10-07, when the batched lens screen replaced them (DECISIONS D-048).

| Run | main at | Review |
|---|---|---|
| 1 | 3176f2d | [2026-10-04](2026-10-04-ux-review.md) |
| 2 | 044b83b | [2026-10-05](2026-10-05-ux-review.md) |

## Records

Per-PR and per-bundle records are the files `YYYY-MM-DD-*.md` in this directory (tier-B combined passes are in `../combined/`), in filename order, so there is no run number to pick. Each opens with a `Record:` line giving PR, package and head SHA; `tools/doclint.py` checks it on files dated 2026-10-09 or later. No run rows are appended to this README, so open PRs do not conflict on it; recurring kinds and the checks that replaced them still are (DOC-4, docs/OPERATING.md §4).

## Recurring kinds (to become checks)

- **A problem text names a step that cannot work** (CH-12): UX run 2 (#124, #126, #132, #133), #327, #423 (STATUS says a release waits for approval when no request is open, [2026-10-09](2026-10-09-pr423.md)), #430 and #434 (staged-adoption texts, [2026-10-09](2026-10-09-pr434.md)). The next package touching owner texts adds a test that flags it ([2026-10-08](2026-10-08-lens-bundle-a.md#recurring-kind)).
- **Finding text names an identifier, or alarms with no step** (#523, #515, #599 (UX 3, L3 2; LATER P3-4b-4c-exhaust l2), [2026-10-09](2026-10-09-pr515.md)): proposed check `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` in `broker/loops`, for the next package touching probe wiring (P3-4b-4b or P3-4b-4c).
- **A digest, STATUS or finding line gives no cause or next step** (the informational variant; the check above covers only alarms): #585 (digest lines, BOARD P3-4b-3r-text), #589 (corpus finding text and the `ProbeFailed` line, LATER P3-4b-4c-corpus l1, l2), #584 (a failed tamper round, LATER P3-4b-4c-tamper l1). The next package touching owner texts extends `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` to digest and STATUS lines.
