# CTRL-card-sock s2 r1: setup makes the Owner Card again when the vault holds none

Board section: Backlog refill; work item #1330. Release finding of the UX and L3 reviews on PR #1309 (CTRL-card-sock s2). It folds in external review 12, item 12 (one call for the card report and finish; Mark's "Yes", 2026-10-14 01:04Z, on #1330).

**Requirements:**
- HW-1: the Owner Card step holds setup until the card is confirmed and provisioned, and a vault that holds no card sends the owner back to the card step instead of a dead end.
- F10: a card step rerun resets the vault before the new card is shown, and a provision refused for an unconfirmed code generator still routes to step 3.
- ARC-2: agentosd links no card, firstboot, claim or localui code (`TestAgentosdLinksNoClaimOrCard`).

**Acceptance:** A1 (setup on hardware, with P2-1).
**Implementation risk:** tier A (setup, vault, card step). **Needs:** CTRL-card-sock (#1115) and s2 (#1309), merged. **Gate:** lenses (security: strongest tier).
**Guard files:** none (no new broker package, no new import).

## The failure

The vault refuses finish's seal while it holds no Owner Card, and agentosd answers `card pending` (localsrv, `EnrollCardRequired`). That happens when the vault was remade under a confirmed latch: egress K22 makes a fresh setup vault at a start that finds no keys file. The page's latch still says confirmed, so `Hold()` is nil, `Display()` is nil (`/setup/card` redirects to `/setup`), `ResetUnlatched` never runs, and `maybeFinish` shows "Could not finish setup. Try again." forever.

## Reading of the work item

The issue says to clear the latch. The on-disk latch is also what agentos-ap reads (`firstboot.CardConfirmed`): once the card was confirmed the setup network is burned, so a latch cleared on disk leaves `want` with neither network and the box serves no Wi-Fi, cutting off the phone that must see the new card. So the rerun clears the card step's hold in the page's process and keeps the disk latch until the new card's confirm writes it again. A restart in between finds the latch confirmed, finishes, gets `card pending` again and reruns again, so the state heals without the disk latch. This is recorded in firstboot's ASSUMPTIONS.

## Scope (files)

- `broker/firstboot/`: `card.go` (`CardStep.Again`), `claim.go` (`ClaimedCard.Again`), `start.go` (`FirstBoot.Again`, the reset kept from `BoxConfig`), `again_test.go`, `ASSUMPTIONS.md` (one row).
- `broker/localapi/`: `setup.go` (`Finish.Card`; `OpSetupCard` and `SetupCard` removed) and `localapi_test.go` (the op list).
- `broker/cmd/agentosd/`: `setup.go` (finish takes the card report) and `setupsock_test.go`.
- `broker/localui/`: `setuphooks.go` (`CardFinish`, `ErrCardAgain`), `setup.go` (`maybeFinish`), `cardsock_test.go`, `localui_test.go` (fake hooks: a refused finish and a failed send), `setuptext_test.go` (a failing line), `pairsend_test.go`, `ASSUMPTIONS.md` (L42 amended, L57).
- `broker/cmd/agentos-localui/`: `main.go` (`CardFinish.Again`) and `main_test.go`.

`tools/risk_tier.py` is unchanged.

## What to build

1. **The rerun.** `CardStep.Again(reset)` makes the hold refuse at once, runs `reset` (the vault's `/card/reset`, a no-op on a remade vault that holds no card), then builds a new card display whose confirm provisions and latches as before. `ClaimedCard.Again` reruns its step once claimed. `FirstBoot.Again` reruns the route's step with `BoxConfig.Reset`; the reinstall route has none.
2. **One call.** `localapi.Finish` gains `card`: the page's report that its card is confirmed and provisioned. agentosd's setup finish in page mode latches the hold from it and then checks the hold, so `page_setup_card` is gone. `CardFinish.Finish` sends `card` from `Card.Hold()`.
3. **The answer.** `CardFinish.Finish`, on `card pending` after it reported the card confirmed, calls `Again` and returns `ErrCardAgain`. `maybeFinish` then clears the recovery step (the card step comes before it) and shows "I need to make your Owner Card again. Any card I showed you before will not work." Setup then routes to the card step with a new card. A failed `Again` keeps "Could not finish setup. Try again." and the next finish tries again.

4. **#1293 folded in** (coordinator, 2026-10-17): the paired text that `numberCode` dropped is surfaced as a one-time note on the page, and `PairTexts` sends a failed reply once more after its retry wait. The widening half of #1293 is already on main.

## Lifecycle: stage by outcome

| Stage | Outcome | Test |
|---|---|---|
| Finish, vault holds a card | finishes, one socket call | cardsock: one call |
| Finish, vault remade (`card pending`) | message, card step, new card | cardsock: card again |
| Confirm of the new card | latches, finish succeeds | cardsock: card again |
| Confirm refused `codes_unconfirmed` | step 3, then the same card | existing F10 test |
| Restart after the rerun, before the confirm | latch confirmed, finish reruns again | firstboot: again after restart |
| Disk latch during the rerun | stays confirmed (agentos-ap keeps the card's network) | firstboot: again keeps the latch |

Integration owner: this package (`cmd/agentos-localui` wiring).

## Acceptance tests

**Acceptance tests:**
- HW-1, F10: `broker/firstboot/again_test.go::TestCardStepAgain`: after `Again` the hold refuses, the reset ran once, `Display()` is a new display, the disk latch still reads confirmed, and the new card's confirm makes the hold nil. Catches a rerun that leaves the step done or shows no card.
- HW-1: `broker/firstboot/again_test.go::TestCardStepAgainAfterRestart`: a step built on a confirmed latch (no display) reruns to a new display. Catches a rerun that needs the first start's display.
- HW-1: `broker/firstboot/again_test.go::TestClaimedCardAgain` and `TestFirstBootAgain`: the claim route reruns its step; the reinstall route refuses. Catches a route that cannot rerun.
- HW-1: `broker/localui/cardsock_test.go::TestCardPendingMakesTheCardAgain`: a page whose finish gets `card pending` shows the fixed message, routes to the card step with a new card, and after its confirm finishes. Catches the "Try again" dead end.
- HW-1: `broker/localui/cardsock_test.go::TestCardFinishSendsOneCall`: a confirmed card makes one `page_setup_finish` call with `card` true; a held card sends `card` false and agentosd refuses. Catches a second call or a report from a held card.
- HW-1: `broker/cmd/agentosd/setupsock_test.go::TestFinishTakesThePageCard`: finish answers `card pending` without `card` and finishes with it; `page_setup_card` is not served. Catches finish passing an unreported card.
- ONB-6, CH-12: `broker/localui/pairsend_test.go::TestNumberCodeSaysWhenThePairedTextDidNotGo` and `TestPairTextsSendAFailedReplyAgain` (#1293). Catch a dropped paired send.
- ARC-2: `TestAgentosdLinksNoClaimOrCard` and `TestThePageLinksNoneOfAgentosd` pass unchanged.

Run tests with `-race`.

## Out of scope

Telling the owner ahead that the code generator must be set up again on a remade vault: the new card's provision still answers `codes_unconfirmed` and routes to step 3 (F10).

## Estimate

About 90k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
