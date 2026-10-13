# CTRL-card-sock: the card step and the claim in `agentos-localui`

Board section: Backlog refill; work item #1115. It follows CTRL-card-vaultop (#1199) and P2-2w c4 (#1218). It carries owner-routing clause R1 from #1210 and LATER CTRL-card l2.

**Requirements:**
- HW-1: the Owner Card step holds setup until the card is confirmed and provisioned.
- HW-10: a preloaded box keeps its claim gate, and a box that lost its claim state keeps the reinstall route (firstboot F11, F12).
- F10: after a vault reset that remade the setup vault, the owner sets up the code generator again before the card.
- ARC-2: agentosd links no card, firstboot, claim or localui code (`TestAgentosdLinksNoClaimOrCard`).
- K9: the claim's residual for a flood of posts.
- Binding conditions: egress K21 and K22, localui L26 and L41, and the #1210 R1 routing clause.

**Acceptance:** A1 (setup on hardware, with P2-1).
**Implementation risk:** tier A. **Needs:** CTRL-card-vaultop (#1199) and P2-2w c4 (#1218), both merged. **Gate:** lenses (security: strongest tier).

## Reading of the work item

The work item asks for "card display, `Hold()` and `card pending`" as localapi ops built in agentos-localui. ARC-2 rules out serving the display from agentosd, because `card` serves its page over `net/http` and agentosd may not link it. So the display, the latch and `Hold()` stay in the page, and one localapi op, `page_setup_card`, reports the page's hold to agentosd. agentosd's finish refuses with `localapi.ErrCardPending` until that report arrives. The page reports just before each finish, so a restart of agentosd loses nothing.

## Scope (files)

- `broker/cmd/agentos-egress/`: `custody.go` (a `reason` on `unlockErr`), `cardvault.go` (the reason on `errCodesUnconfirmed`), `server.go` (`fail` sends it), and `cardvault_test.go`.
- `broker/egress/ASSUMPTIONS.md`: one sentence on K21.
- `broker/localapi/`: `setup.go` (`OpSetupCard`, `SetupCard` and `ErrCardPending`) and `localapi_test.go` (the op list).
- `broker/cmd/agentosd/`: `setup.go` (the page's hold and the op), `main.go` (setup mode's `Card`), and a new `setupsock_test.go`.
- `broker/localui/`:
  - `claim.go` (the bounded claim);
  - `card.go` (routing back to step 3);
  - `setup.go` and `pages.go` (the code-generator note, and the restart note on the card step);
  - `server.go` (`Config.CodesVoid` and the claim queue);
  - `vault.go` (the card ops over the unlock socket and the vault's reason);
  - `setuphooks.go` (`CardFinish`, which wraps `AgentosdSetup`);
  - `firstboot.go` (new: the page's `BoxConfig` from the unlock client);
  - new `cardsock_test.go` and `claimflood_test.go`;
  - `ASSUMPTIONS.md` (one new row).
- `broker/cmd/agentos-localui/`: `main.go` and `main_test.go`.
- `broker/claim/ASSUMPTIONS.md`: K9's residual.

No new broker package. `tools/risk_tier.py` is unchanged.

## What to build

1. **The vault's reason.** The unlock socket's error reply gains a stable `reason` where the page must act on one. The first is `codes_unconfirmed`, on `/card/provision`'s 412 for an unconfirmed code generator (K21). Other 412s (such as `errNotOpen`) carry no reason.
2. **Card ops on the page.** `UnlockClient.ProvisionCard` posts the confirmed card to `/card/provision`, and `ResetCard` posts to `/card/reset` and returns `remade`. A refusal with that reason wraps `localui.ErrCodesUnconfirmed` around its `VaultError`.
3. **Routing back to step 3.** Two answers set the page's `CodesVoid`: a provision refused with `codes_unconfirmed`, and a reset that answers `remade:true`. Setup then marks step 3 not done and shows, on the codes step, a fixed note telling the owner to delete the old agentOS entry in the phone's code generator and add the new one. The note stays until step 3 completes again. A confirm whose provision set the flag redirects to `/setup` instead of showing the 500 retry page, and the card display keeps the card for a retry.
4. **The page's `BoxConfig`.** `localui.CardBox` builds `firstboot.BoxConfig` from an `UnlockClient`, the claim store, the latch store and `CodesVoid`. `Reset` is `ResetCard`; `Card.Provision` is `ProvisionCard` on a background context with a 2-minute limit, as in L38. `cmd/agentos-localui` calls `firstboot.Begin` with it. It never calls `NewCardStep`. `fb.Claim`, when not nil, becomes `Config.Claim`, and `fb.Card` becomes `Config.Card` and the card of `CardFinish`, which wraps the page's `AgentosdSetup`. The claim store is `change.FileStore` at `-claim-state` (default `claim.StatePath`), and the latch is a `change.FileStore` at `-card-latch`. Without `-vault-sock` the page has no card step and setup cannot finish (fail closed, as today).
5. **The shared hold.** `CardFinish.Finish` reports `page_setup_card{confirmed:true}` when `Card.Hold()` is nil, then finishes. A refused report stops the finish. In agentosd, setup mode's `Card` is the page's hold. `page_setup_card` latches it for the process, and finish answers `card pending` until then.
6. **The bounded claim.** `/claim` posts take a slot in a queue of 4 waiting derivations and then run one at a time. A post that finds the queue full gets 503 "I am busy checking codes. Try again in a moment.", and so does a post whose context ends while it waits. `Claim` is never called for a request whose context is done. K9's residual says so.
7. **The restart note.** The card step says that a card printed or saved before the box restarted is void, and that only the card shown now counts (LATER CTRL-card l2).

## Acceptance tests

1. Egress: `/card/provision` on a vault whose code generator is unconfirmed answers 412 with `reason` `codes_unconfirmed`. A 412 for a vault with no setup-open entry carries no reason.
2. `UnlockClient`:
   - `ProvisionCard` sends the card's seven fields and returns nil on `{"ok":true}`;
   - a 412 with the reason gives an error that is `ErrCodesUnconfirmed` and wraps the 412 `VaultError`;
   - `ResetCard` returns `remade` from the reply.
3. Routing: after `CodesVoid` is set by either answer, the next `/setup` is the codes step with the replace note, and step 3 completes again with a new code. The confirm whose provision set the flag answers 303 to `/setup`, and the same card confirms after step 3.
4. The shared hold, in agentosd: finish answers `card pending` before `page_setup_card` and finishes after it. In the page: `CardFinish.Finish` with a held card sends no report, and agentosd refuses the finish; with a confirmed card it reports and then finishes.
5. `Begin` in the page's wiring:
   - with a claim state sealed the way agentos-seller seals it (`claim.Seal` into a `change.FileStore` file), the route is claim and the page's `Config.Claim` gates `/setup`;
   - with no claim state and a preloaded latch, the route is reinstall and the page shows the reinstall text;
   - with neither, the route is download.
6. The flood:
   - 32 concurrent posts against a claim that blocks call `Claim` at most 5 times (one running, four waiting) and answer 503 to the rest;
   - a post whose context is already done never calls `Claim`;
   - a post whose context ends while it waits answers 503 and never calls `Claim`.
7. The card step's page carries the restart note, and the codes step's replace note passes `modem.Segments` as GSM-7.
8. `TestAgentosdLinksNoClaimOrCard` and `TestThePageLinksNoneOfAgentosd` pass unchanged.

Run tests with `-race`.

## Out of scope

The page unit's file access to the claim state and the latch: the unit has `TemporaryFileSystem=/var/lib/agentos:ro` and runs as `agentos-localui`, while the seller writes the claim state as root (seller A2). Giving the page those files belongs to the image package, since the image does not ship the page yet (I13). It is a release finding of this PR. Also out of scope: the access point's switch to the card network (#1185), and the vault refusing finish's seal without a provisioned card.

## Estimate

About 120k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
