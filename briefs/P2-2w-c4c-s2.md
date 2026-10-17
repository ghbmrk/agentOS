# P2-2w c4c s2: setup sends nothing to a wrong PAIR code

Board section: Backlog refill (2026-10-05); work item #1290. Release finding on P2-2w c4c (Security 4a on PR #1269). Serves A1 (§8.1 pairing) and CH-12. Tier: A (localui pairing and localapi's setup texts parse and answer owner-channel input). Builder: strongest model. Usage estimate: 60k tokens. **Needs:** P2-2w c4c (merged); before any A1 run.

**Why.** Before setup has an owner, anyone who knows the box's number can text it. `Server.OfferText` (`broker/localui/setup.go`) answers a `PAIR` text with a wrong code with "That pairing code did not match. Check the setup page.", and `AgentosdSetup.PairTexts` (`broker/localui/setuphooks.go`) texts that reply, twice if the first fails, to the sender. The sender is unverified (From can be spoofed), so a stranger can point up to 10 replies an hour (`PairTriesPerHour`) at any third party, and each one comes out of setup's shared cap of 20 sends an hour (`localapi.SetupTextsPerHour`, counted in `localsrv`), which the owner's number step and paired texts also draw on.

**Route (decided here).** A wrong code gets no reply, and agentosd no longer allows that text at all. Rejected: a per-sender reply budget (From is spoofable, so a per-sender budget is a per-guess budget; it still reflects texts at third parties and still spends the SIM). The owner who mistypes a code loses a "did not match" text; the page keeps showing the pairing step with its code, which is where the owner checks it, so the text carried nothing the page does not.

**Residual (accepted).** The 10-an-hour wrong-code cap still closes pairing by text for the hour, for everyone, so a stranger can keep that one path closed. The cap stays: it is what keeps the card's 40-bit setup code from being guessed by text, and From is spoofable, so no per-sender split keeps that bound. The typing fallback (ONB-6: the owner types their number, the box texts a 6-digit code to it) does not use the cap, so setup's step 2 still passes; s2-3 pins that.

## Requirements

- **P2-2w-c4c-s2-1** (CH-12, §8.1) A `PAIR` text whose code matches neither a phone's one-time pairing code nor the card's setup code is handled with no reply: `OfferText` returns `""` and still counts the try towards `PairTriesPerHour`, and `PairTexts` sends nothing for it, so wrong codes spend none of setup's shared send budget and text no one.
- **P2-2w-c4c-s2-2** (CH-12) agentosd's allow-list (`localapi.SetupText`) no longer admits "That pairing code did not match. Check the setup page.", so `page_setup_send` refuses it even if the page asks.
- **P2-2w-c4c-s2-3** (ONB-6, A1) After `PairTriesPerHour` wrong `PAIR` texts, the number step's typing fallback still pairs the owner within the same hour (its code text goes out and its code is taken).
- **P2-2w-c4c-s2-4** (CH-12) `broker/localui/ASSUMPTIONS.md` records that a wrong code gets no reply, why (unverified sender, shared budget), and the accepted residual above.

**Acceptance tests:**
- P2-2w-c4c-s2-1 `broker/localui/setuptext_test.go::TestWrongPairCodesTextNoOne` (PairTexts over the real `localsrv` setup: `PairTriesPerHour-1` wrong `PAIR` texts from several numbers, then the card's code from the owner: the only text sent is the owner's paired reply; catches any reply to an unverified sender) and the updated `::TestPairTextsReachThePageAndAreAnswered` and `localui_test.go::TestPairingGuessesAreBounded` (a wrong code's reply is `""`, handled).
- P2-2w-c4c-s2-2 `broker/localapi/setup_test.go::TestSetupTextAllowsOnlySetupsFixedTexts` (the wrong-code text moves to the refused list).
- P2-2w-c4c-s2-3 `broker/localui/setuptext_test.go::TestTheTypedNumberPairsAfterTheWrongCodeCap` (cap reached by text, then `/setup/number` and `/setup/number-code` pair the owner in the same hour).
- P2-2w-c4c-s2-4 none: ASSUMPTIONS text, checked by the reviewer.

## Acceptance

The tests above (REQ-marked), `go vet` and `go test -race ./localui/... ./localapi/... ./localsrv/...`; CI green. Tier-A L3 with a threat check: no path left where a text from an unverified sender makes the box send a text other than the paired reply, and the cap still bounds guesses of the card's setup code.

**Guard files:** none

## Scope

`broker/localui/setup.go` (`OfferText` only), `broker/localui/setuptext_test.go`, `broker/localui/localui_test.go`, `broker/localui/ASSUMPTIONS.md` (one row), `broker/localapi/setup.go` (`setupTexts` only), `broker/localapi/setup_test.go`, `broker/localsrv/setup_test.go` (its closed-setup check sends that text; use another allowed one), `briefs/P2-2w-c4c-s2.md`. Not `broker/localui/setuphooks.go` (no change needed: an empty reply already sends nothing), nor `broker/cmd/agentosd/` (sibling c4c r1, PR #2125, owns setup's agentosd side).

**Sequencing (D-111).** No open PR touches these files at the start (checked against the open-PR file lists, 2026-10-17).

## Out of scope

A second pairing-by-text path that survives the cap (residual above); retrying a failed paired reply (c4c l2); the send-failure text's cause (c4c l4).

## Estimate

About 60k tokens for one session. The figure is a checkpoint, not a cap (docs/OPERATING.md §5).
