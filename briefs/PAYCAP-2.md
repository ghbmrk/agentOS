# PAYCAP-2: An optional Link agent-wallet payment adapter

Board section: Outside-the-box limits (2026-10-10).

**Why.** Mark asked (Questions thread, 2026-10-10) how to use Stripe's Link agent wallet as it is today and be ready to upgrade when Stripe ships spending limits, and chose "Add now" on the card "Add a Link wallet adapter to the payment card work?". PAYCAP-1 gives the box one bank-limited card. This row lets that card be paid out through Link, so each purchase is approved by the owner in Link and the bank limit still stacks underneath.

**Source.** Stripe, Link agent wallet: https://docs.stripe.com/agentic-commerce/agents/link-agent-wallet. Treat the page as the reference, and re-read it at Step 0: the product is new and its terms move.

**Step 0 (the builder checks these before any code; if any fails, stop and write the finding on the PR, no adapter is built).**
1. Is the agent API open to self-hosted apps like the box, or only to registered platforms?
2. Which regions does it cover, and does it cover the owner's?
3. Which merchants accept it? Estimate against the purchases the box's recipes make.
4. Does Stripe now ship owner-set limits? If so, the "Later" section below is live: build it in the same pass.

**What.**
- **Connect.** Link is connected just-in-time at the first purchase (SPEC setup step 8 style; ONB-3 unchanged). The box texts a "Connect Link" link, the owner signs in once on their phone, and the PAYCAP-1 bank-limited card is set in Link as its funding source, so both limits stack. Card details are entered only on Link's page or the Wi-Fi page, never by text (CH-6).
- **Per purchase.** The adapter files one Link spend request scoped to one merchant, one amount and a time window. Link returns a one-time card, which the adapter uses once and discards. Prefer this over shared payment tokens: more merchants accept a card. The broker still applies its own checks (OP-8, CH-10, ADP-9) before filing the request; the adapter is a payment method, not a way around them.
- **Approval is a state**, not a flow: `pending`, `approved`, `declined`, `expired`. Only `approved` releases the one-time card. Waiting for the owner is one state among four.
- **One tap.** The Link approval is meant to stand in for the box's own approval so the owner taps once (OWN-8, SPEC.md:58). Until Mark approves a spec-diff (Open question), the box's CH-10 approval is still required and Link's tap is additional.
- **Failures are digest lines** (CH-15, OP-9 wording rules), never prompts: a decline, an expiry, or a Link outage each yield one line saying what happened and what would fix it. The fallback offered in that line is a checkout link the owner can pay on their phone. No retry loops.
- **Decline wording.** The box cannot verify the bank limit the owner typed in PAYCAP-1, and a decline reason depends on what the card network returns. When the box cannot tell a limit decline from any other decline, the line says only "the payment was declined" and names the likely causes (the bank limit, the card, the merchant), never asserting that the limit was reached.
- **"My own card".** PAYCAP-1 lets the owner skip the outside limit ("my own card", "no limit outside the box"). That conflicts with its proposed MUST. This adapter inherits whichever choice the PAYCAP-1 spec-diff makes; with the uncapped option, the connect page shows the same one-line "no limit outside the box" notice.

**Later (when Stripe ships limits).** The owner sets a limit once in the Link app. Under it, the spend request is approved instantly (`pending` skipped); over it, the same tap as today. The box's own amount limit stays at or below the Link limit so the box never asks for something Link will refuse. Because approval is already a state, no new flow is needed. The builder re-reads Stripe's page at Step 0 to catch the launch.

**Open question for Mark (a later spec-diff PR he approves; SPEC.md is not edited here).** Can a Link approval stand in for the CH-10 high-risk owner code (SPEC.md:209-210), so the owner taps once? The code is meant to resist SIM swap and agent self-approval; the spec-diff must show Link's approval keeps that property (it is a signed-in session on the owner's device, not the agent's channel) or keep the code.

**Needs:** PAYCAP-1 (the card Link draws on). Nothing builds until Step 0 passes.

**Tier for the build: A.** The adapter handles payment credentials the broker holds (CRED-1) beside CH-10 and OP-8. A docs-only slice is B or C.

**Failure path to test first:** Link returns `declined` (and separately `expired`, and an outage) with the broker's own spend checks mocked as passing; each shows as one digest line, the box takes no further action, and no one-time card is used.

**Scope:** to be set when the brief is expanded.

**Gate:** Security lens first (the one-time card never reaches the guest or logs; the adapter holds no credential that can raise limits or mint cards beyond a per-purchase spend request; CH-6 holds).
