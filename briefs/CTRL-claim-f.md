# CTRL-claim follow-ups: claim in the risk tiers, claim wired into first boot

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A for each row (tools/risk_tier.py, first boot).
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-10, HW-1
**Acceptance:** A1 (HW-10 acceptance 1, 2 and 3).
**Dependencies:** CTRL-claim merged (PR #1067 is open at the time of writing, head 2ee74c3, with blockers B1 and B2 still to fix).

## Finding

Found in PR #1067's tier A review (comment 6117951797, verdict fix-list). Release findings R1 to R4 make this one brief, with one BOARD row per independent change (OPERATING §2). R3 and R4 are conditions on R2's wiring, so they are folded into it. Checked against BOARD.md on 2026-10-12: no queued row covers any of them. CTRL-card-wire (CTRL-card-f.md) also edits agentosd's first boot.

**Sequencing.** CTRL-claim-tier and CTRL-claim-wire are sequenced, not built in parallel. CTRL-claim-wire also touches the same first-boot call site as CTRL-card-wire, so build one, merge it, then rebase the other. Build CTRL-claim-tier first: it is small, and it puts `broker/claim/` under the tier-A review the wiring needs.

## Row CTRL-claim-tier

Add `claim` to `TIER_A_BROKER` in `tools/risk_tier.py` and to the tier A list in OPERATING §3.

- Serves HW-10 acceptance 3 (the lockout and the one-claim rule).
- Failure path: a later edit to the lockout that touches only `broker/claim/` gets tier-B review, with no threat check or Security re-sign.
- Scope: `tools/risk_tier.py`, `tests/test_risk_tier.py`, `docs/OPERATING.md` §3 (one word in the list). Not SPEC.md.
- Tier: this touches `tools/risk_tier*`, so the PR itself is tier A.

Tests (mark with `REQ: HW-10`):
1. `risk_tier.py` classes a path under `broker/claim/` as tier A.
2. The OPERATING §3 tier A list and `TIER_A_BROKER` agree on `claim` (the existing list-agreement check, extended if it does not already cover it).

## Row CTRL-claim-wire

Wire `claim` into agentosd's first boot so a preloaded box starts at the claim screen, and the setup page is reachable only by the claimant.

- R2 failure path: setup runs unclaimed, so the first phone to reach the box sets it up with no sticker code (HW-10 acceptance 1 and 2 pass only in unit tests).
- Condition 1: mount the claim screen inside localui's server, behind its Host check and pairing check, never a separate listener. Decide, and test, which clients may reach `/claim` before the claim (the Wi-Fi admission question in #1067).
- **R3 (HW-10).** After three locks, each boot allows one wrong code. A client on the access point that posts a wrong code to `/claim` after every restart burns that code, and the owner holding the sticker cannot claim without reinstalling. Fix with a rule the owner can always beat, for example a per-boot floor that is not consumed by an unauthenticated client, or limiting who may reach `/claim`. Record the choice in the package ASSUMPTIONS.md. (L2 in the review: a fixed 5 tries per boot would also blunt this.)
- **R4 (HW-10 acceptance 1).** On a box that already holds first-boot or card state, `claim.ErrNoCode` must not route to the flasher or download path. Failure path: `claim.json` is deleted or lost after the claim, `Open` returns `ErrNoCode`, and a second phone pairs through the download path. A box with first-boot or card state and no claim code shows "already claimed, reinstall me" and nothing else.

Scope: `broker/cmd/agentosd/` (first-boot call site), `broker/firstboot/` and `broker/localui/` (claim routing and mount only), `broker/claim/` only if R3 needs a new option, tests, ASSUMPTIONS.md of each touched package.

Tests (mark with `REQ: HW-10, HW-1`):
1. Through agentosd's real setup path, an unclaimed preloaded box serves only the claim screen; `/setup` refuses a request without the claimant cookie.
2. A foreign `Host` header on `/claim` gets the Host-check refusal.
3. R3: three locks, restart, then a wrong code posted by a non-owner client; the right code still claims on that boot (or the unauthenticated path cannot reach the counter).
4. R4: first-boot or card state present, `claim.json` removed, restart: the box routes to "already claimed, reinstall me", never the download or pairing path, and a second phone cannot pair.
5. A box with no claim state and no first-boot or card state (a bare flasher install) still takes the download path (HW-10 acceptance 1 unchanged).

Synthetic canaries and generated codes only. Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Handoff and estimate

Initial checkpoints, each an estimate rather than a ceiling: CTRL-claim-tier 15k tokens, CTRL-claim-wire 60k. One package per session; run Go packages with race tests on Linux, a fresh strongest-model L3 with an explicit threat check, and the tier-A lens screen for each PR. L1 (a lost claiming phone before the card exists means a reinstall) and L2 stay in LATER.md as the review classed them.
