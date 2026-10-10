# Lanes

Live record of which team owns which paths, and each team's onboarding. The rules for parallel teams are docs/OPERATING.md §7; this file is the state they act on.

Mark's two Claude subscriptions are equal peers (2026-10-10): neither is primary, and there is no lane restriction between them. Either builds any row, reviews and merges under the same rules (OPERATING §7). A lane below binds only a team that is not one of those two subscriptions.

## Lanes

| Lane | Team | Paths |
|---|---|---|
| none | Mark's two Claude subscriptions (peers) | all paths |

A lane is added by an onboarding PR for each other team (another vendor's agent, a teammate). The claude2 lane of 2026-10-07 (broker/browser, broker/desktop, broker/adopt, spikes/S5-browser-actions, rows CRED-4b, ADP-5, ADP-8) is lifted: those paths and rows are open to either subscription, with claims on BOARD.md as usual.

## Onboarding: claude2 (2026-10-07, historical; lane lifted 2026-10-10)

- **Rows:** CRED-4b (credentialed browser executor; unblocked on the S5 fixture suite), ADP-8 (adapter mismatch check; unblocked), ADP-5 (desktop-app executor; blocked on CRED-4b). These rows are pre-assigned to claude2 on BOARD.md, so no claim PR is needed for them; set a row to `building` in the first PR for it. Every other row needs a claim.
- **Start with** CRED-4b or ADP-8. Both are release-critical for A13 (LATER.md).
- **Interfaces you may call, not change:** `broker/vault` (sessions are held by the vault process, CRED-4), `broker/verb` (fixed verb list), `broker/journal`, `broker/egress`, `broker/grants`, `broker/change` (the change pipeline, for ADP-8's agent-drafted adapters), `broker/modelroute`. A change any of them needs goes as a PR or a `lane:primary` issue.
- **Tiers:** the browser and desktop executors hold credentials and gate effects, so they are tier A. The PR that creates `broker/browser/` or `broker/desktop/` adds that name to `TIER_A_BROKER` in `tools/risk_tier.py`; that one edit is inside your lane.
- **Access:** your session needs its own linked GitHub account. Work from a fork of the repo (it is public) and open PRs from the fork; never use another team's login.
