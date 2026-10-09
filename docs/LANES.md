# Lanes

Live record of which team owns which paths, and each team's onboarding. The rules for parallel teams are docs/OPERATING.md §7; this file is the state they act on. The primary team changes it in an onboarding PR.

## Lanes

| Lane | Team | Paths |
|---|---|---|
| executors and adoption (A13) | claude2 (Claude Code, second subscription) | `broker/browser/`, `broker/desktop/`, `broker/adopt/` (new packages), `spikes/S5-browser-actions/`, and only the BOARD.md rows CRED-4b, ADP-5, ADP-8 (and S5's live run if its network policy allows) |
| everything else | primary (Claude, Mark's subscription) | all other paths |

Rows are added by the onboarding PR for each new team; the primary team's lane shrinks to match.

## Onboarding: claude2 (2026-10-07)

- **Rows:** CRED-4b (credentialed browser executor; unblocked on the S5 fixture suite), ADP-8 (adapter mismatch check; unblocked), ADP-5 (desktop-app executor; blocked on CRED-4b). These rows are pre-assigned to claude2 on BOARD.md, so no claim PR is needed for them; set a row to `building` in the first PR for it. Every other row needs a claim.
- **Start with** CRED-4b or ADP-8. Both are release-critical for A13 (LATER.md).
- **Interfaces you may call, not change:** `broker/vault` (sessions are held by the vault process, CRED-4), `broker/verb` (fixed verb list), `broker/journal`, `broker/egress`, `broker/grants`, `broker/change` (the change pipeline, for ADP-8's agent-drafted adapters), `broker/modelroute`. A change any of them needs goes as a PR or a `lane:primary` issue.
- **Tiers:** the browser and desktop executors hold credentials and gate effects, so they are tier A. The PR that creates `broker/browser/` or `broker/desktop/` adds that name to `TIER_A_BROKER` in `tools/risk_tier.py`; that one edit is inside your lane.
- **Access:** your session needs its own linked GitHub account. Work from a fork of the repo (it is public) and open PRs from the fork; never use another team's login.
