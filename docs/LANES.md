# Lanes

Live record of which team owns which paths, and each team's onboarding. The rules for parallel teams are docs/OPERATING.md §7; this file is the state they act on.

Mark's two Claude subscriptions are equal peers (2026-10-10): neither is primary, and there is no lane restriction between them. Either builds any row, reviews and merges under the same rules (OPERATING §7). A lane below binds only a team that is not one of those two subscriptions.

## Lanes

| Lane | Team | Label | Prefix | Paths |
|---|---|---|---|---|
| none | peers (Mark's two Claude subscriptions, D-099) | none | none (`D-NNN`) | all paths |
| codex | codex (OpenAI Codex CLI on Mark's ChatGPT plan, D-110) | `lane:codex` | `CX-` rows, `D-codex-NNN` | tier-C hygiene only: work-item issue titles and labels; product-name text edits in prose, comments and docs; and fixes a CX row names to the board tooling outside `.github/` (`tools/board.py`, `tools/metrics.py`, `tools/doclint.py` and their tests); never a change that `python3 tools/risk_tier.py` rates A or B, so the board.yml workflow file stays out |

A lane is added by an onboarding PR for each other team (another vendor's agent, a teammate). The claude2 lane of 2026-10-07 (broker/browser, broker/desktop, broker/adopt, spikes/S5-browser-actions, rows CRED-4b, ADP-5, ADP-8) is lifted: those paths and rows are open to either subscription, with claims on BOARD.md as usual.

## Onboarding: claude2 (2026-10-07, historical; lane lifted 2026-10-10)

- **Rows:** CRED-4b (credentialed browser executor; unblocked on the S5 fixture suite), ADP-8 (adapter mismatch check; unblocked), ADP-5 (desktop-app executor; blocked on CRED-4b). These rows are pre-assigned to claude2 on BOARD.md, so no claim PR is needed for them; set a row to `building` in the first PR for it. Every other row needs a claim.
- **Start with** CRED-4b or ADP-8. Both are release-critical for A13 (their issues are labelled `class:release`).
- **Interfaces you may call, not change:** `broker/vault` (sessions are held by the vault process, CRED-4), `broker/verb` (fixed verb list), `broker/journal`, `broker/egress`, `broker/grants`, `broker/change` (the change pipeline, for ADP-8's agent-drafted adapters), `broker/modelroute`. A change any of them needs goes as a PR or a `lane:primary` issue.
- **Tiers:** the browser and desktop executors hold credentials and gate effects, so they are tier A. The PR that creates `broker/browser/` or `broker/desktop/` adds that name to `TIER_A_BROKER` in `tools/risk_tier.py`; that one edit is inside your lane.
- **Access:** your project uses Mark's GitHub login; push branches with your `pkg/claude2-…` stem to the repo (no fork). Main's ruleset holds you to the same gates as everyone. Merging is covered in OPERATING §7.

## Onboarding: codex (2026-10-13)

Mark approved a Codex lane for tier-C hygiene in the project's Questions thread, 2026-10-13 14:04:06Z ("Tier c hygiene works; give me the prompt"; D-110). AGENTS.md is Codex's entry point.

- **Rows:** CX-board-render (#1260: `board.py render --repo` and the board.yml workflow fail), CX-issue-states (#1261: work-item state labels that disagree with merged PRs and closed items), CX-name-case (#1262: product text "AgentOS" becomes "agentOS"). All three are queued, labelled `lane:codex` and pre-assigned to codex, so no claim PR is needed for them; set a row's issue to `state:building` before its first PR. Each issue's body is that row's brief (there is no `briefs/CX-*.md`). The CX rows appear in BOARD.md only after CX-board-render lands, so until then work from the issues directly (`gh api 'repos/ghbmrk/agentOS/issues?labels=lane:codex'`). Every other row needs a claim, and only tier-C rows fit this lane.
- **Start with** CX-board-render: while the board cannot render, BOARD.md does not follow the state labels CX-issue-states fixes.
- **Paths:** a PR in this lane must print tier C from `python3 tools/risk_tier.py --git origin/main HEAD`. CI enforces this (CTRL-lane-gate): the `lane-gate` check (`.github/workflows/lane-gate.yml`, run from the base commit on `pull_request_target`) fails a PR whose head branch starts `pkg/codex-` or whose title starts `CX-` unless the base commit's `risk_tier.py` rates its diff C. If it prints A or B, drop the files that raise it and send them to the peers as a `lane:primary` issue; that covers code identifiers, `broker/`, `guest/`, `image/` outside its top-level `*.md`, `.github/` (so board.yml's workflow file itself) and the tier-A tools. SPEC.md is tier B, but Mark approved its "AgentOS" to "agentOS" wording on 2026-10-13 13:31Z ("Minor but agentOS should not have the A capitalized"); a PR carrying that change takes SPEC.md's tier and goes to the peers.
- **Interfaces you may call, not change:** everything under `broker/`. Work-item issues are edited through the GitHub REST API (`gh api`). The board tooling (`tools/board.py`, `tools/metrics.py`, `tools/doclint.py` and their tests) is in the lane only for the fixes a CX row names, and only while `risk_tier.py` rates the change C; `.github/workflows/board.yml` and every other file under `.github/` rate A, so a change they need goes to the peers as a `lane:primary` issue.
- **Open PRs:** at most 3 at a time in this lane (a lane limit; there is no general cap, D-111). The CX-name-case batches are 30 files or fewer each and skip files touched by any open PR.
- **CODEX-1 drafts:** the open CODEX-1 drafts of 2026-10-07/08 (#255-#265, #273, #345, #346, #447) are a parts bin outside this lane: leave them alone; they do not count toward the 3-PR cap.
- **Reviews and merges:** each PR gets a fresh L3 review in a new session before it is marked ready, and merges through `tools/premerge.py` on an L3 accept and green CI (OPERATING §7; tier C has no lens screen). A PR that changes any `tools/*.py` file also needs a fresh Claude L3 accept on its current head (a new Claude Code session from either peer subscription) before `tools/premerge.py`, even when the change to that file is only comments or strings; a Codex L3 alone does not suffice. Every other PR keeps the rule above (Mark, 2026-10-13 16:46Z, Questions thread; CTRL-lane-gate).
- **Access:** push branches with the `pkg/codex-…` stem to the repo (no fork). Main's ruleset holds you to the same gates as everyone. Decisions go in the codex section of DECISIONS.md as `D-codex-NNN`; new rows are `work-item` issues with `CX-` IDs.
