# Hand-off: resume from here

Read this first, on either subscription (both are equal peers, OPERATING §7; D-099). GitHub is the live handoff; this file is the durable map, plus one dated snapshot (§3) that GitHub overrides wherever they differ. Read order: README.md role list, this file, then only the PR or brief you act on.

## 1. Rebuild in-flight state from GitHub alone
1. List open PRs (`list_pull_requests`, state open, newest first). Titles carry the package ID; drafts are reference only.
2. For each PR you may act on, read its latest verdict comment. Every verdict comment ends with the PR's next step and the reviews still owed (OPERATING §4, §5, §7), so that line says what happens next without any chat history.
3. Read the PR's check runs on the current head: green CI plus all required reviews accepting that head means the last-accept session has armed the merge; a coordinator merges only a PR left unarmed.
4. Read BOARD.md rows for state and owner; a row `building` with an owner belongs to that team (OPERATING §7).
5. Read `briefs/SIM.md` for the plan and wave order, and DECISIONS.md for anything newer than the list below.
6. Verify before acting: any thread or status label can be stale.

## 2. Standing decisions and rules
- **D-095** Simplification: the journal is the only durable state, owner messages are intents, one revisable outcome, forget once, a named trusted core. Plan and packages: `briefs/SIM.md`.
- **D-096** Includes SPEC one log (SIM-sd) and the scope freeze and PR cap (off-gate scope frozen until G2 passes; open PRs capped at about 10 per lane; the cap was replaced by the scope-overlap conflict guard in D-111).
- **D-097** Pull-first (STATUS is the primary owner view, only urgent classes pushed, daily digest removed) and key erasure.
- **D-099** Both subscriptions are equal peers; no main one, no lane restriction between them.
- **D-118** G1 freeze: no new builder starts on a non-G1 row; in-flight PRs and started builders finish; lifts when G1-e2e (#1688) passes in QEMU. G1 path is A1 (D-104) per row #1687; the package list awaits Mark's approval.
- The session posting the last required accept arms the merge (head = accepted head, CI green, OPERATING §7; D-120); PRs matching `tools/premerge.py --needs-mark` merge only on Mark's own approval of that PR at its head, cited on the PR (D-125). Asks to Mark are cards, never typed phrases.
- **D-121** Speed rules (OPERATING §5): run CI's exact commands (and a `-count=N` stress run on new concurrency tests) before a PR or verdict; briefs pre-approve their guard files (`tools/risk_tier.py` class, `broker/daemon/arc2_test.go` allowlist, `tools/g1_scope.txt`); readiness reads the code; one push per round; on the G1 critical path stack on a review-accepted interface and run disjoint packages in parallel; tier-A builders on Opus, B/C on Sonnet, no model switch mid-session; fix a flake the second time. Tier A keeps two reviews (Security; Potency/UX/L3).
- **D-122** Phone custody (#1843): an app login on a box-owned dedicated phone is broker custody only if the phone has no SIM, is not on the owner's number, every commit tap is gated by the approval tiers, and it is never the approval phone (CH-4).
- Chat layout: standing threads Decisions, Questions, PR updates, Alerts; finished threads are resolved at once. Project memory may be off, so durable state lives in the repo.

## 3. Snapshot, 2026-10-15 21:20Z
Verify each line against GitHub before acting (§1 step 6).
- **Merged:** #1870 CI sharding (CI-SHARD), 20:35Z.
- **#1864** (#1314 CAP-11-plan, provider-agent route): Security and Potency/UX/L3 delta reviews accepted 66244bc; head is now ec5e481 (a merge of main) and auto-merge is armed.
- **#1865** (#1714 G1-e2e-phone, phone control): Potency/UX/L3 delta accepted e965d1e; the Security delta at e965d1e asks for one blocking change, so it is in a fix round.
- **#1867** (#1701 G1-e2e-ai part 1): in its fix round after the Security and Potency/UX/L3 reviews of d01549f.
- **Guest-task critical path, in order:** #1864 → #809 qualification plus ImageVersion (#1877) → #1264 c4e2 plan sign-in → #1856 widened quota verb → #1701 remainder.
- **Open follow-ups:** #1875 (CI-SHARD-fu), #1876 to #1882 (CAP-11-plan-fu1 to fu7; #1882 is the `modelroute` flake), #1883 (G1-e2e-phonectl-fu1).

Edit sections 1 and 2 only when a standing decision changes; replace the snapshot whole, never per batch. Where DECISIONS.md and this list differ, DECISIONS.md wins.
