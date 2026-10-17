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
- **D-128** G1 proven (run 39042850372); the G1 freeze (D-118) is off and the G2 freeze is on: until A4, A5, A9 and A14 pass on a VM, PRs touch only `tools/g1_scope_g2.txt` paths (the `g1-freeze` check runs every gate list). D-098 rows stay frozen.
- The session posting the last required accept arms the merge (head = accepted head, CI green, OPERATING §7; D-120); PRs matching `tools/premerge.py --needs-mark` merge only on Mark's own approval of that PR at its head, cited on the PR (D-125). Asks to Mark are cards, never typed phrases.
- **D-121** Speed rules (OPERATING §5): run CI's exact commands (and a `-count=N` stress run on new concurrency tests) before a PR or verdict; briefs pre-approve their guard files (`tools/risk_tier.py` class, `broker/daemon/arc2_test.go` allowlist, `tools/g1_scope.txt`); readiness reads the code; one push per round; on the G1 critical path stack on a review-accepted interface and run disjoint packages in parallel; tier-A builders on Opus, B/C on Sonnet, no model switch mid-session; fix a flake the second time. Tier A keeps two reviews (Security; Potency/UX/L3).
- **D-122** Phone custody (#1843): an app login on a box-owned dedicated phone is broker custody only if the phone has no SIM, is not on the owner's number, every commit tap is gated by the approval tiers, and it is never the approval phone (CH-4).
- Chat layout: standing threads Decisions, Questions, PR updates, Alerts; finished threads are resolved at once. Project memory may be off, so durable state lives in the repo.

## 3. Snapshot, 2026-10-17 22:20Z (coordinator handoff to another subscription)
GitHub overrides this wherever they differ (§1 step 6). Reason: Mark's subscription was at 98%, so the project moves to another one. A fresh coordinator reads this, the project instructions, docs/OPERATING.md, and the newest `dispatch/` file (2026-10-17-2200.md, which lives in the old project's shared folder and may not be visible here; rebuild from GitHub).

### Standing threads (chat-project ids do not carry over; recreate by role)
Decisions (every multiple-choice question for Mark becomes a card here), Decisions-merge (merges Mark-tapped Mark-only PRs), Questions, Alerts, PR updates, plus anchor posts for Builds and reviews, Cap code, Spec, Reviews. A new coordinator arms its own 60-minute backstop with the prompt "Hourly work-flow check" (the old one was tied to the old coordinator session).

### Open card
Merge-queue route: Mergify (recommended) / Move to org / Home-built / Up to date. #2292 is paused until Mark taps. Mark asked whether Mergify is a dependency (yes: an outside app with write access) and how big the two-green-PR issue is. Answer: real but not urgent. 29 of main's last 100 CI runs failed, mostly alternating, so likely flakes; the confirmed case is the vet break #2263 fixes. Suggested measuring first with auto-revert plus logging.

### Blocked on a typed line from Mark (card taps are refused by the permission check)
- **#2307** photo store: add three `allow photo/keep` lines to `broker/core/core.txt` (journal.Engine Authorize, Dispatch, Erase) per https://github.com/ghbmrk/agentOS/pull/2307#issuecomment-6241987879. Tap approved 22:12:03Z; head 27a797e. Then combined and Security deltas, then a Merge card.
- **#2319** G2 freeze exemption: add `exempt-pr 2319` to `tools/g1_scope_g2.txt` (refused as "CI Bypass"). Tap approved 22:18:51Z. That PR is Mark-only: Merge card, then edit #2319's body to re-run `g1-freeze`; #2319 then arms with no new review.
- The Alerts thread was asked to request one typed line covering both; relay Mark's typed message to both builders.

### Reviews running
- #2324 CI flake fix (tier A; also filed #2323, skipped broker jobs report green, needs `.github/` so Mark).
- #2326 forget reach tests (tier A): Security accepted at e30a7d3; combined review pending.
- #2327 memory-budget admission, cleanroom and loopbuild (tier A).
- #2304 Security delta.

### Builds running
- UX3-1 provider sign-in (#991, tier A) and its PR #2329.
- SPEC-residue #2325 (tier B, Mark-only spec): delta accepted at f4fd185; Merge card when CI is green. Follow-up owed: retire or re-home HW-8a markers in tier-A broker/hostdisk tests (trace.py flags it), Mark's call.
- #2266: conflict resolved, head 42a2a12, premerge `same`, no delta; green, Merge card.

### Accepted, awaiting CI or arming
#2293, #2295, #2298, #2301, #2302, #2305, #2316, #2230. #2294 accepted by both at a228a90 (Security arms). #2308 at 3ba2b29 (Security arms). The post-hotfix sweep armed #2255 #2258 #2262 #2265 #2267 #2273 #2228 #2304; #2276 merged.

### Mark-only, Merge card when green
#2309 (accepts at e79ff92; waits on #2263 fixing main's reaction_test.go:314, the builder merges main and reports the head), #2289 (risk_tier fix, accepted d24fb26, waits on the main fix), #2285 (INFER-SVC part 1, delta combined review running), #2257 (head 1b57e95b, CI parallelism), #2266, #2307, #2325, and the #2319 exemption PR. Still open from an earlier Decisions thread: Merge #2234 at feeab4c, and the D-098 freeze exemption for the two frozen cap changes.

### Gated
- #2275 provagent pool-cap removal after #2308 and #2309.
- egress DefaultMaxConcurrent removal after #2294.
- #2147 after #2146 and #2307.
- #788 after #2265 and #791.
- DIG-RM-a after #2265.
- #2250 routing half and #2254 after #2262.
- #2240 after #2257.
- JRN s3 after #2285.
- Issues #1526 and #1608 can be closed as done on main (PRs #2074, #2241).
- Nine drafts #2048 to #2070 cross 24h idle about 00:35Z.

### Decided tonight (Mark's taps)
- No arbitrary caps ("No cap", "All three"): concurrency bounded only by real capacity; API routes keep a money cap.
- D-098 Exempt (21:11Z) and Widen (21:39Z): clean-room 4-call limit widened via memory-budget admission in broker/cleanroom with tier A reviews.
- #2307 photo store: approve the three `allow photo/keep` core.txt lines (22:12Z); lines only, a Merge card is still owed after delta reviews.
- #2319: exempt from the G2 freeze (22:18Z); the one-line exemption PR needs Mark's Merge card, then #2319 merges unchanged.
- #2291 spec merged (c5682b3). #2263 hotfix merged (aab406b). #2274, #2314, #1878 closed.
- Models: tier A builds and reviews claude-opus-5-5; tier B/C builds claude-sonnet-5-5.

### Decision-card rules (for whoever runs Decisions)
Never merge or approve; cards only, never ask Mark to type. A Merge card only when CI is green on the head, `python3 tools/premerge.py --base origin/main <accepted_sha> <head>` prints `same`, and every required review accepted that head; check `--needs-mark --base origin/main <head>` yourself. No duplicate cards (check earlier cards and taps; approvals carry forward except D-125 per-head Merge taps). Relay every Merge tap to the merging thread and the coordinator.

### Owed first on the new subscription
1. #2329 provider sign-in "Get a new code" (UX3-1, tier A, premerge `agent`): the combined L3 and Security reviews were held; start them first. Release finding #2328 filed.
2. #2326 combined review.
3. Questions: a measured package splitting CLAUDE.md role rules into skills was recommended; Mark has not decided.

Edit sections 1 and 2 only when a standing decision changes; replace the snapshot whole, never per batch. Where DECISIONS.md and this list differ, DECISIONS.md wins.
