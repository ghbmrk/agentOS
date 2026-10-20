# Hand-off: resume from here

Read this first, on either subscription (both are equal peers, OPERATING §7; D-099). GitHub is the live handoff; this file is the durable map, plus one dated snapshot (§3) that GitHub overrides wherever they differ. Read order: README.md role list, this file, then only the PR or brief you act on.

## 1. Rebuild in-flight state from GitHub alone
1. List open PRs (`list_pull_requests`, state open, newest first). Titles carry the package ID; drafts are reference only.
2. For each PR you may act on, read its latest verdict comment. Every verdict comment ends with the PR's next step and the reviews still owed (OPERATING §4, §5, §7), so that line says what happens next without any chat history.
3. Read the PR's check runs on the current head: green CI plus all required reviews accepting that head means the last-accept session has armed the merge; a coordinator merges only a PR left unarmed.
4. Read BOARD.md rows for state and owner; a row `building` with an owner belongs to that team (OPERATING §7).
5. Read DECISIONS.md for anything newer than the list below; D-139 sets the migration plan and docs/migration/cases.md holds the cases it carries.
6. Verify before acting: any thread or status label can be stale.

## 2. Standing decisions and rules
- **D-139** Capability kernel freeze (supersedes D-095): the trusted core is rebuilt around signed, narrowable capability keys, one holder as the only exit and one append-only log. Steps: 0 freeze and cases, 1 one spec PR, 2 kernel, 3 first slice "Sort my inbox and unsubscribe from and delete the spam" (the only writes are reversible labels and archive, trash, and an RFC 8058 one-click unsubscribe for DKIM-passing bulk senders through the clerk and the hold window; permanent delete forbidden; spam is trashed, never unsubscribed; body links never followed; QEMU and a synthetic mailbox), 4 ports by directory that delete what they replace, 5 delete the old core. No new build starts on the old core (journal, grants, vault, recall, recalltool, egress, holder, checker, projection, replay, durable, sim and their agentosd wiring); its cases are in docs/migration/cases.md.
- **D-096** Includes SPEC one log (SIM-sd) and the scope freeze and PR cap (off-gate scope frozen until G2 passes; open PRs capped at about 10 per lane; the cap was replaced by the scope-overlap conflict guard in D-111).
- **D-097** Pull-first (STATUS is the primary owner view, only urgent classes pushed, daily digest removed) and key erasure.
- **D-099** Both subscriptions are equal peers; no main one, no lane restriction between them, except during the D-139 migration until the old core is deleted (§3).
- **D-128** G1 proven (run 39042850372); the G1 freeze (D-118) is off and the G2 freeze is on: until A4, A5, A9 and A14 pass on a VM, PRs touch only `tools/g1_scope_g2.txt` paths (the `g1-freeze` check runs every gate list). D-098 rows stay frozen.
- The session posting the last required accept arms the merge (head = accepted head, CI green, OPERATING §7; D-120); PRs matching `tools/premerge.py --needs-mark` also need a separate Security accept at an equal head, and no PR waits for Mark's line (D-137). Asks to Mark are cards, never typed phrases.
- **D-121** Speed rules (OPERATING §5): run CI's exact commands (and a `-count=N` stress run on new concurrency tests) before a PR or verdict; briefs pre-approve their guard files (`tools/risk_tier.py` class, `broker/daemon/arc2_test.go` allowlist, `tools/g1_scope.txt`); readiness reads the code; one push per round; on the G1 critical path stack on a review-accepted interface and run disjoint packages in parallel; tier-A builders on Opus, B/C on Sonnet, no model switch mid-session; fix a flake the second time. Tier A keeps two reviews (Security; Potency/UX/L3).
- **D-122** Phone custody (#1843): an app login on a box-owned dedicated phone is broker custody only if the phone has no SIM, is not on the owner's number, every commit tap is gated by the approval tiers, and it is never the approval phone (CH-4).
- Chat layout: standing threads Decisions, Questions, PR updates, Alerts; finished threads are resolved at once. Project memory may be off, so durable state lives in the repo.

## 3. Snapshot, 2026-10-20 11:40Z (migration step 1 done)
- Merged: freeze #2522 (docs/migration/cases.md) and spec #2523 (SPEC v1.0, merge d49cffd80eff). Old-core PRs #2513, #2519, #2499 closed.
- In progress: BOARD cleanup #2524 (its thread owns BOARD.md; it closes the issues the design supersedes and re-sections the rest), then kernel #2525 (step 2).
- The 165 harvested issues stay open until #2518 merges with its issue-close lines; then the freeze thread closes them.
- Until step 4: sub A runs BOARD cleanup, kernel, first slice. Sub B runs only eval set #2527 (evals/slice-inbox/) and hardware (#935, #936, M6 chain); off limits: old-core broker/, the kernel, SPEC/PLAN/BOARD/LANES/OPERATING.
- Kept: STOP/RESUME fixes (#2521, #2535 merged), CI flake fixes, Codex lane; #2292 parked.

### Owed first
1. Merge #2518, then close the 165.
2. Finish #2524, then build #2525.
3. Sub B: #2527 and hardware.

Edit sections 1 and 2 only when a standing decision changes; replace the snapshot whole, never per batch. Where DECISIONS.md and this list differ, DECISIONS.md wins.
