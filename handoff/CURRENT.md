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

## 3. Snapshot, 2026-10-25 11:45Z (step 4 under way; for sub A on its return)
Sub A paused on 2026-10-22 (#2578, comments 6340104703 and 6340351358). This is what sub B (the other project) did and learned since then that lives only in its chat. The rest is on the issues and PRs linked here. Recheck each line against GitHub before acting on it.

**Lanes, from Mark in chat**
- On 2026-10-22, sub B took the step-4 untrusted ports and the rows sub A handed off. On 2026-10-23, Mark widened that to any sub A row that fits in one session (#2578, 6365422670).
- On 2026-10-25 at 11:14Z, Mark said sub A is back, and sub B keeps taking queued rows, sub A's included, unless they overlap ("you have usage they will be wasted if not used"; #2578, 6396935897). Each sub skips any row the other has claimed and any file scope an open PR touches (D-111). Kernel-lane rows (#2525) run one at a time across both subs. Claim with `state:building` plus a comment naming the branch. Every session posts as `ghbmrk`, so a label alone doesn't show which sub claimed a row; the claim comment does.

**Merged from sub A's rows since the pause** (details on each issue)
- STO-2 sealed store and keeper: #2905 (STO-2c), #2998 (restart), #3073 (rundir). Open follow-ups: #2995 and #2987.
- #2682: its start-up slice merged as #3072. The rest is queued and yours (hand-off comment 6394347971).
- Inbox: #2681, #2618, #2601, #2602, #2603 and #2604. Process: #2644, #2720 and #2697. Kernel: #2838 (KEY-spend-parent) and #2989 KEY-oracle-1. In #2989 Mark chose "Rust plus over time": the Rust checker and the formal model stay, and the Go reference model is retired.
- Deletes: #2575 (replay) and #2781 (forget). `cmd/agentosd` chain: #2783 a and b (#3077, #3080), 2784a (#3090) and #2778 (#3093).
- Decision rows: D-149 to D-161, read in DECISIONS.md. D-159 means trusted-core growth that builds an approved design needs no card, only full reviews and a cited decision.

**Taps not yet on main**
- Decisions card cmsg_01R91wiieBzMSvPKFsAJVvuKNMSJeYDwU83rpMEZjXrtfi, 11:36Z: "Yes, #3078 and #3079" (stop generation on RESUME, plus the RETRY line's first-tried time and currency). The D-162 row is PR #3106.
- Card cmsg_01R91wiieBzMSvPKFsAJVvuKFLtE8GpJc4B8mRNgH5rtFs: agentosd's plan-signing holder key lives in agentosd's root-only state dir. This is recorded on #3087 only.

**In flight at 11:45Z**
- Open PRs: #3100 (#3099 BOARD-debounce, a gate file), #3102 (#3095), #3105 (#3104 slice a) and #3106 (D-162).
- `state:building`: #3078, #3087, #3095, #3099 and #3104.
- The `cmd/agentosd` chain slot is free. #2779 is next, but it is blocked (below).

**Questions for sub A** (answer on the issue)
- #2779: three of its items need a passkey to sign, and `kernel/key` takes only raw `ed25519` keys. The proposed split puts a kernel-lane prerequisite first: an external-signer seam plus the WebAuthn verifier (comment of 11:19Z). Sub A's call, since it is the kernel lane.
- #935, piece 3: should the netjoin PSK hand-off reuse the #2682 clerk-main hand-off (recommended), or should the unlock step dial the helper itself? (Comment of 11:17Z.)
- #2780(b) waits on #3104 (the model clerk's plan login), not on #2779 (comment of 11:21Z).

**Process changes**
- Until #3100 merges, every issue event re-renders BOARD.md onto main, which leaves every open PR behind main (#3099).
- #3103: when L3 and Security post in parallel, each lists the other as owed, so neither arms. Until it is fixed, re-read the comments after posting an accept, and arm or merge if the set is complete. #3093 sat fully accepted for 4.5 hours this way.
- Sub B's coordinator rotated overnight, and its hourly backstop lapsed from 06:40Z to 11:13Z. A fresh coordinator re-arms the backstop on its first turn.

**Waiting on Mark, unverified from tools**
- The PREMERGE App settings steps after #3031 (briefs/PREMERGE-source.md). The forged-`premerge` hole stays open until they're done; the card was posted on 2026-10-24 at 20:21Z, with no reply seen.
- `count` and `vulncheck` added to main-checks (Mark tapped Done on 2026-10-23; rulesets can't be read from here).
- The Gmail test account (#1021) is not needed yet. The hardware is bought and on its way.

**Not approved: don't build**
- Local-first model routing waits on a capability benchmark against the plan routes (Mark, 2026-10-24 00:02Z). Private planning on a Mac Studio would need a SPEC change (HW-7, HW-11).
- These are proposals only: one case for all boards; a second-device confirm for high-value widenings; hardware-backdoor measures (chip-vendor diversity, the store key split across vendors); a flip phone plus two FIDO2 keys as root (compare D-146).

### Owed first
1. Sub A: answer #935 and settle the #2779 signer seam. Both gate the next `cmd/agentosd` chain rows.
2. Merge #3106, then build #3078 and #3079.
3. Build #3104 (slices a, b and c), then #2780(b).

Edit sections 1 and 2 only when a standing decision changes; replace the snapshot whole, never per batch. Where DECISIONS.md and this list differ, DECISIONS.md wins.
