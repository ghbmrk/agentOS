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

## 3. Snapshot, 2026-10-30 11:10Z (for sub B, starting fresh; sub A is out of thread starts)
Written by sub A (this project's Decisions thread) at Mark's request, so sub B can work at full parallel speed the moment its usage resets. GitHub overrides any line here that differs from it.

**Why sub B takes over starts.** Sub A's account used 500 of its 500 daily thread starts (each PR cost a builder plus about four review threads). Its threads already running continue, but it cannot start a new builder or reviewer until the count resets. Mark, 2026-10-29 and 2026-10-30: use all usage on work that isn't wasteful, ignore usage pacing, avoid conflicts and duplicates, and move to the other sub when one runs out. The temporary split, sub A on this repo and sub B on agentos-private, is off: sub B works here too and keeps agentos-private.

**Rules new since the 2026-10-25 snapshot** (DECISIONS.md is authoritative)
- **D-245 deletion first.** Among startable rows, start the ones that delete old-core code, and the rows that unblock them, before new features. The coordinator reports the old core's remaining lines (`tools/trace.py` old-core measures) to Mark weekly.
- **Review shape (Mark's tap 2026-10-30, wording PR pending, see below).** One review thread per PR: it runs L3 and spawns the UX/Potency lens screen as a fresh-context subagent that never sees L3's reasoning. Security stays its own fresh thread. Delta re-reviews take the same shape. Use it now.
- **UPD-7w (#3961), Mark's tap 2026-10-30.** #3468 deletes the change engine. UPD-5's local requalification is rebuilt as the very next row, and no stable release goes to an owner box until it is back (a ship gate).
- D-227 to D-244: second line deleted then rebuilt with keeper filters (D-238), OpenWrt One AP (D-228), one Apache-2.0 embedding model (D-230), enforcer with no language runtime (D-231), short-lived codes and erase tombstones (D-239), checker rebuilt as `broker/clerk/codecheck` (D-244).

**Who owns what, to stop today's collisions** (two D-244s; allowlist-file conflicts forced full re-reviews)
- **Decision IDs:** sub B numbers its new rows from **D-300** up and sub A continues from D-246, until the waste-sweep PR's automatic IDs land.
- **Process docs** (CLAUDE.md, AGENTS.md, PLAN.md, docs/OPERATING.md, docs/LANES.md, role skills): only the waste-sweep PR edits them until it merges (thread cmsg_01R91wiieBzMSvPKFsAJVvuKPLhCRLR3dg61qXtt7n6Siw). Sub B files process changes as issues meanwhile.
- **Rows:** claim with `state:building` plus a comment naming the branch and the sub, and never start a row whose files an open PR touches (D-111).

**Sub A threads still running (don't duplicate them)**
- #3974 (MIG-4-exit c2, codecheck): L3 plus the Potency subagent in cmsg_01R91wiieBzMSvPKFsAJVvuK5aZ8Udnq4egyzZ1p6kjaBF, Security in cmsg_01R91wiieBzMSvPKFsAJVvuK9hpTCZHXVK3unJfvyoK8V5. The UX accept carries over.
- #3971: all accepts are in, and its builder merges it on green.
- The UPD-5 requalification rebuild: PR #4033 from builder cmsg_01R91wiieBzMSvPKFsAJVvuK5TAT5R2Wi7aY1LczS1GghE (its reviews are sub B's step 1).
- The waste-sweep process PR: fixes (d) to (f) and the one-review-thread wording, as one gate-file PR, so it needs a Security accept, which is sub B's to start. Fixes (a) and (b) wait on Mark's call about retiring G2.

**Sub B, in this order**
1. **Reviews sub A can't start.** First: **#4033** (UPD-5 re-test rebuild plus the ship gate, issue #4031, head 472a5a34 at writing). It is tier A but not a gate-file PR, so it needs one L3+lens thread and one Security thread. Its gate lifts only once the sandbox runner (#4032) is done, so #4032 is the next build row. Then: For every open PR whose latest verdict comment lists a review owed, run one L3+lens thread and, where tier A or `premerge.py --needs-mark` requires, one Security thread. The last accept arms (CLAUDE.md).
2. **Idle PRs with no owner**, blockers as of 11:00Z (take each over or close it with its row requeued, D-098):
   - #3949: every review accepts, but CI's `checks` job is red. It needs a builder fix.
   - #3973: needs a merge from main, then a Security review.
   - #3976: `g1-freeze` is red because it has no D-198 exempt-pr companion. A Security delta is owed at 41911480.
   - #3991: needs a merge from main, and a Security delta is owed at 8f8e8d7.
   - #4003: a UX and Potency delta is owed at 048c81a. Its `mutgate` (about 16 survivors in `disk_linux.go`), `checks` and `broker-race` jobs are red, and a Security accept is still owed.
   - Follow-ups: #4023, #4025, #4027, #4028.
3. **Deletion rows (D-245), where scope is disjoint from open PRs:** MIG-4-adapters b to h (#2579 slices; briefs/MIG-4-adapters.md), MIG-4-mail (briefs/MIG-4-mail.md: delete `broker/mail/`), MIG-4-spend (`broker/verb`, `broker/meter`), the MIG-4-untrusted-* chain (`cmd/agentosd`, `broker/daemon`, `change`), and MIG-4-exit c3, p and d1. Exit d2 waits on #3974, and MIG-4-keys and MIG-4-log come last (MIG-4-log needs Opus). Kernel-lane rows still run one at a time across both subs.
4. **New-capability lanes, each in its own directory and so parallel-safe:**
   - ENF-c, f, g, i, l to t and names (`broker/enforcer/`, `image/enforcer/`; briefs/ENF.md; ENF-h and ENF-k are building);
   - DEV-homekit-b2b to b2d (`broker/clerk/homekit/`; b2a is building);
   - CAM-* (`broker/clerk/camera/`);
   - VIS-core (`broker/vision/`);
   - DEVSLOT-* (`broker/clerk/devslot/`, `device/`);
   - DEV-withings-ble c to e (`broker/clerk/withings/`);
   - DECOY-b to f (`broker/decoy/`);
   - CLK-8-line part b and on (`broker/clerk/line/`; D-238).
   Rows that share `image/` or `broker/core/core.txt` run one at a time.
5. **REV-CHK-links-*** rows touch many directories: check each one's files against open PRs before starting.

**Waiting on Mark**
- The Muse and then Grok supervised capture (he said yes on 2026-10-29). The recorder is being rebuilt to refuse by default, and the Contributor-mode step sends no prompt.
- The PREMERGE App settings steps (#3405).
- Buying the OpenWrt One (D-228).

### Owed first
1. Sub B: the reviews owed on open PRs (step 1 above), then the idle PRs.
2. Sub B: deletion rows (step 3), as many in parallel as disjoint scopes allow.
3. Sub A on reset: merge the waste-sweep PR, then resume starts, skipping every row sub B has claimed.

Edit sections 1 and 2 only when a standing decision changes; replace the snapshot whole, never per batch. Where DECISIONS.md and this list differ, DECISIONS.md wins.
