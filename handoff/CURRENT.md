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
- **D-306** No path freeze (retires D-128's G2 freeze and D-198): any row's paths may be built; D-098 rows stay frozen.
- The session posting the last required accept arms the merge (head = accepted head, CI green, OPERATING §7; D-120); PRs matching `tools/premerge.py --needs-mark` also need a separate Security accept at an equal head, and no PR waits for Mark's line (D-137). Asks to Mark are cards, never typed phrases.
- **D-121** Speed rules (OPERATING §5): run CI's exact commands (and a `-count=N` stress run on new concurrency tests) before a PR or verdict; briefs pre-approve their guard files (`tools/risk_tier.py` class, `broker/daemon/arc2_test.go` allowlist); readiness reads the code; one push per round; on the G1 critical path stack on a review-accepted interface and run disjoint packages in parallel; tier-A builders on Opus, B/C on Sonnet, no model switch mid-session; fix a flake the second time. Tier A keeps two reviews (Security; Potency/UX/L3).
- **D-122** Phone custody (#1843): an app login on a box-owned dedicated phone is broker custody only if the phone has no SIM, is not on the owner's number, every commit tap is gated by the approval tiers, and it is never the approval phone (CH-4).
- Chat layout: standing threads Decisions, Questions, PR updates, Alerts; finished threads are resolved at once. Project memory may be off, so durable state lives in the repo.

## 3. Snapshot, 2026-10-30 (both subs building; durable rules only)
Written by sub A at Mark's request. Sub B is already building here, so this snapshot holds only what stays true for days. Live state (open PRs, owed reviews, claims, red checks) changes hourly, so rebuild it from GitHub with §1 every time: each PR's latest verdict comment and `tools/premerge.py --check` say what is owed, and an issue's claim comment and `state:building` label say who has a row.

**Why.** Sub A's account used all 500 of its daily thread starts on 2026-10-30. Mark (2026-10-29 and 2026-10-30): spend all usage on work that isn't wasteful, ignore usage pacing, avoid conflicts and duplicates, and move to the other sub when one runs out. The temporary split, sub A on this repo and sub B on agentos-private, is off: both subs build here, and sub B keeps agentos-private.

**Rules new since 2026-10-25** (DECISIONS.md is authoritative)
- **D-245, deletion first.** Among startable rows, start the ones that delete old-core code, and the rows that unblock them, before new features. Report the old core's remaining lines (`tools/trace.py` old-core measures) to Mark weekly.
- **One review thread per PR** (Mark's tap on card cmsg_01R91wiieBzMSvPKFsAJVvuK57ki4Y7D6WVcKzuoTaDAeF; recorded in #4041). The L3 thread spawns the UX/Potency screen as a fresh-context subagent that never sees L3's reasoning. Security stays a separate fresh thread, and delta re-reviews take the same shape. It replaces OPERATING §4's "fresh session per bundle", and Mark's tap applies now.
- **D-247, interim ownership.** Sub B numbers new decision rows from D-300 up, and sub A continues from D-248. Until #4041 merges, only #4041 edits the process docs (CLAUDE.md, AGENTS.md, PLAN.md, docs/OPERATING.md, docs/LANES.md, role skills); file other process changes as issues. If two open PRs claim the same ID, the one that merges second renumbers and updates every line citing it.
- **UPD-7w ship gate (Mark's tap 2026-10-30, recorded on #3961).** #3468 deletes the change engine. UPD-5's local requalification is rebuilt next, and no stable release goes to an owner box until it is back.
- **D-227 to D-244 include:**
  - the old second-line texting deleted (D-227), then rebuilt as a clerk whose keeper ends TLS and filters each outbound text (D-238);
  - the OpenWrt One access point (D-228);
  - one Apache-2.0 embedding model (D-230);
  - an enforcer with no language runtime (D-231);
  - short-lived codes and erase tombstones (D-239);
  - the checker rebuilt as `broker/clerk/codecheck` (D-244).

**How to pick work, either sub**
1. Reviews owed on open PRs come before new builds. Use the one-thread shape above, and the last accept arms, whichever sub posts it.
2. Before starting any row, check its issue for a claim and for merged work (`git log origin/main -- <dir>`), and check open PRs for overlapping files (D-111). Rows that read `queued` may already be merged or claimed.
3. Then, in order: the UPD-5 requalification chain, deletion rows (D-245; kernel-lane rows one at a time across both subs), then the new-capability lanes in their own directories (enforcer, HomeKit, camera, vision, device slot, Withings, decoys, the CLK-8 line).
4. Rows that share `image/` or `broker/core/core.txt` run one at a time.

**Waiting on Mark**
- The Muse and then Grok supervised capture: he said yes on 2026-10-29. The recorder refuses by default, and the Contributor-mode step sends no prompt.
- The PREMERGE App settings steps (#3405).
- Buying the OpenWrt One (D-228).

**Not approved: don't build** (carried forward from 2026-10-25)
- Local-first model routing waits on a capability benchmark against the plan routes (Mark, 2026-10-24 00:02Z). Private planning on a Mac Studio would need a SPEC change (HW-7, HW-11).
- These are proposals only: one case for all boards; a second-device confirm for high-value widenings; hardware-backdoor measures (chip-vendor diversity, the store key split across vendors); a flip phone plus two FIDO2 keys as root (compare D-146).

Edit sections 1 and 2 only when a standing decision changes; replace the snapshot whole, never per batch. Where DECISIONS.md and this list differ, DECISIONS.md wins.
