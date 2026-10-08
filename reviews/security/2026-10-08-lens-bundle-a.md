# Security section, lens bundle 2026-10-08a: #300, #319, #323, #327 (main @ be5a80c)

**Scope.** The tier A PRs in the bundle, each with an L3 accept on the head reviewed here:

| PR | Package | Head | Verdict |
|---|---|---|---|
| #300 | CRED-4b part 1, credentialed browser gate (claude2) | e000ecc | **accept**, 1 release, 1 later |
| #319 | OSS-6e, the 20h floor across broker restarts | abe4598 | **accept**, 1 later (owed LATER.md line) |
| #323 | OSS-10w, follow-fork executor | 72a8693 | **accept**, 1 release |
| #327 | W3-forget-b2b, forget item 2: agent take-back | fc62903 | **accept**, 1 later |

**Method.** The run 1 threat model (assets; adversaries G, T, S, D, C, W, U) applied to each diff on its own and to the four merged together. For each adversary→asset path the stop is recorded as **structural** (code makes it impossible), **procedural** (depends on a check, heuristic or human step) or **none**. This is an independent check: the L3 threat checks were read afterwards, only to avoid duplicating their findings.

**Evidence.** [Fact] All four heads merge onto main together; the only conflict is in BOARD.md. On that merge, `go vet` is clean and `go test -race -count=1` passes for grants, follow, recalltool, cmd/agentosd, browser, pubid, localsrv, localapi and update. [Fact] No non-test code imports `broker/browser` or `broker/follow`, and no code sets `grants.Config.LocalUI` true. So neither new executor can be reached on a running box yet, and the release findings below are not live today. Two probes were run in scratch tests that are not committed: the origin check on 12 URL shapes, and `followName` on finding 323-1.

**Labels:** [Fact] verifiable · [Inference] reasoned, untested. **Costs:** "None" means none found, not none possible.

---

## Summary

| # | Finding | Class | Severity | Adversary | Proposal | UX cost | Potency cost |
|---|---|---|---|---|---|---|---|
| 300-1 | The driver renders hostile pages as the broker's user, with no sandbox (K1). Nothing stops it from being wired in before part 2 | release (CRED-4b part 2 acceptance) | High once wired, none now | G (a hostile page, then a Chromium escape) | Part 2's brief adds a test that fails if non-test code imports `broker/browser` while `Config` can start the driver outside `vm.Manager` | None | None |
| 300-2 | A secret the site shows itself (a newly created API key) is caught only by the heuristic detector. The exact-value redactor knows only vault values, and CRED-6 intents are not classed yet (K5) | later (K5 / ADP-8, already carried) | Medium for CRED-4b | G | No new work: K5 and the K11 corpus already carry it. Record that until K5 lands, the stop is procedural, not structural | — | — |
| 319-1 | When boot_id is missing, the floor fails open at restart (G2); L3 asked for a LATER.md line, but the diff has none | later | Low | D or root on the host (already outside the trusted base) | Add the one LATER.md line before merge (procedural; the code does not change) | None | None |
| 323-1 | An owner-chosen follow name can produce the exact approval line of the switch-back. The line does not say which root is approved | release (OSS-10w2) | Low–Medium, none now (LocalUI is off) | U, through the owner: a fork's install guide says "name it *the AgentOS project again*"; or W holding a local session | Refuse names that case-insensitively start with "the AgentOS project", **and** put the root's short fingerprint (first 8 hex of the digest) and key count in the item's Detail | Low (one more line on the card) | None |
| 327-1 | Check then act: `agentBackWithoutAsking` checks `worked(since)`, then calls `takeBack(…, approved=false)`, and nothing re-checks inside `TakeBack`. Work done in that window is rolled back without asking (CAP-3 says ask first) | later | Low | None hostile (a race with the agent's own work) | Re-check `Work` under `r.run` inside `TakeBack` when `approved` is false | None | Low gain |

No blockers.

---

## #300 CRED-4b part 1: credentialed browser gate (accept)

Assets: credentials (the sessions the browser will hold; site-shown secrets) and the owner's private data on those sites. Main adversary: **G**, which controls page content and steers the agent that sends requests.

| Path | Stop | Kind |
|---|---|---|
| G sends a verb outside the protocol (JS, cookies, devtools) | `Parse` accepts only a closed set of seven verbs and their fields; the driver gets a canonical re-encoding, so no bytes from the agent reach it (G1) | Structural |
| G navigates off the declared origins | `Origins.Declared` checks scheme, lowercased ASCII host and port. [Fact] Probes rejected a trailing-dot host, `\@` and `#@` userinfo tricks, `%2e`, a tab in the host, `https:host`, `https:/host` and a hex IP. Non-ASCII hosts are refused, which closes the gap between Go's host handling and IDNA | Structural (fails closed) |
| A page redirects off-origin after an action | G4: every reply carries `page.url`; an off-origin page, or an ok reply with none, kills the process group. This relies on the driver reporting honestly; the driver is untrusted, but a renderer compromise does not control the Python driver | Procedural, until K1 |
| A secret leaks through text or a screenshot | The exact vault-value redactor, then the CRED-10 detector, run on every string; snapshots before and after a screenshot; downloads and file names are scanned. Pixels (K6), containers and a rewrite after the scan (K10), and labels in a neighbouring node (K11) are open, all carried | Procedural (heuristic) |
| Output path tricks | Flat names only; a regular, singly linked file; read through `O_NOFOLLOW` | Structural |
| Sandbox escape to the broker | **None in part 1**: the driver is a child process sharing the broker's user (K1) → 300-1 | None now |

**300-1 (release).** K1 is honest that part 1 has no sandbox, and today nothing imports the package [Fact]. The risk is order: a later wiring PR could bring the gate up before part 2's `vm.Manager` placement. That would put a hostile-page renderer one escape away from the vault process's user. Proposal: a test in CRED-4b part 2's acceptance (or sooner, in whichever package first imports it) that fails if the driver can start outside `vm.Manager`. This turns a procedural ordering into a structural one. A second PR in this area would make it a lint rule (CLAUDE.md L3 rule).

**300-2 (later, carried).** It is only recorded here: until CRED-6 classes secret-revealing screens as intents (K5), the CRED-1 stop for site-created secrets is the detector alone. That is consistent with security run 2 finding 6.

## #319 OSS-6e: floor across restarts (accept)

Asset: the publication delay, a privacy guarantee (OSS-6). Adversary: whoever moves the wall clock and restarts the broker.

| Path | Stop | Kind |
|---|---|---|
| Restart loop under a moved clock, to count days early | The last count's `CLOCK_BOOTTIME` reading and `boot_id` are persisted and restored on the same boot (`restoreCount`) | Structural |
| A stored count edited ahead of now | Clamped by `min(stored, now)`: counts no day and does not freeze the outbox | Structural |
| An edited `Boot`, or an oversized or malformed record | Refused (`bad last count`, 64-byte cap) | Structural |
| D edits the file offline | A reboot changes `boot_id`, so an offline edit cannot target the next boot | Structural |
| `boot_id` unreadable or a non-Linux build | Falls back to the old rule (each restart can count one day) → 319-1 | None (documented) |

**319-1 (later).** Same finding as L3; this section only notes that the LATER.md line L3 asked for is not in the diff [Fact: `git diff --stat` touches no LATER.md].

## #323 OSS-10w: follow-fork executor (accept)

Assets: the supply chain (who decides what the box installs) and authority. Adversaries: **U** (a hostile fork or root), **W** and **G** (who could reach the local page), and **T** and **S** (the owner channel).

| Path | Stop | Kind |
|---|---|---|
| G or a remote channel asks to follow | `evaluateFollow` denies any origin but `originLocal`; it is tier-4 (code plus ConfirmLocal); localsrv needs the L1 session token (WF3) | Structural |
| An executed root differs from the approved digest | `held` is keyed by the digest `DescribeRoot` computed from those bytes; Reconcile compares `RootDigest(TrustedRoot)` and the name | Structural |
| A switch back to a root that only looks like the project's | WF1: root-role key material equal to the shipped root | Structural |
| An expired root accepted under a moved clock | `Latest` is never zero (it uses the box clock or the floor), and Latest is the strict answer for expiry [Fact: `clock.Guard.Latest`]. Ignoring its Status is therefore safe | Structural |
| The approval line misleads the owner | → 323-1 | None |

**323-1 (release).** [Fact] `followName("the AgentOS project again")` is true (printable, no digits, 25 characters), so `object = "get updates from " + name` is byte-identical to the switch-back line `"get updates from the AgentOS project again"`. The item's Detail is empty, so nothing on the approval card binds it to the root. The owner approves a sentence, not a key set. The root-summary page shows keys earlier, but the code is entered against the card. Who can reach it: U, by social engineering through a fork's install guide; or anyone holding the owner's local session. Both still need the owner's code, which is why the severity is low. It is not a blocker because `LocalUI` is false everywhere today, so the gate denies every follow. It must land before the wiring row. Proposal: reserve the project name (refuse names that case-insensitively start with "the agentos project"), and put `root <first 8 hex> · <n> keys` in Detail for both kinds of line, so two different roots never produce the same card. L3 review 5450390728 #5 noted that the text matches ProjectName but did not raise the collision.

## #327 W3-forget-b2b: agent take-back (accept)

Assets: authority (who may roll an agent back), the owner's private data (CAP-3 deletion reach), and the owner's work. Adversaries: **G** (stopping a rollback, or forcing one), **T** and **S** (owner FORGET).

| Path | Stop | Kind |
|---|---|---|
| G submits a forget or take-back | The gate needs `OriginForget` and `ForgetExecutor`; the line comes from the broker's lookup, never from params; an owner YES with the request's code is required. The ID prefixes `forget/`, `forget-agent/` and `follow/` cannot be confused (`CutPrefix("forget/")` does not match `forget-agent/`) | Structural |
| Item 2 approved without item 1 | Execute refuses `item 1 not approved` | Structural |
| A rollback repeated after later work | Marked owed before the reset; done is kept in memory if the write fails; `TakeBack` returns early once done. A restart before any write lands can repeat it once (L3, later) | Structural, with one residual window |
| G keeps forgotten data by working after the read | The rollback restores the machine snapshot; actions already taken stay done (CAP-3 accepts this) | Structural for state, none for effects (by spec) |
| T or S sends FORGET | Same owner-channel strength as item 1; no new exposure | Procedural (pre-existing) |
| Work rolled back without asking | `worked` then `takeBack(approved=false)` is a check-then-act sequence → 327-1 | None (small window) |

**327-1 (later).** [Inference, from reading `forget.go` and `reach.go`] Nothing hostile gains from this, so it is later. The fix is cheap: in `Reach.TakeBack`, when `approved` is false, re-check `Work` under `r.run`.

## Cross-PR interactions

- #323 and #327 both edit `grants/gate.go` and `grants/grant.go`, in separate cases (`ActionUpdateFollow`, `ActionLearnForget`) and with separate ID prefixes. They merge without conflict, and the race tests pass on the merge [Fact].
- #300 and #319 share no code with the other two. Neither new executor is wired into `agentosd`, so the bundle changes no running box's attack surface; the release rows (300-1, 323-1) gate the wiring.

## Decisions

- All four: **accept** for Security. No blockers.
- New release items for the coordinator to file: 300-1 as an acceptance line in CRED-4b part 2; 323-1 in OSS-10w2 (already the release row for #323's deferrals).
- Later lines: 319-1 (the builder adds it to LATER.md), 327-1.
