# Security section, lens bundle 2026-10-08b: #320, #322, #324, #329, #321 (main @ be5a80c)

Record: PRs #320 #321 #322 #324 #329 · packages P2-2w c1, W3-forget-b2, P2-2w d, SR2-3g, P2-2a f1 · heads 35febcd, 24f3d9d, 11fa1f2, cee016a, 3a79399 · main be5a80c

**Scope.** The tier A PRs in the bundle, plus a brief check of one tier B PR, each with an L3 accept on the head reviewed here. Every head matched the commit named in the bundle; none had moved.

| PR | Package | Head | Verdict |
|---|---|---|---|
| #320 | P2-2w c1, owner TOTP enrollment closed outside setup mode | 35febcd | **accept**, no new findings (agrees with its LATER f1-f3) |
| #322 | P2-2w d, LocalUI on when agentosd serves the Wi-Fi page | 11fa1f2 | **accept**, 1 release (carried), 1 cross-PR ordering note |
| #324 | SR2-3g, guest error canaries and the guesterr AST guard | cee016a | **accept**, 1 release (carried: SR2-3j) |
| #329 | P2-2a f1, sum-mismatch flag and the owner notice | 3a79399 | **accept** |
| #321 | W3-forget-b2, requeue in-flight builds (tier B, brief check) | 24f3d9d | **accept** (security only; the combined lens pass is elsewhere) |

**Method.** The run 1 threat model (assets; adversaries G, T, S, D, C, W, U) applied to each diff on its own and to the five merged together, with the bundle's three trigger classes checked explicitly for each PR: **U** (a hostile upstream), **W** (someone on the box's Wi-Fi), and a **compromised agentosd** (the process boundary to the vault process). For each adversary→asset path the stop is recorded as **structural** (code makes it impossible), **procedural** (depends on a check, heuristic or human step) or **none**. This is an independent check from the diffs and the cited requirement IDs; L3 reasoning was not used.

**Evidence.** [Fact] All five heads merge onto main together; the only conflicts are in BOARD.md and LATER.md (row additions, resolved as a union). On that merge, `go build ./...` and `go vet ./...` are clean, and `go test -race -count=1` passes for cmd/agentos-egress, modelroute, egress, cmd/agentosd, daemon, grants, guest, guesterr, question, recalltool, workers and loops. [Fact] The Security L6-L8 conditions from the P2-2w plan review are not in DECISIONS.md, reviews/ or docs/ (grep), so #320 was checked against BOARD rows P2-2w and P2-2w c and its own egress K17; this is #320's LATER f1. [Fact] `grants.FollowIntent` has no non-test caller on main, and no non-test code imports `broker/follow`.

**Labels:** [Fact] verifiable · [Inference] reasoned, untested. **Costs:** "None" means none found, not none possible.

---

## Summary

| # | Finding | Class | Severity | Adversary | Proposal | UX cost | Potency cost |
|---|---|---|---|---|---|---|---|
| 322-1 | #322 turns LocalUI on whenever `-localui-uid` is set. Bundle-a's 323-1 (a follow name that reproduces the switch-back line) was "not live" because LocalUI was off everywhere; after #322 its only stop is that nothing builds a follow intent or runs its executor | release (carried: OSS-10w2 before the follow wiring row) | Low–Medium once wired, none now | U, through the owner; or W holding a page session | No new row: OSS-10w2 lands 323-1's fix before any page op calls `FollowIntent` or agentosd registers the follow executor. Bundle-a already says so; this records that the LocalUI stop is gone | None | None |
| 324-1 | `effect_status` copies the gate's `Permission.Reason` to the guest outside `guesterr.Filter`; the engine stores a policy error's raw `Error()` there, and the AST guard covers only errors. One guest-reachable wrapping path exists (the gate's `check` at dispatch: "cannot read the intent's attempts: %w"); its inner error is the in-memory engine's lookup, so no host path found today | release (carried: SR2-3j, which #324 adds from L3's finding 3) | Low | G | No new row. Agree with SR2-3j: fixed reasons at the gate, a ref otherwise, and a canary policy in the integration test | None | None |

No blockers.

Cross-PR note (not a finding): #329's notice fires only for local (CH-3 confirmation) items approved on the page, which exist only with LocalUI on, so #322 is what makes it reachable. Merge #329 no later than #322, or an owner can be told "Approved" on the page for a changed item that then silently does not run (CH-12).

---

## #320 P2-2w c1: setup's code-generator enrollment (accept)

Assets: authority (the owner channel's seed is what every code approval rests on) and credentials (the seed itself, CRED-8). Adversaries: a **compromised agentosd** (the only peer of `verify.sock`), **W** (who reaches the page that will relay the seed in c2), **D** (who edits the drive).

| Path | Stop | Kind |
|---|---|---|
| A compromised agentosd swaps the seed for one it holds on a box already in use | `enroll` and `confirmEnroll` answer 410 unless the vault holds `owner-totp-setup-open` of kind `totp_setup_open`; only `init -setup` writes it, and the first confirmation deletes it and writes `owner-totp-enrolled`. [Fact] `TestEnrollIsClosedOutsideSetupMode` covers plain `init` and the owner's seed staying valid | Structural |
| agentosd forges the open entry through another write | `custody.put` (the local UI's credential write) accepts only built-in adapter names, as kind `api_key`, never over another kind; `enrolledLocked` requires the exact kind. No other vault write takes a name from agentosd [Fact: every `Put` in cmd/agentos-egress] | Structural |
| D reopens enrollment by editing the drive | The open and sealed marks are vault entries, not the state file; replaying an older vault file is the vault's own rollback check [Inference: `vault.ErrRolledBack`, not retested here] | Structural |
| agentosd grinds codes against the pending seed | Wrong confirmations count in the channel's `wrongCounted` window (`MaxWrongCounted` per `VerifyWindow`), checked after the sealed check, so a sealed box spends nothing [Fact: `TestWrongConfirmationsAreBounded`] | Structural |
| The same code confirms twice, or replays a code the channel already used | The match spends its step in the shared `LastStep` (K7), persisted before the seed moves | Structural |
| A crash mid-confirmation leaves a sealed vault with the old seed | Order is seed, then seal, then delete open and pending; every prefix is finished or refused by the next call. A leftover pending copy after the seal is #320's LATER f2 (unreadable: no path reads it once sealed) | Structural, one later residual |
| agentosd sees the seed during setup | Accepted residual (Security L7): the page must show it; the window closes at the first confirmation. Before then the channel's seed is the one `init -setup` wrote and showed nobody, so no owner code works and nothing can be approved by code in that window | None (accepted, by design) |
| A peer other than agentosd on `/enroll` | `verify.sock` is SO_PEERCRED to agentosd's uid (unchanged); no negative test on the new routes is #320's LATER f3 | Structural, test owed later |

No new findings. The link is never logged (`EnrollResult.String`), and the HTTP answer is `no-store`.

## #322 P2-2w d: LocalUI on (accept)

Assets: authority (what the owner can be asked to approve, and where), and the supply chain through OSS-10. Adversaries: **G** (asks for wider grants), **W** (on the access point), a **compromised agentosd** (no change: it is the gate).

| Path | Stop | Kind |
|---|---|---|
| LocalUI on without a page to answer | `gcfg.LocalUI = cfg.PageSocket != nil` in `daemon.Run`, and `newEvidence` takes the same flag, so the gate and the evidence path cannot disagree; a caller's own `Grants.LocalUI` is overridden [Fact: `TestServingThePageTurnsLocalUIOn`] | Structural |
| G asks for a new or wider grant (CH-3), now asked rather than refused | Approval needs the owner's code-generator code on the page (`LocalAnswer`; a texted code is refused there), a page session from `localui.sock`, and the item's sum must match what the page showed (Security P1). The owner's judgement of the card is the residual | Structural for binding, procedural for judgement |
| W approves on the page | Untokened ops are only status, STOP, grid and sign-in; sign-in and every approval need a code; tries are counted per socket (P2-2w a) | Structural |
| A follow root approved by a misleading card | → 322-1. [Fact] No page op builds `FollowIntent` and no follow executor is wired, so not reachable today | None now |
| Reason text tells G more than before | The new `NoPage*` reasons are constants; the gate's "local page" wording change is text only | Structural |

**322-1 (release, carried).** Bundle-a classed 323-1 as release, not blocker, partly because "LocalUI is false everywhere today". With #322, any box run with `-localui-uid` has LocalUI on. The finding is still unreachable, but only because nothing calls `FollowIntent` and nothing registers the follow executor. Its fix stays with OSS-10w2, before the wiring row; no new row is needed.

L3's F3 (LocalUI tracks the socket, not the page process) is liveness only: a page-asked item waits while the page is down and nothing is approved. Agree it is later.

## #324 SR2-3g: one filter on guest-facing tool errors (accept)

Asset: host and broker internals (paths, IDs) that would help G plan an escape or target another machine. Adversary: **G**.

| Path | Stop | Kind |
|---|---|---|
| A tool's error carries host text to the guest | Both guest-facing error writes in `guest/mcp.go` go through `guesterr.Filter`: a `Safe` error shows only `GuestText`; anything else becomes `<tool> failed (ref <8 hex>)` with the detail in the broker's log | Structural |
| A wrapped or embedding type smuggles its own text | Only the error's own method set counts; a wrapped `Safe` is a ref; an embedding type shows only the embedded text; types declaring `GuestText` are an allowlist test [Fact: `TestAnEmbeddingTypeShowsOnlyTheEmbeddedText`, `TestOnlyAllowlistedTypesAreSafe`] | Structural |
| Error text built from a variable | `New` takes `Literal`, which a string value does not convert to; `Newf` takes only `Num` and `Guest`; the AST guard refuses `Literal(…)`, `Text(…)`, `Text{}`, a dot-import, and an error passed to `Guest`/`Num` | Structural, except a host-path *constant* (#324's LATER f6, deliberate misuse only) |
| G forges broker log lines through the ref path | The error is logged with `%q`; the tool name in the log is one a tool set already matched (unknown names answer a `Safe` text and log nothing) [Inference] | Structural |
| Text reaches the guest by another field | `effectState.Reason` = the engine's stored policy error, outside the filter → 324-1 | Procedural |

**324-1 (release, carried by SR2-3j).** [Fact] `guest/mcp.go` `state()` returns `st.Permission.Reason`, which `journal/engine.go` sets from `perr.Error()` on a denial; the guard only looks at error construction. [Fact] Most gate `err.Error()` reasons are on broker-account or `meta.*` branches, which the plane refuses before the journal, but the gate's `check` at dispatch wraps `g.tries`' error and runs for ordinary owner-approved guest effects. [Inference] `g.tries` reads the in-memory engine, whose error names the intent, so no host path reaches the guest today; the stop is procedural until SR2-3j lands. #324 already files SR2-3j (and SR2-3k for run-time `Guest` checks) from its L3 review; this section agrees with both and adds no row.

## #329 P2-2a f1: notice after a changed page approval (accept)

Assets: authority (the owner's belief about what ran, CH-12 honesty) and the owner channel's integrity. Adversaries: **G** (changes an item under the owner), **T**/**S** (owner channel content).

| Path | Stop | Kind |
|---|---|---|
| A page approval of an item that changed since it was shown runs anyway | Unchanged: a sum mismatch sets `Approved = false` and the item is denied; the PR adds only the notice | Structural |
| G puts its own text into the owner notice | The notice is a fixed format around `d.Request`, the owner channel's request ID (broker-minted), clipped to 64 bytes; no item field from the agent appears [Fact: `Decision.Request` is set from `r.id` / `p.ID` in owner] | Structural |
| G spams the owner with "did not run" texts | Each notice needs an owner approval with a fresh code on the page; one per decision | Structural |

No findings. See the cross-PR note on merge order with #322.

## #321 W3-forget-b2: requeue in-flight builds (brief check, accept)

Asset: the owner's private data under CAP-3 (a forgotten task must not end up in a kept or proposed candidate). Adversary: none hostile; the path is only the owner's authenticated forget.

- A build that read the forgotten goal is cancelled with `ErrRequeued`; the check against `forgotAt` and the tried/asked marks are in one critical section, so no forget lands between them, and `propose` drops a candidate whose goal is gone. Structural for kept state.
- A proposal that already reached the owner before the forget may be asked again after the rebuild: LATER "W3-forget-b2 dup ask". No data leaves the box that did not already; CAP-3 accepts effects already taken.
- Requeue is triggered only by `ForgetGoal`, so G cannot loop the scheduler; requeued units still add to `spent`. No findings.

## Cross-PR interactions

- [Fact] #322, #324 and #329 all touch `cmd/agentosd/main.go` or `grants/gate.go`, in separate places; they merge without code conflicts, and the race tests pass on the merge.
- #322 is the bundle's one change to a running box's attack surface: on boxes run with `-localui-uid`, CH-3, CH-20 and CHG-4 items are now asked on the page rather than refused. CH-20 still denies with no destination account (`Destination` is nil in agentosd), and OSS-10 has no caller (322-1).
- #320 (vault process) and #322 (agentosd) do not interact yet; c2 wires the page to `Verifier.Enroll`. c2's review should check that agentosd never logs or stores the link, and that the page shows it only to a signed-in setup session.
- #329 should merge no later than #322 (see the Summary note).

## Decisions

- All five: **accept** for Security. No blockers.
- Release, no new rows: 322-1 is carried by OSS-10w2 (bundle-a 323-1); 324-1 by SR2-3j (added in #324).
- Later: none new; agrees with the builders' LATER lines (#320 f1-f3, #322 f3, #324 f6, #321 dup ask).
- For P2-2w c2's brief: the two checks in the cross-PR section, and #320's LATER f1 (record L6-L8) before c2's own security review.
