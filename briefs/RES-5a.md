# RES-5a: usage pools by window, their names, and the reserve's passkey

Work item #1004. Tier A (`broker/kernel`, `broker/clerk`). Written 2026-10-29 against main at 1a37568. Rescoped from the old core (`modelroute`, `provagent`) onto the kernel and the model clerk, per the 2026-10-29 pre-migration triage §4. ONB-9a (#1005, `briefs/ONB-9a.md`) builds the owner's lines on what this row adds.

## What main already has

MIG-4-spend-b (`broker/clerk/model/ASSUMPTIONS.md` b5, b6, b9, p1) built RES-5's core: `pool.read`, `pool.reset`, `pool.reserve.raised` and `.lowered` in the log; `Kernel.ReadPool`, `Reserve`, `AdmitPool`; a pool closed at the owner's reserve until its reset time, which is the route's cooldown; a reading that can only narrow. `broker/clerk/plan` reads the Codex pool from its answer headers (`Pool.reading`, `meter.go`), and `broker/clerk/model.Settle` writes it. Do not rebuild any of that.

Three gaps stop ONB-9's line ("ChatGPT Codex: 42% of the 5-hour limit, resets 14:00; 81% of the week") and its reserve setting from being built on it:

1. `Pool.reading` keeps only the window nearest its limit, so the log holds one figure per pool, not one per window.
2. Nothing names a pool or its windows as the provider does; the declaration has only header prefixes.
3. Lowering the reserve is a widening (KEY-6, KEY-4), but `Reserve` lowers on any owner-socket call with no passkey signature. No owner side calls it yet, so nothing is exposed today; ONB-9a's page would be the first caller.

A fourth read is for ONB-9's failover line ("Used the API instead: $0.42 today"): nothing reads metered spend by route over a time span.

## Goal

1. **A reading is per window.** `pool.read` moves to version 2: `{pool, windows: [{window, used, reset_at}]}`, per mille as now. `State.Pools[p]` keeps each window's used and reset time, and the owner's reserve. A pool is open while every window's used plus the reserve is under 1000. Each window narrows and resets on its own: `pool.reset` v2 names the window, and a 5-hour window resetting does not reopen a pool whose weekly window is still at the reserve. A window missing from a reading keeps its last figure. A full reading with no usable reset time falls back to that window's declared length (below), then to `PoolWindowMS`. The `Reached` header still reads as every window full at the latest reset time. Version 1 entries are refused, not misread, as KRN-schema did for `key.issued` v2 (no box holds a log yet). Failure path: the 5-hour window resets while the week is spent, and plan work runs into the weekly limit the owner kept back.
2. **Pools are named as the provider names them.** `plan.Declaration` gains `Title`, the plan as the owner names it ("ChatGPT", as `PLAN ChatGPT ON` spells it, CH-11), and `plan.Pool` gains `ID` (the pool's kernel name, which `model.Price.Pool` already carries), `Name` ("ChatGPT Codex") and per window `{ID, Prefix, Label, Every}` (`5h`, `X-Codex-Primary-`, "5-hour limit", 5 h; `7d`, `X-Codex-Secondary-`, "week", 7 days, per the #809 reading `plan.go` cites). The clerk's reading carries window IDs only; names stay in the image's declaration and never enter the log. `run.PlanState` (the `planstate` owner call) gains `Title` and `Pool {ID, Name, Windows [{ID, Label}], Routes}`, where `Routes` lists the model routes that draw on the pool, so the owner side can tell plan spend from API spend. Failure path: the page invents a name or a window the provider does not use.
3. **Lowering the reserve takes a passkey's signature.** `Reserve(now, pool, reserve, cos ...key.Cosign)`: raising needs none (a text is enough, KEY-6); lowering needs one cosign by a passkey live in `key.Passkeys` (an anchor or an enrolled phone passkey) over `ReserveHash(pool, from, to)`, else `ErrReserveSig`, logged as nothing. The unsigned-call-then-challenge shape is `BackupTarget`'s (`kernel/backuptarget.go`, `cmd/agentosd/backupchoice.go`), so ONB-9a reuses the page's tap. Lowering stays a `Widening` and anchors as now (b6, b12). Failure path: a compromised owner-side process lowers the reserve the owner set and spends the share they kept.
4. **Spend by route over a span.** `State.Spent(since)` answers metered spend per route (minor units) from `model.used` entries at or after `since`, kept for at least the last 48 hours and pruned beyond, so state does not grow with the log. Failure path: STATUS reports failover with no figure, or one summed over the box's whole life.
5. **The sockets carry it.** `kernel/proc`: `readpool` takes windows, `reserve` takes the cosign and returns `ErrReserveSig` as itself, `pools` returns the windows, and a new read `spent {since}`. docs/LANES.md's owner seam and metering lists name the new signatures and the `Spent` read, as the frozen seam requires. `broker/owner/kernelsock` (sub B's client) is ONB-9a's, not this row's.

Not here, each a new `work-item` row filed with this brief:
- **RES-5b (#3928), spare draw:** spare-class work drawing a pool only down to the larger of the reserve and the foreground forecast, and the last-hours use of what would reset unused (RES-5, HLD-4). The kernel has no admission class on a model call yet; `AdmitPool` would need one.
- **RES-5c (#3929), rate-limit slow start:** slowing new starts on a pool only while its provider returns rate-limit errors, with no fixed cap (RES-5).
- One pool per route stands (b9). Failover routing is PLN-7's.

## Lifecycle

| Stage | Outcome |
|---|---|
| first boot | No pool entries; every pool open at reserve 0 (D-115). |
| restart | Replay rebuilds every window, the reserve and `Spent`'s 48 hours from the log; a lowering survives only under an anchor (KRN-7). |
| update | A declaration change of names or labels changes no log entry. A window the new declaration no longer reads stays as logged until its reset time, then reopens and is not read again. |
| recovery | A restore to an older head reopens nothing the restored log keeps closed. |

Integration owner: this row for the kernel and clerk; ONB-9a wires the owner side.

## Scope

`broker/kernel/` (`state.go`, `kernel.go`, `proc/kernelsock.go`, their tests, and `sim/` if its pool calls change), `broker/clerk/plan/` (`meter.go`, `plan.go`'s Codex declaration, tests), `broker/clerk/model/` (`model.go`'s `PoolReading`, tests, ASSUMPTIONS), `broker/clerk/run/` (`plan.go`'s reading conversion, `plansignin.go`'s `PlanState`, tests, ASSUMPTIONS), `docs/LANES.md` (the seam's signatures; a gate file), `briefs/RES-5a.md`.

**Guard files:** none (no new package). `docs/LANES.md` makes this a gate-file PR as well as tier A: it needs the separate Security accept (OPERATING §7).

## Acceptance tests

**Acceptance tests:**
- RES-5: `broker/kernel/spend_test.go::TestEachWindowNarrowsAndResetsOnItsOwn` (a 5-hour reset leaves a pool closed while its week is at the reserve), `::TestAReadingWithoutAWindowKeepsItsLastFigure`, `::TestAFullWindowWithoutResetFallsBackToItsLength`, `::TestPoolStateSurvivesReplay` (extended to windows).
- KRN-1: `broker/kernel/kernel_test.go::TestEntryTypesAreClosed` (a v1 `pool.read` or `pool.reset` is refused).
- KEY-6, KEY-4: `broker/kernel/spend_test.go::TestRaisingTheReserveNeedsNoSignature`, `::TestLoweringTheReserveNeedsALivePasskey` (no cosign, a cosign over another hash, and a cut-off passkey's each refuse `ErrReserveSig` and log nothing).
- LOG-7, ONB-9: `broker/kernel/spend_test.go::TestSpentSumsRoutesSinceAndPrunesPastTwoDays`.
- RES-5, CLK-7: `broker/clerk/plan/body_test.go::TestPlanPoolReading` (extended: each window read on its own; an unreadable window is no reading of it), `::TestTheCodexPoolIsNamedAsTheProviderNamesIt`.
- RES-5: `broker/clerk/model/model_test.go::TestPoolRouteReadsUtilizationAndStopsAtTheReserve` (extended to windows).
- CLK-7, ONB-9: `broker/clerk/run/plansignin_test.go::TestPlanStateNamesThePoolWithoutFigures`.
- `broker/kernel/proc` socket tests: every new or changed call is the direct call (`TestEverySocketCallIsTheDirectCall` pattern), and `ErrReserveSig` crosses as itself.

Recurring kinds (`reviews/*/README.md` for the kernel and clerks) are acceptance criteria: a widening that survives a restart without an anchor, and a refusal that logs.

## Open point (asked on #1004)

KEY-4 holds a widening "about 24 hours" before it is live. The reserve is the owner's keep-back on a pool already granted to the plan route, not a key caveat, and MIG-4-spend-b6 already treats a lowering as live once anchored. Recommendation: live at once on the passkey's signature, recorded as an ASSUMPTIONS row for Security to confirm. If the hold applies, `pool.reserve.lowered` gains a hold like a grant's, which adds about 15k to the estimate.

## Estimate

About 80k tokens, one session (Opus, tier A).
