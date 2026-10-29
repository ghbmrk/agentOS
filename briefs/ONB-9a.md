# ONB-9a: plans in plain words on the Wi-Fi page and in STATUS

Work item #1005. Tier A (`cmd/agentosd`, `localsrv`, `localui`, `owner`). Written 2026-10-29 against main at 1a37568. Rescoped from the old core (`provagent`, `modelroute`, `planusage.go`) onto the kernel's pools and the model clerk's plan owner calls, per the 2026-10-29 pre-migration triage §4. Serial `cmd/agentosd` chain (D-111).

**Needs:** RES-5a (#1004, `briefs/RES-5a.md`: pools by window, their names, the reserve's passkey, `Spent`), and #2780 (b3) (`localsrv/accountsock.Plan`, the client of `planstate`; it deletes `planusage.go`, `pagesignin.go` and the provider parts of `planwire.go`, and moves ONB-9's sign-in line onto `planstate.Stopped`). Live figures appear once a guest's plan endpoint is served (`cmd/agentos-clerk-model` ASSUMPTIONS MIG-4-untrusted-exit-b2b-3); until then the lines show "no reading yet", and every test drives fakes.

## Goal

Every line is built by agentosd from two reads: the kernel's `Pools` and `Spent` (owner socket) and the model clerk's `planstate` (names, windows, routes, stop). Text is fixed wording filled with the declaration's names and the kernel's numbers, never a provider's or planner's words.

1. **One line per pool on the Wi-Fi page** (ONB-9). `<Pool name>: <n>% of the <first window label>, resets <HH:MM>; <n>% of the <next label>`, for example "ChatGPT Codex: 42% of the 5-hour limit, resets 14:00; 81% of the week". Percent rounds up from per mille, so 99.1% never shows as 99%. A window at the reserve also shows its reset time; one more than 24 hours off shows the weekday ("resets Tue 09:00"). Times are in the owner's local time, as STATUS shows them. A pool with no reading yet: "ChatGPT Codex: no reading yet". Failure path: the owner sees a figure for the wrong window, or a rounded-down figure that hides a spent limit.
2. **Kept for your own use: N%.** Each pool line carries the setting, 0% by default, not asked in onboarding (D-115). The page shows a percent from 0 to 100 in whole steps; the kernel gets per mille.
   - Raising needs only the page session (a narrowing, KEY-6). It calls `Reserve` with no cosign and is live at once.
   - Lowering is a widening (RES-5a goal 3). The page asks for the passkey tap the way `backupchoice.go` does: an unsigned call whose `ErrReserveSig` says the change is well formed, then the challenge over `ReserveHash`, then the assertion found among the live passkeys. When the kernel answers `ErrNeedsCosign` (a big lowering), the page says a hardware key's tap is needed too and asks for it over the same hash.
   - **A pending lowering shows until it is live** (KEY-4 notice). The pool line reads "Kept for your own use: 40%, lowering to 0% from Tue 14:00" with a **Cancel** button, which raises the reserve back to its current value (a narrowing, session only) and so cancels the lowering. STATUS carries one line per pending lowering ("ChatGPT Codex: keeping 40% for you until Tue 14:00, then 0%. Cancel it on my Wi-Fi page if you did not mean it."), and agentosd sends the owner one text when the lowering is logged, with the same words.
   - Failure paths: a page session alone lowers the reserve; or a lowering waits its hold with no word to the owner.
3. **STATUS at the reserve** (ONB-9). One line per pool whose windows reach the reserve, naming the earliest time the pool opens again: "ChatGPT plan: at your reserve until 14:00. Nothing to do; work uses the API meanwhile." when an API key serves (`apikeystate` reports `serves: true`), else "ChatGPT plan: at your reserve until 14:00. Work waits until then." Failure path: STATUS says "nothing to do" when nothing can run.
4. **Failover is told, not asked** (ONB-9). When a window is at the provider's limit (used 1000, not just the reserve) and API routes were metered since the owner's local midnight (`Spent`, summed over routes not in any plan's `Routes`), the line instead reads "ChatGPT plan limit reached until 14:00. Used the API instead: $0.42 today.", in agentosd's `-currency` as RETRY lines are (#3079). With no API spend, item 3's line stands.
5. **Stopped plans.** b3 moves the refused-login line (CLK-3, "signed out ... sign in again") onto `planstate.Stopped`; this row adds the `unswappable` stop: "ChatGPT plan stopped: its answers changed shape; only an update brings it back." on the page and in STATUS, with no reply command (as ONB-9's security-notice line). A stopped plan's pool line stays, and its route is skipped (the clerk already refuses it). The line renderer takes a closed set of stop reasons, and an unknown one shows "ChatGPT plan stopped; only an update brings it back." rather than nothing.
6. **Spare work waiting for a reset is never texted** (HLD-4). Nothing in this row texts on its own: items 3 to 5 are STATUS and page lines only.

Not here:
- **The "Waiting for your ChatGPT plan to reset" text** the first time a foreground task waits, and its cheapest-route hint (ONB-9). The kernel logs no wait and has no admission class yet; it comes with RES-5b (#3928, spare draw), which adds the class, as a slice after it.
- **Paused, unconfirmed and security-notice lines** (`PLAN <plan> OFF`, consent, withdrawal; CLK-7). Those states are not built; each row that builds one adds its case to item 5's closed set.
- **Setting the reserve by text.** CH-11 has no control word for it; the L1 spec-diff is ONB-9-text (#3933).
- Pool lines for Muse or Grok: their routes are PLAN-muse and PLAN-grok (#1379, #1378).

## Lifecycle

| Stage | Page | STATUS |
|---|---|---|
| setup, plan just signed in | pool line "no reading yet", Kept 0% | nothing |
| first reading | figures | nothing below the reserve |
| at the reserve / limit | figures, reset time | item 3 or 4's line |
| after the reset | figures | line gone (the kernel's `pool.reset`) |
| lowering signed | "lowering to 0% from Tue 14:00", Cancel | the pending line; one text when logged |
| lowering live, or cancelled | the new reserve, or the old one | pending line gone |
| restart of agentosd | the same lines from the two reads; nothing kept in agentosd | the same |
| kernel or clerk unreachable | "Plan figures unavailable right now." in place of the lines | STATUS's existing kernel-unreached note; no pool line |

Integration owner: this row (agentosd wires both reads into the page and STATUS).

## Scope

`broker/cmd/agentosd/` (a new `planpools.go` and test: the reads, the line text, the reserve's begin and finish; STATUS's note hook), `broker/owner/kernelsock/` (`Pools`, `Reserve` with cosign and `ErrReserveSig`, `Spent`), `broker/localapi/` (the pool view and reserve op types and names), `broker/localsrv/` (the ops; ASSUMPTIONS), `broker/localui/` (the plan lines and the setting on the providers page), `broker/control/` only if STATUS needs a new note slot, `briefs/ONB-9a.md`.

**Guard files:** none (no new package).

## Acceptance tests

**Acceptance tests:**
- ONB-9: `broker/cmd/agentosd/planpools_test.go::TestPoolLineNamesEachWindowAsTheProviderDoes` (the SPEC example line from fake reads), `::TestPercentRoundsUpFromPerMille`, `::TestAPoolWithNoReadingSaysSo`, `::TestFarResetShowsTheWeekday`.
- ONB-9, RES-5: `::TestStatusAtTheReserveSaysWhetherAnythingRuns` (with and without a serving API key), `::TestFailoverLineNamesTodaysAPISpend` (plan routes' spend not counted; spend before local midnight not counted), `::TestStatusLineGoesAtTheReset`.
- ONB-9, CLK-7: `::TestAnUnswappablePlanSaysOnlyAnUpdateBringsItBack`, `::TestAnUnknownStopIsStillALine`.
- KEY-6, KEY-4: `::TestRaisingTheReserveTakesTheSessionOnly`, `::TestLoweringTheReserveTakesAPasskeyTap` (no assertion, or one over another change, lowers nothing), `::TestABigLoweringAsksForTheHardwareKey`.
- KEY-4: `::TestAPendingLoweringShowsItsTimeAndCancels` (the page line, the STATUS line and the one text; Cancel raises back to the current reserve and the pending line goes).
- `broker/owner/kernelsock/kernelsock_test.go`: the three calls against the real `kernel/proc` handler, `ErrReserveSig` matched by its text.
- `broker/localsrv/` op tests: the ops need a live session; a percent outside 0 to 100 is refused before any kernel call.
- `broker/localui/` page test: the lines and the setting render from a fake view, escaped.

UX lens recurring kinds for owner-facing text (`reviews/ux/README.md`) are acceptance criteria: every line says what to do or that nothing is needed, and names times the owner can read.

## Resolved: the text path

The open point asked on #1005 (comment 6506144212) is agreed as a spec gap (L3 on #3930, comment 6506184326). This row builds the page path only, and ONB-9-text (#3933) is the L1 spec-diff for a raise-only control word.

## Estimate

About 95k tokens, one session (Opus, tier A).
