# W3-forget-b3r: The local Wi-Fi page lists older tasks and can forget one

Board section: Integration: wiring merged packages into the box. Carried from W3-forget-b3 (briefs/W3-forget-b3.md); SPEC CAP-3, CH-7, CH-8.

**Sources:** potency R2 (carried by W3-forget-b3); L3 on #425, first round, finding F8 ("release, agreed"): the page needs a new page, a socket route and a forget path in `broker/localui`, outside W3-forget-b3's files.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): deletion requests propagate; the owner is told when the forget is done, and only after the save. A forget started from the page follows the same order as a texted one (owe the text, save the tombstone, then tell), through the existing `ownerForget` path in `broker/cmd/agentosd/forget.go`. The page adds no second forget implementation.
- **CH-7, CH-8** (SPEC): the local page needs sign-in (localui ASSUMPTIONS L3); a page mounted with `Mount` is signed-in only.
- **R2** (potency): older tasks are listed so the owner can pick one; a texted forget needs the task's words, and the page needs none.

**Needs:** W3-forget-b3 (merged)

**Work:**
1. A signed-in page lists older tasks: a date and a short label per task, newest first. The source is `ownerForget.tasks.recent(forgetList)` in `broker/cmd/agentosd/forget.go`, the same list a texted `FORGET` shows, labelled by `shown`. The `forget.go` hook adds a lister the route reads (goal ID, date, label) and nothing else, so the page can list only tasks the owner could forget by text.
2. A forget button per task posts to a new socket route carrying the goal ID only. The route calls `ownerForget.ask`, as texted `FORGET n` does, so the gate's owner request (YES) still comes before anything is deleted; the page adds no direct path to `forgetTask`. It answers with fixed text.
3. The forget form is a POST. `s.post` only checks the method and caps the body at 16 KiB; cross-site protection is `sameOrigin` (Sec-Fetch-Site and Origin) plus SameSite=Strict cookies, applied to every POST in the server's top-level handler. The route sits behind `signedIn` and `s.post`, and the page adds no weaker check. A GET never forgets.
4. **Locked vault.** `Text` serves `FORGET` only when `unlocked` is true (`forget.go:228`; it lists the owner's own texts and the ask deletes their data). The hook applies the same condition: while the session is locked the lister returns nothing and `ask` refuses, and the page shows fixed text saying so. The hook takes the same unlocked signal `Text` is given; the page adds no weaker rule.
5. **Locking.** `Text` holds `f.mu` for its whole path, and `ask` does `f.seq++` relying on that lock. The route runs on an HTTP goroutine, so the hook takes `f.mu` as `Text` does (or exports a wrapper that does); the page never calls `ask` bare.
6. The done text still goes by the owed-text path W3-forget-b3 built (told only after the save; a failed send stays owed). The page shows "asked", never "forgotten", until the text path reports the save.

**Not in this package:** a backup-delete pointer in any text (until P2-2w); folding the owed stores (LATER W3-forget-b3 rr2); any change to W3-forget-b3's owed-text logic.

**Tests (write first, each with a `REQ:` marker):**
- Signed-out request to the list and to the forget route is refused; the page lists nothing and forgets nothing.
- A GET to the forget route forgets nothing.
- A signed-in POST with a cross-origin `Origin` or `Sec-Fetch-Site: cross-site` header is refused (403) and submits no forget.
- A signed-in POST for a listed task submits one forget request and deletes nothing until the owner approves it; once approved, the owed entry is written before the tombstone (the b3 order test, driven through the route).
- While the vault is locked, the list is empty and a POST submits no forget, on the same condition `Text` uses.
- A `-race` test fires the route and `Text` concurrently: no race on `seq`, and every intent ID is distinct.
- The list holds only goals `tasks.recent` returns, so a task the owner could not forget by text never appears.
- A POST for an unknown or already-forgotten task id forgets nothing and says so in fixed text.
- The list and every page text hold no task words other than the label the box already shows the owner; a synthetic canary in a task body never appears in logs.
- A failed save says the task was not forgotten (briefs/W3-forget.md).

**Scope:** `broker/localui/` (new page, route, tests, ASSUMPTIONS.md), the socket route's wiring in `broker/localsrv/`, and the narrow, additive hook in `broker/cmd/agentosd/forget.go` that exposes the task lister and `ask` to the route. W3-forget-b4 (S1-S3) edits `learn.go` and `Execute`/`retry`; this hook adds new methods only and touches neither, so the two land in either order. Nothing else.

**Gate:** tier A (`tools/risk_tier.py` prints A for `broker/localui/`, `broker/localsrv/` and `broker/cmd/`): L3 on the strongest model with a threat check, lens screen with a Security section, Security re-sign on later deltas (OPERATING §3-4).

**Threat check to answer in the PR:** who can reach the route (signed-in local device only), what a replayed or cross-site request can do (nothing: `sameOrigin` and SameSite=Strict refuse it, and it could only submit an owner request), what the list reveals on a shared Wi-Fi (nothing before sign-in, and nothing while the vault is locked), and whether the route can forget a task the owner never approved (it can only submit a request for what the signed-in owner picks, and nothing is deleted until the owner approves, as with a text).

**Estimate:** under 120k tokens on the strongest model. Builder model: strongest (tier A).
