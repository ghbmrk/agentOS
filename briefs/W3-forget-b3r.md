# W3-forget-b3r: The local Wi-Fi page lists older tasks and can forget one

Board section: Integration: wiring merged packages into the box. Carried from W3-forget-b3 (briefs/W3-forget-b3.md); SPEC CAP-3, CH-7, CH-8.

**Sources:** potency R2 (carried by W3-forget-b3); L3 on #425, first round, finding F8 ("release, agreed"): the page needs a new page, a socket route and a forget path in `broker/localui`, outside W3-forget-b3's files.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): deletion requests propagate; the owner is told when the forget is done, and only after the save. A forget started from the page follows the same order as a texted one (owe the text, save the tombstone, then tell), through the existing `ownerForget` path in `broker/cmd/agentosd/forget.go`. The page adds no second forget implementation.
- **CH-7, CH-8** (SPEC): the local page needs sign-in (localui ASSUMPTIONS L3); a page mounted with `Mount` is signed-in only.
- **R2** (potency): older tasks are listed so the owner can pick one; a texted forget needs the task's words, and the page needs none.

**Needs:** W3-forget-b3 (merged)

**Work:**
1. A signed-in page lists older tasks: a date and a short label per task, newest first. It shows no more than the task list the box already keeps for the owner.
2. A forget button per task posts to a new socket route; the route calls the same forget executor as the texted path and answers with fixed text.
3. The forget form is a POST with the page's existing CSRF/`post` guard (`s.post`). A GET never forgets.
4. The done text still goes by the owed-text path W3-forget-b3 built (told only after the save; a failed send stays owed). The page shows "asked", never "forgotten", until the text path reports the save.

**Not in this package:** a backup-delete pointer in any text (until P2-2w); folding the owed stores (LATER W3-forget-b3 rr2); any change to W3-forget-b3's owed-text logic.

**Tests (write first, each with a `REQ:` marker):**
- Signed-out request to the list and to the forget route is refused; the page lists nothing and forgets nothing.
- A GET to the forget route forgets nothing.
- A signed-in POST for a listed task runs the forget once and writes the owed entry before the tombstone (the b3 order test, driven through the route).
- A POST for an unknown or already-forgotten task id forgets nothing and says so in fixed text.
- The list and every page text hold no task words other than the label the box already shows the owner; a synthetic canary in a task body never appears in logs.
- A failed save says the task was not forgotten (briefs/W3-forget.md).

**Scope:** `broker/localui/` (new page, route, tests, ASSUMPTIONS.md), the socket route's wiring in `broker/localsrv/`, and the narrow hook in `broker/cmd/agentosd/forget.go` that exposes the forget executor to the route. Nothing else.

**Gate:** tier A (`tools/risk_tier.py` prints A for `broker/localui/`, `broker/localsrv/` and `broker/cmd/`): L3 on the strongest model with a threat check, lens screen with a Security section, Security re-sign on later deltas (OPERATING §3-4).

**Threat check to answer in the PR:** who can reach the route (signed-in local device only), what a replayed or cross-site request can do (nothing without the guard), what the list reveals on a shared Wi-Fi (nothing before sign-in), and whether the route can forget a task the owner never approved (it can only forget what the signed-in owner picks, which is what a YES by text does).

**Estimate:** under 120k tokens on the strongest model. Builder model: strongest (tier A).
