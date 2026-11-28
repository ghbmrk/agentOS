# ENF-light-f2: page words for a trip the owner cannot clear

Board section: Devices, hardware and image (SPEC §13-14). Work item #6011, a release finding from the ENF-light-f1 build (#4305, PR #6012).

**Problem, checked on main b97a19d0:** since ENF-light-f1, `alert.Resolve` refuses `Trip`, `RecordMissing` and `ChannelPaused`, and `broker/cmd/agentos-enforcer/state.go` marks all three `Fixed`, so the page offers no clear on them. Two page strings still describe the old behaviour:
1. `broker/enforcer/page/templates/home.html` line 11 tells the owner the red light "goes off when the cut lifts or you clear its alert below". No alert that lights the light has a clear.
2. `broker/enforcer/page/status.go` `errFixed` answers a clear drawn on any `Fixed` alert with "this alert clears when the channel resumes". For an edge trip or an edge missing record that names the wrong step. Failure path: the owner with a red light from an edge trip reads "clear its alert below", finds no button, and a crafted clear request is told to resume a channel that is not paused, so the edge stays cut with no step named.

**Requirements:** KRN-12 (Response), NET-2 (Texts and calls).

1. The red-light line names the only way the light goes off: the cut lifting, by lifting the edge's cut or resuming the core's channel with the passkey on this page. It offers no clear.
2. `errFixed` names both real steps, so it is right for every `Fixed` kind (a paused channel and a core trip close on resuming the core's channel; an edge trip or edge missing record on lifting the edge's cut). The page's `Alert` carries no kind, and the ENF-light-f1 call-site test pins every lighting alert to `coreDevice` or `edgeDevice`, so these two steps are the whole list. A per-kind answer would add a field crossing from `broker/cmd/agentos-enforcer`; the generic answer the work item allows needs none.

**Scope:** `broker/enforcer/page/templates/home.html`, `broker/enforcer/page/status.go` (`errFixed` only), `broker/enforcer/page/zz_light_words_test.go` (new), this brief.

**Acceptance tests:**
- KRN-12: `page::TestRedLightNamesTheLiftStep`. With the light red, home names lifting the edge's cut and resuming the core's channel and contains no "clear its alert". Catches the line that sends the owner to a clear that does not exist.
- NET-2: `page::TestFixedClearNamesBothSteps`. A clear drawn on a `Fixed` alert gets 409 with words naming both steps and not "when the channel resumes" alone. Catches the answer that names the wrong step for an edge trip.
