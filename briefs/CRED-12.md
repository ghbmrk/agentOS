# CRED-12: Computer-use retry before the owner

Board section: Backlog refill (row next to ADP-5).

**Why.** Mark decided (2026-10-10, Questions thread): "Computer use attempt should be an attempt between failure and bothering owner." When the credentialed executor (CRED-4b) fails a step because a site refuses automation, the box retries that step once by computer use before the owner hears about it. The spec text is CRED-12 in SPEC.md §7.3, added by the spec-diff PR that carries this stub; this brief does not restate it.

**Ladder.** Executor step fails (block page, bot-protection status, unresponsive control) → one computer-use retry of the same step → owner (a human check waits for the live view and is listed in the digest; anything else is one digest line). A page that shows a human check skips the retry.

**What to build (to be expanded).**
- A computer-use mode for the CRED-4b browser in the same sandbox and profile: restart without the remote-debugging endpoint, webdriver flag or automation extension; input through the sandbox's own virtual display; reads through the OS accessibility tree (AT-SPI on Linux) and screenshots. Reuse ADP-5's kiosk driver rather than a second input stack.
- Request-level binding: the retry inherits the failed step's authorization (its matched operation's declared requests once each, or none beyond declared background requests). Click hit-testing against the accessibility tree refuses a click on a different submit control. Unknown-recipe pages keep ADP-14's unknown-submit approval.
- Failure classifier for "the site refused automation" versus other failures; only the first class triggers the retry.
- Journal entry per retry; one digest line per site; per-site and global off switch (CH-11).

**Step 0 (before code).**
1. Confirm a Chromium build with no debugging port still exposes a usable AT-SPI tree for web content on the box's Linux base, including role, name and bounds for form controls.
2. Confirm the egress proxy that enforces ADP-14 request matching sees computer-use traffic identically (same sandbox egress), so no matching moves into the browser.
3. List which automation markers the CRED-4b browser exposes today (navigator.webdriver, CDP runtime traces, headless traits) and check each is absent in computer-use mode against a public fingerprinting page in a fixture.

**Failure path to test first:** in computer-use mode, a click that the accessibility tree resolves to a submit control other than the step's matched one sends no request, and a state-changing request outside the matched operation is blocked and journaled (A13, CRED-12, ADP-14).

**Open (later, recheck):** whether routing (ADP-4) may learn to start a site's steps in computer-use mode. Mark's ladder places it only after a failure, so this stays out unless Mark decides otherwise.

**Needs:** CRED-4b part 2 (the executor), ADP-5 (kiosk driver), ADP-14a (recipe matching and the request gate).

**Tier for the build: A.** It changes how the credentialed executor is driven and where submit authorization is enforced (CRED-10, ADP-14, CH-21).

**Gate:** Security lens first (no state change outside the step's authorization; no off-origin navigation; human checks never answered; CRED-10 withholding on screenshots).

**Scope:** to be set when the brief is expanded.
