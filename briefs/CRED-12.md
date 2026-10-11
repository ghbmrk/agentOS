# CRED-12: Computer-use retry before the owner

Board section: Backlog refill (row next to ADP-5).

**Why.** Mark decided (2026-10-10, Questions thread): "Computer use attempt should be an attempt between failure and bothering owner." When the credentialed executor (CRED-4b) fails a step because a site refuses automation, the box retries that step once by computer use before the owner hears about it. The spec text is CRED-12 in SPEC.md §7.3, added by the spec-diff PR that carries this stub; this brief does not restate it.

**Ladder.** Executor step fails (block page, bot-protection status, unresponsive control) → one computer-use retry of the same step → owner (a human check waits for the live view and is listed in the digest; anything else is one digest line). A page that shows a human check skips the retry.

**What to build (to be expanded).**
- A computer-use mode for the CRED-4b browser in the same sandbox and profile: restart without the remote-debugging endpoint, webdriver flag or automation extension; input through the sandbox's own virtual display; reads through the OS accessibility tree (AT-SPI on Linux) and screenshots. Reuse ADP-5's kiosk driver rather than a second input stack.
- Request-level binding at the sandbox's egress, outside the browser process: a TLS-terminating gate applying ADP-14's request rule and refusing undeclared top-level navigations (`Sec-Fetch-Dest: document`); UDP/QUIC and WebRTC blocked; the mode fails closed without the gate. The retry inherits the failed step's authorization, with "once each" counted across both attempts, and a step whose state-changing request was already forwarded (and not refused before processing) is never retried.
- Browser policy: developer tools off, internal and `file://` schemes blocked, downloads confined to the workspace; a closed key and chord set filtered before the display.
- Click hit-testing against the accessibility tree refuses a click on a different submit control or in a recognized human-check widget; it is advisory, the egress gate is the boundary. Type only after re-checking focus (a page can move focus between fields).
- Unknown-recipe pages keep ADP-14's unknown-submit approval, with labels read from the accessibility tree at the activating click and quoted as site text.
- CRED-10 detector on accessibility text plus OCR of each screenshot; an unreadable screenshot is withheld.
- Failure classifier for "the site refused automation" versus other failures; only the first class triggers the retry.
- Journal entry per retry; one digest line per site ending with the off phrase; per-site and global off by CH-11's configuration path (fixed-wording readback, `YES`) or the Wi-Fi page; re-enabling needs a code-generator code (CH-3 row).

**Step 0 (before code).**
1. Confirm a Chromium build with no debugging port still exposes a usable AT-SPI tree for web content on the box's Linux base, including role, name and bounds for form controls.
2. ADP-14a's request gate may be built inside the browser (request interception), which this mode removes. Confirm or build the out-of-browser egress gate described above, and that the sandbox has no other egress; without it the mode stays off.
3. List which automation markers the CRED-4b browser exposes today (navigator.webdriver, CDP runtime traces, headless traits) and check each is absent in computer-use mode against a public fingerprinting page in a fixture.

**Failure path to test first:** in computer-use mode, a click that the accessibility tree resolves to a submit control other than the step's matched one sends no request, and a state-changing request outside the matched operation is blocked and journaled (A13, CRED-12, ADP-14).

**Release (from the #1027 L3, R1):** a browser restart loses in-page state, so a multi-step checkout can lose its cart and every retry fail (A13 "completes the same step"). The expanded brief says whether the retry restores the session and replays steps since the last navigation, each replayed step under its own bounds.

**Open (later, recheck):** whether routing (ADP-4) may learn to start a site's steps in computer-use mode. Mark's ladder places it only after a failure, so this stays out unless Mark decides otherwise.

**Needs:** CRED-4b part 2 (the executor), ADP-5 (kiosk driver), ADP-14a (recipe matching and the request gate).

**Tier for the build: A.** It changes how the credentialed executor is driven and where submit authorization is enforced (CRED-10, ADP-14, CH-21).

**Gate:** Security lens first (no state change outside the step's authorization; no off-origin navigation; human checks never answered; CRED-10 withholding on screenshots; the hit-test and the click cannot be separated by a page change into an effect the egress gate would not also stop).

**Scope:** to be set when the brief is expanded.
