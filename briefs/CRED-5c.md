# CRED-5c: Consent ask placement and wording for unconfirmed broker-held routes

Board section: Phase 0: harness and risk spikes.

Source: the #328 combined lens record (`reviews/combined/2026-10-08-pr328.md`, S1+U1+U2) and #421 L3 point 5. CRED-5 says when consent for an unconfirmed broker-held route is asked (at connection, when a route becomes unconfirmed, and on resuming one, #421), but not where or at what tier.

- Name the consent ask's channel and tier, and journal the consent record so a pause or withdrawal can cite it. An unconfirmed route is not granted until consent stands, so the ask sits at CH-10's tier for new or wider grants; the low-tier resume code (CRED-5) binds only confirmed routes and refused-login resumes.
- §8 step 6: show the ask right after an unconfirmed plan's sign-in, outside **Use the defaults** (which never records consent), and correct the "I use your plans first" line for an unconfirmed plan without consent.
- Name the route resume command (CRED-5, CH-11) in SPEC's control-word list. When a bare RESUME arrives with no halted work while a route is paused, the reply names that command (#421 lens screen, release).
- Mid-life ask: one digest line naming the plan and the choice, e.g. "ChatGPT plan paused until you say yes; using your other routes meanwhile", and the same state on ONB-9's per-plan line.

- **Notice-paused route (lens, #421, decision for Mark).** CRED-5 does not say whether the owner can resume a route a security notice paused. Recommended: a notice-paused route counts as withdrawn on that box and cannot be resumed; its STATUS line says only an update brings the plan back (see LATER `CRED-5t-msg`). The alternative lets the owner run a route the provider prohibits.
An L1 spec-diff (SPEC.md changes need Mark's approval), plus a test that **Use the defaults** never records consent.

**Requirements:** CRED-5, CH-10, CH-11, ONB-9

**Needs:** #421 merged
