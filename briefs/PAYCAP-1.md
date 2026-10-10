# PAYCAP-1: A spending limit set outside the box

Board section: Outside-the-box limits (2026-10-10).

**Why.** Every money control in SPEC is enforced by the broker: OP-8 meters model spend, CH-10 sets the owner's amount limit for the low-risk tier, and ADP-9 caps pre-allowances. If the broker is compromised, all of them fail together. A limit set by the owner's bank sits outside the box and holds either way. Mark asked for this on 2026-10-10 (Questions thread) with one constraint: the limit adds no friction in normal use and bites only in the "in case" scenario.

**What.** The box pays with one card whose spending limit the owner's own bank or card provider enforces. The owner sets the limit there, once, well above normal use, and gives the box that card in place of a main card. Examples, none required: a second debit account holding only a small balance, a low-limit credit card, or a limited virtual card from the owner's existing bank. No merchant lock: per-merchant cards are too much work for the owner (Mark, 2026-10-10), and the broker's own rules already decide where money goes. The box never talks to the bank or card provider, and never creates cards or changes a limit: anything that can mint cards or raise limits can mint uncapped ones, which would put the backstop back inside the box. The box sees only the card number and the limit the owner types. It cannot verify that limit, so it uses it only to confirm back to the owner and to word the decline line.

No card provider is named in SPEC, the row or the tests (a named provider is a dependency and a security risk, Mark, 2026-10-10).

**Intended UX.**
1. No setup step. The card is asked for just in time, the first time a task needs to pay (as SPEC's setup step 8 does for other grants); ONB-3 is unchanged.
2. The Wi-Fi page offers "Use a card with a spending limit set by your bank" (recommended), or "my own card" with the one line "no limit outside the box". The owner enters the number and the limit, then confirms with an approval code (a CH-10 high-risk grant). Card details are entered only there, never by text (CH-6).
3. A text confirms the card's last four digits and the limit.
4. Day to day nothing changes.
5. A decline at the limit becomes one digest line, with no prompt and no retry.

**No friction.** The box asks for nothing in normal use. When the bank declines a charge (limit reached), the box does not prompt. It reports the decline as one line in the next digest (CH-15, OP-9 wording rules), with what would fix it (raise the limit with the bank). The box holds no credential that can change the limit.

**Proposed requirement text (for a spec-diff PR, not edited here).** The payment card the box holds MUST carry a spending limit set and enforced outside the box; the box MUST NOT hold a credential that can create cards or change that limit; a decline at the limit MUST reach the owner as a digest line, not an approval prompt.

**Needs:** none (documentation and owner setup first). The code part waits on the broker holding a payment credential at all (CRED-1 custody applies); no row builds that yet.

**Tier for the build: A.** The card number is a credential the broker holds (CRED-1), and the work sits beside the money controls CH-10 and OP-8 (`tools/risk_tier.py` rates `broker/` credential paths A). A docs-only slice (the Wi-Fi page copy and the decline wording) would be B or C.

**Failure path to test first:** a charge the card's limit declines, with the broker's own spend checks mocked as passing, shows in the digest as one line and the box takes no further action (no prompt, no retry).

**Scope:** to be set when the brief is expanded.

**Gate:** Security lens first (nothing in the box can change the limit or create a card; the card number is entered only on the Wi-Fi page).
