# PAYCAP-1: Spend limits the card issuer enforces

Board section: Outside-the-box limits (2026-10-10).

**Why.** Every money control in SPEC is enforced by the broker: OP-8 meters model spend, CH-10 sets the owner's amount limit for the low-risk tier, and ADP-9 caps pre-allowances. If the broker is compromised, all of them fail together. A card limit set by the issuer sits outside the box and holds either way. Mark asked for this on 2026-10-10 (Questions thread) with one constraint: the limits add no friction in normal use and bite only in the "in case" scenario.

**What.** The card the box is given to pay with is a virtual card the issuer has locked to named merchants and capped (a monthly total, and where the issuer allows it a per-charge cap). The owner creates it at the issuer once, at setup, with caps set well above normal use, and gives the box only that card. Candidates, to be checked against the issuer's own documentation in step 0:
- A merchant-locked virtual card with a monthly cap (Privacy.com-style).
- Agent-payment tokens scoped to merchant, amount and expiry (Stripe's), if consumers can obtain them. Stripe Link is out (Mark, 2026-10-10).

**No friction.** The box asks for nothing in normal use. When the issuer declines a charge (cap reached or wrong merchant), the box does not prompt. It reports the decline as one line in the next digest (CH-15, OP-9 wording rules), with what would fix it (raise the cap at the issuer). The box never raises a cap itself, and holds no credential that can.

**Proposed requirement text (for a spec-diff PR, not edited here).** The payment card the box holds MUST be capped by its issuer per merchant and per month, at limits the owner sets outside the box; the broker MUST NOT hold a credential that can change them; an issuer decline MUST reach the owner as a digest line, not an approval prompt.

**Needs:** none (documentation and owner setup first). The code part waits on the broker holding a payment credential at all (CRED-1 custody applies); no row builds that yet.

**Tier for the build: A.** The card number is a credential the broker holds (CRED-1), and the work sits beside the money controls CH-10 and OP-8 (`tools/risk_tier.py` rates `broker/` credential paths A). A docs-only slice (the owner's setup page and the decline wording) would be B or C.

**Failure path to test first:** a charge to a merchant not on the card's list, or past the cap, is declined by the issuer with the broker's own spend checks mocked as passing; the box reports it in the digest and takes no further action.

**Step 0 (builder):** read each issuer's current documentation for merchant lock, caps, who can change them, and whether a consumer can get the account. Record dates and results in the package's `ASSUMPTIONS.md`. If none fits, record that and mark the row `dropped`.

**Scope:** to be set when the brief is expanded.

**Gate:** Security lens first (the cap must not be changeable from the box).
