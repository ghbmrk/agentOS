# Cancellable fixed owner notices (unenabled candidate)

`InformContext` uses the existing configured owner, `Disclose` and `control.Fit`
checks for a broker-owned fixed-wording notice. Agent-composed text continues to
use Notify; this entry point is not a disclosure exception. Secret-shaped text
becomes the existing local pointer. Nil or already-cancelled contexts refuse
before invoking a modem. A modem without ContextSender is refused; no blocking
legacy Send fallback is attempted. Existing Inform is unchanged.

The watched modem delegates context sends and records an attempted send's error
in lineFailed, just as Send does. Auto-reply timing must not interpret failed
owner contact as owner silence. Capability refusal before an actual send is not
a line failure. Cancellation can occur after bridge handoff: inspect the
transport error's evidence; never infer remote undo or non-delivery from a
cancelled wait. Neither a successful send nor its nil error establishes owner
visibility, acceptance, an effect outcome or permission.

This is a single-text capability, not a digest dispatcher. Fit can truncate or
sanitize input. A future digest sender must render a complete bounded reviewed
summary or segment it with explicit associations; it must not acknowledge full
batch delivery after silently cutting lines. Source receipts stay private.
Cadence, STOP, quiet hours, priority, shared pacing, resource admission, current
source eligibility, queued forget reach and durable outcome classification need
assembled tests and independent broker/security review before wiring.
