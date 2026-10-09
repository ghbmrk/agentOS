# CH-20w: Evidence delivery

Board section: Integration: wiring merged packages into the box.

Evidence delivery (CH-20): the vault process runs the mail adapter with its redactor (`mail.Config.Redact`); the gate declares `mail.deliver` (`Config.Declared`, `Config.Delivery`) and agentosd gets a `mailbox` (the account's own and main addresses) so EVIDENCE ON/TO can be set and replies are redirected; the guest bridge passes the agent's `summary`; the digest's sender carries `evidence.digestLines`; a set destination with mail not connected shows one STATUS line (potency C2); the summary also passes CH-21's check once #141 lands; the ADP-13 box mailbox is wired with `mail.Config.Box` so it is never a destination. From L3 on #148: once the vault redactor replaces `redactAll`, keep reply bodies out of the journal or redacted, and keep the destination's params readable so it survives restarts (GR15); redact vault values in the texted summary and the kept-replies file too (CRED-7); Loop 1 already skips broker-origin intents. Until then nothing can be set and every reply goes by text, as before (UX U1)

**Precondition:** CH-20 merged; P2-6m wired into the vault process

**Owner:** —

**State on the board before the 2026-10-08 index split:** queued, blocked on mail wiring
