# OSS-6p: Relay count, delivery rule, queue bound, relay list source

Board section: Backlog refill (2026-10-05).

Release finding 4 of the L3 review on #330. OSS-6 gives no values for "several relays" or "dropped at the queue bound". Set the minimum relay count per batch, how many acknowledgements count as delivered, the queue bound, and where the relay list comes from (for example pinned in the image and changed only through UPD). The values go in the OSS-6s brief and its ASSUMPTIONS.md; the spec or an ASSUMPTIONS row names the source of the relay list. Requirement IDs: OSS-6, UPD-2.

**Needs:** #330 merged

**Gate:** L3; lenses (security, privacy)
