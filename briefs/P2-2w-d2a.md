# P2-2w d2a: Home page shows the owner line's note, last outage and counts

Board section: Backlog refill (2026-10-05). Split from P2-2w d2 (2026-10-08).

The signed-in home page (`/home`) shows `Link.OwnerLineNote`, `Link.LastOutage` with its counts by kind, and the bridge's counts (`Others`, `TimedOut`, `Dropped`) (U-B1, UX-170-1, P2-3w carry). The counts go over a new tokened `localapi` op, `page_line`; the untokened `page_status` keeps only the fixed note and carries no counts (Security D1). The notes' wording ("on my Wi-Fi page", the home page's "below") and the control they point at are P2-2w d2b.

**Requirements:** CH-7 (the local UI shows it, behind sign-in), CH-1 (the owner line's state)

**Scope:** `broker/localapi`, `broker/localsrv`, `broker/daemon` (PageSocket wiring), `broker/cmd/agentosd` (from the modem link), `broker/localui` (home page), `broker/localui/ASSUMPTIONS.md`

**Needs:** P2-2w d

**Gate:** lenses (UX, security)
