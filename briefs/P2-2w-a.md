# P2-2w a: `localui.sock` in agentosd

Board section: Backlog refill (2026-10-05).

`localui.sock` in agentosd (`localapi`, `localsrv`): agentosd mints and checks the page's session token, counts refused codes for the socket, bounds every field, untokened only status, STOP, grid cell and sign-in; RESUME past 15 minutes takes a code; opt-in `-localui-uid` (Security L1-L4, L9, S1, S2 option B; Potency R2, R3; carry in [localui L25](../broker/localui/ASSUMPTIONS.md))

**Needs:** P2-2a

**Gate:** lenses (security: new process boundary)

**State on the board before the 2026-10-08 index split:** in review (P3-2 thread)
