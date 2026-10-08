# P2-2w d2b: Page control to confirm a SIM swap and set up the owner number

Board section: Backlog refill (2026-10-05). Split from P2-2w d2 (2026-10-08).

A signed-in page control to confirm a SIM swap (the bridge records the new owner-line ICCID, today read from `agentos-modem`'s roles file at start, so this needs a bridge op agentosd can ask and the bridge can refuse) and to set up the owner number when the line is unbound, so the notes' "on my Wi-Fi page" and the home page's "below" point at something that exists. Confirming a swap re-opens the owner channel to a new SIM, so it takes a code-generator code or grid cell like RESUME past `FreshFor` (CH-19: a SIM swapper holds no such code). Check overlap with P2-2w c2 (setup in agentosd) before starting.

**Requirements:** CH-1, CH-7, CH-19

**Needs:** P2-2w d2a

**Gate:** lenses (UX, security)
