# W5a: Loop 2 passive checks

Board section: Integration: wiring merged packages into the box.

Loop 2 passive checks (#54) as a scheduler Source: K-S1, K-S2 (loop2-origin grant pause needs origin auth), and PS1 (a regression fixture stays must-not-regress while its finding is open)

**Precondition:** #54 merged, W3

**Owner:** builder B (lenses)

**State on the board before the 2026-10-08 index split:** in review (#169; Security signed): K-S2 pause origin, PS1 grading (change C24), Urgent cadence, guard wired as a source with an empty Box; K-S1, Box inputs and MORE wait on W5b, the advisory feed, vault metadata and W5 (loops S9). **FixturesLive gate (Security L3, amended):** before `FixturesLive` turns on, a test must prove only the Guard's `AddSecurityCase` can create or change a `loop2/` case; a Guard-generated fixture counts as trusted. **L6 carries** to the drift-wiring PR. Hard conditions before the first Box input lands: UX W1 (per-alert MORE IDs) and W5a-resume. Follow-up (L3 S1/S2 on #169) on pkg/next-item-b.
