# PE5b: Bound owner-exempt cuts per candidate

Board section: Integration: wiring merged packages into the box.

Follow-up (security B2 on #127, MUST-2 option a): bound owner-exempt cuts per candidate across passes and restarts. After 2 exempt cuts of the same (candidate, case), the next cut counts as a normal interruption under F1 (`MaxInterruptions` 2); the per-(candidate, case) count is persisted with the kept pairs (`ResumeFor`), so a restart cannot reset it; the idle pass skips a candidate parked in this pass or the previous one unless no other candidate is waiting. Tests: the third exempt cut counts; the count survives a restart; a parked candidate is not picked again straight away while another waits. Gate: lands before PE7 and before anything sets `admission.Request.Owner`

**Precondition:** PE5

**Owner:** Next build item B

**State on the board before the 2026-10-08 index split:** in review (#145); blocks PE7 and any `Request.Owner` setter
