# PE5: Count only real interruptions toward MaxInterruptions

Board section: Integration: wiring merged packages into the box.

Follow-up (potency on #111): count toward change `MaxInterruptions` only the interruptions a candidate could cause: pressure-driven ones (scheduler `Busy` from PSI, `admission.ErrPressure`), ideally only with the candidate's machine the largest consumer; never a preemption for accepted work arriving. Needs the cause carried through (scheduler `context.WithCancelCause`, admission's preemption reason). Weakens security F1 on #103 if done loosely, so it needs a security check and the arbitrator. Interim option: cap 3 and log the cause per interruption

**Precondition:** PE3

**Owner:** Next build item B

**State on the board before the 2026-10-08 index split:** in review (#127); owner-work dormant until `Request.Owner` is set; setting it needs PE5b
