# PE3: Replay machine admission refusal interrupts, not fails

Board section: Integration: wiring merged packages into the box.

Follow-up (potency on #103): admission refusing or preempting a replay machine while the run's context is still live counts as interrupted (no verdict, keep finished sides, change C15) rather than a failure on that side; only a guest timeout fails (replay R6). Keep the C15 per-case limit on candidate-side interruptions. UX note on #103: if evaluations keep getting preempted, say so on the digest's loop line ("learning paused by busy time")

**Precondition:** PE1

**Owner:** Next build item D

**State on the board before the 2026-10-08 index split:** building
