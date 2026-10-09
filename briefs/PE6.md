# PE6: Default -capacity-mb

Board section: Integration: wiring merged packages into the box.

Follow-up (R1 on #114): default `-capacity-mb` = min(4500, MemTotal − host − inference − browser), read at start and logged; the N95 pool is about 3496 MB, not 3900, so admission can over-commit today

**Precondition:** PE2

**Owner:** Next build item D

**State on the board before the 2026-10-08 index split:** merged (#118)
