# PE4: Preempted Loop 2 fix proposal

Board section: Integration: wiring merged packages into the box.

Follow-up (L3 on #103): a Loop 2 fix proposal preempted mid-evaluation (`secure.go` `Propose` returning `change.ErrInterrupted`) is recorded with an empty fix and never retried; keep the finding's fix pending and offer it again, reusing the fixer's candidate as Loop 1 does (loops L19)

**Precondition:** PE1, P3-4

**Owner:** Next build item A

**State on the board before the 2026-10-08 index split:** in review (#112)
