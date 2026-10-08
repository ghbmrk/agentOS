# P2-gr8: GR8 fix: approval used up inside the dispatch commit

Board section: Phase 2: real hardware, and the cloud parts first.

GR8 fix (Security ruling on #76): the gate uses an owner approval up inside the dispatch commit, with an attempt count checked at PhaseDispatch, so a concurrent `Dispatch` on the same ID never starts a second attempt; `-race` stress test shows 0 double attempts in N. Deadline: before the first adapter declares a `reversible.Form` or the guest plane is wired to the gate with concurrent Dispatch (OP-3, OP-4, REV-3)

**Needs:** P2-rev3

**State on the board before the 2026-10-08 index split:** in review
