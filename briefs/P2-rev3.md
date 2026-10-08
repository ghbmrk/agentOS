# P2-rev3: Reversible conversions

Board section: Phase 2: real hardware, and the cloud parts first.

Reversible conversions: an owner-approved irreversible effect whose adapter declares a form is held for its undo window with `UNDO <id>` and the run time in the approval's confirmation, staged first as an inert draft or staging copy where declared (sent at release only if unchanged), and cancelled (and unstaged) by UNDO or a restart; pre-allowed effects and secrets are never held (REV-3, CH-16, REV-2) ([assumptions](../broker/reversible/ASSUMPTIONS.md)). Carry-forward: adapters (P2-6, P2-7, mail #69) declare `grants.Config.Forms` next to `Declared`, and implement inert stages, an inverse guarded by the provider's version or etag precondition, and the checked completion (gone = cancel; edited = not sent, owner told) (RV7); the updater's planned restart waits until no held effect remains, bounded by the longest window (UX-76-2); a boot sweep unstages each succeeded stage with no inverse whose parent has not succeeded, covering a stage in flight at a crash and a STOP-held release carried over a restart (RV11, L3 F2); effect shadow runs wait on an adapter sandbox (RV1); GR8 (a concurrent Dispatch on the same ID can start a second attempt before `spend` runs; L3 on #76, also on main before it) must be fixed before the first adapter declares a `reversible.Form`, and before the guest plane is wired to the gate with concurrent Dispatch, whichever comes first: the approval is used up inside the dispatch commit with an attempt count checked at PhaseDispatch, with a -race stress test showing 0 double attempts in N (Security ruling); done in P2-gr8

**Needs:** P2-grants

**State on the board before the 2026-10-08 index split:** in review
