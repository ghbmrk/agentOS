# W5b: Loop 3 update checks

Board section: Integration: wiring merged packages into the box.

Loop 3 update checks (#53) as a scheduler Source: PM1 (a hidden security release is still surfaced) and PM2 (soak counted from first sight on the fast channel). Conditions (maintain M12): `maintain.New` with the box's locked `update.Store`, the owner's mirrors, network state from the modem or Wi-Fi (`Online` required, security C4), the scheduler's `Settings`, the channel setting, the pipeline and a `change.FileStore`; add it to `loops.Config.Sources`; `Status().Line` in STATUS and on the local page; adding an owner attestor is a high-tier owner action (code plus local page); `maintain.Config.Attestors` is the one source of the allow-list and interim keys, read from the owner's setting at each call (SR3-6f-1, maintain M12), and every write of that setting calls `Loop3.AttestorsChanged`, which notes it with `update.Store.NoteAttestors` (first boot passes no attestors); channel changes (UPD-4) come through the owner channel; box clock from authenticated time (TIM-1) ; and the applier from UPD-a (#133), per `apply/ASSUMPTIONS.md` A1, A6, A7: gate delegation of `meta.release`, `update` executor and origin reserved to the applier, `Working` counting only the owner's work, a security fix asked about once after 24 hours not free, Loop 3's status corrected after a fallback with a way for the owner to retry

**Precondition:** #53 merged, W3, network state (P2-3 modem or Wi-Fi), and the before-W5b follow-ups merged: SR3-4-f2 and f5 (package SR3-4f-1), SR3-4-f3, f4 and SR3-6-f3 (SR3-4f-2), SR3-6-f1 (SR3-6f-1). Those packages add their wiring lines to this brief.

**Owner:** Loop 3 thread (P3-5)

**State on the board before the 2026-10-08 index split:** queued
