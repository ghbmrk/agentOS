# POT-P10: Qualify economical fork, test and keep

**Owner:** primary, unclaimed. **Class:** release for existing A15 qualification; artifact transport extension later unless measured necessary. **Tier:** A when worker custody/admission changes.
**Requirements:** CAP-1/7/8, RES-2, OP-8, REV-1/2/5, A15.
**Needs:** CAP-8/CAP-1 and actual host admission, POT-P1/H6 measurement, qualified guest/worker images. Reuse existing fork/diff/rollback/keep tools; no new orchestration substrate.

Freeze one workload where independent implementation plus independent review is useful. Add a guest procedure and real floor-host qualification to the existing worker harness. A fake runtime with no quota does not establish throughput, nor does eight concurrent machine records establish eight accepted useful results. Admission determines practical concurrency, including sequential progress at the floor.

Acceptance: ≥8 workers through the specified A15 sequence within real limits; private inheritance; all branch model spend reserved and counted; spare preemption yields to foreground; a killed branch has no successful result; the kept result meets an independent oracle. Tests passing never authorize an external effect. Compare accepted-task time and owner effort against sequential and direct CLI baselines.

Only if measurement identifies artifact transfer as a bottleneck, split a later proposal for broker-held bounded artifact handles/manifests. That extension must bind current machine/task/label/version, count quota, revoke on deletion and honor STOP; it cannot turn a handle into authorization. Do not silently start it with this qualification row.

Declare exact existing worker/e2e fixture paths in the implementation brief. Tests first, Linux/race and floor-host results, strongest-model L3/threat check and separate Security/lens passes. Initial checkpoint: 25k tokens per qualification slice.
