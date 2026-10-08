# POT-P6b: Route by trusted accepted-task outcomes and total cost

**Owner:** primary, unclaimed. **Class:** release, A10/A15. **Tier:** A when task, budget or adoption wiring changes.
**Requirements:** CAP-9, ADP-4, CHG-1/2, LOOP-5/6, OP-7/8, REV-5; D-039's no-dearer-route ceiling.
**Needs:** POT-P6, POT-P2/P3/P3b, qualified provider-version identity and existing modelroute/vault structural adoption checks.

The first P6 slice isolates transport measurements. HTTP success and time to headers remain explicitly different from task acceptance and completed-task latency. Do not mark CAP-9 scoring complete on that slice.

## Scope and acceptance

1. Use broker-bound task/result IDs and authenticated acceptance to aggregate class × qualified provider/model version. Count abandoned work, all calls, retries, failed branches, escalation and complete latency. Store no prompt/body in score records.
2. Version changes suspend the affected scores until requalified. Sparse evidence preserves the approved order. Replay cannot mint outcomes or multiply one task's contribution. Deletion/correction invalidates dependent evidence.
3. Compare candidate routes with frozen, counterbalanced workloads. Keep units distinct: subscription runs/pool headroom, token usage, monetary cost, time and acceptance. Define minimum evidence and the acceptance floor before trial; do not choose them from the same held-out results.
4. Reorder only already-granted routes through the existing change pipeline. Preserve private-provider filtering, grant checks, price ceiling and held-out/security tests. The evaluation budget stays separate and capped; Loop 1 cannot raise it or the production limit. A costlier path needs the existing owner-approved policy path, not this score.
5. Demonstrate differing class preferences with actual accepted outcomes, then an exhausted route and a revoked/private-ineligible route. No wrong-class evidence, stale version or fast failed task can improve a score.

Declare exact route/task/journal/modelroute paths in each implementation slice. Tests first; strongest-model L3/threat check and separate Security/lens passes. Initial checkpoint: 25k tokens per attribution or score slice.
