# POT-P7: Complete resource-aware plan delegation

**Owner:** primary, unclaimed; executor changes require the owning lane. **Class:** release, A3/A15. **Tier:** A.
**Requirements:** CAP-9/11/12, RES-2/5, OP-8, CRED-1/5, ARC-7, REV-5.
**Needs:** reconcile quota [#220](https://github.com/ghbmrk/agentOS/pull/220), declarations/resources [#221](https://github.com/ghbmrk/agentOS/pull/221), S8-W1 and provider-specific custody/CLI qualification. D-061 permits an unconfirmed broker-held Codex route only within its recorded-consent conditions; it does not qualify a live route. Inspect current main before proceeding.

## Scope

Finish the existing plan-run path rather than creating a second scheduler: qualified declaration → caller-specific resources → preference → rechecked admission and retained real-run lease → task/label-bound worker → bounded artifact result → settlement and plain fallback digest. Freeze library interfaces only after their owning PRs are accepted. Split construction, lifecycle/settlement and qualification into separate briefs with exact paths.

No provider worker may reach the owner channel or adapters. Credentials stay within the selected qualified custody boundary; egress reaches only declared endpoints. Recheck stale resource snapshots at dispatch. Spare work yields to foreground and waits for reset instead of silently buying API calls. Foreground paid fallback requires an already-granted route and reservation.

## Acceptance

Run two qualified pools in parallel; an exhausted/reserve-bound pool refuses new leases; provider cutoff settles quota and retries on a granted route; no revoked route runs. Assert wall-clock/concurrency/cgroup caps, STOP, crash/restart cleanup, private labels, and credential canaries across every tool/child process. Verify headroom against provider state and measure accepted tasks per reset. Live account qualification and terms decisions remain separate gates; simulated quota libraries alone do not pass A15.

Tests first, Linux/race and floor-host evidence, strongest-model L3/threat check and separate Security/lens passes. Initial checkpoint: 25k tokens per composition slice.
