# IMG-4: Broker cgroups check and agentosd.service hardening

Board section: Backlog refill (2026-10-05).

After onboarding runs in CI: check the broker's cgroups exist under `agentosd.service` with their limits, and harden `agentosd.service` (Security R2 on #41)

**Needs:** P2-1, P2-2

**Gate:** security

**State on the board before the 2026-10-08 index split:** queued

## Scope

`image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service`, `image/ci_boot.sh`, `broker/cgroup/cgroup.go` (read only unless a limit is missing), `.github/workflows/image.yml`, `image/ASSUMPTIONS.md`. Tier A. Shares `image/` and `image.yml` with IMG-1 to IMG-3.
