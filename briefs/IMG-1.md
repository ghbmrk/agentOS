# IMG-1: Image checks for P2-1

Board section: Backlog refill (2026-10-05).

Image checks for P2-1 (HW-1, ONB-2): CI scans the built image for per-owner secrets; host disks are never mounted or written (no automount, udev policy, a test that boots with a host disk attached and checks it untouched); a DIY drive generates its card on first boot only with a local display, printer or local web session

**Needs:** P2-1 (#41, draft since 01:07Z)

**Gate:** skip (tooling), security check

**State on the board before the 2026-10-08 index split:** queued, blocked on P2-1
