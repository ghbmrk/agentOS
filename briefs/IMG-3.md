# IMG-3: Forced-fail fallback boot in CI

Board section: Backlog refill (2026-10-05).

Forced-fail fallback boot in CI: boot the image with health forced to fail and check the entry stays unblessed with its counter decremented, then falls back once a second release exists (UPD-1; SHOULD on #41)

**Needs:** P2-1, update package

**Gate:** skip (tooling)

**State on the board before the 2026-10-08 index split:** queued
