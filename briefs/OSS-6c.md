# OSS-6c: Publication clock hardening

Board section: Backlog refill (2026-10-05).

Publication clock hardening (L3 SHOULDs on #163): the floor clock is CLOCK_BOOTTIME so a suspend never stalls counting; behavioural tests pin the 20h floor and that a deferred day stays unseen

**Needs:** OSS-6

**Gate:** lenses (security)

**State on the board before the 2026-10-08 index split:** in review
