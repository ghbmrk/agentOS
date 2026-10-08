# OSS-6e: Floor across restarts

Board section: Backlog refill (2026-10-05).

Floor across restarts (Security ruling on #180, tightening only): the outbox keeps the last count's CLOCK_BOOTTIME and boot_id; on the same boot the 20h floor holds across a broker restart, a stored value ahead of the current one is corrupt and counts no day; another boot_id is ignored. DECISIONS "OSS-6 clock" G2 line updated

**Needs:** OSS-6c

**Gate:** lenses (security)

**State on the board before the 2026-10-08 index split:** queued (A, after #180)
