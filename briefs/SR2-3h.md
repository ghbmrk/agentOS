# SR2-3h: runsc's own messages never reach the guest

Board section: Backlog refill (2026-10-05).

runsc's own messages never reach the guest (security on #181, workers K21): `runsc exec` diagnostics go to a broker-only 0600 log under the state dir (bounded, rotated) via `--log`/`--debug-log`; runsc's own failure exits, before the guest process starts, map to a ref, never to stderr; a fake runsc writing a canary host path to stderr shows no tool output or error carries it

**Needs:** RES-4, CAP-8

**Gate:** security check (strongest tier: executor path)

**State on the board before the 2026-10-08 index split:** queued (recall thread, after SR2-3g)
