# SR2-3k: guesterr.Guest values checked at run time

Board section: Backlog refill (2026-10-05).

`guesterr.Guest` values checked at run time (finding 4, L3 on #324): `Newf` rejects or replaces a `Guest` value not matching `^[A-Za-z0-9._-]{1,64}$`, so a path passed as guest text cannot reach the guest; every current caller already fits

**Needs:** SR2-3g

**Gate:** security check
