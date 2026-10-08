# W3-values-mix: HMAC explicit runs in mixed shapes

Board section: Integration: wiring merged packages into the box.

Follow-up to W3-values (potency on #119): when a shape mixes explicit and implicit runs, HMAC the explicit run's clear values with the box key and compare them with the implicit runs' HMACs, so a leaf equal across runs stays a constant (value from the explicit run) instead of becoming a skill input. Also count values refused by the F1 scrub (a count-only log line; Loop 1's digest has no guard-hit line). Land next after W4 (potency on #120).

**Precondition:** W3-values, after W4

**Owner:** loops thread (P3-2)

**State on the board before the 2026-10-08 index split:** review
