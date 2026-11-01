# CTRL-spike: assumptions

| # | Assumption | Rests on | Revisit when |
|---|---|---|---|
| CS-1 | "Line rate" for USB4 networking means at least 94% of a 2.5GbE port 2 (2350 Mbit/s), because HW-12 offers USB4 as an alternative to port 2. | HW-12 | Mark names a different bar |
| CS-2 | The booted stick carries `agentos.stick=1` on its kernel command line as the boot marker. | probe.py | The stick image defines its own marker |
| CS-3 | Key presses are counted by the operator, since firmware cannot report them. | HW-13 | A way to measure them appears |
| CS-4 | The harness is built and unit-tested in CI; the acceptance tests need the physical unit, so the row returns to `queued` once the harness merges and is claimed again when the unit arrives. | brief Dependencies | The unit arrives |
