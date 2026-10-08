# RES-2c: Lift the 4500 MiB admission cap on larger boxes

Board section: Backlog refill (2026-10-05).

Lift the 4500 MiB admission cap on larger boxes (budget R2): capacity `min(mem, max(4500, headroom + floor(cores/2) × OpenClawMB))`, so a box with more memory and cores runs more machines while the N95 floor is unchanged. Check it on A2's large-host run

**Needs:** P2-5r merged, A2 large-host run

**Gate:** lenses

**State on the board before the 2026-10-08 index split:** in review (#140); carry: A2 large-host run, on an SMT box (logical CPUs, potency R1 on #140)
