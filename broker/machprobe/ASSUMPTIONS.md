# machprobe: assumptions

Built for P3-4b-4b against LOOP-7 (tamper and resource-exhaustion probes). The scripts run inside an agent machine with guest authority only and are fixed (D-067): a fixed marker written to the paths the broker names, and bounded CPU, memory, disk and process pressure. Verdicts are broker-side (`loops` S33–S36).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| M1 | **Untrusted output.** `Tamper`'s count and `Press`'s result are for logs only; the broker digests its targets and reads the cgroup and quota itself. | LOOP-7 | — |
| M2 | **Bounded pressure.** Memory and disk pressure stay under the machine's limits and process pressure stops at the first refused start, so the round does not end in an OOM kill of the sandbox. | LOOP-7, RES-2 | — |
| M3 | **Production runner.** Only the gVisor test guest runs these scripts; starting them in a box's agent machine is P3-4b-4c's daemon wiring. | LOOP-7 | — |
