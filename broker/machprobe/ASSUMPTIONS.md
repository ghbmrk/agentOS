# machprobe: assumptions

Built for P3-4b-4b against LOOP-7 (tamper and resource-exhaustion probes). The scripts run inside an agent machine with guest authority only and are fixed (D-067): a fixed marker written beside the paths the broker names, and bounded CPU, memory, disk and process pressure. Verdicts are broker-side (`loops` S33–S36).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| M1 | **Untrusted output.** `Tamper`'s count and `Press`'s result are for logs only; the broker digests its targets and reads the cgroup and quota itself. | LOOP-7 | — |
| M2 | **Bounded pressure.** Memory and disk pressure stay under the machine's limits and process pressure stops at the first refused start, so the round does not end in an OOM kill of the sandbox. `Press` refuses before pressing a duration, or its kind's size, count, directory or child command, that is unset, zero or negative (P3-4b-4c-bounds: on main a negative `MemMB` panicked and the others returned nil, a press logged that never ran; `TestPressRefusesWhatItCannotPress`). | LOOP-7, RES-2 | — |
| M3 | **Production runner.** Only the gVisor test guest runs these scripts; starting them in a box's agent machine is P3-4b-4c's daemon wiring. | LOOP-7 | — |
| M4 | **Sibling writes only (P3-4b-4c-restore).** `Tamper` creates one new file per path, named `Sibling(nonce)` and opened `O_CREATE\|O_EXCL`: a file's sibling in its directory, a directory's inside it. It never opens a path for writing, truncates, renames or removes one, skips a path it cannot see and leaves an existing sibling alone, so a probe that finds an evaluator or grader writable does not damage it. The broker removes the siblings (`loops` S33). | LOOP-7 | If a target can only be shown writable by changing it, copy it broker-side first and restore the copy after the verdict. |
