# sockprobe: assumptions

Built for P3-4b-3 against LOOP-7 (bullet 2) and LOOP-9. The probe runs inside an agent machine with guest authority only: it reads the guest's socket directory and writes frames to the sockets it can open. Strictly off-the-shelf (D-067): a fixed list of four malformed frames, no generated or searched-for inputs.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| P1 | **Declared sockets.** "Only declared sockets are reachable" is checked from the guest's view: every entry in the socket directory that is not declared is dialled, and any that answers fails the round; every declared socket must answer a ping. Sockets outside that directory are out of the probe's reach by construction. | LOOP-7 | If guests get sockets elsewhere, add each directory to `Config`. |
| P2 | **Frames.** Not JSON, a field of the wrong type, an unknown op and a frame one byte over `sockets.MaxRequest`. Each is sent on a fresh connection and must be answered with its own refusal code (`sockets` errors); a server that accepts one, or answers another code, fails the round. | LOOP-7 | Add a frame when the sockets package adds a refusal code. |
| P3 | **Responsive and unchanged.** After every frame the probe pings again and compares the answer with the first ping: a socket that stops answering, or answers as another peer, fails the round. | LOOP-7 | — |
| P4 | **Without effect, journaled: broker side.** A guest cannot read the journal, so the probe only returns what it sent; `loop7.Journaled` checks the broker's trail for one refusal note per code for the machine and no intent from it during the round. | LOOP-7 | — |
| P5 | **Production runner.** Nothing in this PR starts the probe inside a real agent machine; the daemon wiring (an exec into the guest, its result back over the control path) is a release finding. | LOOP-7 | — |
