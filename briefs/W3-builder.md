# W3-builder: W3 step 3c: model-backed Loop 1 builder

Board section: Integration: wiring merged packages into the box.

W3 step 3c: the model-backed Loop 1 builder (design /mnt/project-files/w3/step3-builders-design.md). Rulings: a minimal builder image (toolchain plus brief client; arbitrator, security C-3c-3, potency); one fresh private `lb-` machine per job, never from the agent machine, socket-only egress, destroyed after, experiments class, one job at a time (C-3c-1); a dedicated socket serving only `/brief` (hypothesis and explicit dev cases), `/candidate` and the model route, everything else 404 with a test (C-3c-2); the builder is treated as compromised, so the broker clips files and bytes, admits only the hypothesis's classes (never `security/`, `routing/`, update namespaces), sets source, origin and Public=false, and extends change C6's new-literal check to every text file a builder writes (C-3c-4); its own `meter.Share` with `Max` about 30-40% of Loop 1's spare, evaluation first, per-job token cap and timeout, never `EvalShare` (C-3c-5, potency); private egress (C-3c-6); the `lb-` machine aims at 768 MB or less on the N95 (lens note)

**Precondition:** W3 step 3a

**Owner:** loops thread (P3-2)

**State on the board before the 2026-10-08 index split:** merged (#126)
