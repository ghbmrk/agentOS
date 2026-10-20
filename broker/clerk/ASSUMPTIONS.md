# Clerk exit: assumptions

Built for MIG-4-exit (#2571, D-139 step 4), slice 1: the declaration-driven exit in `broker/clerk` (`exit.go`, `secrets.go`). Each row is a reading a reviewer may want to change.

| ID | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-4-exit-a | **A declared request shape is a verb plus a fixed HTTPS URL template.** Arguments fill `{name}` slots in the path only, each escaped as one segment; the scheme and host are never templated. One op per verb per clerk. | CLK-3 | Header or query templates are new `Op` fields and a test. |
| MIG-4-exit-b | **The exit gives back only an outcome and "http N".** Response bodies are drained, never returned, so a hostile page cannot reach the log or the planner. Reads that need a body go through the model clerk (CLK-7), a later slice. | CLK-4, CLK-7 | A body-returning op needs a quarantined reader. |
| MIG-4-exit-c | **Outcome from status:** 2xx done; 4xx and redirects failed (nothing happened; redirects are never followed, so a credential cannot leave for another host); 408, 5xx and no answer unknown, left to the probe. | KRN-8 | A remote with its own status semantics gets its own op field. |
| MIG-4-exit-d | **Probe is the clerk's own memory.** `done` and `unknown` per idempotency key, held in memory; the key is also sent as `Idempotency-Key` so a remote that honours it dedupes a retry. A restart forgets, and the kernel's boot rule (in flight becomes unknown) covers that. | KRN-8 | Persisting the table is one store write. |
| MIG-4-exit-e | **Secrets are sealed slots opened for one request.** AES-256-GCM with the slot name as AAD; no method returns plaintext; transport errors are scrubbed of the secret raw and escaped. The sealing key is supplied by the caller; binding it to the TPM is the `tpmseal` side, wired when `vault` is replaced. | CLK-1, STO-2..4 | A `Sealer` backed by the TPM replaces `AESSealer`. |
| MIG-4-exit-f | **Slice 1 is additive.** `broker/{egress,holder,checker,vault}` and their `cmd/` binaries stay until their slices port and delete them, in that order; `tools/old_core.txt` loses a line per deletion. | D-139 | none |
