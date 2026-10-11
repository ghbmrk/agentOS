# S8-W1a: tool-seam feasibility (inventory result)

Package S8-W1a, tier C. Source draft: #262 (Codex), rechecked against main at
`256b7cc`. All anchors below are at that commit. This is an inventory, not a
qualification: it claims no coverage of CRED-5 or A14.

## Result

No enforced seam between a provider CLI's credential authority and its model-driven
tools exists in the repository. Worker-held routes stay blocked (BOARD S8-W1).
This is a statement about the repo, not a recommendation that a Bash-only sandbox or
an instruction classifier would suffice.

## What main contains (changed since the draft)

- Custody modes are in SPEC (CRED-5, W1–W9) and the S8 stub results are merged
  (`spikes/S8-provider-workers/RESULT.md`, #186).
- Broker-held machinery exists: egress proxy with declared-operation injection
  (`broker/egress/proxy.go`), vault redactor (`broker/vault/redact.go`), recall
  scrubber (`broker/recall/scrub.go`), canary tooling with encoding coverage
  (`tools/canary.py`, `tools/canary_controls.py`), worker machines
  (`broker/vm/worker.go`).
- Not present: a CONNECT/SNI-bound tunnel, a per-provider login volume, a
  provider-worker image or managed-policy files, a PID/UID seam for tool
  subprocesses, and any snapshot-exclusion rule for a login volume.

## What is still unobserved

Pinned versions are Claude Code 2.1.289 and Codex CLI 0.160.1 (S8). Enabled tool
names and process identities have to be observed per pinned CLI and image; the
S8 stub run lists 22 Claude tools but none for Codex (the stub serves no catalog).
No login or configuration file was read for this inventory, and no live run was made.

## Decision boundary for S8-W1

If a CLI performs credential-authorized actions and arbitrary tool actions in one
process with no separable seam, W1 does not qualify it; the gap is recorded and the
route stays blocked, and the choice of another custody mode goes to the spec process,
not to a workaround. Whether a seam exists per CLI is S8-W1's question
(D-064: stubs and synthetic canaries only, supervised).
