# Provider agents (worker-held custody): assumptions

Built for BOARD S8-W1 (SPEC CRED-5 W1) on the S8 spike
(`spikes/S8-provider-workers/RESULT.md`).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| P1 | Tool subprocesses run as uid 1000 with `/proc` mounted `hidepid=2`, so they cannot read the CLI's `/proc/<pid>/environ`. The CLI keeps the login (root or a distinct cli user). | CRED-5 W1 | Image rootfs + runsc exec for tools. |
| P2 | The login volume is mounted only at `/var/lib/agentos/provider-login` and is absent from snapshots, recall, and the journal (W2, W9 follow in a later package). | CRED-5 W2 | Volume mount wiring. |
| P3 | Managed policy (`image/claude-managed-settings.json`) denies the login path and common `/proc/*/environ` probes, and turns off provider-side fetch tools. This is defense in depth beside the uid/hidepid boundary. | CRED-5 W1, W4 | Per-CLI settings path. |
| P4 | `Surfaces` is a tripwire on results leaving the worker (CRED-7 shapes for this canary). It does not replace W1 containment. | CRED-5 W1, A14 | Encoding list. |
| P5 | This package does not yet start Claude Code or install the worker image. Qualification against a live CLI is S8-live. | S8-W1, S8-live | — |
