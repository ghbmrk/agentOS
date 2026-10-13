# S8-W1-volume: per-provider login volume, kept out of every copy

Board section: Release rows carried from LATER.md (2026-10-10). Source: work item #1015 (from the S8-W1a inventory, #543; `docs/security/provider-worker-isolation.md` row "Credential login volume"). Tier A (vm, credentials). On G1's plan-login path (Mark chose "Plan login", 2026-10-13): third in the chain #808 → #807 → this → #1014 → CAP-11-plan → #1264.

**Why.** CRED-5's worker-held mode keeps a provider's plan login on "a per-provider login volume mounted only into that provider's workers", the one exception to CRED-1. At current main nothing creates, checks or mounts such a volume, and the worker plane (`broker/vm/worker.go`, `broker/workers`) has no notion of one: a worker's files all live in its overlay, so checkpoint, fork, diff, park and file reads would carry a login with them.

**Requirements:** CRED-5 worker-held W2 (volume holds the login only; only the login file writable; schema checked at every mount) and W9 (removing a plan deletes the volume), CRED-1 and CRED-7 (the login never reaches journal, logs, recall or a guest-bound result), A14 ("the login volume is absent from every snapshot, the recall index, and the journal"; "a file or hook written by one worker is absent in the next"), ARC-1 (the worker-held exception stays under CRED-1's conditions).

**Change.**
- A `loginvol` unit (new package under `broker/vm/`, or a file in `broker/vm` if smaller) owns one volume per provider declaration ID, root-owned on the drive under the encrypted data area (CRED-8), outside every machine overlay and every snapshot root.
- The provider's declaration names the login file's relative path and a closed schema (allowed keys and value shapes, size cap). For Claude: the file the CLI reads after `claude setup-token`; the builder records the exact path and schema from the pinned CLI version in `ASSUMPTIONS.md`, measured against a stub CLI, never a real login.
- Mount: only `vm.Manager.CreateWorker` for a worker whose spec names that provider attaches it. The directory is bind-mounted read-only and the one login file read-write; nothing else on the volume is visible. Before each mount the schema check runs: any extra file, a symlink, a hardlink, a device, a key off the schema or a size over the cap refuses the mount, journals the refusal by provider ID only (no content), and tells the owner once that the plan's sign-in must be redone.
- Never mounted into the guest, a builder or replay machine, another provider's worker, or a worker made by `fork`. Checkpoint, fork, diff, park, rollback and `read`/`write` tools never see the mount point (the overlay layer stops at it; the tool path check refuses it).
- Settings, hooks, MCP configuration, memory and transcripts never come from the volume (W2): the worker gets them from the image or per-worker scratch that is destroyed with the worker.
- Removal: deleting a plan deletes the volume (overwrite then unlink) and returns the provider's revoke location for the owner line (W9). The owner line itself ships with #1264.
- The recall indexer, journal writer and snapshot pruner skip the volume root by construction (it is outside their roots); a test proves each.

**Tests first.** Volume mounts only into its provider's worker; a second provider's worker, the guest, a builder machine and a forked worker see nothing. Schema check refuses each of: extra file, symlink, hardlink, key off schema, oversize, non-regular file; the refusal journals no content. A write outside the login file fails inside the worker. Checkpoint and fork of a worker with the volume mounted produce a snapshot holding no canary; `diff` and `read` cannot name the path. A canary login seeded on the volume is absent from the journal, recall index, every snapshot, and guest-bound tool output (`tools/canary.py` patterns). A file or hook written into scratch by one worker is absent in the next. Removing the plan leaves no volume and no canary on the drive.

**Threats Security must check.** Path tricks at mount (symlink or `..` in the declared file, a hardlink planted by a previous worker, TOCTOU between check and bind: check the opened fd, mount by fd or re-check after mount). A worker writing a schema-valid file that carries a hook or settings the CLI would load (W2: the CLI must read settings only from the image; prove the volume file cannot redirect it). Snapshot or fork reaching the bind mount through gVisor's gofer. The volume ending up in a backup set (BAK-1) or a deletion-reach copy. Log lines or error strings that echo file content.

**Needs:** #807 S8-W1 (the sandbox that hides the path from tools; this package can build and test against stub CLIs before it lands, but does not ship a worker-held route on its own). #808 S8-W1a inventory for the surface list.

**Out of scope.** The tunnel (#1014), the route and its broker tool (CAP-11-plan), sign-in on the page (#1264), live qualification (S8-live).

**Scope:** `broker/vm/loginvol/*` (new) or `broker/vm/loginvol.go`, `broker/vm/worker.go`, `broker/vm/vm.go` (Spec field only), `broker/vm/overlay/*` (exclusion only), `broker/vm/gvisor/gvisor.go` (mount wiring), `broker/vm/*_test.go`, `broker/vm/ASSUMPTIONS.md`, `broker/workers/workers.go` (path check), `broker/workers/*_test.go`, `broker/workers/ASSUMPTIONS.md`, this brief.

**Usage estimate:** 140k tokens. Builder model: Opus-class (tier A).
