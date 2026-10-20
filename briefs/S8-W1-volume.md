# S8-W1-volume: Codex plan login in the vault, placeholders in the worker

Board section: Release rows carried from LATER.md (2026-10-10). Source: work item #1015 (from the S8-W1a inventory, #543; `docs/security/provider-worker-isolation.md` row "Credential login volume"). Tier A (vm, credentials, vault). On G1's plan path: third in the chain #808 → #807 → this → #1014 → CAP-11-plan (#1314) → #1264. No real login reaches it before S8-live (#809).

**Re-scoped 2026-10-13 (D-114).** Codex (ChatGPT plan) is the default plan route. It is broker-held, unconfirmed (D-061), so CRED-1 holds unchanged: the login stays in the vault process, and the worker gets placeholders. **There is no login volume, no per-worker login socket and no launcher.** This replaces the #1315 design, in which agentos-egress decrypted a Claude setup token and served it once over a per-worker socket. That design is dropped; it is in this file's history at 509f094. Claude has no plan route (D-140).

**Why.** CRED-5's broker-held mode needs three things. The real Codex login must be a vault entry. Each Codex worker must start with a placeholder `auth.json` the egress swap recognises. And nothing in a worker may ever hold a real value. The swap itself is already merged: `broker/egress/exchange.go` (#426) injects at declared endpoints and swaps a refresh response back to placeholders, all or none. What is missing is the vault entry for a Codex token set and the worker-side placeholder file.

**Requirements:**
- CRED-5 broker-held: the CLI holds a placeholder, and the proxy injects into declared endpoints only, including the refresh.
- CRED-1 and CRED-7: no real value in a worker, the journal, logs, recall or a guest-bound result.
- CRED-8: at rest, the login is a vault entry under the vault's key hierarchy.
- A14: the login is absent from every snapshot, the recall index and the journal.
- W9 as CRED-5 states it for plan removal: removing the plan deletes the entry and tells the owner where to revoke.

**Change.**
- **At rest.** The Codex token set is one vault entry keyed by provider declaration ID: access token, refresh token, `id_token` and account ID, as `auth.json` holds them (`spikes/S8-provider-workers/fake_codex_auth.py`). It is written only by the egress swap when sign-in (#1014's sign-in endpoints, started from the page by #1264) or a refresh completes. A locked vault means no plan route (refusal reason `vault-locked`).
- **Placeholders.** At worker create, `vm` writes a placeholder `auth.json` into that worker's scratch. The placeholder set comes from the vault process: synthetic values the swap maps to the real ones, plus an unsigned synthetic `id_token` carrying the real account ID, which S8 found the CLI does not verify. The builder decides, and records in `broker/egress/ASSUMPTIONS.md`, whether placeholders are per worker or per provider. Per worker is preferred, so that one worker's placeholder is useless in another.
- **Refresh writes back.** Codex rewrites `auth.json` after a refresh. The placeholders it writes are the swapped ones, so the file never holds a real value. Refresh tokens are single-use (CODEX-TERMS), so the vault entry is updated before the swapped response is released (the Swapper's all-or-none rule, CRED-5b item 1).
- **Provider workers stay broker-owned.** `Manager.Workers(lineage)` never lists them, and `vm` refuses `checkpoint`, `fork` and `rollback` on them. Only placeholders are inside, but the worker's scratch holds the brief and the run's data. CAP-11-plan builds the tool-side refusal across the 13 worker tools.
- **Removal.** Deleting the plan deletes the vault entry and returns the provider's revoke location for the owner line (W9). The line itself ships with #1264.

**Tests first.**
- A canary token set stored for Codex is absent from the drive outside vault ciphertext, and absent from the journal, the recall index, every snapshot and guest-bound output (`tools/canary.py` patterns).
- A worker's `auth.json` holds only placeholders.
- A refresh through the stub swap leaves only placeholders in the worker's `auth.json`, and updates the vault entry before the response is released.
- A second worker's placeholder does not inject for the first worker's requests, if placeholders are per worker.
- `Workers(lineage)` omits a provider worker. `checkpoint`, `fork` and `rollback` refuse one.
- A locked vault refuses with `vault-locked`.
- Removing the plan leaves no vault entry and no canary on the drive.

**Revert mutants (each must turn a test red).**
- Write the real access token into `auth.json`.
- Release the swapped refresh response before the vault update.
- List provider workers in `Workers(lineage)`.
- Let `fork` accept a provider worker.
- Keep the vault entry on plan removal.

**Threats Security must check.**
- A placeholder reused from another worker or another box.
- Partial refresh state when the box loses power between the upstream answer and the vault write: the single-use refresh token is lost, and the route must fall to a refused-login stop, not loop.
- Log lines or error strings that echo a real value.
- The `id_token` placeholder leaking the account's email or plan claims into the worker.

**Needs:** #807 S8-W1 (image and tool sandbox). #808 S8-W1a inventory for the surface list.

**Out of scope.**
- Worker egress and the declared endpoints (#1014).
- The route and its broker tool (CAP-11-plan).
- Sign-in on the page (#1264).
- Consent for an unconfirmed route (CRED-5c).
- Route failure and fallback (CRED-5b).
- Live qualification (S8-live, #809).

**Scope:** `broker/vm/worker.go`, `broker/vm/vm.go` (Spec field only), `broker/vm/*_test.go`, `broker/vm/ASSUMPTIONS.md`, `broker/vault/*_test.go` (canary at rest only), `broker/egress/*` (placeholder set and vault entry write only), `broker/cmd/agentos-egress/*`, `broker/egress/ASSUMPTIONS.md`, `broker/cmd/agentosd/main.go` (wiring), `broker/journal/*_test.go`, `broker/recall/*_test.go` (canary absence only), this brief.

**Usage estimate:** 90k tokens, less than the worker-held design because nothing is served into the worker. Builder model: Opus-class (tier A).
