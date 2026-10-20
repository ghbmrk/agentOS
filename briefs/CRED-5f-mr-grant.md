# CRED-5f-mr-grant: a stored provider key grants the agent machine

Board section: Phase 0: harness and risk spikes. Source: work item #814 (release, Potency/L3/Security on #566; updated at #1242's merge). Tier A (egress, credentials, cmd). On G1's path: until it lands, a box set up with a key has no model route.

**Why.** #1242 stores a provider API key at setup, but the vault process's model grants come only from `-grant` flags read at start (broker/cmd/agentos-egress/main.go, egress K8). A box set up with a key gives no machine a grant, and agentosd reads "no AI plan or key connected".

**Requirements:** CRED-5 (keys broker-held, the agent never sees one), A11, OP-9 (C1/C2 model lines), CAP-9 (private data reaches a provider only when the owner allowed it), CRED-1 (no key in logs or state).

**Change.**
- The egress proxy asks a per-request `Config.Granted(machine, adapter)` where no static grant covers the call. The vault process answers it from the open vault: the agent machine (`-agent-machine`, default `agent`, empty turns it off) is granted a provider while the open vault holds that provider's API key. No rebuild of the proxy, so caps, usage and requalify stops (ErrRequalify) are untouched.
- The model router's grant check also asks the same stored-key callback, so routing and the proxy agree. The private-data rule is unchanged: a private call still needs the owner's setup answer (CAP-9).
- The model state's `granted` follows stored keys: a non-secret `keyed` mark in the unlock state answers while the vault is locked, after a restart too.
- `serveCustody` factors serveCmd's custody construction so a test sees `granted` follow `-grant` and the hook bound.
- Only `KindAPIKey` entries grant; nothing else changes for plan logins.

**Tests first.** Stored key grants the agent machine end to end (router + proxy, locked/unlocked, other provider, other machine, builder machine); key held at unlock grants; storedGrant only for the agent's open API keys; model state follows stored keys and the state file never holds the key; serveCustody follows the flags; `-agent-machine` rejects builder/replay prefixes.

**Out of scope (split).** A served add-key step past setup, so `modelNoGrant` can name a page (`TestModelNoGrantNamesAServedStep` keeps the line honest until then): release row CRED-5f-mr-addkey.

**Scope:** `broker/egress/proxy.go`, `broker/egress/*_test.go`, `broker/egress/ASSUMPTIONS.md`, `broker/cmd/agentos-egress/*`, `broker/cmd/agentosd/ASSUMPTIONS.md`, `broker/cmd/agentosd/capoff.go` (comment only), this brief.

**Usage estimate:** 150k tokens. Builder model: Opus-class (tier A).
