# CRED-5f-mr-addkey: serve a provider add-key step past setup

Board section: Phase 0. Work item: #1278 (split from #814 CRED-5f-mr-grant). **Tier A** (`broker/localui`, `broker/localsrv`, `broker/cmd/agentosd`; credentials). Serves OP-9, ONB-3, CRED-5.

**Why / failure path.** Past setup, `localui.AgentosdSetup.ConnectAPIKey` (`setuphooks.go:193`) is reachable only from setup's AI step. An owner who skipped the key, or wants another provider, gets `modelNoGrant` (`capoff.go:51`): "a later box version adds this". Nothing they can do names a page.

**Requirements:**
- CRED-5f-mr-addkey-1: after setup, an owner-authenticated page stores a provider API key through the same vault path as setup (`OpSetupAPIKey`, `ConnectAPIKey`); the vault checks the key with its provider first (ONB-3), and the key never touches the page, agentosd's disk or a log (CRED-1).
- CRED-5f-mr-addkey-2: the stored key grants the agent machine with no restart (CRED-5f-mr-grant's stored-key grant).
- CRED-5f-mr-addkey-3: `modelNoGrant` names the served page and no longer says "a later box version"; `TestModelNoGrantNamesAServedStep` flips with it (`capoff_test.go:645`), and `agentosd/ASSUMPTIONS.md` M1 is updated.
- CRED-5f-mr-addkey-4: the step is refused for a caller that is not the signed-in owner, and for a setup-closed state it must not be reachable through the setup-only route (`ErrSetupClosed`).

**Acceptance tests:** (REQ: CRED-5f-mr-addkey-1..4)
- `broker/localui/*_test.go::TestAddKeyPastSetupStoresThroughTheVault` (-1; mutant: the page keeps the key; mutant: skip the provider check).
- `broker/localui/*_test.go::TestAddKeyPastSetupNeedsTheOwner` (-4; mutant: drop the auth check).
- `broker/cmd/agentosd/capoff_test.go::TestModelNoGrantNamesAServedStep` (-3, flipped; mutant: restore the "later box version" text).
- `broker/cmd/agentosd/*_test.go::TestStoredKeyGrantsWithoutRestart` (-2; mutant: grant read once at boot).

**Builder first reads** `setuphooks.go:27-55` and `:241`, and how `localsrv` mounts owner pages, then picks the smallest route that reuses `ConnectAPIKey`. No new key-storage path (reuse; a second path needs a sentence in the PR).

**Scope:** `broker/localui/setuphooks.go`, `broker/localui/*_test.go`, `broker/localsrv/*`, `broker/cmd/agentosd/capoff.go`, `capoff_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md`, this brief.

**Usage estimate:** 110k tokens; checkpoint at 80k. Split the page from the grant check if the diff passes 600 lines.
