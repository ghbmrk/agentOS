# CRED-5f-mr-addkey: serve a provider add-key step past setup

Board section: Phase 0. Work item: #1278 (split from #814 CRED-5f-mr-grant). **Tier A** (`broker/localui`, `broker/localsrv`, `broker/cmd/agentosd`, `broker/cmd/agentos-egress`; credentials). Serves OP-9, ONB-3, CRED-5.

**Why / failure path.** Past setup, the vault's `POST /setup/providers/key` is sealed (410, egress ASSUMPTIONS K23) and `localui.AgentosdSetup.ConnectAPIKey` (`setuphooks.go:193`) is reachable only from setup's AI step, which `localsrv/setup.go:227` wraps in `s.open(...)` (`errSetupClosed` once setup closes). An owner who skipped the key, or wants another provider, gets `modelNoGrant` (`capoff.go:51`): "a later box version adds this". Nothing they can do names a page.

**What already exists (do not rebuild).** The stored-key grant is merged: a stored key grants its provider to the agent machine in the vault (K24, `storedgrants.go`); agentosd grants nothing. The past-setup providers page exists (`localui/providers.go`, `pages.go`) over the unlock-socket `GET /providers` and `POST /providers/private` (K25, `cmd/agentos-egress/privatechange.go`). The setup key path stays closed past setup; this package adds a key step to the providers page, not a second setup route.

**Requirements:**
- CRED-5f-mr-addkey-1: past setup, the providers page offers an add-key step that stores a provider API key through an unlock-socket route in `privatechange.go` (a sibling of `/providers/private`); the vault checks the key with its provider first (ONB-3), and the key never touches the page's HTML, agentosd's disk or a log (CRED-1).
- CRED-5f-mr-addkey-2: `modelNoGrant` names the served page and no longer says "a later box version"; `TestModelNoGrantNamesAServedStep` flips with it (`capoff_test.go:645`), and `agentosd/ASSUMPTIONS.md` M1 is updated.
- CRED-5f-mr-addkey-3: the step is refused for anyone other than the signed-in owner; the setup ops stay closed after finish (the setup route still answers closed, not served by the new step).

**Acceptance tests:** (REQ: CRED-5f-mr-addkey-1..3)
- `broker/localui/*_test.go::TestAddKeyPastSetupStoresThroughTheVault` (-1; mutant: the page keeps the key; mutant: skip the provider check).
- `broker/cmd/agentos-egress/*_test.go::TestAddKeyRouteStoresThroughTheVault` (-1, vault side; mutant: store before the provider check).
- `broker/localui/*_test.go::TestAddKeyPastSetupNeedsTheOwner` (-3; mutant: drop the auth check).
- `broker/localsrv/*_test.go::TestSetupKeyOpStaysClosedAfterFinish` (-3; mutant: route the setup op through the new step).
- `broker/cmd/agentosd/capoff_test.go::TestModelNoGrantNamesAServedStep` (-2, flipped; mutant: restore the "later box version" text).

**Builder first reads** `localui/providers.go`, `privatechange.go:130-150` and K23-K25, then adds the smallest route beside `/providers/private`. No new key-storage path: the vault's existing store is reused (a second path needs a sentence in the PR).

**Scope:** `broker/localui/providers.go`, `broker/localui/pages.go`, `broker/localui/*_test.go`, `broker/localui/setuphooks.go`, `broker/localsrv/*`, `broker/cmd/agentos-egress/*`, `broker/egress/ASSUMPTIONS.md`, `broker/cmd/agentosd/capoff.go`, `capoff_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md`, this brief. Open #2428 also touches `broker/egress/ASSUMPTIONS.md`: start after it merges (D-111).

**Usage estimate:** 110k tokens; checkpoint at 80k. Split the page from the vault route if the diff passes 600 lines.
