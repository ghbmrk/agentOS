# CTRL-card-rot-ap-2-s8: agentosd puts the vault's committed Wi-Fi network back in ap-net.json at start and after unlock

Board section: CTRL-card-rot-ap-2. Source: #1696 (Security R3 on #1614; promotes #1526 item 1, P-1). Tier: A. Builder: strongest model. Usage estimate: 120k tokens.

**Why.** A Wi-Fi rotation commits the new network to the vault, then agentosd takes the vault process's five-minute one-shot permit (`POST /rotate/wifi`, #1522) to rewrite `ap-net.json`. When agentosd is down, crashes, or misses the window, the permit lapses and the access point keeps serving the old network while the card in the owner's hand prints the new one. Nothing ever repairs that: the owner cannot join the box's Wi-Fi with the card. The vault already holds the committed network (the stored Owner Card's Wi-Fi name and password), so agentosd can reconcile from it whenever the vault is open.

## Requirements

- **CTRL-card-rot-ap-2-s8-1** (REC-4, CRED-8, ARC-1) The vault process's verify socket (broker UID only) answers `GET /committed-wifi` with the Owner Card's committed Wi-Fi network while the vault is open: 503 while locked, 404 when the vault keeps no Owner Card, 409 while a rotation still owes its Wi-Fi part (the stored card may not be the network in effect). The route is read-only (it takes or changes nothing, so the `/rotate/wifi` permit is untouched) and answers no other method. The client (`modelroute.Verifier.CommittedWiFi`) never prints the password.
- **CTRL-card-rot-ap-2-s8-2** (REC-4, CH-7) agentosd, at start and on each locked-to-open change of the vault, reads the committed network and rewrites `ap-net.json` when the file differs from it. It writes only when the file already holds a network of the same name and the committed one passes `apnet.Validate`; it writes durably (`durable.WriteFile`, 0600, a failed directory sync after the rename counts as written), and a write and a page rotation never interleave. Anything else is refused, leaves the file as it was, and the refusal names neither network.

**Acceptance tests:** CTRL-card-rot-ap-2-s8-1 `broker/cmd/agentos-egress/committedwifi_test.go::TestTheCommittedWiFiRouteAnswersTheVaultsNetwork`, `broker/cmd/agentos-egress/committedwifi_test.go::TestTheCommittedWiFiRouteAnswersNothingUncertain`, `broker/cmd/agentos-egress/committedwifi_test.go::TestTheCommittedWiFiRouteIsNarrow`, `broker/cmd/agentosd/apnetrot_test.go::TestTheCommittedNetworkIsReadFromTheVaultProcess`; CTRL-card-rot-ap-2-s8-2 `broker/cmd/agentosd/apnetrot_test.go::TestAStaleNetworkIsPutBackAtStartAndAfterUnlock`, `broker/cmd/agentosd/apnetrot_test.go::TestReconcileRefusesAnotherNameOrAnInvalidNetwork`, `broker/cmd/agentosd/apnetrot_test.go::TestReconcileWritesDurablyAndOnlyWhenTheFileDiffers`, `broker/cmd/agentosd/apnetrot_test.go::TestReconcileRetriesUntilTheVaultAnswers`, `broker/cmd/agentosd/apnetrot_test.go::TestReconcileAndRotationShareOneLock`.

## Acceptance

`ap-net.json` holds a stale network and the vault a different committed one of the same name: after start, and after a lock and unlock, the file holds the vault's. A different name or an invalid network is refused and the file is untouched. The tests above carry `REQ:` markers; CI green.

**Guard files:** none

## Scope

`broker/cmd/agentosd/apnetrot.go`, `broker/cmd/agentosd/apnetrot_test.go`, `broker/cmd/agentosd/main.go` (one wiring line next to `watchAPUp`; #2015 touches another hunk), `broker/cmd/agentosd/ASSUMPTIONS.md`, `broker/cmd/agentos-egress/committedwifi.go`, `broker/cmd/agentos-egress/committedwifi_test.go`, `broker/cmd/agentos-egress/server.go` (one route block and the 405 text; #1628 is queued on this file, no PR open), `broker/cmd/agentos-egress/ASSUMPTIONS.md`, `broker/modelroute/verify.go`, `broker/modelroute/ASSUMPTIONS.md`, `briefs/CTRL-card-rot-ap-2-s8.md`. Not `broker/cmd/agentos-egress/rotation.go` (#1695).
