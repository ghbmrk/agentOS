# WIFI-del-a2: agentosd's access point, the card's Wi-Fi hand-offs and the captive redirect out of the core

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3234, slice a2, after a1 (#3326). D-178: the core and the edge never turn Wi-Fi on. Serial `cmd/agentosd` slot (D-111). Tier A.

**Split (re-cut from `briefs/WIFI-del-a.md`'s a2 bullet, to stay under 150k):**
- **a2 (this brief):** agentosd's access-point lifecycle: `apnetrot` (the page rotation's write and the vault reconcile of `ap-net.json`), `apupwatch`, `-ap-net`, `OpSetupAPNet` and `OpRotateAPNet` with their `localsrv` and `daemon` wiring. The card's Wi-Fi network hand-offs: the card step's report (`ServeCardNet`, `withCardNet`, `cardnet`) and the rotation's (`rotwifi`), with the rotation form's Wi-Fi part. The captive-portal redirect in `Server.ServeHTTP` (ONB-5). Stale "network step" and "step 7" comments in boxe2e.
- **a3 (stays on #3234, brief to write):** the page served off the core's wired page port in place of `APConfig` (CH-9). The core's wired address comes from DHCP (`20-agentos-uplink.network`), so the page can no longer bind to a fixed `10.42.0.1/24` or admit clients by subnet, and the enforcer routes the Owner network to it. That changes `Listen`, `Config.AP`, the box-address host and about 18 localui test files, and needs its own design.
- **WIFI-del-b (#3235) gains:** agentosd's owned marker (`-owned`, `owned.go`), whose only reader is `agentos-ap`. The image still enables `agentos-ap`, and without the marker an owned box with no latch would put the sticker's setup network back on the air, so the marker goes with the loader. It also gains the vault's now-unused Wi-Fi permit and committed-network reads (`modelroute`'s `TakeRotatedWiFi` and `CommittedWiFi`, and egress's handlers for them).

**Requirement IDs:**
- **CH-9** (D-178): the core runs no access point. agentosd keeps no access point's network, and no card part is a Wi-Fi password the core serves.
- **ONB-5** (D-178): the core runs no captive portal. A captive-portal check is refused, never redirected.
- **HW-1, REC-4**: the Owner Card step and its rotation no longer hand the card's Wi-Fi network to anything.

**Acceptance tests:**
- CH-9, ONB-5: `broker/cmd/agentosd/wifidel_test.go::TestSetupServesNoWiFiOp` (extended). Setup mode, page card step included, answers no `page_setup_ap_net`.
- CH-9: `broker/cmd/agentosd/wifidel_test.go::TestAgentosdRunsNoAccessPoint`. `main.go` has no `-ap-net` flag, `watchAPUp`, `watchCommittedWiFi` or `RotateAPNet`, and neither `localapi.Ops` nor `localapi.SetupOps` lists `page_rotate_ap_net` or `page_setup_ap_net`. It catches an access point lifecycle left in agentosd.
- CH-9, REC-4: `broker/localui/wifidel_test.go::TestRotationOffersNoWiFiPart`. The rotation form offers no Wi-Fi part, and a post asking for one is 400 and never reaches the vault process.
- ONB-5: `broker/localui/wifidel_test.go::TestCoreAnswersNoCaptiveCheck`. Four platforms' captive-portal checks get 421 with no `Location`, for GET, HEAD and POST.

**Scope:** in `broker/cmd/agentosd`, `apnetrot.go` and `apupwatch.go` with their tests and `pagewire_test.go` (deleted), `main.go`, `setup.go`, `setupsock_test.go`, `setupclaim_test.go`, `wifidel_test.go` and `ASSUMPTIONS.md`; `broker/localapi` (`localapi.go`, `setup.go`, `localapi_test.go`); `broker/localsrv` (`localsrv.go`, `localsrv_test.go`, `rotateapnet_test.go` deleted); `broker/daemon` (`daemon.go`, `rotateapnet_test.go` deleted); in `broker/localui`, `server.go`, `setuphooks.go`, `rotation.go`, `rotwire.go`, `cardnet_test.go` and `rotwifi_test.go` (deleted), `page_test.go`, `localui_test.go`, `rotwire_test.go`, `cardwire_test.go`, `claim_test.go`, `tls_test.go`, `wifidel_test.go` and `ASSUMPTIONS.md`; `broker/cmd/agentos-localui` (`main.go`, `main_test.go`); comments in `broker/e2e/boxe2e`. No `image/` file and no unit line changes.

**Gate:** tier A. L3 on the strongest model. Security, because the PR changes the page's host check (CH-9, ONB-5) and the card rotation. Estimate: under 150k tokens.
