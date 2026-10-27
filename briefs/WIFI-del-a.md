# WIFI-del-a: setup's home-network step and the claim's Wi-Fi step out of the core

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3234, slice a1. D-178: the core and the edge never turn Wi-Fi on, and setup runs on the enforcer's networks (SPEC #3233, merged). Serial `cmd/agentosd` slot (D-111). Tier A.

**Split.** #3234 is about 14k lines across agentosd, localui, the two Wi-Fi binaries and their libraries, which is too much for one session. The AP and netjoin binaries import localui's access-point code (`APConfig`, `APLoader`, `Hostapd`, the station interface code), so that code can only go with them.
- **a1 (this brief):** the steps the core serves to the owner. Setup has no home-network step, and the claim has no Wi-Fi step. That covers the setup network and join ops in `localapi`, `localsrv`, `cmd/agentosd` and `localui`, the never-online note and `Config.Station`, `cmd/agentos-localui`'s wiring, boxe2e's steps, and agentosd's `-netjoin-sock` and `-setup-net` flags. The one unit line that passed `-netjoin-sock`, with its image tests and boot report, comes out too, so the image still starts agentosd.
- **a2 (stays on #3234; re-cut in `briefs/WIFI-del-a2.md`, which moves the wired page port to a3 and the owned marker to WIFI-del-b):** agentosd's access-point lifecycle: `apnetrot`, `apupwatch`, the owned marker, `-ap-net`, `OpSetupAPNet` and `OpRotateAPNet`. Also the page served off its wired page port in place of `APConfig` (CH-9), the captive-portal redirect in `Server.ServeHTTP` (ONB-5), and the card's Wi-Fi network step (`cardnet`, `rotwifi`).
- **WIFI-del-b (#3235):** the `agentos-ap` and `agentos-netjoin` binaries, `apnet`, `netjoin` and localui's access-point and station code, together with the image side.

**Requirement IDs:**
- **ONB-5** (SPEC, D-178): the core runs no captive portal or passthrough. In a1, setup no longer joins the home network through the core.
- **CH-9** (D-178): the core and the edge run no access point. In a1, no setup-network password rotation is served.
- **HW-10** (D-178): the claim sticker names the enforcer's setup network. After the claim, the claimant goes straight to setup.
- **ONB-4**: setup's progress is ready once the box has an uplink (its cable to the enforcer), and offline before.

**Acceptance tests:**
- CH-9, ONB-5, HW-10: `broker/localui/wifidel_test.go::TestSetupHasNoWiFiStep`. After the claim, the claimant lands on `/setup`, which starts at "1. Text your box" and names no Wi-Fi, Ethernet or network step, and `/claim/wifi` and `/setup/network` are 404. It catches a page that still sends the claimant to a Wi-Fi step or still offers a join.
- CH-9, ONB-5: `broker/cmd/agentosd/wifidel_test.go::TestSetupServesNoWiFiOp`. Setup mode, including the page card step, answers none of `page_setup_join`, `page_setup_networks`, `page_setup_wifi_name` or `page_setup_wifi`, and `localapi.SetupOps` lists neither join nor networks. It catches agentosd still relaying a join or rotating the setup network.
- ONB-4: `broker/cmd/agentosd/uplink_test.go::TestUplinkProgress` (rewritten). The phase is ready with a default route and offline without, and nothing waits on a join.
- Image: `tests/test_image.py` (`test_the_broker_starts_before_onboarding` and `test_the_modem_and_netjoin_sockets_are_where_agentosd_looks`) and `tests/test_image_quota.py`'s canonical command. agentosd's unit passes no `-netjoin-sock`.

**Scope:** `broker/localapi/setup.go` and its test; `broker/localsrv/setup.go`, with its join and scan tests deleted; in `broker/cmd/agentosd`, `setup.go`, `uplink.go`, `main.go`, `setupwifi.go` (deleted), the tests for these, and `ASSUMPTIONS.md`; in `broker/localui`, `setup.go`, `setuphooks.go`, `server.go`, `claim.go`, `pages.go`, `claimwifi.go` and `station.go` (deleted), the tests for these, and `ASSUMPTIONS.md`; `broker/cmd/agentos-localui` (`main.go`, its tests, `station_test.go` deleted); `broker/e2e/boxe2e` (the claim's Wi-Fi step, the network step, and the step numbers in its fixtures); `broker/claim/ASSUMPTIONS.md` (K11 retired); `broker/daemon/arc2_test.go` (agentosd no longer links `netjoin`); `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service`, `image/mkosi/mkosi.extra/usr/lib/agentos/boot-report`, `image/ASSUMPTIONS.md` I17, `tests/test_image.py` and `tests/test_image_quota.py`, for the one flag.

**Gate:** tier A. L3 on the strongest model, plus Security, because the PR touches agentosd's unit line. Estimate: under 150k tokens.
