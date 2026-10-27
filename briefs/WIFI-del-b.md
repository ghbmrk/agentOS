# WIFI-del-b: the image ships no access point, Wi-Fi join or Wi-Fi firmware

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3235, slice b1. D-178: the core and the edge never turn Wi-Fi on, so the image (one image for both, HW-10) carries no access point, no home Wi-Fi helper and no radio firmware. Tier A.

**Why.** After WIFI-del-a (#3326, #3340, #3350) nothing in agentosd or the page uses the access point or the join, but the image still builds, installs and enables `agentos-ap` and `agentos-netjoin`, installs hostapd, dnsmasq, wireless-regdb and the MT7922 firmware, and CI boots a mac80211_hwsim copy to test them. While `agentos-ap` ships, a preloaded box with a radio keeps serving the sticker's setup network after the claim (claim ASSUMPTIONS K11, #3235 comment 6430760737), so this slice must merge before any image release.

**Split.** The issue's row also deletes the binaries and libraries. Their last importers are `cmd/agentosd` (the owned marker, `-owned`, `apnet.Owned`) and `cmd/agentos-seller`'s test (`apnet.Dir`), and localui's access point code (`APConfig`, `apexempt.go`) reads the image's `agentos-ap-exempt@.service`. Those directories are held by other work (D-111), so:
- **b1 (this brief):** `image/`, `.github/workflows/` and `tests/` only. Nothing Wi-Fi is built into, installed in or enabled in the image, and the tree check refuses it if it comes back.
- **b2 (follow-up, on #3235):** delete `cmd/agentos-ap`, `cmd/agentos-netjoin`, `apnet`, `netjoin`, agentosd's owned marker, localui's `APConfig`, aploader and apexempt code, the image's `ap-exempt` script and `agentos-ap-exempt@.service` (with `tests/test_inbound_netns.py`'s access point cases and inbound I12), the `/var/lib/agentos/ap` tmpfiles line once WIFI-del-d (#3354) stops `prep` sealing into it, and the vault's unused Wi-Fi reads (comment 6431950367). Needs the serial `cmd/agentosd` slot.

**Changes.**
1. **Packages.** `mkosi.conf` drops hostapd, dnsmasq-base, wireless-regdb and firmware-mediatek, and `Repositories=` and the build's apt sources drop non-free-firmware (firmware-mediatek was its only package). That folds in IMG-fw-later: no Wi-Fi firmware at all.
2. **Units, users, policy.** `build.sh` stops building `agentos-ap` and `agentos-netjoin` and installing their units, the netjoin polkit rule and its D-Bus policy; the preset stops enabling them and drops the hostapd.service line; sysusers drops `agentos-netjoin` and `agentos-hostapd`; `exec.allow` drops the two policy files and dnsmasq's D-Bus file; `10-agentos-wlan.link` goes (nothing names `wlan0` any more).
3. **Tree check.** `radio_violations` (firmware required) becomes `wifi_violations` (refused): the MT7922 firmware under any suffix the loader tries, the regulatory database, hostapd and dnsmasq, the two binaries and their units in any unit directory. `CARD_UNITS` and `SERVICE_DIRS` drop the access point's and the helper's entries.
4. **Boot check.** `ci_boot.sh` drops the mac80211_hwsim boot and its reboot (the station beside the access point, ASSUMPTIONS P2-2w-c3-r4b-2-I1) and the NetworkManager check's `pkcheck yes for agentos-netjoin`. Every other assertion stays, and the first boot's existing wired-uplink checks (a lease on the cable, the forwards' probes, the reboot's no-wait) are the uplink proof. G1 stays proven (D-128).
5. **CI.** `ci.yml` drops the "hostapd runs as its own user (#1426)" step; `image.yml` no longer triggers on `broker/cmd/agentos-ap/**` (it keeps `broker/apnet/**`, which agentosd still imports until b2). The in-image e2e harness (`broker/e2e/boxe2e`) no longer stops `agentos-ap.service`, which the image no longer has.

NetworkManager, wpasupplicant and polkitd stay in this slice: the issue's row does not name them, and removing NetworkManager rewrites its own tree checks (`networkmanager_violations`, `nm_unit_violations`, `tests/test_image_nm.py`) and the inbound ordering in I11. It is a finding for a follow-up row, since NetworkManager now manages nothing.

**Requirement IDs:** CH-9 and NET-2 as D-178 applies them (the core never turns Wi-Fi on; setup runs on the enforcer's networks), HW-10 (one image for the core and the edge).

**Acceptance tests:**
- CH-9, NET-2: `tests/test_image_wifidel.py::TestImageShipsNoWiFi::test_no_wifi_package_or_component`. `mkosi.conf` and the apt sources name none of the four packages and only `main`.
- CH-9, NET-2: `::test_no_access_point_or_join_is_built_or_enabled`. `build.sh` builds and installs neither command, unit, polkit rule nor D-Bus policy; the preset enables neither; sysusers makes neither user; `exec.allow` lists none of their files.
- CH-9, NET-2, HW-10: `::test_tree_check_refuses_wifi`. A tree that otherwise passes is refused with one named line for each of the radio firmware (plain, `.xz`, `.zst`), `regulatory.db`, hostapd, dnsmasq, each binary and each unit; the image's own tree passes.
- G1: `::test_boot_check_has_no_radio`. `ci_boot.sh` loads no mac80211_hwsim, mentions neither unit, and still asserts the wired lease and the inbound probes; `ci.yml` has no hostapd step.
- Updated, not new: `tests/test_image.py` (fixtures without the radio files, the network, setup-unit, sysusers and build tests), `tests/test_image_keeper.py` and `tests/test_image_noexec.py` (fixtures on `agentos-modem.service`), `tests/test_ci_scope.py` (its continue-on-error fixture step). `tests/test_image_station.py` is deleted with the boot it tested.

**Scope:** `image/mkosi/mkosi.conf`, `image/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources`, `image/mkosi/mkosi.finalize`, `image/mkosi/exec.allow`, `image/mkosi/mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset`, `image/mkosi/mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf`, `image/mkosi/mkosi.extra/usr/lib/systemd/network/10-agentos-wlan.link` (deleted), comments in `agentos-egress.service`, `agentos-no-bluetooth.conf`, `20-agentos-uplink.network` and `tmpfiles.d/agentos.conf`, `image/build.sh`, `image/ci_boot.sh`, `image/README.md`, `image/ASSUMPTIONS.md` (I8, I16, I17, I19, I20, P2-2w-c3-r4b-2-I1), `.github/workflows/ci.yml`, `.github/workflows/image.yml`, `tests/test_image.py`, `tests/test_image_keeper.py`, `tests/test_image_noexec.py`, `tests/test_image_station.py` (deleted), `tests/test_ci_scope.py`, `tests/test_image_wifidel.py` (new), `tests/test_image_nm.py`, `assurance/vulncheck.json` (the dnsmasq record), `broker/e2e/boxe2e/main_linux.go` and its `ASSUMPTIONS.md` (E2), and the two b2-package tests that required the image wiring (`broker/cmd/agentos-ap/unit_test.go`'s sysusers check, `broker/cmd/agentos-netjoin/busconfig_test.go`'s `TestTheImageInstallsTheBusPolicy`).

**Guard files:** `.github/workflows/` and `image/mkosi/exec.allow` may be gate files; the builder runs `premerge.py --needs-mark` and states the result.

**Estimate:** about 120k tokens, one session, mostly deletion. Checkpoint at 120k.

## b2: the code goes (#3235, after #3399, #3402 and #3440)

Built 2026-10-27 against main at 111cdd0, in the serial `cmd/agentosd` slot (D-111). b1 left nothing in the image that runs the access point or the join helper. b2 deletes the code that still built them, and what read their files:
- `broker/cmd/agentos-ap`, `broker/cmd/agentos-netjoin`, `broker/apnet` and `broker/netjoin`. That drops godbus (D-108) and mdlayher/genetlink and netlink (D-144) from `go.mod` and `vendor/`.
- localui's access point (`ap.go`, `apexempt.go`, `aphost.go`, `aploader.go`, `hostapd.go`, `stationiface.go`, `testdata/`, and their tests). The page's port and name constants and three validators that the wired page still uses move to `pagename.go`.
- agentosd's owned marker (`owned.go`, `-owned`).
- firstboot's setup network (`BoxConfig.SetupNet`, `Network`, `SetupNetwork`, `CardConfirmed`). The core keeps none since WIFI-del-d, so a box with no claim state routes to reinstall unless it is the download's.
- `claim.SetupNet.Rotate`, with `ErrRotated` and `NewSetupPassword`. `SetupNet` stays for the seller's hand-off to the enforcer, and `SetupNetPath` stays only as the path the seller's test checks prep leaves empty.
- The image's `ap-exempt` script, `agentos-ap-exempt@.service` and the `/var/lib/agentos/ap` tmpfiles line. The tree check now refuses anything in `/var/lib/agentos`, an empty `ap` directory included.
- The lists that named them: `broker/core/core.txt`, the ARC-2 and launcher tests, `durable/stores.txt`, `tools/g1_scope_g2.txt` and `tests/test_g1_scope.py`'s binaries, `tools/risk_tier.py` with OPERATING §3's tier-A list (a test holds the two equal), `tools/trusted_base_parsers.txt`, `image.yml`'s path filter, `assurance/dependencies.json`, the legacy ASSUMPTIONS IDs and the product-name baseline.

The vault's Wi-Fi reads (comment 6431950367) went with WIFI-del-e (#3402: `committedwifi.go`, the card vault's Wi-Fi part). b2 leaves localui's `ErrWiFiQR` scan answer in place: it is a refusal, not a read.

**Acceptance tests:** `tests/test_wifidel_b2.py::TestNoAccessPointCode`, whose five tests each catch one piece coming back. Updated: `tests/test_image.py` (the tree check on `/var/lib/agentos`; `ApExemptTest` deleted), `tests/test_inbound_netns.py` (`AccessPointThroughTheDrop` deleted), `tests/test_image_noexec.py`, `tests/test_image_keeper.py`, and `broker/firstboot` (the setup-network tests deleted).

**Guard files:** `broker/core/core.txt`, `tools/risk_tier.py`, `tools/g1_scope_g2.txt`, `tests/test_g1_scope.py` and `.github/workflows/image.yml`, so this is a gate-file PR (`premerge.py --needs-mark`).
