# WIFI-del-nm: the image ships no Wi-Fi client

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3387, a release finding from WIFI-del-b b1 (#3235, #3388). D-178: the core and the edge never turn Wi-Fi on. Tier A.

**Why.** After b1, NetworkManager still starts at boot, configured to manage `wlsta0`, which nothing creates; wpasupplicant is installed and D-Bus activatable; polkitd answers only NetworkManager's actions. Any root process could bring a station up through `nmcli` on a box whose radio firmware comes back, so the Wi-Fi client stays one step away.

**Changes.**
1. **Packages and files.** `mkosi.conf` drops network-manager, wpasupplicant and polkitd and the NetworkManager `RemoveFiles=` lines; `mkosi.extra` loses `usr/lib/NetworkManager/` and the `NetworkManager.service.d` drop-ins; the preset loses its three NetworkManager lines. `exec.allow` and `tmpfiles.allow` drop the entries those packages shipped. `drop.py` drops libbluetooth3, libmm-glib0, libnewt0.52, libslang2 and the NetworkManager plugin and `nmtui` files: without NetworkManager none is installed, and `dpkg-query -L` on a missing package would fail the build. So do the account tools (passwd, login.defs, adduser, libsemanage2, libsemanage-common, libsepol2) and `PERL_TOOLS`' sgml-base and xml-core, which only polkitd pulled in (the #3440 build (b) log lists the install). `assurance/vulncheck.json` drops the records for every source none of whose packages that install has: network-manager, wpa, policykit-1, duktape, glib2.0, curl and its libraries, and b1's firmware-nonfree.
2. **Tree check.** `networkmanager_violations`, `nm_unit_violations`, `nm_unit` and the `NM_*` constants go; `exec_entries` stops pinning NetworkManager's unit; `nm_walk` becomes `policy_walk` (the policy directories still use it). `wifi_violations` also refuses `NetworkManager`, `nmcli`, `wpa_supplicant`, `wpa_cli` and their units.
3. **Boot check.** `ci_boot.sh`'s NetworkManager check becomes `agentos-units`: no failed unit (kept from the old check), no Wi-Fi client unit or command, `systemd-networkd` active. The polkitd version check and `compare_manifests.py --polkitd` go.
4. **Docs.** `image/ASSUMPTIONS.md` I11, I16, I17, I21 and VULN-debian are updated and NM-1 is removed; `image/README.md` loses the NM-1 clause.

polkitd: nothing else on the box asks it. The box's own D-Bus caller was `agentos-netjoin`, gone in b1; units that call `systemctl` run as root (`+` lines). Without polkitd, systemd's bus services answer root only.

**Requirement IDs:** CH-9 and NET-2 as D-178 applies them, HW-10.

**Acceptance tests:**
- CH-9, NET-2: `tests/test_image_wifidel_nm.py::TestImageShipsNoWiFiClient::test_no_wifi_client_package_or_file`. None of the three packages is listed and no NetworkManager file ships. The preset enables networkd and not NetworkManager, and neither allowlist, `drop.py` nor vulncheck names their files or records.
- CH-9, NET-2, HW-10: `::test_tree_check_refuses_a_wifi_client`. A tree that otherwise passes is refused with one named line for each Wi-Fi client binary and unit, and the NetworkManager checks are gone.
- G1: `::test_boot_check_asks_no_wifi_client`. `ci_boot.sh` runs no `nmcli` or `pkcheck` and keeps the failed-units line.
- Updated, not new: `tests/test_image.py` (the exec.allow path pattern, the old NetworkManager drop-in test), `tests/test_image_noexec.py` (credential variable names). `tests/test_image_nm.py` is deleted along with the checks it tested.

**Scope:** `image/mkosi/mkosi.conf`, `image/mkosi/mkosi.finalize`, `image/mkosi/exec.allow`, `image/mkosi/tmpfiles.allow`, `image/mkosi/drop.py`, `image/mkosi/mkosi.extra/usr/lib/NetworkManager/` (deleted), `image/mkosi/mkosi.extra/usr/lib/systemd/system/NetworkManager.service.d/` (deleted), `image/mkosi/mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset`, `image/ci_boot.sh`, `image/compare_manifests.py`, `image/ASSUMPTIONS.md`, `image/README.md`, `assurance/vulncheck.json`, `tests/test_image_wifidel_nm.py` (new), `tests/test_image_nm.py` (deleted), `tests/test_image.py`, `tests/test_image_noexec.py`. Not `cmd/agentosd`.

**Guard files:** `image/mkosi/exec.allow` and the image checks may be gate files; the builder runs `premerge.py --needs-mark` and states the result.

**Estimate:** about 100k tokens, one session, mostly deletion.
