# WIFI-del-nm (#3387, D-178): NetworkManager, wpasupplicant and polkitd managed only the home Wi-Fi
# station, which WIFI-del-b removed, so the image installs none of them, the tree check refuses
# NetworkManager and wpa_supplicant if they come back, and systemd-networkd is the only network
# manager. Brief: briefs/WIFI-del-nm.md.
# REQ: CH-9, NET-2, HW-10
import importlib.util
import json
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, IMG, ROOT, bt_block, check, ini, nodump, uplink, write  # noqa: E402

spec = importlib.util.spec_from_file_location("drop", MK / "drop.py")
drop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drop)

PACKAGES = ("network-manager", "wpasupplicant", "polkitd")
NM = re.compile(r"NetworkManager|nm-|nm_|wpa_supplicant|PolicyKit1|policykit\.policy|50-default\.rules|polkit-tmpfiles")


class TestImageShipsNoWiFiClient(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        write(self.root, "usr/lib/agentos/agentosd", "\x7fELF", 0o755)
        (self.root / "var/lib/agentos").mkdir(parents=True)
        nodump(self.root)
        bt_block(self.root)
        uplink(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_wifi_client_package_or_file(self):
        conf = (MK / "mkosi.conf").read_text()
        pkgs = ini(MK / "mkosi.conf")["Content"]["Packages"].split()
        for p in PACKAGES:
            with self.subTest(p):
                self.assertNotIn(p, pkgs)
        self.assertNotIn("NetworkManager", re.sub(r"(?m)^#.*\n", "", conf))
        self.assertEqual(sorted((MK / "mkosi.extra/usr/lib").glob("NetworkManager*")), [])
        self.assertEqual(sorted((MK / "mkosi.extra/usr/lib/systemd/system").glob("NetworkManager*")), [])
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertNotIn("NetworkManager", preset)
        self.assertRegex(preset, r"(?m)^enable systemd-networkd\.service$")
        # Nothing on the allowlists was shipped by the three packages.
        self.assertEqual([rel for rel, _ in check.exec_allowed() if NM.search(rel)], [])
        tmpfiles = (MK / "tmpfiles.allow").read_text()
        self.assertEqual([ln for ln in tmpfiles.splitlines() if not ln.startswith("#") and NM.search(ln)], [])
        # Nor the packages' forced drops, which only NetworkManager's plugins and nmtui needed.
        self.assertEqual([p for p in drop.FILES if re.search(r"NetworkManager|nmtui", p)], [])
        for p in ("libbluetooth3", "libmm-glib0", "libnewt0.52", "libslang2"):
            self.assertNotIn(p, drop.DROP)
        # And no advisory record accepts a source the image no longer ships. policykit-1's stay while
        # its library may: an unused record only warns, a missing one fails the scan.
        records = json.loads((ROOT / "assurance/vulncheck.json").read_text())["accepted"]
        self.assertEqual([r["id"] for r in records if r.get("package") in ("network-manager", "wpa")], [])

    def test_tree_check_refuses_a_wifi_client(self):
        self.assertEqual(check.violations(self.root), [])
        programs = ["usr/sbin/NetworkManager", "usr/bin/nmcli", "usr/sbin/wpa_supplicant", "usr/sbin/wpa_cli"]
        programs += ["%s/%s" % (d, u) for d in ("usr/lib/systemd/system", "etc/systemd/system")
                     for u in ("NetworkManager.service", "wpa_supplicant.service", "wpa_supplicant@.service")]
        for rel in programs:
            with self.subTest(rel):
                f = write(self.root, rel, "")
                v = check.violations(self.root)
                self.assertEqual([x for x in v if x.startswith(rel + ":")],
                                 ["%s: serves or joins Wi-Fi; the box never turns Wi-Fi on (D-178)" % rel], v)
                f.unlink()
        # The NetworkManager-only checks are gone with it.
        for name in ("networkmanager_violations", "nm_unit_violations", "nm_unit", "NM_KEYS"):
            self.assertFalse(hasattr(check, name), name)

    def test_boot_check_asks_no_wifi_client(self):
        ci_boot = (IMG / "ci_boot.sh").read_text()
        for gone in ("nmcli -t", "pkcheck", "agentos-nm", "--polkitd", "nm_cred"):
            with self.subTest(gone):
                self.assertNotIn(gone, ci_boot)
        # The failed-units line the NetworkManager check carried stays, now beside a Wi-Fi client check.
        for want in ("agentos-units: no failed units", "agentos-units: Wi-Fi client checked",
                     "agentos-units: systemd-networkd.service active", 'hasnt "$W/console.log" "agentos-units: FAIL"'):
            with self.subTest(want):
                self.assertIn(want, ci_boot)
        self.assertNotIn("polkitd", (IMG / "compare_manifests.py").read_text())


if __name__ == "__main__":
    unittest.main()
