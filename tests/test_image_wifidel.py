# WIFI-del-b (#3235, D-178): the core and the edge never turn Wi-Fi on, so the image builds, installs
# and enables no access point, home Wi-Fi helper or radio firmware, the tree check refuses them if
# they come back, and CI's boot check has no radio. Brief: briefs/WIFI-del-b.md.
# REQ: CH-9, NET-2, HW-10
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, IMG, ROOT, bt_block, check, ini, link, nodump, uplink, write  # noqa: E402

WIFI_PACKAGES = ("hostapd", "dnsmasq-base", "dnsmasq", "wireless-regdb", "firmware-mediatek")
CMDS = ("agentos-ap", "agentos-netjoin")


class TestImageShipsNoWiFi(unittest.TestCase):

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

    def test_no_wifi_package_or_component(self):
        # The four packages and non-free-firmware (firmware-mediatek's only reason) are gone.
        c = ini(MK / "mkosi.conf")
        pkgs = c["Content"]["Packages"].split()
        for p in WIFI_PACKAGES:
            with self.subTest(p):
                self.assertNotIn(p, pkgs)
        self.assertEqual(c["Distribution"]["Repositories"].split(","), ["main"])
        sources = (MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources").read_text()
        self.assertEqual(re.findall(r"^Components: (.*)$", sources, re.M), ["main", "main"])

    def test_no_access_point_or_join_is_built_or_enabled(self):
        build = (IMG / "build.sh").read_text()
        loop = re.search(r"^for cmd in ([^;]*);", build, re.M).group(1).split()
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        for cmd in CMDS:
            with self.subTest(cmd):
                self.assertNotIn(cmd, loop)
                self.assertNotIn("broker/cmd/%s/" % cmd, build)
                self.assertNotRegex(preset, r"(?m)^enable %s\b" % cmd)
        self.assertNotIn("polkit-1", build)
        self.assertNotIn("dbus-1", build)
        self.assertNotIn("hostapd", preset)
        users = (MK / "mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf").read_text()
        for u in ("agentos-netjoin", "agentos-hostapd"):
            self.assertNotRegex(users, r"(?m)^u %s\b" % u)
        listed = [rel for rel, _ in check.exec_allowed()]
        self.assertEqual([rel for rel in listed if re.search(r"netjoin|hostapd|dnsmasq", rel)], [])
        # The only link file named the radio (wlan0) for the loader; nothing does now.
        self.assertEqual(sorted((MK / "mkosi.extra/usr/lib/systemd/network").glob("*.link")), [])

    def test_tree_check_refuses_wifi(self):
        self.assertEqual(check.violations(self.root), [])
        firmware = [rel + sfx for rel in check.RADIO_FIRMWARE for sfx in ("", ".xz", ".zst")]
        self.assertIn("usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7922_1.bin", firmware)
        self.assertIn("usr/lib/firmware/regulatory.db", firmware)
        programs = ["usr/sbin/hostapd", "usr/sbin/dnsmasq", "usr/bin/dnsmasq", "usr/sbin/hostapd_cli"]
        programs += ["usr/lib/agentos/%s" % c for c in CMDS]
        programs += ["%s/%s" % (d, u) for d in ("usr/lib/systemd/system", "etc/systemd/system")
                     for u in ("agentos-ap.service", "agentos-netjoin.service", "hostapd.service")]
        for rel in firmware + programs:
            with self.subTest(rel):
                # Any entry counts, even an empty file: the check is about presence, not content.
                f = write(self.root, rel, "")
                v = check.violations(self.root)
                self.assertEqual([x for x in v if x.startswith(rel + ":")],
                                 ["%s: %s; the box never turns Wi-Fi on (D-178)"
                                  % (rel, "radio firmware" if rel in firmware else "serves or joins Wi-Fi")], v)
                f.unlink()
        # Through a link as the booted image resolves it (lib is usr/lib on trixie).
        (self.root / "lib").symlink_to("usr/lib")
        write(self.root, "usr/lib/firmware/mediatek/real.bin", "fw")
        link(self.root, "usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7922_1.bin", "/lib/firmware/mediatek/real.bin")
        self.assertIn("usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7922_1.bin: radio firmware; the box never turns "
                      "Wi-Fi on (D-178)", check.wifi_violations(self.root))

    def test_boot_check_has_no_radio(self):
        ci_boot = (IMG / "ci_boot.sh").read_text()
        for gone in ("mac80211_hwsim", "agentos-ap", "agentos-netjoin", "hostapd", "dnsmasq", "wlan0", "console-hwsim"):
            with self.subTest(gone):
                self.assertNotIn(gone, ci_boot)
        # G1 keeps its wired proof: the first boot's lease and the inbound probes (D-128).
        self.assertIn('lease', ci_boot)
        self.assertIn("probe_inbound.py", ci_boot)
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertNotIn("hostapd", ci)
        self.assertNotIn("TestHostapdChildRunsAsItsOwnUser", ci)
        self.assertNotIn("broker/cmd/agentos-ap/", (ROOT / ".github/workflows/image.yml").read_text())


if __name__ == "__main__":
    unittest.main()
