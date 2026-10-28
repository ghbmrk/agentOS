# WIFI-del-b2 (#3235, D-178): the core and the edge never turn Wi-Fi on, so after b1 took the access
# point, the join helper and the radio firmware out of the image, b2 takes their code out of the
# tree: the two commands, broker/apnet and broker/netjoin, localui's access point code, the image's
# ap-exempt script and its template unit, the /var/lib/agentos/ap directory, agentosd's owned marker
# and firstboot's setup network. Brief: briefs/WIFI-del-b.md (b2). Each test catches that piece
# coming back.
# REQ: CH-9, NET-2, HW-10
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
BROKER = ROOT / "broker"
EXTRA = ROOT / "image/mkosi/mkosi.extra"
GONE_PKGS = ("apnet", "netjoin", "cmd/agentos-ap", "cmd/agentos-netjoin")
# localui's access point: its config and generators, bring-up and the exempt unit's caller, the
# loader, hostapd and the station beside the access point.
GONE_LOCALUI = ("ap.go", "apexempt.go", "aphost.go", "aploader.go", "hostapd.go", "stationiface.go", "testdata")


def go_sources():
    for p in BROKER.rglob("*.go"):
        if "vendor" not in p.relative_to(BROKER).parts:
            yield p


class TestNoAccessPointCode(unittest.TestCase):

    def test_no_access_point_or_join_package(self):
        for p in GONE_PKGS:
            with self.subTest(p):
                self.assertFalse((BROKER / p).exists())
        for f in GONE_LOCALUI:
            with self.subTest(f):
                self.assertFalse((BROKER / "localui" / f).exists())
        imp = re.compile(r'"github\.com/ghbmrk/agentos/broker/(apnet|netjoin)"')
        self.assertEqual([str(p.relative_to(ROOT)) for p in go_sources() if imp.search(p.read_text())], [])

    def test_no_wifi_dependency(self):
        # godbus was netjoin's (D-108), genetlink and netlink agentos-ap's (D-144).
        mod = (BROKER / "go.mod").read_text()
        for m in ("github.com/godbus/dbus", "github.com/mdlayher/genetlink", "github.com/mdlayher/netlink"):
            with self.subTest(m):
                self.assertNotIn(m, mod)
                self.assertFalse((BROKER / "vendor" / m).exists())

    def test_image_has_no_exempt_unit_or_loader_directory(self):
        self.assertFalse((EXTRA / "usr/lib/agentos/ap-exempt").exists())
        self.assertFalse((EXTRA / "usr/lib/systemd/system/agentos-ap-exempt@.service").exists())
        for f in (EXTRA / "usr/lib/tmpfiles.d/agentos.conf", ROOT / "image/mkosi/tmpfiles.allow"):
            with self.subTest(f.name):
                self.assertNotIn("/var/lib/agentos/ap", f.read_text())

    def test_agentosd_makes_no_owned_marker(self):
        src = "".join(p.read_text() for p in (BROKER / "cmd/agentosd").glob("*.go"))
        self.assertNotIn('"owned"', src)
        self.assertNotIn("markOwned", src)

    def test_firstboot_reads_no_setup_network(self):
        src = (BROKER / "firstboot/start.go").read_text()
        for name in ("SetupNet", "func (f *FirstBoot) Network", "func SetupNetwork", "func CardConfirmed"):
            with self.subTest(name):
                self.assertNotIn(name, src)
        self.assertNotIn("func (n SetupNet) Rotate", (BROKER / "claim/setupnet.go").read_text())


if __name__ == "__main__":
    unittest.main()
