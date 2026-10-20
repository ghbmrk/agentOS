# Tests for NetworkManager in the device image (#936, P2-2w-c3-r4a): its shipped configuration, the
# build-time check that pins it, and the packages and units around it. The boot checks are in
# image/ci_boot.sh, which the image workflow runs.
# REQ: ONB-3, ONB-4, DEV-2, CH-9, STO-2
import json
import os
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, IMG, ROOT, check, ini, load, write  # noqa: E402

CONF = "usr/lib/NetworkManager/conf.d/50-agentos.conf"
CONF_SRC = MK / "mkosi.extra" / CONF
SHIPPED = {
    ("main", "plugins"): "keyfile",
    ("main", "no-auto-default"): "*",
    ("main", "dns"): "systemd-resolved",
    ("main", "auth-polkit"): "true",
    ("keyfile", "unmanaged-devices"): "*,except:interface-name:wlsta0",
    ("keyfile", "path"): "/run/NetworkManager/system-connections",
    ("connectivity", "enabled"): "false",
}


def nm_tree(root, conf=None):
    """A tree holding NetworkManager and the image's own file (or CONF in its place)."""
    write(root, "usr/sbin/NetworkManager", "\x7fELF", 0o755)
    write(root, CONF, CONF_SRC.read_text() if conf is None else conf)


def refused(root):
    return check.networkmanager_violations(root)


class ShippedConfTest(unittest.TestCase):
    # REQ: ONB-3, DEV-2
    def test_the_file_holds_exactly_the_property_key_by_key(self):
        p = ini(CONF_SRC)
        got = {(s, k): v for s in p.sections() for k, v in p[s].items()}
        self.assertEqual(got, SHIPPED)

    # REQ: ONB-3, DEV-2
    def test_the_file_is_plain_ascii(self):
        data = CONF_SRC.read_bytes()
        self.assertTrue(all(b in (9, 10) or 0x20 <= b <= 0x7e for b in data))

    # REQ: ONB-3, DEV-2, STO-2
    def test_removing_or_changing_any_line_fails(self):
        # Every key line removed, and every value changed, is refused by the check on the real file.
        text = CONF_SRC.read_text()
        lines = text.split("\n")
        keyed = [n for n, ln in enumerate(lines) if "=" in ln and not ln.startswith("#")]
        self.assertEqual(len(keyed), len(SHIPPED))
        for n in keyed:
            key, _, val = lines[n].partition("=")
            for label, new in (("removed", None), ("changed", "%s=x" % key)):
                with self.subTest(key=key, how=label):
                    mut = lines[:n] + ([] if new is None else [new]) + lines[n + 1:]
                    with tempfile.TemporaryDirectory() as d:
                        root = pathlib.Path(d)
                        nm_tree(root, "\n".join(mut))
                        self.assertTrue(refused(root))
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            nm_tree(root)
            self.assertEqual(refused(root), [])


class FinalizeCheckTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        nm_tree(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def conf_with(self, key, val):
        """The shipped file with KEY's line given VAL; None removes the line."""
        text = re.sub(r"(?m)^%s=.*\n" % re.escape(key), "" if val is None else "%s=%s\n" % (key, val),
                      CONF_SRC.read_text())
        write(self.root, CONF, text)

    # REQ: DEV-2, CH-9
    def test_a_clean_tree_passes(self):
        self.assertEqual(refused(self.root), [])

    # REQ: DEV-2
    def test_a_tree_without_networkmanager_is_not_checked(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(refused(pathlib.Path(d)), [])

    # REQ: DEV-2, CH-9
    def test_a_connection_file_is_refused(self):
        for body in ("[ipv4]\nmethod=shared\n", "[ipv6]\nmethod=shared\n", "[ipv4]\nforwarding=1\n",
                     "[connection]\nid=home\ntype=wifi\n"):
            with self.subTest(body=body):
                f = write(self.root, "etc/NetworkManager/system-connections/home.nmconnection", body, 0o600)
                self.assertIn("system-connections", " ".join(refused(self.root)))
                f.unlink()
        shutil.rmtree(self.root / "etc/NetworkManager/system-connections")
        self.assertEqual(refused(self.root), [])

    # REQ: STO-2
    def test_a_connection_location_in_any_form_is_refused(self):
        for d in check.NM_CONNECTIONS:
            with self.subTest(d=d):
                (self.root / d).mkdir(parents=True)
                self.assertIn(d, " ".join(refused(self.root)))
                (self.root / d).rmdir()

    # REQ: STO-2
    def test_a_keyfile_path_off_run_is_refused(self):
        for path in ("/etc/NetworkManager/system-connections", "/var/lib/NetworkManager", "/runx/a",
                     "run/NetworkManager", "/run/../etc/x", "/run"):
            with self.subTest(path=path):
                self.conf_with("path", path)
                self.assertIn("path", " ".join(refused(self.root)))
        self.conf_with("path", None)
        self.assertIn("path", " ".join(refused(self.root)))

    # REQ: DEV-2, CH-9
    def test_unmanaged_devices_that_stop_covering_wired_and_wlan0_are_refused(self):
        for val in ("interface-name:wlsta0", "*,except:interface-name:wlan0",
                    "*,except:interface-name:wlsta0,except:interface-name:eth0",
                    "*,except:type:ethernet", "except:interface-name:wlsta0", ""):
            with self.subTest(val=val):
                self.conf_with("unmanaged-devices", val)
                self.assertIn("unmanaged-devices", " ".join(refused(self.root)))

    # REQ: DEV-2
    def test_an_unknown_key_or_section_is_refused(self):
        base = CONF_SRC.read_text()
        for extra in ("[main]\nfoo=bar\n", "[main]\ndhcp=dhclient\n", "[keyfile]\nunmanaged-devices+=interface-name:eth0\n",
                      "[device]\nwifi.scan-rand-mac-address=no\n", "[logging]\nlevel=TRACE\n"):
            with self.subTest(extra=extra):
                write(self.root, CONF, base + "\n" + extra)
                self.assertTrue(refused(self.root))

    # REQ: DEV-2
    def test_a_key_set_twice_is_refused(self):
        write(self.root, CONF, CONF_SRC.read_text() + "\n[connectivity]\nenabled=false\n")
        self.assertIn("set 2 times", " ".join(refused(self.root)))

    # REQ: DEV-2
    def test_other_conf_files_are_read_too(self):
        # NetworkManager reads /etc, /run and /usr/lib conf.d and the main file; a later file can
        # reset a value, so each is held to the same keys.
        for rel in ("etc/NetworkManager/conf.d/99-x.conf", 
                    "usr/lib/NetworkManager/conf.d/99-x.conf", "etc/NetworkManager/NetworkManager.conf",
                    "usr/lib/NetworkManager/NetworkManager.conf"):
            with self.subTest(rel=rel):
                f = write(self.root, rel, "[keyfile]\nunmanaged-devices=interface-name:nothing\n")
                self.assertTrue(refused(self.root))
                f.unlink()

    # REQ: DEV-2
    def test_a_non_ascii_or_control_byte_is_refused(self):
        for tail in ("# café\n", "# a\x01b\n", "# a\x00b\n", "# tail \\\n"):
            with self.subTest(tail=tail):
                write(self.root, CONF, CONF_SRC.read_text() + tail)
                self.assertTrue(refused(self.root))

    # REQ: DEV-2, CH-9
    def test_an_unreadable_file_is_refused(self):
        # A link in conf.d is one the check cannot read (#1543); it is refused, never skipped.
        os.symlink("/etc/hostname", self.root / "etc/NetworkManager/conf.d/99-x.conf") \
            if (self.root / "etc/NetworkManager/conf.d").mkdir(parents=True) is None else None
        self.assertIn("99-x.conf: unreadable", " ".join(refused(self.root)))

    # REQ: DEV-2, CH-9
    def test_a_check_that_skips_an_unreadable_file_would_fail_this_suite(self):
        # The mutant: the byte check's refusals are dropped, so the unreadable file is passed over.
        # It must be able to pass the unreadable fixture (so the test above is what catches it).
        src = (MK / "mkosi.finalize").read_text()
        old = "        bad = byte_violations(f)\n        out += bad\n"
        self.assertEqual(src.count(old), 1)
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as t:
            t.write(src.replace(old, "        bad = byte_violations(f)\n"))
        try:
            mutant = load("image_check_mutant", t.name)
        finally:
            os.unlink(t.name)
        mutant.TREE_OWNER, mutant.TREE_GROUP = check.TREE_OWNER, check.TREE_GROUP
        (self.root / "etc/NetworkManager/conf.d").mkdir(parents=True)
        os.symlink("/etc/hostname", self.root / "etc/NetworkManager/conf.d/99-x.conf")
        self.assertEqual(mutant.networkmanager_violations(self.root), [])
        self.assertTrue(check.networkmanager_violations(self.root))

    # REQ: DEV-2, CH-9
    def test_an_executable_dispatcher_script_is_refused(self):
        for d in check.NM_DISPATCH:
            with self.subTest(d=d):
                f = write(self.root, d + "/10-x", "#!/bin/sh\n", 0o755)
                self.assertIn("10-x", " ".join(refused(self.root)))
                f.unlink()
                self.assertEqual(refused(self.root), [])
        # A link into the directory is refused whatever it points to.
        (self.root / "etc/NetworkManager/dispatcher.d").mkdir(parents=True, exist_ok=True)
        os.symlink("/dev/null", self.root / "etc/NetworkManager/dispatcher.d/10-x")
        self.assertIn("10-x", " ".join(refused(self.root)))

    # REQ: DEV-2
    def test_the_check_is_part_of_the_tree_check(self):
        # The wiring: a bad NetworkManager tree fails violations() itself. The allowlists are patched
        # out; they have their own tests.
        self.conf_with("path", "/var/lib/x")
        for name in ("exec_allow_violations", "tmpfiles_allow_violations"):
            p = unittest.mock.patch.object(check, name, return_value=[])
            p.start()
            self.addCleanup(p.stop)
        self.assertIn("path", " ".join(check._violations(self.root)))


class ImageFilesTest(unittest.TestCase):
    # REQ: ONB-3, ONB-4
    def test_the_packages_are_listed(self):
        pkgs = ini(MK / "mkosi.conf")["Content"]["Packages"].split()
        for p in ("network-manager", "polkitd", "wpasupplicant"):
            self.assertIn(p, pkgs)

    # REQ: ONB-3
    def test_the_preset_enables_networkmanager_and_leaves_the_waiters_off(self):
        lines = [ln.split() for ln in (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset")
                 .read_text().split("\n") if ln and not ln.startswith("#")]
        self.assertIn(["enable", "NetworkManager.service"], lines)
        self.assertIn(["disable", "NetworkManager-wait-online.service"], lines)
        self.assertIn(["disable", "NetworkManager-dispatcher.service"], lines)

    # REQ: DEV-2
    def test_networkmanager_needs_the_inbound_drop_first(self):
        d = ini(MK / "mkosi.extra/usr/lib/systemd/system/NetworkManager.service.d/agentos-inbound.conf")["Unit"]
        self.assertIn("agentos-inbound.service", d["Requires"].split())
        self.assertIn("agentos-inbound.service", d["After"].split())

    # REQ: STO-2
    def test_the_distro_connection_and_dispatcher_locations_are_removed(self):
        rm = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        for p in ("/etc/NetworkManager/system-connections", "/etc/NetworkManager/dispatcher.d",
                  "/usr/lib/NetworkManager/dispatcher.d", "/etc/NetworkManager/NetworkManager.conf"):
            self.assertIn(p, rm)

    # REQ: ONB-3, DEV-2
    def test_only_the_netjoin_rule_answers_yes(self):
        # The rule is installed by build.sh from broker/cmd/agentos-netjoin; nothing else may ship
        # one under a polkit rules directory.
        rules = [ROOT / "broker/cmd/agentos-netjoin/50-agentos-netjoin.rules"]
        rules += [p for p in MK.rglob("*.rules") if "polkit-1" in p.parts]
        self.assertTrue(all("netjoin" in p.name for p in rules), rules)
        self.assertIn("polkit-1/rules.d/50-agentos-netjoin.rules", (IMG / "build.sh").read_text())
        for p in rules:
            self.assertEqual(len(re.findall(r"polkit\.Result\.YES", p.read_text())), 1, p)

    # REQ: ONB-3, DEV-2
    def test_ci_boot_checks_networkmanager_on_the_first_boot(self):
        t = (IMG / "ci_boot.sh").read_text()
        for needle in ("NetworkManager.service", "nmcli -t -f DEVICE,STATE device", "systemctl --failed",
                       "inbound=drop swap=off dumps=off forward=off", "pkcheck", "org.freedesktop.NetworkManager.settings.modify.system",
                       "agentos-netjoin", "/etc/NetworkManager/system-connections"):
            self.assertIn(needle, t)

    # REQ: ONB-3, DEV-2, STO-2
    def test_assumptions_name_the_files_and_the_guard(self):
        t = (IMG / "ASSUMPTIONS.md").read_text()
        row = lambda i: next(ln for ln in t.split("\n") if ln.startswith("| %s " % i))
        self.assertNotRegex(row("I17"), r"(?i)(NetworkManager|NM) (is )?(absent|not)")
        for needle in ("conf.d", "system-connections", "dispatcher.d"):
            self.assertIn(needle, row("I21"))
        nm = row("NM-1")
        for needle in ("/run", "STO-2", "#935"):
            self.assertIn(needle, nm)


class PolkitVersionTest(unittest.TestCase):
    """The built image's polkitd, read from the package manifest mkosi writes (ManifestFormat=json)."""

    cm = load("compare_manifests", IMG / "compare_manifests.py")

    def ok(self, packages):
        with tempfile.TemporaryDirectory() as d:
            m = [{"name": n, "version": v} for n, v in packages]
            pathlib.Path(d, "agentos.manifest").write_text(json.dumps({"packages": m}))
            return self.cm.polkitd_ok(d)

    # REQ: ONB-3
    def test_the_version_is_read_from_the_manifest(self):
        for v, want in (("126-2", True), ("0.106-1", True), ("0.105-33", False), ("0.99", False),
                        ("x", False)):
            with self.subTest(v=v):
                self.assertEqual(self.ok([("dbus", "1.0"), ("polkitd", v)]), want)
        self.assertFalse(self.ok([("dbus", "1.0")]))

    # REQ: ONB-3
    def test_ci_boot_runs_the_check_on_the_manifest_beside_the_image(self):
        t = (IMG / "ci_boot.sh").read_text()
        self.assertIn("compare_manifests.py\" --polkitd", t)
        self.assertIn('dirname "$IMG"', t)


if __name__ == "__main__":
    unittest.main()
