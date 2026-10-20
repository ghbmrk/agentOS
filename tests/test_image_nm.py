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


UNIT = "usr/lib/systemd/system/NetworkManager.service"
DROPIN_SRC = MK / "mkosi.extra" / check.NM_DROPIN


def nm_tree(root, conf=None):
    """A tree holding NetworkManager, its unit and drop-in, and the image's own file (or CONF in its place)."""
    write(root, "usr/sbin/NetworkManager", "\x7fELF", 0o755)
    write(root, UNIT, "[Service]\nExecStart=%s\n" % check.NM_EXEC)
    write(root, check.NM_DROPIN, DROPIN_SRC.read_text())
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
    def test_any_other_file_in_a_place_networkmanager_reads_is_refused(self):
        # A closed list: NetworkManager reads these files (nm-system-settings.conf in place of the main
        # file, the intern file over the user's, /run conf.d, and the main file itself), and none may
        # exist, whatever it holds. The first two repro Security's false pass on #2607 (a file that
        # turns Wi-Fi MAC randomisation off).
        body = "[connection]\nwifi.cloned-mac-address=permanent\n"
        for rel in ("etc/NetworkManager/nm-system-settings.conf",
                    "var/lib/NetworkManager/NetworkManager-intern.conf",
                    "run/NetworkManager/conf.d/99-x.conf", "etc/NetworkManager/conf.d/99-x.conf",
                    "usr/lib/NetworkManager/conf.d/99-x.conf", "etc/NetworkManager/NetworkManager.conf",
                    "var/lib/NetworkManager/seen-bssids", "usr/lib/NetworkManager/conf.d/50-agentos.conf.orig"):
            with self.subTest(rel=rel):
                f = write(self.root, rel, body)
                self.assertIn(rel, " ".join(refused(self.root)))
                f.unlink()
        self.assertEqual(refused(self.root), [])

    # REQ: DEV-2
    def test_a_root_that_is_a_link_or_a_file_is_refused(self):
        for d in ("etc/NetworkManager", "var/lib/NetworkManager"):
            with self.subTest(d=d):
                (self.root / d).parent.mkdir(parents=True, exist_ok=True)
                os.symlink("/tmp", self.root / d)
                self.assertIn(d, " ".join(refused(self.root)))
                (self.root / d).unlink()
        self.assertEqual(refused(self.root), [])

    # REQ: DEV-2
    def test_the_unit_is_closed_to_the_shipped_exec_and_drop_in(self):
        # Each repro from Security and the combined review on #2607 round 2: a unit that reaches
        # configuration the closed list does not cover, by a flag, a plugin, a variable or a drop-in
        # systemd finds under another name or directory.
        bad = "[Service]\n%s\n"
        cases = {
            "system-config-dir": (UNIT, bad % "ExecStart=/usr/sbin/NetworkManager --no-daemon --system-config-dir=/x"),
            "ifupdown": (UNIT, bad % "ExecStart=/usr/sbin/NetworkManager --no-daemon --plugins=ifupdown"),
            "env-expansion": (UNIT, "[Service]\nEnvironment=A=--config=/x\n"
                                    "ExecStart=/usr/sbin/NetworkManager --no-daemon $A\n"),
            "env-file": (UNIT + ".d/10-x.conf", "[Service]\nEnvironmentFile=/x\n"),
            "continuation": (UNIT + ".d/10-x.conf", "[Service]\nExecStart=\nExecStart=/usr/sbin/NetworkManager "
                                                    "--no-daemon \\\n  --system-config-dir=/x\n"),
            "alias-dropin": ("etc/systemd/system/dbus-org.freedesktop.NetworkManager.service.d/10-x.conf",
                             bad % "ExecStart=\nExecStart=/usr/sbin/NetworkManager --plugins=ifupdown"),
            "usr-local-lib-dropin": ("usr/local/lib/systemd/system/NetworkManager.service.d/10-x.conf",
                                     bad % "ExecStart=\nExecStart=/x --no-daemon --config=/x"),
            "service.d-dropin": ("etc/systemd/system/service.d/10-x.conf", bad % "ExecStart=\nExecStart=/x"),
            "second-exec": (UNIT + ".d/10-x.conf", bad % "ExecStart=/usr/sbin/NetworkManager --no-daemon"),
            "masking-dropin": ("etc/systemd/system/NetworkManager.service.d/agentos-inbound.conf", "[Unit]\n"),
            "altered-dropin": (check.NM_DROPIN, DROPIN_SRC.read_text() + "[Service]\nExecStart=\n"),
        }
        for label, (rel, body) in cases.items():
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as d:
                    root = pathlib.Path(d)
                    nm_tree(root)
                    if label == "alias-dropin":
                        (root / "etc/systemd/system").mkdir(parents=True, exist_ok=True)
                        os.symlink("/usr/lib/systemd/system/NetworkManager.service",
                                   root / "etc/systemd/system/dbus-org.freedesktop.NetworkManager.service")
                    write(root, rel, body)
                    self.assertTrue(refused(root))

    # REQ: DEV-2
    def test_the_unit_as_debian_ships_it_and_its_alias_pass(self):
        nm_tree(self.root)
        self.assertEqual(refused(self.root), [])
        (self.root / "etc/systemd/system").mkdir(parents=True)
        os.symlink("/usr/lib/systemd/system/NetworkManager.service",
                   self.root / "etc/systemd/system/dbus-org.freedesktop.NetworkManager.service")
        self.assertEqual(refused(self.root), [])

    # REQ: DEV-2
    def test_the_unit_or_the_inbound_drop_in_missing_is_refused(self):
        (self.root / UNIT).unlink()
        self.assertIn("missing", " ".join(refused(self.root)))
        write(self.root, UNIT, "[Service]\nExecStart=%s\n" % check.NM_EXEC)
        (self.root / check.NM_DROPIN).unlink()
        self.assertIn("missing", " ".join(refused(self.root)))

    # REQ: DEV-2
    def test_the_shipped_drop_in_is_the_text_the_check_allows(self):
        self.assertEqual(DROPIN_SRC.read_bytes(), check.NM_DROPIN_TEXT)

    # REQ: DEV-2
    def test_a_file_behind_a_linked_parent_is_refused(self):
        # var/lib is a link to state: NetworkManager reads var/state/NetworkManager through it.
        shutil.rmtree(self.root / "var", ignore_errors=True)
        write(self.root, "var/state/NetworkManager/NetworkManager-intern.conf", "[connection]\n")
        os.symlink("state", self.root / "var/lib")
        self.assertIn("NetworkManager-intern.conf", " ".join(refused(self.root)))

    # REQ: DEV-2
    def test_a_directory_that_cannot_be_listed_is_refused(self):
        d = self.root / "var/lib/NetworkManager"
        d.mkdir(parents=True)
        real = check.tree_listdir

        def deny(root, rel):
            if rel.endswith("var/lib/NetworkManager"):
                raise PermissionError(13, "Permission denied")
            return real(root, rel)

        with unittest.mock.patch.object(check, "tree_listdir", deny):
            self.assertIn("var/lib/NetworkManager", " ".join(refused(self.root)))

    # REQ: DEV-2
    def test_a_non_ascii_or_control_byte_is_refused(self):
        for tail in ("# café\n", "# a\x01b\n", "# a\x00b\n", "# tail \\\n"):
            with self.subTest(tail=tail):
                write(self.root, CONF, CONF_SRC.read_text() + tail)
                self.assertTrue(refused(self.root))

    # REQ: DEV-2, CH-9
    def test_an_unreadable_shipped_file_is_refused(self):
        # A link in place of the file is one the check cannot read (#1543); refused, never skipped.
        (self.root / CONF).unlink()
        os.symlink("/etc/hostname", self.root / CONF)
        self.assertIn("50-agentos.conf", " ".join(refused(self.root)))

    # REQ: DEV-2, CH-9
    def test_an_executable_dispatcher_script_is_refused(self):
        for d in ("etc/NetworkManager/dispatcher.d", "usr/lib/NetworkManager/dispatcher.d"):
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

    # REQ: DEV-2
    def test_the_driver_and_thunderbolt_udev_rules_are_removed_and_not_allowlisted(self):
        # They do nothing for wlsta0; dropping them leaves less root-run udev code to pin. The
        # unmanaged-devices rule (85) stays pinned as Debian ships it; the wired port is kept off NetworkManager
        # by [keyfile] unmanaged-devices in 50-agentos.conf, not by this rule.
        rm = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        allow = (MK / "exec.allow").read_text()
        for n in ("84-nm-drivers.rules", "90-nm-thunderbolt.rules"):
            self.assertIn("/usr/lib/udev/rules.d/" + n, rm)
            self.assertNotIn(n, allow)
        self.assertIn("85-nm-unmanaged.rules", allow)
        self.assertNotIn("/usr/lib/udev/rules.d/85-nm-unmanaged.rules", rm)

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
