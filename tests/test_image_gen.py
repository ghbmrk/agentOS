"""IMG-keeper-reach-gen (#5289): no generator or credential adds a unit or mount the tree check does
not read.

The tree check (mkosi.finalize: made.allow, the unit-made directory rules, the keeper check) reads the
unit directories, fstab and system.conf. Four other routes give PID 1 units or mounts:
- systemd-gpt-auto-generator mounts /home, /srv, /var or /var/tmp from partitions of those types on
  the root's disk, and systemd-repart makes any partition its definitions name. finish_image.py pins
  the built disk to exactly mkosi.repart's partitions, the definitions to the ESP, /usr, its verity
  and root, /usr/lib/repart.d to mkosi.extra's files (through plain directories only), and the
  root partition's /etc and /run to hold no repart.d, so gpt-auto finds only the ESP and root.
- systemd.mount-extra= (fstab-generator) on the kernel command line: the line is an allowlist.
- the systemd.extra-unit.* (debug-generator) and fstab.extra (fstab-generator) credentials: the
  command line may set only the two shipped unit-dropin credentials, the ESP may hold no credential
  file, and the image's credential stores hold only
  mkosi's four named credentials (I21). Credentials from firmware (SMBIOS, fw_cfg) are I22."""
# REQ: STO-2, DEV-2, CH-9
import json
import pathlib
import subprocess
import tempfile
import unittest
import unittest.mock

from test_image import ENTRY, H, MK, finish, ini

TABLE = [{"type": g.upper()} for g in (finish.ESP, finish.USR_GUID, finish.USR_VERITY_GUID, finish.USR_GUID,
                                        finish.USR_VERITY_GUID, finish.ROOT_GUID)]
# Partition types gpt-auto acts on in the booted system (Discoverable Partitions Specification),
# and Linux data, which repart could make for anything.
GPT_AUTO = {"home": "933ac7e1-2eb4-4f13-b844-0e14e2aef915", "srv": "3b8f8425-20e0-4f3b-907f-1a25a76f98e8",
            "var": "4d21b016-b534-45c2-a9fb-5c16e091fd2d", "var-tmp": "7ec6f557-3bc5-4aca-b293-16ef5df639d1",
            "swap": finish.SWAP_GUID, "xbootldr": "bc13c2ff-59e6-4262-a352-b275fd6f7172",
            "linux-generic": "0fc63daf-8483-4772-8e79-3d69d8477de4"}


def defs(d, **files):
    for name, body in files.items():
        (pathlib.Path(d) / name).write_text(body)
    return pathlib.Path(d)


class GptAutoTest(unittest.TestCase):

    def test_definitions_name_only_the_four_types(self):
        # Every shipped definition, build time and first boot, names one allowed type.
        for d in (finish.REPART_DIR, finish.REPART_D):
            got = finish.repart_types(d)
            self.assertTrue(got, d)
            for name, t in got:
                with self.subTest(f=name):
                    self.assertIn(t, finish.REPART_TYPES)
                    self.assertEqual(ini(d / name)["Partition"]["Type"], t)
        self.assertEqual(finish.REPART_DIR, MK / "mkosi.repart")
        self.assertEqual(finish.REPART_D, MK / "mkosi.extra/usr/lib/repart.d")
        self.assertEqual([t for _, t in finish.repart_types(finish.REPART_D)], ["root"])
        # systemd-repart reads /etc and /usr/local too; the image puts nothing there.
        for d in ("etc/repart.d", "usr/local/lib/repart.d", "run/repart.d"):
            self.assertFalse((MK / "mkosi.extra" / d).exists(), d)
        self.assertIn("RepartDirectories=mkosi.repart", (MK / "mkosi.conf").read_text())

    def test_built_disk_holds_exactly_the_defined_partitions(self):
        self.assertEqual(finish.partition_violations(TABLE), [])
        for name, guid in GPT_AUTO.items():
            for at in (1, len(TABLE)):
                with self.subTest(added=name, at=at):
                    t = TABLE[:at] + [{"type": guid.upper()}] + TABLE[at:]
                    v = finish.partition_violations(t)
                    self.assertEqual(len(v), 1, v)
                    self.assertIn(guid, v[0])
        for t in (TABLE[:-1], TABLE[1:], TABLE[::-1], [], TABLE + [TABLE[0]]):
            with self.subTest(table=[p["type"][:8] for p in t]):
                self.assertNotEqual(finish.partition_violations(t), [])

    def test_a_definition_of_another_type_is_refused(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            ok = "[Partition]\nType=root\n"
            build, first = defs(a, **{"30-root.conf": ok}), defs(b, **{"50-root.conf": ok})
            root = [{"type": finish.ROOT_GUID}]
            self.assertEqual(finish.partition_violations(root, build, first), [])
            for body in ("[Partition]\nType=home\n", "[Partition]\nType=var\n", "[Partition]\nType=swap\n",
                         "[Partition]\nType=linux-generic\n", "[Partition]\n# Type=root\n",
                         "[Partition]\nType=root\nType=srv\n", "[Other]\nType=root\n", "",
                         "[Partition]\nType=%s\n" % GPT_AUTO["home"]):
                for d, tag in ((build, "build"), (first, "first boot")):
                    with self.subTest(body=body, at=tag):
                        f = d / "40-x.conf"
                        f.write_text(body)
                        try:
                            v = finish.partition_violations(root, build, first)
                        finally:
                            f.unlink()
                        self.assertTrue(any("40-x.conf" in x for x in v), v)
            # Whitespace around the key and value is systemd's, not a new type.
            (first / "50-root.conf").write_text("[Partition]\n Type = root \n")
            self.assertEqual(finish.partition_violations(root, build, first), [])

    def test_usr_ships_only_the_first_boot_definitions(self):
        f = finish.REPART_D / "50-root.conf"
        row = ["lib/repart.d/50-root.conf", "f", "0644", 0, 0, 0, 1, f.stat().st_size, finish.sha256(f)]
        rows = [["lib", "d", "0755", 0, 0, 0, 0, 0, ""], ["lib/repart.d", "d", "0755", 0, 0, 0, 0, 0, ""], row]
        self.assertEqual(finish.usr_repart_violations(rows), [])
        bad = {"another file": rows + [["lib/repart.d/60-home.conf"] + row[1:]],
               "changed": rows[:2] + [row[:-1] + ["0" * 64]],
               "a link": rows[:2] + [["lib/repart.d/50-root.conf", "l", "0777", 0, 0, 0, 1, 0, row[-1]]],
               "/usr/local": rows + [["local/lib/repart.d/60-var.conf"] + row[1:]],
               "missing": rows[:2],
               # A link or a file at a step points systemd-repart's directory elsewhere (L3, Security B).
               "local/lib a link": rows + [["local", "d"] + row[2:-1] + [""], ["local/lib", "l"] + row[2:-1] + ["../share/x"],
                                           ["share/x/repart.d/60-home.conf"] + row[1:]],
               "local a link": rows + [["local", "l"] + row[2:-1] + ["share/y"],
                                       ["share/y/lib/repart.d/60-home.conf"] + row[1:]],
               "local/lib/repart.d a link": rows + [["local/lib/repart.d", "l"] + row[2:-1] + ["../../lib/x"]],
               "lib/repart.d a link": [rows[0], ["lib/repart.d", "l"] + row[2:-1] + ["../share/x"], row],
               "lib/repart.d a file": [rows[0], ["lib/repart.d", "f"] + row[2:]],
               "local a file": rows + [["local", "f"] + row[2:]]}
        for why, r in bad.items():
            with self.subTest(why):
                self.assertNotEqual(finish.usr_repart_violations(r), [])

    def test_root_carries_no_repart_d(self):
        # systemd-repart reads /etc/repart.d and /run/repart.d too, from the writable root.
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)

            def disk(*make):
                t = d / "t"
                subprocess.run(["rm", "-rf", str(t)], check=True)
                for p in ("etc/agentos", "run", "var"):
                    (t / p).mkdir(parents=True)
                for m in make:
                    m(t)
                img = d / "p.img"
                img.unlink(missing_ok=True)
                subprocess.run(["truncate", "-s", "8M", str(img)], check=True)
                subprocess.run(["mkfs.ext4", "-q", "-F", "-E", "offset=%d" % (2048 * 512), "-d", str(t), str(img),
                                "4M"], check=True, env={"PATH": "/usr/sbin:/sbin:/usr/bin:/bin"})
                return str(img), {"partitions": [{"type": finish.ESP.upper(), "start": 34},
                                                 {"type": finish.ROOT_GUID.upper(), "start": 2048}]}

            self.assertEqual(finish.root_repart_violations(*disk()), [])
            cases = {"etc/repart.d": lambda t: (t / "etc/repart.d").mkdir(),
                     "etc/repart.d file": lambda t: (t / "etc/repart.d").write_text("[Partition]\nType=home\n"),
                     "etc/repart.d link": lambda t: (t / "etc/repart.d").symlink_to("/var/x"),
                     "run/repart.d": lambda t: (t / "run/repart.d").mkdir(),
                     "etc a link": lambda t: ((t / "etc").rename(t / "etc2"), (t / "etc").symlink_to("var")),
                     "no run": lambda t: (t / "run").rmdir()}
            for why, m in cases.items():
                with self.subTest(why):
                    self.assertNotEqual(finish.root_repart_violations(*disk(m)), [])
            img, table = disk()
            self.assertNotEqual(finish.root_repart_violations(img, {"partitions": table["partitions"][:1]}), [])
            self.assertNotEqual(finish.root_repart_violations(img, {"partitions": table["partitions"] * 2}), [])
            # A listing debugfs cannot give (wrong offset: no file system) refuses rather than passes.
            self.assertNotEqual(finish.root_repart_violations(img, {"partitions": [
                {"type": finish.ROOT_GUID, "start": 4}]}), [])

    def test_build_stops_on_an_undefined_partition(self):
        class Proc:
            @staticmethod
            def check_output(*a, **k):
                return "::/loader/entries/a.conf\n"

            @staticmethod
            def run(*a, **k):
                return None

        ok = dict(subprocess=Proc, esp_offset=lambda img: 0, counted_entry=lambda src, v: ("a+3.conf", "entry"),
                  esp_violations=lambda paths, text: [], cmdline_violations=lambda text: [],
                  swap_violations=lambda parts, text: [], quota_violations=lambda img, table, text: [],
                  noexec_violations=lambda text: [], secret_violations=lambda img, table: [])
        home = TABLE + [{"type": GPT_AUTO["home"]}]
        with tempfile.TemporaryDirectory() as d, unittest.mock.patch.multiple(
                finish, partition_table=lambda img: {"partitions": home}, **ok):
            with self.assertRaises(SystemExit) as e:
                finish.main(d, "1.0")
        self.assertIn("#5289", str(e.exception.code))
        self.assertIn(GPT_AUTO["home"], str(e.exception.code))
        with tempfile.TemporaryDirectory() as d, unittest.mock.patch.multiple(
                finish, partition_table=lambda img: {"partitions": TABLE},
                root_repart_violations=lambda img, table: ["/etc/repart.d: on root"], **ok):
            with self.assertRaises(SystemExit) as e:
                finish.main(d, "1.0")
        self.assertIn("#5289", str(e.exception.code))
        self.assertIn("/etc/repart.d", str(e.exception.code))
        ok["root_repart_violations"] = lambda img, table: []

        # Past the disk, the /usr list it writes is held to the first-boot definitions.
        def usr_list(data, dst):
            pathlib.Path(dst).write_text(json.dumps(["lib/repart.d/60-home.conf", "f", "0644", 0, 0, 0, 1, 1, "x"]) + "\n")
            return 1

        with tempfile.TemporaryDirectory() as d, unittest.mock.patch.multiple(
                finish, partition_table=lambda img: {"partitions": TABLE}, boot_files=lambda text: [],
                usrhash=lambda text: H, verify_usr=lambda *a: None, slot_a_violations=lambda *a: [],
                write_usr_list=usr_list, **ok):
            with self.assertRaises(SystemExit) as e:
                finish.main(d, "1.0")
        self.assertIn("#5289", str(e.exception.code))
        self.assertIn("60-home.conf", str(e.exception.code))


class CredentialRouteTest(unittest.TestCase):
    """systemd.mount-extra= and the systemd.extra-unit.* and fstab.extra credentials, at every source
    the image controls."""

    def entry(self):
        args = finish.config_cmdline()
        return (ENTRY % H).replace("console=tty0 console=ttyS0 rw quiet", "usrhash=%s %s" % (H, " ".join(args)))

    def test_command_line_refuses_mount_and_unit_routes(self):
        entry = self.entry()
        self.assertEqual(finish.cmdline_violations(entry), [])
        cred = "systemd.set_credential%s=%s:W1VuaXRdCg=="
        routes = ["systemd.mount-extra=/dev/sdb1:/var/lib/agentos-store", "systemd.mount_extra=LABEL=x:/srv",
                  "rd.systemd.mount-extra=/dev/sdb1:/sysroot/var", "SYSTEMD.MOUNT-EXTRA=/dev/sdb1:/home",
                  "systemd.swap-extra=/dev/sdb2", "systemd.gpt_auto=1", "rd.systemd.gpt_auto=0",
                  "systemd.wants=x.service", "systemd.mask=agentos-keeper-kernel.service", "systemd.debug_shell",
                  "systemd.ssh_listen=22", "systemd.unit=rescue.target", "root=/dev/sdb1", "mount.usr=/dev/sdb2",
                  "systemd.import_credentials=yes"]
        for name in ("systemd.extra-unit.x.service", "systemd.extra-unit.agentos-keeper.slice", "fstab.extra",
                     "systemd.unit-dropin.agentos-keeper-kernel.service", "ssh.listen", "getty.ttys.serial",
                     "systemd.extra-unit.x.mount", "FSTAB.EXTRA", '"fstab.extra"'):
            for suffix in ("", "_binary", "-binary"):
                routes += [cred % (suffix, name), "rd." + cred % (suffix, name)]
        for bad in routes:
            with self.subTest(bad=bad):
                self.assertNotEqual(finish.cmdline_violations(entry.replace("quiet", "quiet " + bad)), [])
        # mkosi.conf lists none of them, and listing a credential there would not pass it either.
        for w in finish.config_cmdline():
            with self.subTest(listed=w):
                k = w.lower().replace("-", "_")
                self.assertFalse(k.removeprefix("rd.").startswith(
                    ("systemd.mount_extra", "systemd.swap_extra", "systemd.gpt_auto", "systemd.wants",
                     "systemd.mask", "systemd.debug_shell", "systemd.ssh", "root=", "mount.")), w)
        with tempfile.TemporaryDirectory() as d:
            conf = pathlib.Path(d) / "mkosi.conf"
            # Each listed in mkosi.conf, so the credential rule, not the allowlist, refuses it.
            for w in [p + cred % (s, n) for n in ("systemd.extra-unit.x.service", "fstab.extra", "FSTAB.EXTRA")
                      for s in ("", "_binary", "-binary") for p in ("", "rd.")]:
                with self.subTest(listed=w):
                    conf.write_text("[Content]\nKernelCommandLine=quiet %s\n" % w)
                    v = finish.cmdline_violations("options quiet %s\n" % w, conf)
                    self.assertEqual(len(v), 1, v)
                    self.assertIn("only the shipped credentials", v[0])

    def test_shipped_credentials_are_the_two_dropins(self):
        # The two that pass (I4) add a drop-in to emergency.service and rescue.service only: no unit,
        # no mount, and neither is a keeper unit.
        self.assertEqual(finish.SHIPPED_CREDENTIALS, ("systemd.unit-dropin.emergency.service",
                                                       "systemd.unit-dropin.rescue.service"))
        creds = [w.split("=", 1)[1].split(":", 1)[0] for w in finish.config_cmdline() if "set_credential" in w]
        self.assertEqual(sorted(creds), sorted(finish.SHIPPED_CREDENTIALS))

    def test_esp_carries_no_credential(self):
        # systemd-boot and systemd-stub hand loader/credentials/*.cred and a UKI's .extra.d/*.cred to
        # PID 1; the ESP allowlist refuses every such file, whichever loader would read it.
        self.assertEqual(ini(MK / "mkosi.conf")["Content"]["UnifiedKernelImages"], "no")
        entry = self.entry()
        for p in ("loader/credentials/fstab.extra.cred", "loader/credentials/systemd.extra-unit.x.service.cred",
                  "EFI/Linux/agentos.efi.extra.d/fstab.extra.cred", "EFI/Linux/agentos.efi",
                  "loader/addons/x.addon.efi"):
            with self.subTest(p=p):
                self.assertEqual(finish.esp_violations([p], entry), [p])


if __name__ == "__main__":
    unittest.main()
