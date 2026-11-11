"""IMG-keeper-reach-gen (#5289): no generator or credential adds a unit or mount the tree check does
not read.

The tree check (mkosi.finalize: made.allow, the unit-made directory rules, the keeper check) reads the
unit directories, fstab and system.conf. Five other routes give PID 1 units, mounts or devices:
- systemd-gpt-auto-generator mounts /home, /srv, /var or /var/tmp from partitions of those types on
  the root's disk, and systemd-repart makes any partition its definitions name. finish_image.py pins
  the built disk to exactly mkosi.repart's partitions, the definitions to the ESP, /usr, its verity
  and root, /usr/lib/repart.d to mkosi.extra's files (through plain directories only), and the
  root partition's /etc and /run to hold no repart.d, so gpt-auto finds only the ESP and root. The
  root ext4 has no feature that hides a name from debugfs (encrypt, casefold), and the root and /usr
  hold no sysext or confext image either (#5418), which would merge another /usr or /etc over them.
- the cryptsetup, veritysetup and integritysetup generators, from crypttab, veritytab and integritytab:
  the main tree has none (exec.allow), and the initrd's tabs hold no entry (finish_image.initrd_violations,
  on the tree the entry's initrds unpack to, which also refuses an initrd repart.d, fstab entry, stored
  credential, sysext or confext image, or unit outside /usr/lib).
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

from test_image import ENTRY, H, MK, check, finish, ini

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


def root_disk(d, *make, features=()):
    """An 8 MiB disk image in directory D whose ext4 root (at sector 2048) holds /etc/agentos, /run and
    /var/lib, then whatever each MAKE(tree) adds, made with mkfs.ext4 -O FEATURES; and its table."""
    d = pathlib.Path(d)
    t = d / "t"
    subprocess.run(["rm", "-rf", str(t)], check=True)
    for p in ("etc/agentos", "run", "var/lib"):
        (t / p).mkdir(parents=True)
    for m in make:
        m(t)
    img = d / "p.img"
    img.unlink(missing_ok=True)
    subprocess.run(["truncate", "-s", "8M", str(img)], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-E", "offset=%d" % (2048 * 512), "-d", str(t)]
                   + ["-O" + f for f in features] + [str(img), "4M"],
                   check=True, env={"PATH": "/usr/sbin:/sbin:/usr/bin:/bin"})
    return str(img), {"partitions": [{"type": finish.ESP.upper(), "start": 34},
                                     {"type": finish.ROOT_GUID.upper(), "start": 2048}]}


DIR, LINK = "040755", "120777"


def fake_ls(tree):
    """An ls for root_repart_violations that reads {path: {name: mode}} TREE, "." added to each."""
    return lambda img, offset, path: dict(tree[path], **{".": DIR}) if path in tree else None


GOOD = {"/": {"etc": DIR, "run": DIR, "var": DIR}, "/etc": {}, "/run": {}, "/var": {"lib": DIR}, "/var/lib": {}}


def newc(members):
    """A newc cpio archive of MEMBERS, then the trailer: (name, mode, content), each its own inode, or
    (name, mode, content, ino, nlink) for a hard link group."""
    out = b""
    for i, m in enumerate(list(members) + [("TRAILER!!!", 0, b"")]):
        (n, mode, body), (ino, nlink) = m[:3], (m[3:] or (1000 + i, 1))
        name = n.encode() + b"\0"
        out += b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, nlink, 0, len(body), 0, 0, 0, 0, len(name), 0))
        out += name + b"\0" * (-(110 + len(name)) % 4) + body + b"\0" * (-len(body) % 4)
    return out


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

    def test_root_carries_nothing_systemd_reads(self):
        # systemd-repart reads /etc/repart.d and /run/repart.d, systemd-sysext /etc, /run and /var/lib's
        # extensions, and systemd-confext /run and /var/lib's confexts, all from the writable root.
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(finish.root_repart_violations(*root_disk(d)), [])
            cases = {"etc/repart.d": lambda t: (t / "etc/repart.d").mkdir(),
                     "etc/repart.d file": lambda t: (t / "etc/repart.d").write_text("[Partition]\nType=home\n"),
                     "etc/repart.d link": lambda t: (t / "etc/repart.d").symlink_to("/var/x"),
                     "run/repart.d": lambda t: (t / "run/repart.d").mkdir(),
                     "etc a link": lambda t: ((t / "etc").rename(t / "etc2"), (t / "etc").symlink_to("var")),
                     "run missing": lambda t: (t / "run").rmdir(),
                     "etc/extensions": lambda t: (t / "etc/extensions").mkdir(),
                     "run/extensions": lambda t: (t / "run/extensions").mkdir(),
                     "run/confexts": lambda t: (t / "run/confexts").mkdir(),
                     "var/lib/extensions": lambda t: (t / "var/lib/extensions/x/usr/lib/repart.d").mkdir(parents=True),
                     "var/lib/confexts": lambda t: ((t / "var/lib/confexts").mkdir(), (t / "var/lib/confexts/x.raw").write_text("x")),
                     "var/lib/confexts link": lambda t: (t / "var/lib/confexts").symlink_to("/tmp"),
                     "var a link": lambda t: ((t / "var").rename(t / "v"), (t / "var").symlink_to("v")),
                     "var/lib a link": lambda t: ((t / "var/lib").rename(t / "var/l"), (t / "var/lib").symlink_to("l")),
                     "var/lib missing": lambda t: (t / "var/lib").rmdir()}
            for why, m in cases.items():
                with self.subTest(why):
                    v = finish.root_repart_violations(*root_disk(d, m))
                    self.assertEqual(len(v), 1, v)
                    self.assertIn("/" + why.split()[0], v[0])
            img, table = root_disk(d)
            self.assertNotEqual(finish.root_repart_violations(img, {"partitions": table["partitions"][:1]}), [])
            self.assertNotEqual(finish.root_repart_violations(img, {"partitions": table["partitions"] * 2}), [])
            # No file system at the offset refuses rather than passes.
            self.assertEqual(finish.root_repart_violations(img, {"partitions": [
                {"type": finish.ROOT_GUID, "start": 4}]}), ["root is not ext4"])

    def test_an_empty_listing_is_unreadable(self):
        # L3 delta release 6787077038: {} for a readable step is refused like None, at every step.
        with tempfile.TemporaryDirectory() as d:
            img, table = root_disk(d)
            self.assertEqual(finish.root_repart_violations(img, table, fake_ls(GOOD)), [])
            for step in GOOD:
                for got in ({}, None):
                    with self.subTest(step=step, got=got):
                        tree = dict(GOOD)
                        ls = fake_ls(tree)
                        v = finish.root_repart_violations(img, table, lambda i, o, p: got if p == step else ls(i, o, p))
                        self.assertEqual(v, ["%s: unreadable on root" % step], v)

    def test_root_ext4_hides_no_name(self):
        # Security delta 6787098770 item 2: under encrypt or casefold a directory's names are not what
        # debugfs prints, so the superblock is read first, as quota_violations reads it.
        with tempfile.TemporaryDirectory() as d:
            for feature in ("encrypt", "casefold"):
                with self.subTest(feature):
                    v = finish.root_repart_violations(*root_disk(d, features=[feature]))
                    self.assertEqual(v, ["root ext4 has the %s feature; debugfs would not read its names as systemd "
                                         "does" % feature])
            v = finish.root_repart_violations(*root_disk(d, features=["encrypt", "casefold"]))
            self.assertEqual(len(v), 2, v)

    def test_each_guard_refuses_alone(self):
        # Lens R1 6787118062: a linked /etc whose own listing has "." is refused by the mode test alone,
        # and a directory /etc whose listing lacks "." by debugfs_ls's guard alone.
        with tempfile.TemporaryDirectory() as d:
            img, table = root_disk(d)
            linked = dict(GOOD, **{"/": dict(GOOD["/"], etc=LINK)})
            self.assertEqual(finish.root_repart_violations(img, table, fake_ls(linked)),
                             ["/etc: not a plain directory on root (%s)" % LINK])
            rows = {"/": "/2/040755/0/0/.//\n/2/040755/0/0/..//\n/12/040755/0/0/etc//\n/13/040755/0/0/run//\n"
                         "/14/040755/0/0/var//\n",
                    "/var": "/14/040755/0/0/.//\n/15/040755/0/0/lib//\n", "/var/lib": "/15/040755/0/0/.//\n",
                    "/run": "/13/040755/0/0/.//\n", "/etc": "/12/040755/0/0/.//\n"}

            def run(argv, **k):
                path = argv[2].split(" ", 2)[2]
                return subprocess.CompletedProcess(argv, 0, rows[path], "debugfs 1.47.2 (1-Jan-2025)\n")

            with unittest.mock.patch.object(finish.subprocess, "run", run):
                self.assertEqual(finish.root_repart_violations(img, table), [])
                rows["/etc"] = "/16/100644/0/0/x/1/\n/2/040755/0/0/..//\n"
                self.assertEqual(finish.root_repart_violations(img, table), ["/etc: unreadable on root"])

    def test_a_debugfs_failure_is_the_tools(self):
        # Lens R2: debugfs exits 0 when it cannot open the image; its stderr says so, and a non-zero exit
        # or any stderr line but its banner stops the build as a tool failure, not the image's.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as bin_:
            img, table = root_disk(d)
            fake = pathlib.Path(bin_) / "debugfs"
            for script, says in (("echo 'debugfs 1.47.2 (1-Jan-2025)' >&2; exit 1", "exited 1: no message"),
                                 ("echo 'debugfs 1.47.2 (1-Jan-2025)' >&2; echo 'ls: Filesystem not open' >&2",
                                  "exited 0: ls: Filesystem not open"),
                                 ("echo '/2/040755/0/0/.//'; echo 'bad' >&2", "exited 0: bad")):
                with self.subTest(script):
                    fake.write_text("#!/bin/sh\n%s\n" % script)
                    fake.chmod(0o755)
                    with unittest.mock.patch.dict(finish.os.environ, PATH="%s:%s" % (bin_, finish.os.environ["PATH"])):
                        v = finish.root_repart_violations(img, table)
                    self.assertEqual(v, ["debugfs ls -p / %s; a tool failure, not the image's" % says])
            # A line that is not a row, or a name listed twice, is the tool's too (Security 6804479798 release a).
            for out, says in (("/2/040755/0/0/.//\nrepart.d\n", "printed a line that is not a row: 'repart.d'"),
                              ("/2/040755/0/0/.//\n/9/040755/0/0/etc//\n/9/040755/0/0/etc//\n", "listed 'etc' twice")):
                with self.subTest(out), unittest.mock.patch.object(finish.subprocess, "run", lambda a, **k: (
                        subprocess.CompletedProcess(a, 0, out, "debugfs 1.47.2 (1-Jan-2025)\n"))):
                    self.assertEqual(finish.root_repart_violations(img, table),
                                     ["debugfs ls -p / %s; a tool failure, not the image's" % says])
            # Real debugfs on a missing image: it exits 0 and says so on stderr.
            with self.assertRaisesRegex(finish.ToolError, "while trying to open"):
                finish.debugfs_ls(str(pathlib.Path(d) / "none.img"), 0, "/")

    def test_usr_ships_no_confext(self):
        # systemd-confext merges /usr/lib/confexts and /usr/local/lib/confexts over /etc.
        f = finish.REPART_D / "50-root.conf"
        row = ["lib/repart.d/50-root.conf", "f", "0644", 0, 0, 0, 1, f.stat().st_size, finish.sha256(f)]
        rows = [["lib", "d", "0755", 0, 0, 0, 0, 0, ""], ["lib/repart.d", "d", "0755", 0, 0, 0, 0, 0, ""], row]
        for extra in (["lib/confexts", "d"], ["lib/confexts/x.raw", "f"], ["local/lib/confexts", "l"],
                      ["local/lib/confexts/x/etc/repart.d/a.conf", "f"]):
            with self.subTest(extra[0]):
                v = finish.usr_repart_violations(rows + [extra + row[2:]])
                self.assertEqual(v, ["/usr/%s: systemd-confext would merge it over /etc" % extra[0]])

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

        # Security item 3: main() runs the real check on a built ext4 root, so dropping the call fails.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as w:
            raw = pathlib.Path(root_disk(w, lambda t: (t / "etc/repart.d").mkdir())[0])
            raw.rename(pathlib.Path(d) / "agentos_1.0.raw")
            disk = [dict(p, start=34) for p in TABLE[:-1]] + [{"type": finish.ROOT_GUID, "start": 2048}]
            real = {k: v for k, v in ok.items() if k != "root_repart_violations"}

            class Debugfs(Proc):
                @staticmethod
                def run(argv, **k):
                    return subprocess.run(argv, **k) if argv[0] == "debugfs" else None

            real["subprocess"] = Debugfs
            with unittest.mock.patch.multiple(finish, partition_table=lambda img: {"partitions": disk}, **real):
                with self.assertRaises(SystemExit) as e:
                    finish.main(d, "1.0")
        self.assertIn("#5289", str(e.exception.code))
        self.assertIn("/etc/repart.d: on root; systemd-repart would make what it defines", str(e.exception.code))

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


class InitrdTest(unittest.TestCase):
    """#5418: the initrd adds no unit, mount, device or partition the checks do not read."""
    D, F, L = 0o040755, 0o100644, 0o120777
    STOCK = [("etc", D, b""), ("etc/fstab", F, b"# empty\n\n"), ("etc/crypttab", F, b"# <target name> <source>\n"),
             ("usr", D, b""), ("usr/lib", D, b""), ("lib", L, b"usr/lib"), ("usr/lib/credstore", D, b""), ("usr/lib/credstore/firstboot.locale", F, b"C.UTF-8"),
             ("etc/systemd/system", D, b""), ("etc/systemd/system/sysinit.target.wants", D, b""),
             ("etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service", L,
              b"/usr/lib/systemd/system/systemd-timesyncd.service"),
             ("etc/systemd/system/x.service", L, b"/dev/null"),
             ("usr/lib/systemd/system/initrd.target", F, b"[Unit]\n"), ("run/x", F, b"hidden by the tmpfs")]

    def test_stock_shapes_pass(self):
        self.assertEqual(finish.initrd_violations(finish.cpio_members(newc(self.STOCK))), [])
        self.assertEqual(finish.cpio_names(newc(self.STOCK)), [n for n, _, _ in self.STOCK])

    def test_each_route_is_refused(self):
        D, F, L = self.D, self.F, self.L
        cases = [("etc/repart.d", D, b""), ("etc/repart.d/50-home.conf", F, b"[Partition]\nType=home\n"),
                 ("usr/lib/repart.d", D, b""), ("usr/local/lib/repart.d/a.conf", F, b""), ("lib/repart.d/a.conf", F, b""),
                 ("usr/lib/repart.d", L, b"/tmp"),
                 ("etc", L, b"run/e"), ("usr/local", L, b"share"), ("usr/local/lib", F, b""),
                 ("etc/fstab", F, b"/dev/sda4 /sysroot/home ext4 defaults 0 0\n"),
                 ("etc/fstab", F, b"# x\n  LABEL=home /home ext4 x-initrd.mount\n"),
                 ("etc/crypttab", F, b"home /dev/sda4 none\n"), ("etc/veritytab", F, b"v /dev/a /dev/b " + b"0" * 64 + b"\n"),
                 ("etc/integritytab", F, b"i /dev/sda5\n"), ("etc/fstab", L, b"/run/fstab"),
                 ("etc/credstore/fstab.extra", F, b"/dev/sda4 /home ext4\n"),
                 ("usr/lib/credstore/systemd.extra-unit.x.service", F, b"[Service]\n"),
                 ("usr/lib/credstore.encrypted/x", F, b""), ("lib/credstore/firstboot.locale", F, b""),
                 ("usr/local/lib/credstore/x", L, b"/run/x"),
                 ("etc/systemd/system/x.service", F, b"[Service]\nExecStart=/bin/true\n"),
                 ("etc/systemd/system/x.service.d/a.conf", F, b"[Unit]\n"),
                 ("etc/systemd/system/home.mount", L, b"/run/home.mount"),
                 ("etc/systemd/system/y.service", L, b"../../../usr/lib/systemd/system/y.service"),
                 ("etc/systemd/system/z.service", L, b"/usr/lib/systemd/system/sub/z.service"),
                 ("etc/systemd/system-generators/g", F, b"#!/bin/sh\n"),
                 ("usr/local/lib/systemd/system/x.mount", F, b"[Mount]\n"),
                 ("usr/local/lib/systemd/system-generators/g", L, b"/usr/lib/systemd/system/g")]
        for m in cases:
            with self.subTest(m[:2]):
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + [m])))
                self.assertEqual(len(got), 1, got)
                self.assertTrue(got[0].startswith(m[0] + ": "), got)
                # The same member in a second, compressed archive behind the first is read too.
                comp = {b"\x1f\x8b": finish.ungzip}
                import gzip
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK) + gzip.compress(newc([m])), comp))
                self.assertEqual(len(got), 1, got)

    def test_build_stops_on_an_initrd_route(self):
        # Every initrd of the entry, in boot order, is one tree: a link the first makes counts for the second.
        first, second = newc(self.STOCK), newc([("etc/crypttab", self.F, b"home /dev/sda4 none\n")])
        members = finish.check_initrd("a", first) + finish.check_initrd("b", second)
        with self.assertRaises(SystemExit) as e:
            finish.check_initrd_tree(["a", "b"], members)
        self.assertIn("#5418", str(e.exception.code))
        self.assertIn("etc/crypttab", str(e.exception.code))
        finish.check_initrd_tree(["a"], finish.check_initrd("a", first))
        linked = finish.check_initrd("a", newc(self.STOCK + [("x", self.L, b"/etc/fstab")]))
        with self.assertRaises(SystemExit) as e:
            finish.check_initrd_tree(["a", "b"], linked + finish.check_initrd(
                "b", newc([("x", self.F, b"/dev/sda4 /sysroot/home ext4 defaults 0 0\n")])))
        self.assertIn("x: replaces a link at x", str(e.exception.code))

    def test_credentials_allowed_are_the_tree_checks(self):
        self.assertEqual(finish.INITRD_CREDS_ALLOWED, check.CREDSTORE_ALLOWED)
        # /run is a tmpfs in the initrd, and its /lib is a link to usr/lib, which nothing is unpacked through.
        self.assertEqual(set(finish.INITRD_CREDSTORES),
                         {d for d in check.CREDSTORE_DIRS if not d.startswith(("run/", "lib/"))})

    def test_hard_links_are_read_as_one_inode(self):
        # Security 6804479798 blocker 1: GNU cpio puts a group's data on its last link; the kernel's
        # maybe_link() links the later name to the first and writes into the shared inode.
        F, line = self.F, b"/dev/vda9 /mnt ext4 defaults 0 0\n"
        for order in ((("etc/fstab", F, b"", 7, 2), ("usr/x", F, line, 7, 2)),
                      (("usr/x", F, b"", 7, 2), ("etc/fstab", F, line, 7, 2)),
                      (("usr/x", F, line, 7, 2), ("etc/fstab", F, b"", 7, 2)),
                      (("etc/crypttab", F, b"", 9, 3), ("usr/a", F, b"", 9, 3), ("usr/b", F, b"home /dev/sda4 none\n", 9, 3))):
            with self.subTest(order[0][0]):
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + list(order))))
                self.assertEqual(len(got), 1, got)
                self.assertRegex(got[0], r"^etc/(fstab|crypttab): has an entry")
        # A plain file written over a hard-linked one goes into the shared inode (O_TRUNC, same inode).
        got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + [
            ("usr/x", F, b"", 7, 2), ("etc/fstab", F, b"", 7, 2), ("usr/x", F, line)])))
        self.assertEqual(len(got), 1, got)
        # Security delta 6804788432: the entry's two initrds are one tree, and the kernel's link table restarts
        # only at a trailer, so the same ino in the second file is a new file, never the first file's fstab.
        one = newc([("etc", self.D, b""), ("etc/fstab", F, line, 9, 2)])
        two = newc([("usr", self.D, b""), ("usr/y", F, b"#" * 40 + b"\n", 9, 2)])
        archive = [0]
        members = finish.check_initrd("a", one, archive) + finish.check_initrd("b", two, archive)
        with self.assertRaises(SystemExit) as e:
            finish.check_initrd_tree(["a", "b"], members)
        self.assertIn("etc/fstab: has an entry", str(e.exception.code))
        self.assertEqual(archive, [2])
        # The kernel frees its link table at each trailer: the same ino in the next archive is a new file.
        got = finish.initrd_violations(finish.cpio_members(
            newc(self.STOCK + [("etc/fstab", F, b"", 7, 2)]) + newc([("usr/x", F, line, 7, 2)])))
        self.assertEqual(got, [])

    def test_nothing_is_unpacked_through_a_link(self):
        # Security 6804479798 blocker 2: a link on a step above a checked directory, or the directory
        # itself linked, would put units where the check reads nothing.
        D, F, L = self.D, self.F, self.L
        unit = b"[Service]\nExecStart=/bin/true\n"
        for step in finish.initrd_checked()[1]:
            with self.subTest(step=step):
                got = finish.initrd_violations(finish.cpio_members(newc(
                    [m for m in self.STOCK if m[0] != step and not m[0].startswith(step + "/")]
                    + [(step, L, b"/usr/lib/systemd/system/x")])))
                self.assertEqual(got, ["%s: not a directory; a checked path could be reached through it" % step])
        cases = {"etc/systemd": [("opt/s/system", D, b""), ("etc/systemd", L, b"/opt/s"),
                                 ("etc/systemd/system/evil.service", F, unit)],
                 "generators": [("etc/systemd", L, b"/opt/s"), ("etc/systemd/system-generators/g", F, b"#!/bin/sh\n")],
                 "a link and ..": [("q", L, b"usr/share"), ("q/../etc/fstab", F, b"/dev/sda4 /home ext4\n")],
                 "write through a final link": [("z", L, b"/etc/fstab"), ("z", F, b"/dev/sda4 /home ext4\n")],
                 "a link replaced": [("etc/systemd/system/a.d", L, b"/opt/d"), ("etc/systemd/system/a.d", L, b"/dev/null")],
                 # clean_path() follows the old link to /dev/null, unlinks it, and the new link stands.
                 "a mask replaced": [("etc/systemd/system/a.d", L, b"/dev/null"), ("etc/systemd/system/a.d", L, b"/opt/d")],
                 "a file replaced by a dir": [("usr/y", F, b""), ("usr/y", D, b"")]}
        for why, ms in cases.items():
            with self.subTest(why):
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + ms)))
                self.assertTrue(got, why)
        # Names resolve as the kernel resolves them.
        for name in ("/etc/fstab", "etc//fstab", "./etc/./fstab", "usr/../etc/fstab", "../../etc/fstab"):
            with self.subTest(name):
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + [
                    (name, F, b"/dev/sda4 /home ext4\n")])))
                self.assertEqual(got, ["etc/fstab: has an entry; a generator would make a mount or device from it"])

    def test_every_unit_directory_is_read(self):
        # L3 6804604094 blocker 1: the initrd's systemd reads system.control and system.attached too; the
        # list is mkosi.finalize's UNIT_PATHS outside /usr/lib, not a second one.
        D, F, L = self.D, self.F, self.L
        units = finish.initrd_checked()[0]
        self.assertEqual(units, tuple(d for d in check.UNIT_PATHS if not d.startswith("usr/lib/")))
        self.assertEqual(set(units), {"etc/systemd/system.control", "etc/systemd/system", "etc/systemd/system.attached",
                                      "usr/local/lib/systemd/system"})
        for d in units:
            for ms in ([(d + "/evil.service", F, b"[Service]\nExecStart=/bin/true\n")],
                       [(d + "/initrd.target.wants", D, b""), (d + "/initrd.target.wants/evil.service", L, b"../evil.service")],
                       [(d + "/initrd.target.d", D, b""), (d + "/initrd.target.d/x.conf", F, b"[Unit]\nWants=evil.service\n")]):
                with self.subTest(d=d, m=ms[-1][0]):
                    got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + ms)))
                    self.assertEqual(got, ["%s: a unit or drop-in outside /usr/lib" % ms[-1][0]])
            with self.subTest(d=d, ok="enablement link"):
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + [
                    (d + "/initrd.target.wants", D, b""),
                    (d + "/initrd.target.wants/a.service", L, b"/usr/lib/systemd/system/a.service")])))
                self.assertEqual(got, [])

    def test_no_link_turns_on_an_extension_merge(self):
        # L3 6804604094 blocker 2: an enablement link to systemd-sysext or systemd-confext would run it in
        # the initrd, over mkosi-initrd's preset.
        for unit in ("systemd-sysext.service", "systemd-confext.service", "systemd-sysext.socket",
                     "systemd-sysext@.service", "systemd-confext.socket"):
            with self.subTest(unit):
                name = "etc/systemd/system/sysinit.target.wants/" + unit
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + [
                    ("etc/systemd/system/sysinit.target.wants", self.D, b""),
                    (name, self.L, b"/usr/lib/systemd/system/" + unit.encode())])))
                self.assertEqual(got, ["%s: a unit or drop-in outside /usr/lib" % name])

    def test_initrd_ships_no_extension_image(self):
        # Security 6804479798 release b: systemd-sysext's and systemd-confext's initrd search paths.
        for d in finish.INITRD_IMAGE_DIRS:
            with self.subTest(d):
                got = finish.initrd_violations(finish.cpio_members(newc(self.STOCK + [(d + "/x.raw", self.F, b"x")])))
                self.assertEqual(got, ["%s/x.raw: an image systemd-sysext or systemd-confext would merge" % d])

    def test_main_tree_has_no_crypt_generators(self):
        # Item 2 of #5418: the main tree's cryptsetup, veritysetup and integritysetup generators would read
        # /etc/crypttab, /etc/veritytab and /etc/integritytab, which the tree check does not. The image
        # installs none of them (systemd-cryptsetup is not in mkosi.conf's Packages=, only cryptsetup-bin's
        # tools), and exec.allow, which every generator must be on, lists none, so one that comes back
        # fails the build.
        allow = (MK / "exec.allow").read_text()
        gens = [ln.split()[0] for ln in allow.splitlines() if "/system-generators/" in ln and not ln.startswith("#")]
        self.assertIn("usr/lib/systemd/system-generators/systemd-gpt-auto-generator", gens)
        for g in gens:
            with self.subTest(g):
                self.assertNotRegex(g.rsplit("/", 1)[1], r"crypt|verity|integrity")
        self.assertNotIn("systemd-cryptsetup\n", (MK / "mkosi.conf").read_text())


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
