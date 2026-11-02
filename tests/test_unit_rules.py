"""image/unit_rules.py: which files each unit of a built tree loads, from the tree's own systemd, and
whose they are (#4677). The rules themselves, and the fixtures run under a real systemd, are
broker/kernel/privfile's (TestUnitRulesUnderSystemd, TestBuiltUnits); these pin the reader.

REQ: KRN-2
"""
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "image"))
import offline_systemd  # noqa: E402
import unit_rules as r  # noqa: E402

LIB, ETC = "/usr/lib/systemd/system/", "/etc/systemd/system/"


def tree(d, files):
    """Lay FILES (path in the tree -> text, or "-> target" for a link) out under d/root, with /usr
    under d/usr, and return the View."""
    root, usr = pathlib.Path(d) / "root", pathlib.Path(d) / "usr"
    root.mkdir()
    usr.mkdir()
    for p, text in files.items():
        f = usr / p[5:] if p.startswith("/usr/") else root / p.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        if text.startswith("-> "):
            f.symlink_to(text[3:])
        else:
            f.write_text(text)
    return r.View(root, usr)


class ViewTest(unittest.TestCase):
    def test_links_resolve_in_the_tree_and_dotdot_stops_at_its_root(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {ETC + "a.service": "-> " + LIB + "a.service", LIB + "a.service": "x",
                         ETC + "b.service": "-> ../../../../../usr/lib/systemd/system/a.service",
                         "/lib": "-> usr/lib", ETC + "c.service": "-> /lib/systemd/system/a.service",
                         ETC + "host.service": "-> /etc/passwd"})
            for e in ("a", "b", "c"):
                with self.subTest(e=e):
                    self.assertEqual(v.resolve(ETC + e + ".service")[0], LIB + "a.service")
            self.assertEqual(v.resolve(ETC + "c.service")[1], [ETC + "c.service", "/lib"])
            # The runner's /etc/passwd is never read: the tree has none.
            self.assertIsNone(v.lstat(v.resolve(ETC + "host.service")[0]))
            self.assertEqual(v.resolve(ETC + "a.service", last=False), (ETC + "a.service", []))

    def test_a_loop_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {ETC + "x.service": "-> y.service", ETC + "y.service": "-> x.service"})
            with self.assertRaisesRegex(SystemExit, "more than 40 links"):
                v.resolve(ETC + "x.service")


class ProvenanceTest(unittest.TestCase):
    def prov(self, d, files, packaged):
        v = tree(d, files)
        return r.Provenance(v, r.unit_dirs(v), lambda p: p in packaged)

    def test_a_package_file_is_ours_once_a_link_of_ours_brings_it_in(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {LIB + "y.service": "y", "/usr/share/p/z.conf": "z", "/usr/share/p/x.service": "x",
                              ETC + "a.service": "-> " + LIB + "y.service",  # an alias: y's provenance
                              ETC + "x.service": "-> /usr/share/p/x.service",  # a linked unit: ours
                              ETC + "y.service.d/z.conf": "-> /usr/share/p/z.conf",
                              ETC + "q.service.d": "-> /usr/share/p"},
                          {LIB + "y.service", "/usr/share/p/z.conf", "/usr/share/p/x.service"})
            self.assertFalse(p.ours(LIB + "y.service"))
            self.assertFalse(p.ours(ETC + "a.service"))
            self.assertTrue(p.ours(ETC + "x.service"))
            self.assertTrue(p.ours("/usr/share/p/x.service"))  # as a linked unit's fragment, named by target
            self.assertTrue(p.ours(ETC + "y.service.d/z.conf"))
            self.assertTrue(p.ours(ETC + "q.service.d/z.conf"))

    def test_a_link_out_of_the_search_path_that_links_back_makes_the_last_file_ours(self):
        # #4737 L3 6588613477 1: classed by the link's own target, and the file it reaches is held.
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {LIB + "y.service": "y", ETC + "w.service": "-> /usr/share/p/w.service",
                              "/usr/share/p/w.service": "-> " + LIB + "y.service"}, {LIB + "y.service"})
            self.assertTrue(p.ours(ETC + "w.service"))
            self.assertTrue(p.ours(LIB + "y.service"))

    def test_an_alias_is_decided_by_its_target_resolved_in_the_tree(self):
        # #4779 L3 1: the .. is taken after /usr/share/l is followed, so the link leaves the search path.
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {ETC + "x.service": "-> /usr/share/l/../../lib/systemd/system/y.service",
                              "/usr/share/l": "-> /usr/share/doc/p/ex/sub", "/usr/share/doc/p/ex/sub/.keep": "",
                              "/usr/share/doc/p/lib/systemd/system/y.service": "y", LIB + "y.service": "y"},
                          {"/usr/share/doc/p/lib/systemd/system/y.service", LIB + "y.service"})
            self.assertIsNone(p.alias_target(ETC + "x.service"))
            self.assertTrue(p.ours(ETC + "x.service"))
            self.assertTrue(p.ours("/usr/share/doc/p/lib/systemd/system/y.service"))
            self.assertFalse(p.ours(LIB + "y.service"))

    def test_a_path_systemd_names_through_a_link_is_ours(self):
        # A link no unit-directory walk marks (here, a drop-in directory's parent) still makes it ours.
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {"/usr/share/p/z.conf": "z", "/etc/agentos": "-> /usr/share/p"}, {"/usr/share/p/z.conf"})
            self.assertTrue(p.ours("/etc/agentos/z.conf"))
            self.assertFalse(p.ours("/usr/share/p/z.conf"))

    def test_a_file_not_listed_as_a_packages_is_ours(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {LIB + "y.service": "y", LIB + "z.service": "z"}, {LIB + "y.service"})
            self.assertFalse(p.ours(LIB + "y.service"))
            self.assertTrue(p.ours(LIB + "z.service"))


class DpkgTest(unittest.TestCase):
    def write(self, out, md5sums, status):
        (out / "agentos.dpkg-md5sums").write_text(md5sums)
        (out / "agentos.dpkg-status").write_text(status)

    def test_only_a_byte_identical_file_is_a_packages(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {LIB + "a.service": "a", LIB + "b.service": "changed", "/etc/c.conf": "c", "/etc/d.conf": "d2",
                         "/lib": "-> usr/lib", LIB + "e.service": "e"})
            out = pathlib.Path(d)
            self.write(out, "%s  usr/lib/systemd/system/a.service\n%s  usr/lib/systemd/system/b.service\n"
                            "%s  lib/systemd/system/e.service\n" % (md5("a"), md5("b"), md5("e")),
                       "Package: p\nConffiles:\n /etc/c.conf %s\n /etc/d.conf %s\nDescription: x\n" % (md5("c"), md5("d")))
            packaged = r.dpkg_packaged(out)(v)
            self.assertEqual([p for p in (LIB + "a.service", LIB + "b.service", "/etc/c.conf", "/etc/d.conf",
                                          LIB + "e.service", LIB + "f.service") if packaged(p)],
                             [LIB + "a.service", "/etc/c.conf", LIB + "e.service"])

    def test_a_listed_path_through_a_link_of_ours_is_not_a_packages(self):
        # #4779 Security 2: our link at or above a path dpkg lists does not make our file the package's.
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {"/usr/share/doc/foo": "-> /etc/systemd/system/bar.service.d", ETC + "bar.service.d/x.conf": "x",
                         "/etc/agentos.conf": "-> /etc/real.conf", "/etc/real.conf": "c"})
            out = pathlib.Path(d)
            self.write(out, "%s  usr/share/doc/foo/x.conf\n" % md5("x"),
                       "Package: p\nConffiles:\n /etc/agentos.conf %s\n" % md5("c"))
            packaged = r.dpkg_packaged(out)(v)
            self.assertFalse(packaged(ETC + "bar.service.d/x.conf"))
            self.assertFalse(packaged("/etc/real.conf"))

    def test_no_listed_files_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.write(pathlib.Path(d), "", "Package: p\n")
            with self.assertRaises(SystemExit):
                r.dpkg_packaged(d)


def md5(t):
    return hashlib.md5(t.encode()).hexdigest()


def shown(units):
    """systemctl's reply, as Manager.show() returns it: UNITS maps a name to (load state, fragment,
    [drop-ins], [other names])."""
    out = {}
    for n, (state, frag, drops, *more) in units.items():
        names = [n] + (more[0] if more else [])
        out[n] = {"Id": n, "Names": " ".join(names), "LoadState": state, "FragmentPath": frag,
                  "DropInPaths": " ".join(drops)}
        for a in names[1:]:
            out[a] = dict(out[n])
    return out


class RecordsTest(unittest.TestCase):
    FILES = {LIB + "x.service": "[Service]\n", ETC + "x.service.d/a.conf": "a", ETC + "x.service.d/m.conf": "-> /dev/null",
             ETC + "service.d/w.conf": "w", ETC + "x-.service.d/p.conf": "p", ETC + "gone.service.d/g.conf": "g",
             LIB + "t@.service": "t", ETC + "t@.service.d/t.conf": "tt", ETC + "lone@.service.d/l.conf": "l",
             ETC + "y.service.d/y.conf": "y", "/run/systemd/generator/gen.service": "[Service]\n"}

    def recs(self, d, units):
        v = tree(d, self.FILES)
        dirs = r.unit_dirs(v)
        return r.records(v, shown(units), dirs, r.Provenance(v, dirs, lambda p: p == LIB + "x.service"))

    def test_systemd_gives_the_files_and_the_reader_the_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            got = self.recs(d, {
                # systemd's order; the /dev/null mask is dropped; y is an alias, so y.service.d is x's
                "x.service": ("loaded", LIB + "x.service", [ETC + "x.service.d/a.conf", ETC + "x.service.d/m.conf",
                                                            ETC + "service.d/w.conf", ETC + "y.service.d/y.conf"],
                              ["y.service"]),
                "t@agentos-unit-lint.service": ("loaded", LIB + "t@.service", [ETC + "t@.service.d/t.conf"]),
                "lone@agentos-unit-lint.service": ("not-found", "", []),
                "gone.service": ("not-found", "", []),
                "gen.service": ("loaded", "/run/systemd/generator/gen.service", []),
                "m.service": ("masked", "/etc/systemd/system/m.service", [])})
            units = [(u["unit"], u["alone"], [(f["path"], f["ours"]) for f in u["files"]]) for u in got["units"]]
            self.assertEqual(units, [
                ("gen.service", False, [("/run/systemd/generator/gen.service", True)]),  # a generated unit is read
                ("t@agentos-unit-lint.service", False, [(LIB + "t@.service", True), (ETC + "t@.service.d/t.conf", True)]),
                ("x.service", False, [(LIB + "x.service", False), (ETC + "x.service.d/a.conf", True),
                                      (ETC + "service.d/w.conf", True), (ETC + "y.service.d/y.conf", True)]),
                ("gone.service", True, [(ETC + "gone.service.d/g.conf", True)]),  # names no loaded unit
                # #4779 L3 2: a template whose planted instance did not load
                ("lone@.service", True, [(ETC + "lone@.service.d/l.conf", True)]),
                (".service", True, [(ETC + "service.d/w.conf", True)]),  # type-wide: also alone
                ("x-.service", True, [(ETC + "x-.service.d/p.conf", True)])])  # prefix: also alone
            self.assertIsNone(got["fstab"])

    def test_a_quoted_list_entry_is_one_name(self):
        # systemctl quotes a list entry with a backslash in it as a shell word (#4767): a\x2db.service
        # must read as the unit that owns a\x2db.service.d, not as a name that loads nothing
        files = {LIB + "a\\x2db.service": "[Service]\n", ETC + "a\\x2db.service.d/q.conf": "q"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            n = "a\\x2db.service"
            got = r.records(v, {n: {"Id": n, "Names": "'%s'" % n, "LoadState": "loaded", "FragmentPath": LIB + n,
                                    "DropInPaths": "'%s'" % (ETC + n + ".d/q.conf")}},
                            dirs, r.Provenance(v, dirs, lambda p: False))
            self.assertEqual([(u["unit"], u["alone"], [f["path"] for f in u["files"]]) for u in got["units"]],
                             [(n, False, [LIB + n, ETC + n + ".d/q.conf"])])

    def test_a_packaged_fstab_may_not_name_a_device(self):
        # fstab-generator skips a device line in a container, so its unit would go unread (#4767)
        for text, refused in (("proc /proc proc defaults 0 0\n# /dev/x /y ext4\n", False),
                              ("/dev/x /mnt ext4 ro 0 0\n", True), ("UUID=1 /mnt ext4 ro 0 0\n", True)):
            for ours in (False, True):
                with self.subTest(text=text, ours=ours), tempfile.TemporaryDirectory() as d:
                    v = tree(d, {"/etc/fstab": text})
                    dirs = r.unit_dirs(v)
                    prov = r.Provenance(v, dirs, lambda p: not ours)
                    if refused and not ours:
                        with self.assertRaisesRegex(SystemExit, "names a device"):
                            r.records(v, {}, dirs, prov)
                    else:
                        got = r.records(v, {}, dirs, prov)
                        self.assertEqual(got["fstab"] is not None, ours)

    def test_what_systemd_names_must_be_in_the_tree(self):
        for name, units, want in (
                ("an unknown load state", {"x.service": ("stub", "", [])}, "load state"),
                ("a fragment the tree lacks", {"x.service": ("loaded", LIB + "nope.service", [])}, "does not hold"),
                ("a relative drop-in", {"x.service": ("loaded", LIB + "x.service", ["x.conf"])}, "not an absolute"),
                ("a path with an unsafe byte", {"x.service": ("loaded", LIB + "x service", [])}, "not an absolute")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, want):
                    self.recs(d, units)


class ShowTest(unittest.TestCase):
    """Manager.show() reads systemctl's reply block by block, and refuses one it cannot read whole."""

    def show(self, reply, units):
        m = offline_systemd.Manager.__new__(offline_systemd.Manager)
        m.ctl = lambda args: type("R", (), {"stdout": reply})()
        return m.show(units, r.PROPS)

    def block(self, n, **kw):
        p = dict(Id=n, Names=n, LoadState="loaded", FragmentPath=LIB + n, DropInPaths="")
        p.update(kw)
        return "\n".join("%s=%s" % (k, p[k]) for k in r.PROPS) + "\n"

    def test_one_block_per_name(self):
        got = self.show(self.block("a.service") + "\n" + self.block("x.service", Names="x.service b.service"),
                        ["a.service", "b.service"])
        self.assertEqual(got["b.service"]["Id"], "x.service")

    def test_a_reply_it_cannot_read_whole_fails_closed(self):
        a = self.block("a.service")
        for name, reply, want in (
                ("a missing block", a, "blocks"),
                ("a block for another name", a + "\n" + self.block("c.service"), "systemctl gave"),
                ("an extra line", a + "\n" + self.block("b.service") + "Alias=a\n", "systemctl line"),
                ("a repeated key", a + "\n" + self.block("b.service") + "Id=b.service\n", "systemctl line")):
            with self.subTest(name=name):
                with self.assertRaisesRegex(SystemExit, want):
                    self.show(reply, ["a.service", "b.service"])


class NamesTest(unittest.TestCase):
    def test_every_name_a_unit_directory_holds(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {LIB + "a.service": "", LIB + "t@.service": "", ETC + "t@b.service.d/z.conf": "",
                         ETC + "multi-user.target.wants/getty@tty1.service": "-> " + LIB + "t@.service",
                         ETC + "service.d/z.conf": "", LIB + "README": ""})
            self.assertEqual(r.names(v, r.unit_dirs(v)),
                             ["a.service", "getty@tty1.service", "t@agentos-unit-lint.service",
                              "t@b.service"])

    def test_a_name_systemctl_could_not_carry_is_refused(self):
        for p in (ETC + "a b.service", ETC + "x.service.d/z\n.conf", ETC + "x.wants/a\tb.service"):
            with self.subTest(p=p), tempfile.TemporaryDirectory() as d:
                v = tree(d, {p: ""})
                with self.assertRaisesRegex(SystemExit, "a name with a byte outside"):
                    r.names(v, r.unit_dirs(v))

    def test_the_control_is_a_drop_in_of_ours_on_a_packaged_root_unit(self):
        (p, text), = r.CONTROL.items()
        self.assertTrue(p.startswith("etc/systemd/system/systemd-journald.service.d/"))
        self.assertIn("LD_PRELOAD", text)
        self.assertEqual(r.CONTROL_WANT, 'variable "LD_PRELOAD"')


if __name__ == "__main__":
    unittest.main()
