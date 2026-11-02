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


def dump(units):
    """A test-mode dump in systemd's layout: UNITS maps a name to its setting lines."""
    out = ["-> By units:"]
    for name, lines in units.items():
        out.append("\t-> Unit %s:" % name)
        out += ["\t\t" + l for l in lines]
    return "\n".join(out + ["-> By jobs:"]) + "\n"


LINT_UNIT = {r.LINT: ["Unit Load State: loaded", "Fragment Path: /etc/systemd/system/" + r.LINT]}


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

    def test_a_file_not_listed_as_a_packages_is_ours(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {LIB + "y.service": "y", LIB + "z.service": "z"}, {LIB + "y.service"})
            self.assertFalse(p.ours(LIB + "y.service"))
            self.assertTrue(p.ours(LIB + "z.service"))


class DpkgTest(unittest.TestCase):
    def test_only_a_byte_identical_file_is_a_packages(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {LIB + "a.service": "a", LIB + "b.service": "changed", "/etc/c.conf": "c", "/etc/d.conf": "d2",
                         "/lib": "-> usr/lib", LIB + "e.service": "e"})
            out = pathlib.Path(d) / "out"
            out.mkdir()
            md5 = lambda t: hashlib.md5(t.encode()).hexdigest()  # noqa: E731
            (out / "agentos.dpkg-md5sums").write_text(
                "%s  usr/lib/systemd/system/a.service\n%s  usr/lib/systemd/system/b.service\n"
                "%s  lib/systemd/system/e.service\n" % (md5("a"), md5("b"), md5("e")))
            (out / "agentos.dpkg-status").write_text(
                "Package: p\nConffiles:\n /etc/c.conf %s\n /etc/d.conf %s\nDescription: x\n" % (md5("c"), md5("d")))
            packaged = r.dpkg_packaged(v, out)
            self.assertEqual([p for p in (LIB + "a.service", LIB + "b.service", "/etc/c.conf", "/etc/d.conf",
                                          LIB + "e.service", LIB + "f.service") if packaged(p)],
                             [LIB + "a.service", "/etc/c.conf", LIB + "e.service"])

    def test_no_listed_files_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {})
            out = pathlib.Path(d)
            (out / "agentos.dpkg-md5sums").write_text("")
            (out / "agentos.dpkg-status").write_text("Package: p\n")
            with self.assertRaises(SystemExit):
                r.dpkg_packaged(v, out)


class RecordsTest(unittest.TestCase):
    FILES = {LIB + "x.service": "[Service]\n", ETC + "x.service.d/a.conf": "a", ETC + "x.service.d/m.conf": "-> /dev/null",
             ETC + "service.d/w.conf": "w", ETC + "x-.service.d/p.conf": "p", ETC + "gone.service.d/g.conf": "g",
             LIB + "t@.service": "t", ETC + "t@.service.d/t.conf": "tt", ETC + "lone@.service.d/l.conf": "l",
             ETC + "gen.service.d/n.conf": "n"}

    def recs(self, d, units, planted=(), status=0):
        v = tree(d, self.FILES)
        dirs = r.unit_dirs(v)
        return r.records(v, dump(dict(LINT_UNIT, **units)), "", status, dirs,
                         r.Provenance(v, dirs, lambda p: p == LIB + "x.service"), list(planted))

    def test_systemd_gives_the_files_and_the_reader_the_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            got = self.recs(d, {
                "x.service": ["Unit Load State: loaded", "Fragment Path: " + LIB + "x.service",
                              "DropIn Path: " + ETC + "x.service.d/a.conf", "DropIn Path: " + ETC + "x.service.d/m.conf",
                              "DropIn Path: " + ETC + "service.d/w.conf"],
                "t@agentos-unit-lint.service": ["Unit Load State: loaded", "Fragment Path: " + LIB + "t@.service",
                                                "DropIn Path: " + ETC + "t@.service.d/t.conf"],
                "gone.service": ["Unit Load State: not-found"],
                "gen.service": ["Unit Load State: loaded", "Fragment Path: /tmp/systemd-temporary-x/generator/gen.service",
                                "DropIn Path: " + ETC + "gen.service.d/n.conf"],
                "m.service": ["Unit Load State: masked", "Fragment Path: /etc/systemd/system/m.service"]},
                planted=["x.service", "gone.service"])
            units = [(u["unit"], u["alone"], [(f["path"], f["ours"]) for f in u["files"]]) for u in got["units"]]
            self.assertEqual(units, [
                ("gen.service", True, [(ETC + "gen.service.d/n.conf", True)]),  # a generated fragment is not read
                ("t@agentos-unit-lint.service", False, [(LIB + "t@.service", True), (ETC + "t@.service.d/t.conf", True)]),
                # systemd's order; the /dev/null mask is dropped
                ("x.service", False, [(LIB + "x.service", False), (ETC + "x.service.d/a.conf", True),
                                      (ETC + "service.d/w.conf", True)]),
                ("gone.service", True, [(ETC + "gone.service.d/g.conf", True)]),  # names no loaded unit
                ("lone@.service", True, [(ETC + "lone@.service.d/l.conf", True)]),  # a template no instance loads
                (".service", True, [(ETC + "service.d/w.conf", True)]),  # type-wide: also alone
                ("x-.service", True, [(ETC + "x-.service.d/p.conf", True)])])  # prefix: also alone
            self.assertIsNone(got["fstab"])

    def test_what_the_dump_cannot_show_fails_closed(self):
        x = ["Unit Load State: loaded", "Fragment Path: " + LIB + "x.service"]
        for name, units, planted, status, want in (
                ("a failed run", {}, (), 1, "test run failed"),
                ("a planted name systemd never names", {}, ("y.service",), 0, "lacks"),
                ("an unknown load state", {"x.service": ["Unit Load State: stub"]}, (), 0, "load state"),
                ("two fragments", {"x.service": x + ["Fragment Path: /a"]}, (), 0, "fragments"),
                ("a planted unit with no files", {"x.service": ["Unit Load State: loaded"]}, ("x.service",), 0,
                 "no Fragment Path"),
                ("two units read as one", {"x.service": x + ["Unit Load State: loaded"]}, (), 0, "Load State")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, want):
                    self.recs(d, units, planted, status)

    def test_an_alias_answers_a_planted_name(self):
        with tempfile.TemporaryDirectory() as d:
            self.recs(d, {"x.service": ["Alias: y.service", "Unit Load State: loaded", "Fragment Path: " + LIB + "x.service"]},
                      planted=["y.service"])


class NamesTest(unittest.TestCase):
    def test_every_name_a_unit_directory_holds(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {LIB + "a.service": "", LIB + "t@.service": "", ETC + "t@b.service.d/z.conf": "",
                         ETC + "multi-user.target.wants/getty@tty1.service": "-> " + LIB + "t@.service",
                         ETC + "service.d/z.conf": "", LIB + "README": "", ETC + r.LINT: ""})
            self.assertEqual(r.names(v, r.unit_dirs(v)),
                             ["a.service", "getty@tty1.service", "t@agentos-unit-lint.service",
                              "t@b.service"])

    def test_the_control_is_a_drop_in_of_ours_on_a_packaged_root_unit(self):
        (p, text), = r.CONTROL.items()
        self.assertTrue(p.startswith("etc/systemd/system/systemd-journald.service.d/"))
        self.assertIn("LD_PRELOAD", text)
        self.assertEqual(r.CONTROL_WANT, 'variable "LD_PRELOAD"')


if __name__ == "__main__":
    unittest.main()
