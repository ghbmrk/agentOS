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

    def test_an_alias_named_through_a_linked_unit_directory_is_an_alias(self):
        # #4779 L3 release 1: p's own directory is resolved in the tree before it is matched to a unit
        # directory, so /lib/systemd/system/a.service, an alias of b, keeps b's provenance
        with tempfile.TemporaryDirectory() as d:
            p = self.prov(d, {"/lib": "-> usr/lib", LIB + "a.service": "-> b.service", LIB + "b.service": "b"},
                          {LIB + "b.service"})
            self.assertEqual(p.alias_target("/lib/systemd/system/a.service"), LIB + "b.service")
            self.assertFalse(p.ours("/lib/systemd/system/a.service"))

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

    def test_a_merged_link_counts_only_to_usr_of_its_own_name(self):
        # #4779 Security R-b: /lib -> etc made our /etc/systemd/system/bar.service.d/x.conf the package's
        # lib/systemd/system/bar.service.d/x.conf; and a link of ours before a merged one (#4779 L3 release 1)
        for name, files, listed, mine in (
                ("a top link to /etc", {"/lib": "-> etc"}, "lib/systemd/system/bar.service.d/x.conf",
                 ETC + "bar.service.d/x.conf"),
                ("a top link to another /usr name", {"/lib": "-> usr/share"}, "lib/systemd/system/bar.service.d/x.conf",
                 "/usr/share/systemd/system/bar.service.d/x.conf"),
                ("a top link through a link of ours", {"/lib": "-> l", "/l": "-> usr/lib"},
                 "lib/systemd/system/bar.service.d/x.conf", LIB + "bar.service.d/x.conf"),
                ("a link of ours before a merged one", {"/etc/l": "-> /lib", "/lib": "-> usr/lib"},
                 "etc/l/systemd/system/bar.service.d/x.conf", LIB + "bar.service.d/x.conf")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                v = tree(d, dict(files, **{mine: "x"}))
                out = pathlib.Path(d)
                self.write(out, "%s  %s\n" % (md5("x"), listed), "Package: p\n")
                self.assertFalse(r.dpkg_packaged(out)(v)(mine))
        with tempfile.TemporaryDirectory() as d:  # the control: /lib -> usr/lib as the package laid it out
            v = tree(d, {"/lib": "-> usr/lib", LIB + "bar.service.d/x.conf": "x"})
            out = pathlib.Path(d)
            self.write(out, "%s  lib/systemd/system/bar.service.d/x.conf\n" % md5("x"), "Package: p\n")
            self.assertTrue(r.dpkg_packaged(out)(v)(LIB + "bar.service.d/x.conf"))

    def test_a_link_of_ours_on_a_listed_path_is_a_mask(self):
        # #5072 Security round 6: a link of ours on a unit directory, a parent of one or a listed drop-in
        # directory took the listed path out of want and so out of listed, and its files read as ours
        sock = "systemd-udevd-control.socket"
        for name, files, want in (
                ("a link on a parent of a unit directory",
                 {"/usr/lib/systemd": "-> systemd.real", "/usr/lib/systemd.real/system/" + sock: "open"}, [LIB + sock, LIB + sock + ".d/p.conf"]),
                ("a link on a unit directory",
                 {LIB[:-1]: "-> /usr/share/s", "/usr/share/s/" + sock: "open"}, [LIB + sock, LIB + sock + ".d/p.conf"]),
                ("a link on a listed drop-in directory, its file gone",
                 {LIB + sock: "kept", LIB + sock + ".d": "-> /etc/agentos-d"}, [LIB + sock + ".d/p.conf"]),
                ("a listed fragment replaced by a link of ours",
                 {LIB + sock: "-> /etc/agentos/" + sock, "/etc/agentos/" + sock: "open", LIB + sock + ".d/p.conf": "drop"},
                 [LIB + sock]),
                ("a listed drop-in replaced by a link to /dev/null",
                 {LIB + sock: "kept", LIB + sock + ".d/p.conf": "-> /dev/null", "/dev/null": ""}, [LIB + sock + ".d/p.conf"]),
                ("the control: as dpkg laid it out, through /lib -> usr/lib",
                 {LIB + sock: "kept", LIB + sock + ".d/p.conf": "drop"}, [])):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                v = tree(d, dict(files, **{"/lib": "-> usr/lib"}))
                out = pathlib.Path(d)
                self.write(out, "%s  lib/systemd/system/%s\n%s  usr/lib/systemd/system/%s.d/p.conf\n"
                           % (md5("kept"), sock, md5("drop"), sock), "Package: p\n")
                packaged = r.dpkg_packaged(out)(v)
                self.assertEqual(sorted(packaged.listed), [LIB + sock, LIB + sock + ".d/p.conf"])
                units = shown({sock: ("loaded", LIB + sock, [])})
                self.assertEqual([m["path"] for m in r.unread(v, units, r.unit_dirs(v), packaged)], want)

    def test_a_listed_path_keeps_a_top_link_that_is_not_merged(self):
        # #5072 Security round 6: with /lib -> etc, dpkg's lib/systemd/system/x.service is our /etc file,
        # held as reached by a link, not read as a /usr/lib path that is gone
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {"/lib": "-> etc", ETC + "x.service": "x"})
            out = pathlib.Path(d)
            self.write(out, "%s  lib/systemd/system/x.service\n" % md5("x"), "Package: p\n")
            packaged = r.dpkg_packaged(out)(v)
            self.assertEqual(sorted(packaged.listed), ["/lib/systemd/system/x.service"])
            self.assertEqual([m["path"] for m in r.unread(v, {}, r.unit_dirs(v), packaged)],
                             ["/lib/systemd/system/x.service"])

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
                  "DropInPaths": " ".join(drops), "Triggers": "", "TriggeredBy": ""}
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
                "lone@m.service": ("masked", "/dev/null", []),  # #4779 L3 2: masked stands for no template dir
                "lone@n.service": ("loaded", LIB + "t@.service", []),  # an instance is judged as itself
                "lone@b.service": ("bad-setting", LIB + "t@.service", []),  # as at boot: judged as itself
                "t@agentos-unit-lint.socket": ("bad-setting", LIB + "t@.service", []),  # the lint's: alone too
                "gone.service": ("not-found", "", []),
                "gen.service": ("loaded", "/run/systemd/generator/gen.service", []),
                "m.service": ("masked", "/etc/systemd/system/m.service", [])})
            units = [(u["unit"], u["alone"], [(f["path"], f["ours"]) for f in u["files"]]) for u in got["units"]]
            self.assertEqual(units, [
                ("gen.service", False, [("/run/systemd/generator/gen.service", True)]),  # a generated unit is read
                ("lone@b.service", False, [(LIB + "t@.service", True)]),
                ("lone@n.service", False, [(LIB + "t@.service", True)]),  # judged as itself
                ("t@agentos-unit-lint.service", False, [(LIB + "t@.service", True), (ETC + "t@.service.d/t.conf", True)]),
                ("t@agentos-unit-lint.socket", False, [(LIB + "t@.service", True)]),
                ("t@agentos-unit-lint.socket", True, [(LIB + "t@.service", True)]),
                ("x.service", False, [(LIB + "x.service", False), (ETC + "x.service.d/a.conf", True),
                                      (ETC + "service.d/w.conf", True), (ETC + "y.service.d/y.conf", True)]),
                ("gone.service", True, [(ETC + "gone.service.d/g.conf", True)]),  # names no loaded unit
                # a shared directory (template, type-wide, prefix) is read alone too, whatever loaded
                ("lone@.service", True, [(ETC + "lone@.service.d/l.conf", True)]),
                (".service", True, [(ETC + "service.d/w.conf", True)]),
                ("t@.service", True, [(ETC + "t@.service.d/t.conf", True)]),
                ("x-.service", True, [(ETC + "x-.service.d/p.conf", True)])])
            self.assertIsNone(got["fstab"])

    def test_a_loaded_unit_with_no_fragment_reads_only_its_files_of_ours_alone(self):
        # #4779 L3 release 1: usr.mount from mountinfo loads with no fragment; a package's drop-in on it
        # is not printed, one of ours is, alone
        files = {"/usr/lib/systemd/system/usr.mount.d/p.conf": "p", ETC + "usr.mount.d/z.conf": "z"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            got = r.records(v, shown({"usr.mount": ("loaded", "", [ETC + "usr.mount.d/z.conf",
                                                                "/usr/lib/systemd/system/usr.mount.d/p.conf"])}),
                            dirs, r.Provenance(v, dirs, lambda p: p.startswith("/usr/")))
            self.assertEqual([(u["unit"], u["alone"], [(f["path"], f["ours"]) for f in u["files"]]) for u in got["units"]],
                             [("usr.mount", True, [(ETC + "usr.mount.d/z.conf", True)])])

    def test_the_lint_instance_in_error_fails_the_run(self):
        # #4821 Security R1: its template's files were not read, so a drop-in of ours that masks a
        # package's User= line in a shared directory, and what the package's lines run, go unseen
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(SystemExit, "t@agentos-unit-lint.service: load state error"):
                self.recs(d, {"t@agentos-unit-lint.service": ("error", "", [])})
        with tempfile.TemporaryDirectory() as d:  # another instance in error is judged as itself
            got = self.recs(d, {"t@x.service": ("error", LIB + "t@.service", [])})["units"]
            self.assertEqual([u["alone"] for u in got if u["unit"] == "t@x.service"], [False])

    def test_only_the_lint_instance_itself_is_read_as_it(self):
        # #4779 round 4 M5: x@fooagentos-unit-lint is an instance of its own, judged as itself
        with tempfile.TemporaryDirectory() as d:
            got = self.recs(d, {"t@fooagentos-unit-lint.service": ("bad-setting", LIB + "t@.service", []),
                                "t@fooagentos-unit-lint.socket": ("error", "", [])})
            self.assertEqual([(u["unit"], u["alone"]) for u in got["units"]
                              if u["unit"].startswith("t@foo")], [("t@fooagentos-unit-lint.service", False)])

    def test_a_socket_feeding_a_packages_service_is_a_packages(self):
        # #5072 Security 1: by its name (an /etc fragment of ours hiding a package's), by the service it
        # activates (Service=, or a template's), or by a package's service taking it (Sockets=)
        files = {LIB + "u.socket": "p", ETC + "u.socket": "o", LIB + "u.service": "p", ETC + "a.socket": "o",
                 ETC + "b.socket": "o", ETC + "c.socket": "o", ETC + "c.service": "o", LIB + "t@.service": "p",
                 ETC + "t@1.socket": "o"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            units = shown({n: ("loaded", f, []) for n, f in (
                ("u.socket", ETC + "u.socket"), ("u.service", LIB + "u.service"), ("a.socket", ETC + "a.socket"),
                ("b.socket", ETC + "b.socket"), ("c.socket", ETC + "c.socket"), ("c.service", ETC + "c.service"),
                ("t@1.socket", ETC + "t@1.socket"))})
            units["a.socket"]["Triggers"] = "u.service"
            units["u.service"]["TriggeredBy"] = "u.socket b.socket"
            units["c.socket"]["Triggers"] = "c.service"
            units["t@1.socket"]["Triggers"] = "t@1.service"
            got = r.records(v, units, dirs, r.Provenance(v, dirs, lambda p: p.startswith("/usr/")))
            self.assertEqual(sorted(u["unit"] for u in got["units"] if u["package"]),
                             ["a.socket", "b.socket", "t@1.socket", "u.socket"])

    def test_a_hidden_package_socket_by_its_name_alone_and_the_service_it_feeds(self):
        # #5072 L3 round 2: a package's name hidden by a fragment of ours, with no Triggers or TriggeredBy,
        # and a package's name reached only through an alias in Names; and a service of ours fed by such a
        # socket (Security round 2)
        files = {LIB + "u.socket": "p", ETC + "u.socket": "o", LIB + "w.socket": "p", ETC + "x.service": "o"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            units = shown({"u.socket": ("loaded", ETC + "u.socket", []), "v.socket": ("loaded", ETC + "u.socket", [], ["w.socket"]),
                           "x.service": ("loaded", ETC + "x.service", [])})
            units["x.service"]["TriggeredBy"] = "u.socket"
            got = r.records(v, units, dirs, r.Provenance(v, dirs, lambda p: p.startswith("/usr/")))
            self.assertEqual(sorted((u["unit"], u["package"], u["fed"]) for u in got["units"]),
                             [("u.socket", True, False), ("v.socket", True, False), ("x.service", False, True)])

    def test_a_service_a_packages_socket_feeds_is_read_from_the_socket_side(self):
        # #5072 Security round 3: the lint's manager drops an inactive service between show calls, so its
        # TriggeredBy is empty for a socket's Service=, implicit name or Accept=yes template. Each route
        # alone marks its service: Triggers (t), implicit name (i), template (a@...), TriggeredBy (s), alias (v)
        files = {LIB + n: "p" for n in ("t.socket", "i.socket", "a.socket", "s.socket", "v.socket")}
        files.update({ETC + n: "o" for n in ("tt.service", "i.service", "a@.service", "x.service", "vv.service",
                                             "o.socket", "o.service")})
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            units = shown({n: ("loaded", (LIB if n in ("t.socket", "i.socket", "a.socket", "s.socket", "v.socket")
                                           else ETC) + n.replace("@agentos-unit-lint", "@").replace("@x.", "@."), [])
                           for n in ("t.socket", "i.socket", "a.socket", "s.socket", "v.socket", "tt.service",
                                     "i.service", "a@agentos-unit-lint.service", "a@x.service", "x.service",
                                     "vv.service", "o.socket", "o.service")})
            units["vv.service"]["Names"] = "vv.service valias.service"
            units["t.socket"]["Triggers"] = "tt.service"
            units["v.socket"]["Triggers"] = "valias.service"
            units["x.service"]["TriggeredBy"] = "s.socket"
            units["o.socket"]["Triggers"] = "o.service"  # a socket of ours feeding a service of ours
            got = r.records(v, units, dirs, r.Provenance(v, dirs, lambda p: p.startswith("/usr/")))
            self.assertEqual(sorted(u["unit"] for u in got["units"] if u["fed"]),
                             ["a@agentos-unit-lint.service", "a@x.service", "i.service", "tt.service",
                              "vv.service", "x.service"])

    def test_an_instance_a_packages_socket_names_feeds_its_template(self):
        # #5072 round 4: Service=b@x.service names an instance the lint's manager never shows; the template,
        # its lint instance and its alone records are fed, by Triggers and by TriggeredBy alike
        files = {LIB + "f.socket": "p", LIB + "g.socket": "p", ETC + "b@.service": "o", ETC + "c@.service": "o",
                 ETC + "d@.service": "o"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            units = shown({"f.socket": ("loaded", LIB + "f.socket", []), "g.socket": ("loaded", LIB + "g.socket", []),
                           "b@agentos-unit-lint.service": ("loaded", ETC + "b@.service", []),
                           "c@agentos-unit-lint.service": ("loaded", ETC + "c@.service", []),
                           "c@y.service": ("loaded", ETC + "c@.service", []),
                           "d@agentos-unit-lint.service": ("loaded", ETC + "d@.service", [])})
            units["f.socket"]["Triggers"] = "b@x.service"
            units["c@y.service"]["TriggeredBy"] = "g.socket"
            got = r.records(v, units, dirs, r.Provenance(v, dirs, lambda p: p.startswith("/usr/")))
            self.assertEqual(sorted(u["unit"] for u in got["units"] if u["fed"]),
                             ["b@agentos-unit-lint.service", "c@agentos-unit-lint.service", "c@y.service"])
            fed = r.fed_services(units, {"f.socket", "g.socket"})
            self.assertTrue(fed("b@.service") and fed("c@.service") and not fed("d@.service"))

    def test_a_file_of_ours_named_as_a_packages_drop_in_is_a_mask(self):
        # #5072 round 4: a /dev/null link, an empty file or any file of ours, by name in a drop-in directory
        # of the same type (a more specific one overrides a shared one), or at the path a package lists
        files = {LIB + "u.socket.d/p.conf": "SocketMode=0600", ETC + "u.socket.d/p.conf": "-> /dev/null",
                 LIB + "service.d/q.conf": "User=x", ETC + "v.service.d/q.conf": "",
                 LIB + "w.service.d/r.conf": "User=x", ETC + "w.socket.d/r.conf": "", ETC + "w.service.d/o.conf": "",
                 LIB + "z.service.d/e.conf": "edited"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            packaged = lambda p: p.startswith("/usr/") and p != LIB + "z.service.d/e.conf"  # noqa: E731
            packaged.listed = {p for p in files if p.startswith("/usr/")}
            got = r.records(v, {}, dirs, r.Provenance(v, dirs, packaged))
            self.assertEqual(sorted((m["path"], m["hides"]) for m in got["masks"]), [
                (ETC + "u.socket.d/p.conf", LIB + "u.socket.d/p.conf"),
                (ETC + "v.service.d/q.conf", LIB + "service.d/q.conf"),
                (LIB + "z.service.d/e.conf", LIB + "z.service.d/e.conf")])

    def test_a_unit_file_a_package_lists_is_read_as_installed(self):
        # #5072 round 5 (Security 1, L3 1): provenance by current bytes made a package's unit file changed in
        # place, or deleted and supplied again, ours, and a deleted drop-in left no file of ours to see.
        # Every listed unit file and drop-in must be there, a regular file as installed, unless its unit is
        # gone whole (drop.py's dpkg-db-backup)
        keep = "kept"
        for name, files, units, listed, want in (
                ("a fragment changed in place", {LIB + "u.socket": "edited"}, {"u.socket": LIB + "u.socket"},
                 [LIB + "u.socket"], [LIB + "u.socket"]),
                ("a fragment deleted and supplied again", {ETC + "u.service": "ours"}, {"u.service": ETC + "u.service"},
                 [LIB + "u.service"], [LIB + "u.service"]),
                ("a template fragment deleted while an instance loads", {ETC + "t@.service": "ours"},
                 {"t@agentos-unit-lint.service": ETC + "t@.service"}, [LIB + "t@.service"], [LIB + "t@.service"]),
                ("a drop-in deleted", {LIB + "u.socket": keep}, {"u.socket": LIB + "u.socket"},
                 [LIB + "u.socket", LIB + "u.socket.d/p.conf"], [LIB + "u.socket.d/p.conf"]),
                ("a drop-in made a directory", {LIB + "u.socket": keep, LIB + "u.socket.d/p.conf/x": ""},
                 {"u.socket": LIB + "u.socket"}, [LIB + "u.socket", LIB + "u.socket.d/p.conf"],
                 [LIB + "u.socket.d/p.conf"]),
                ("a drop-in made a link", {LIB + "u.socket": keep, LIB + "u.socket.d/p.conf": "-> /dev/null"},
                 {"u.socket": LIB + "u.socket"}, [LIB + "u.socket", LIB + "u.socket.d/p.conf"],
                 [LIB + "u.socket.d/p.conf"]),
                ("a shared drop-in deleted", {}, {}, [LIB + "service.d/p.conf"], [LIB + "service.d/p.conf"]),
                ("a unit removed whole", {}, {}, [LIB + "b.service", LIB + "b.timer", LIB + "b.service.d/p.conf"], []),
                ("a unit kept as installed", {LIB + "u.socket": keep, LIB + "u.socket.d/p.conf": keep},
                 {"u.socket": LIB + "u.socket"}, [LIB + "u.socket", LIB + "u.socket.d/p.conf"], []),
                ("a path outside the unit directories", {}, {}, ["/usr/lib/systemd/network/80-x.network",
                                                                 LIB + "a.wants/b.service"], [])):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as d:
                v = tree(d, files)
                dirs = r.unit_dirs(v)
                packaged = lambda p: v.kind(p) == 0o100000 and pathlib.Path(v.host(p)).read_text() == keep  # noqa: E731
                packaged.listed = set(listed)
                got = r.records(v, shown({n: ("loaded", f, []) for n, f in units.items()}), dirs,
                                r.Provenance(v, dirs, packaged))
                self.assertEqual(sorted(m["path"] for m in got["masks"] if m["path"] == m["hides"]), want)

    def test_held_names_every_package_socket_and_fed_service(self):
        # #5072 round 5 (Security 2): a [Unit] line of ours in any unit naming one of these adds an edge on it
        files = {LIB + "s.socket": "p", LIB + "s.service": "p", LIB + "q@.socket": "p", ETC + "o.service": "o"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            units = shown({"s.socket": ("loaded", LIB + "s.socket", [], ["t.socket"]),
                           "s.service": ("loaded", LIB + "s.service", []), "o.service": ("loaded", ETC + "o.service", [])})
            units["s.socket"]["Triggers"] = units["t.socket"]["Triggers"] = "s.service"
            got = r.records(v, units, dirs, r.Provenance(v, dirs, lambda p: p.startswith("/usr/")))
            self.assertEqual(got["held"]["names"], ["s.service", "s.socket", "t.service", "t.socket"])
            self.assertIn("s@", got["held"]["prefixes"])

    def test_a_quoted_list_entry_is_one_name(self):
        # systemctl quotes a list entry with a backslash in it as a shell word (#4767): a\x2db.service
        # must read as the unit that owns a\x2db.service.d, not as a name that loads nothing
        files = {LIB + "a\\x2db.service": "[Service]\n", ETC + "a\\x2db.service.d/q.conf": "q"}
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, files)
            dirs = r.unit_dirs(v)
            n = "a\\x2db.service"
            got = r.records(v, {n: {"Id": n, "Names": "'%s'" % n, "LoadState": "loaded", "FragmentPath": LIB + n,
                                    "DropInPaths": "'%s'" % (ETC + n + ".d/q.conf"), "Triggers": "",
                                    "TriggeredBy": ""}},
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
        p = dict(Id=n, Names=n, LoadState="loaded", FragmentPath=LIB + n, DropInPaths="", Triggers="", TriggeredBy="")
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
                ("a repeated key", a + "\n" + self.block("b.service") + "Id=b.service\n", "systemctl line"),
                # #4779 L3 release 1: a missing key fails by name, not through a KeyError
                ("a missing key", a + "\n" + self.block("b.service").replace("LoadState=loaded\n", ""),
                 "systemctl gave")):
            with self.subTest(name=name):
                with self.assertRaisesRegex(SystemExit, want):
                    self.show(reply, ["a.service", "b.service"])


class NoHostLinkTest(unittest.TestCase):
    """#5703 Security delta 1 and 2: every reader resolves each component of a path in the tree, so no
    link the tree holds is followed on the runner's host, in a directory component or the last one."""

    def test_a_linked_directory_is_listed_and_read_in_the_tree(self):
        with tempfile.TemporaryDirectory() as d:
            # absolute: on the host it would list the runner's own /usr/lib/tmpfiles.d
            v = tree(d, {"/etc/tmpfiles.d": "-> /usr/lib/tmpfiles.d", "/usr/lib/tmpfiles.d/zz-agentos-only.conf": "x\n"})
            self.assertEqual(v.entries("/etc/tmpfiles.d"), ["zz-agentos-only.conf"])
            self.assertEqual(v.kind("/etc/tmpfiles.d/zz-agentos-only.conf"), 0o100000)
            self.assertEqual(v.text("/etc/tmpfiles.d/zz-agentos-only.conf"), "x\n")

    def test_a_link_out_of_the_tree_is_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d) / "out"
            out.mkdir()
            (out / "secret.conf").write_text("host\n")
            v = tree(d, {"/etc/x": "-> " + str(out)})  # in the tree, a dangling link
            self.assertEqual(v.entries("/etc/x"), [])
            self.assertIsNone(v.lstat("/etc/x/secret.conf"))
            with self.assertRaises(OSError):
                v.text("/etc/x/secret.conf")
            self.assertIsNone(v.readlink("/etc/x/secret.conf"))

    def test_boot_view_hides_a_file_reached_through_a_link_into_run(self):
        with tempfile.TemporaryDirectory() as d:
            b = r.BootView(tree(d, {"/etc/td": "-> ../run/td", "/run/td/x.conf": "x\n"}))
            self.assertEqual(b.entries("/etc/td"), [])
            self.assertIsNone(b.lstat("/etc/td/x.conf"))
            with self.assertRaises(OSError):
                b.text("/etc/td/x.conf")


class BootLinksTest(unittest.TestCase):
    """#5703: every boot mount (BootView) is empty at boot, so the links the records hold read nothing the
    tree has under one, and no tmpfiles.d file is read through a link."""
    LINE = {"/usr/lib/tmpfiles.d/x.conf": "L /run/agentos-x - - - - /run/udev\n"}

    def links(self, d, more):
        return r.boot_links(tree(d, {**self.LINE, **more}))

    def test_a_tree_entry_at_the_path_does_not_stop_the_link(self):
        for more in ({"/run/agentos-x/.keep": ""}, {"/run/agentos-x": "a file"}, {"/run/agentos-x": "-> /etc"}):
            with self.subTest(more=more), tempfile.TemporaryDirectory() as d:
                self.assertEqual(self.links(d, more).get("/run/agentos-x"), "/run/udev")

    def test_a_tree_file_in_run_tmpfiles_d_hides_nothing(self):
        for more in ({"/run/tmpfiles.d/x.conf": "# benign\n"}, {"/run/tmpfiles.d/x.conf": "-> /dev/null"}):
            with self.subTest(more=more), tempfile.TemporaryDirectory() as d:
                self.assertEqual(self.links(d, more).get("/run/agentos-x"), "/run/udev")

    def test_a_target_is_not_stepped_through_the_trees_run(self):
        with tempfile.TemporaryDirectory() as d:
            got = self.links(d, {"/run/udev": "-> /etc"})
            self.assertEqual(got.get("/run/agentos-x"), "/run/udev")
            self.assertNotIn("/run/udev", got)  # nor is a link the tree holds under /run one at boot

    # #5703 Security delta 2 (6872706105): every boot mount, not /run and /tmp alone.
    def test_every_boot_mount_reads_as_an_empty_directory(self):
        for m in ("/dev", "/proc", "/sys", "/run", "/tmp"):
            for case in ("entry", "linked mount", "target"):
                line = {"/usr/lib/tmpfiles.d/x.conf": "L %s/agentos-x - - - - %s/t\n" % (m, m)}
                more = {"entry": {m + "/agentos-x/.keep": ""},
                        "linked mount": {m: "-> /var/m", "/var/m/agentos-x/.keep": ""},
                        "target": {m + "/t": "-> /etc", m + "/agentos-x": "-> /etc"}}[case]
                with self.subTest(mount=m, case=case), tempfile.TemporaryDirectory() as d:
                    v = tree(d, {**line, **more})
                    b = r.BootView(v)
                    self.assertEqual((b.kind(m), b.entries(m)), (0o040000, []))
                    if m in r.API_MOUNTS:  # a target there fails the run (MagicLinkTest)
                        with self.assertRaisesRegex(SystemExit, "a link to %s/t, under %s" % (m, m)):
                            r.boot_links(v)
                        continue
                    got = r.boot_links(v)
                    self.assertEqual(got.get(m + "/agentos-x"), m + "/t")
                    self.assertNotIn(m + "/t", got)

    def test_a_tmpfiles_d_directory_reached_through_a_link_fails_the_run(self):
        # 6872531168 (/run) and 6872706105 (/dev, /proc, /sys): a tmpfiles.d directory linked to a boot
        # mount reads as empty at boot; any link at all on the way fails closed, so no mount can be missed.
        links = [("/etc/tmpfiles.d", "-> " + t, t.lstrip("./") + "/x.conf")
                 for m in ("dev", "proc", "sys", "run", "tmp") for t in ("../%s/td" % m, "/%s/td" % m)]
        links += [("/etc/tmpfiles.d", "-> /var/run/td", "run/td/x.conf"),
                  ("/etc/tmpfiles.d", "-> /var/td", "var/td/x.conf"),
                  ("/usr/local/lib/tmpfiles.d", "-> /sys/td", "sys/td/x.conf")]
        links += [("/etc", "-> /%s/etc" % m, "%s/etc/tmpfiles.d/x.conf" % m) for m in ("dev", "proc", "sys", "run", "tmp")]
        for at, link, f in links:
            with self.subTest(at=at, link=link), tempfile.TemporaryDirectory() as d:
                more = {at: link, "/" + f: "# benign\n", "/var/run": "-> ../run"}
                with self.assertRaisesRegex(SystemExit, "tmpfiles.d directory reached through a link"):
                    self.links(d, more)

    def test_a_tmpfiles_d_file_that_is_a_link_fails_the_run_but_a_dev_null_mask(self):
        for t in ("/sys/td/x.conf", "/proc/x.conf", "/dev/x.conf", "/run/x.conf", "/tmp/x.conf",
                  "/etc/y.conf", "../../dev/null", "/dev/null/"):
            with self.subTest(target=t), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "a tmpfiles.d file that is a link"):
                    self.links(d, {"/etc/tmpfiles.d/x.conf": "-> " + t, "/etc/y.conf": "# benign\n"})
        with tempfile.TemporaryDirectory() as d:
            self.assertNotIn("/run/agentos-x", self.links(d, {"/etc/tmpfiles.d/x.conf": "-> /dev/null"}))

    # #5703 Security 6872820441: a package .mount unit hides the tree's content under its Where= at boot,
    # so what the tree holds at an L path, mounted over or not, never drops the link: with nothing there it
    # counts, and with a tree entry there the run fails (L3 6872965749, RetainedEntryTest).
    def test_a_tree_entry_under_a_package_mount_does_not_stop_the_link(self):
        mount = {"/usr/lib/tmpfiles.d/foo.conf": "L /var/lib/foo/s - - - - /run/agentos-x/s\n",
                 "/usr/lib/systemd/system/var-lib-foo.mount":
                     "[Mount]\nWhat=tmpfs\nWhere=/var/lib/foo\nOptions=nosuid,nodev,noexec\n",
                 "/usr/lib/systemd/system/local-fs.target.wants/var-lib-foo.mount": "-> ../var-lib-foo.mount"}
        for more in ({}, {"/var/agentos-x/.keep": ""}):
            with self.subTest(more=more), tempfile.TemporaryDirectory() as d:
                got = r.boot_links(tree(d, {**mount, **more}))
                self.assertEqual(got.get("/var/lib/foo/s"), "/run/agentos-x/s")
        for more in ({"/var/lib/foo/s/.keep": ""}, {"/var/lib/foo/s": "a file"}):
            with self.subTest(more=more), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "a plain L leaves in place"):
                    r.boot_links(tree(d, {**mount, **more}))

    def test_a_tree_link_on_the_path_or_the_target_fails_the_run(self):
        # A tree link under a mount the reader cannot see is not there at boot, so none is followed.
        for line, more, want in (
                ("L /var/lib/foo/s - - - - /run/agentos-x", {"/var/lib/foo": "-> /var/lib/bar"}, "its path's directory"),
                ("L /run/agentos-y - - - - /var/lib/foo/t", {"/var/lib/foo": "-> /run/udev"}, "its target"),
                ("L /run/agentos-y - - - - /var/run/udev", {"/var/run": "-> ../run"}, "its target"),
                ("L /run/agentos-y - - - - t/u", {"/run/t": "-> /etc"}, None)):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                v = tree(d, {"/usr/lib/tmpfiles.d/x.conf": line + "\n", **more})
                if want is None:  # a tree link the boot view hides is not followed, nor refused
                    self.assertEqual(r.boot_links(v).get("/run/agentos-y"), "/run/t/u")
                    continue
                with self.assertRaisesRegex(SystemExit, want + " passes through a link in the tree"):
                    r.boot_links(v)


class RetainedEntryTest(unittest.TestCase):
    """#5703 L3 6872965749: a plain L line leaves a link, directory or file the tree already has at its path
    (systemd 255), so the records would move the path away from where it lands at boot: the run fails,
    but at a tree link that resolves where the line's does. L+ removes the entry, so its link counts."""

    def test_a_tree_entry_at_a_plain_l_path_fails_the_run(self):
        for mod in ("L", "L?", "L!", "L$"):
            for entry in ({"/var/pkglink": "-> ../run/agentos-x"}, {"/var/pkglink/.keep": ""},
                          {"/var/pkglink": "a file"}, {"/var/pkglink": "-> /run/pkgdir/x"}):
                line = {"/usr/lib/tmpfiles.d/x.conf": "%s /var/pkglink - - - - /run/pkgdir\n" % mod}
                with self.subTest(mod=mod, entry=entry), tempfile.TemporaryDirectory() as d:
                    with self.assertRaisesRegex(SystemExit, "the tree already holds /var/pkglink there"):
                        r.boot_links(tree(d, {**line, **entry}))

    def test_a_tree_link_to_the_same_target_or_l_plus_passes(self):
        for line, entry, key, want in (
                ("L /var/pkglink - - - - /run/pkgdir", {"/var/pkglink": "-> ../run/pkgdir"}, "/var/pkglink", "/run/pkgdir"),
                ("L /etc/mtab - - - - ../proc/self/mounts", {"/etc/mtab": "-> ../proc/self/mounts"}, "/etc/mtab",
                 "/proc/self/mounts"),
                ("L /var/lock - - - - ../run/lock", {"/var/lock": "-> /run/lock"}, "/var/lock", "/run/lock"),
                ("L+ /var/pkglink - - - - /run/pkgdir", {"/var/pkglink": "-> ../run/agentos-x"}, "/var/pkglink", "/run/pkgdir"),
                ("L+ /etc/default/locale - - - - ../locale.conf", {"/etc/default/locale": "LANG=C\n",
                                                                  "/etc/locale.conf": "LANG=C\n"}, "/etc/default/locale", None)):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                got = r.boot_links(tree(d, {"/usr/lib/tmpfiles.d/x.conf": line + "\n", **entry}))
                self.assertEqual(got.get(key), want)


class MagicLinkTest(unittest.TestCase):
    """#5703 L3 6872796820: the kernel's links under /proc, /sys and /dev lead back into /, so a link, an L
    line's or the tree's, whose target resolves there fails the run, but at exactly API_TARGETS."""

    def test_a_target_in_an_api_mount_fails_the_run(self):
        for t in ("/proc/self/root/run/agentos-x", "/proc/1/root/run/agentos-x", "/proc/thread-self/root/run",
                  "/dev/fd/3", "/proc/self/cwd", "/sys/fs/cgroup", "/dev", "/proc", "../proc/self/root",
                  "/dev/shm/x", "/proc/self/mounts/x"):
            for how in ("L", "tree"):
                files = ({"/usr/lib/tmpfiles.d/x.conf": "L /run/pkglink - - - - %s\n" % t} if how == "L"
                         else {"/etc/pkglink": "-> " + t})
                with self.subTest(target=t, how=how), tempfile.TemporaryDirectory() as d:
                    with self.assertRaisesRegex(SystemExit, "whose own links the reader does not follow"):
                        r.boot_links(tree(d, files))

    # #5703 Security 6872976172: resolve keeps a target as given from its first missing component on, so a
    # .. after a directory that is there only at boot (or after a link's rewrite) would leave /proc unseen.
    def test_a_target_keeping_dot_or_dotdot_fails_the_run(self):
        for line in ("L /run/pkglink - - - - /run/systemd/../../proc/self/root/run/agentos-x",
                     "L /run/pkglink - - - - lock/../../proc/self/root/run/agentos-x",
                     "L /run/pkglink - - - - /var/lib/zz/../../../proc/1/root/run/agentos-x",
                     "L /run/pkglink - - - - /run/lock/../../dev/fd/0/run/agentos-x",
                     "L /run/pkglink - - - - /run/x/./y",
                     "L /run/a - - - - /run/lock\nL /run/pkglink - - - - /run/a/../../proc/self/root/run/agentos-x"):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "a target with . or .. the reader does not follow"):
                    r.boot_links(tree(d, {"/usr/lib/tmpfiles.d/x.conf": line + "\n"}))
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(SystemExit, "/etc/pkglink: a link to .*, a target with . or .."):
                r.boot_links(tree(d, {"/etc/pkglink": "-> /run/systemd/../../proc/self/root/run/agentos-x"}))

    def test_the_images_own_api_targets_pass(self):
        lines = ("L /run/shm - - - - /dev/shm\nL+ /etc/mtab - - - - ../proc/self/mounts\n"
                 "L /run/agentos-m - - - - /dev/null\n")
        with tempfile.TemporaryDirectory() as d:
            got = r.boot_links(tree(d, {"/usr/lib/tmpfiles.d/debian.conf": lines,
                                        "/etc/systemd/system/x.service": "-> /dev/null"}))
            self.assertEqual((got.get("/run/shm"), got.get("/etc/mtab"), got.get("/run/agentos-m")),
                             ("/dev/shm", "/proc/self/mounts", "/dev/null"))
            self.assertEqual(got.get("/etc/systemd/system/x.service"), "/dev/null")


class CopyLineTest(unittest.TestCase):
    """#5707 (KRN-2): systemd-tmpfiles copies a link as a link for a C line, so a C line whose source is, or
    holds, a link fails the run, and so does one whose source the reader cannot read."""

    def run_line(self, d, line, more=None):
        return r.boot_links(tree(d, {"/usr/lib/tmpfiles.d/x.conf": line + "\n", **(more or {})}))

    def test_a_source_that_is_or_holds_a_link_fails_the_run(self):
        for line, more, at in (
                ("C /run/x - - - - /usr/share/pkg/lnk", {"/usr/share/pkg/lnk": "-> /run/agentos-x"}, "/usr/share/pkg/lnk"),
                ("C /run/x - - - - /usr/share/pkg/f", {"/usr/share/pkg/f": "-> /etc/f", "/etc/f": "x"}, "/usr/share/pkg/f"),
                ("C /run/x - - - - /usr/share/pkg", {"/usr/share/pkg/a/b/lnk": "-> /run/agentos-x"}, "/usr/share/pkg/a/b/lnk"),
                ("C+ /run/x - - - - /etc/pkg", {"/etc/pkg/lnk": "-> ../../run/agentos-x"}, "/etc/pkg/lnk"),
                ("C /run/x", {"/usr/share/factory/run/x/lnk": "-> /run/agentos-x"}, "/usr/share/factory/run/x/lnk"),
                ("C! /run/x - - - - /etc/pkg", {"/etc/pkg/dangling": "-> /nowhere"}, "/etc/pkg/dangling")):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "C line .*: its source is or holds a link, %s" % at):
                    self.run_line(d, line, more)

    def test_a_source_through_a_link_fails_the_run(self):
        for line, more, at in (
                ("C /run/x - - - - /var/pkg/f", {"/var/pkg": "-> /etc/pkg", "/etc/pkg/f": "x"}, "/var/pkg"),
                ("C /run/x - - - - /var/lib/foo/f", {"/usr/lib/tmpfiles.d/a.conf": "L /var/lib/foo - - - - /etc/pkg\n",
                                                    "/etc/pkg/f": "x"}, "/var/lib/foo")):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, r"C line .*: its source passes through a link \(%s\)" % at):
                    self.run_line(d, line, more)

    def test_a_source_at_under_or_above_an_l_line_fails_the_run(self):
        # #5715 L3 6874735402 and Security 6874738412: an L line's link at boot, not in the tree.
        for files, at in (
                ({"/usr/lib/tmpfiles.d/x.conf": "L /etc/pkg/lnk - - - - /var/lib\nC /run/x - - - - /etc/pkg\n",
                  "/etc/pkg/f": "x", "/var/lib/k": "y"}, "/etc/pkg/lnk"),
                ({"/usr/lib/tmpfiles.d/x.conf": "L /var/lib/foo - - - - /etc/f\nC /run/x - - - - /var/lib/foo\n",
                  "/etc/f": "x"}, "/var/lib/foo"),
                ({"/usr/lib/tmpfiles.d/a.conf": "L /var/lib/pkg/lnk - - - - /run/agentos-x\n",
                  "/usr/lib/tmpfiles.d/x.conf": "C /run/x - - - - /var/lib/pkg\n", "/var/lib/pkg/f": "x"}, "/var/lib/pkg/lnk"),
                ({"/usr/lib/tmpfiles.d/a.conf": "L /var/lib/pkgsrc/lnk - - - - /run/agentos-x\n",
                  "/usr/lib/tmpfiles.d/x.conf": "C /run/x - - - - /var/lib/pkgsrc\n"}, "/var/lib/pkgsrc/lnk"),
                ({"/usr/lib/tmpfiles.d/x.conf": "L+ /etc/pkg/a/lnk - - - - /run/agentos-x\nC /run/x - - - - /etc/pkg\n"},
                 "/etc/pkg/a/lnk"),
                ({"/usr/lib/tmpfiles.d/a.conf": "L /usr/share/factory/run/x/d/lnk - - - - /run/agentos-x\n",
                  "/usr/lib/tmpfiles.d/x.conf": "C /run/x\n"}, "/usr/share/factory/run/x/d/lnk"),
                ({"/usr/lib/tmpfiles.d/a.conf": "L /usr/share/pkg - - - - /usr/share/f\n",
                  "/usr/lib/tmpfiles.d/x.conf": "C /run/x - - - - /usr/share/pkg/a\n", "/usr/share/f": "x"}, "/usr/share/pkg")):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "C line .*: an L line makes a link at, under or above "
                                                        "its source, %s" % at):
                    r.boot_links(tree(d, files))

    def test_a_source_outside_usr_fails_the_run(self):
        # #5715 L3 6874735402: /etc and /var keep what a service left there between boots.
        for line, more in (("C /run/x - - - - /etc/pkg", {"/etc/pkg/f": "x"}),
                           ("C /run/x - - - - /var/lib/pkg/f", {"/var/lib/pkg/f": "x"}),
                           ("C /run/x - - - - /usrx/f", {"/usrx/f": "x"}),
                           ("C /run/x - - - - /", {})):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "C line .*: its source is not under /usr"):
                    self.run_line(d, line, more)

    def test_a_extra_source_fails_the_run(self):
        # #5715 L3 6874919503 and Security 6874914212: a /.extra exception compared path text, so //, /./ or a
        # link on the way (a tree link or an L line) made /.extra at boot with the lint passing. No source
        # outside /usr is kept: the image's own stub lines (absent /.extra) fail too, and mkosi.conf drops them.
        c = "C /run/x - - - - /.extra/profile\n"
        for files in (
                {"/usr/lib/tmpfiles.d/x.conf": c},
                {"/usr/lib/tmpfiles.d/x.conf": "C /run/systemd/stub/profile 0444 root root - /.extra/profile\n"},
                {"/usr/lib/tmpfiles.d/x.conf": "d /.extra/profile 0777 - - -\n" + c},
                {"/usr/lib/tmpfiles.d/x.conf": "d //.extra/profile 0777 - - -\n" + c},
                {"/usr/lib/tmpfiles.d/x.conf": "d /./.extra/profile 0777 - - -\n" + c},
                {"/usr/lib/tmpfiles.d/x.conf": "d /usr/../.extra/profile 0777 - - -\n" + c},
                {"/usr/lib/tmpfiles.d/x.conf": "L /foo - - - - .\nd /foo/.extra/profile 0777 - - -\n" + c},
                {"/usr/lib/tmpfiles.d/x.conf": "d /foo/.extra/profile 0777 - - -\n" + c, "/foo": "-> ."},
                {"/usr/lib/tmpfiles.d/x.conf": "d /foo/.extra/profile 0777 - - -\n" + c, "/foo": "-> /"},
                {"/usr/lib/tmpfiles.d/x.conf": c, "/.extra/profile": "x"}):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "C line .*: its source is not under /usr"):
                    r.boot_links(tree(d, files))

    def test_a_non_normal_path_fails_the_run(self):
        # normpath keeps a leading //, so a text match against an L line or /usr could miss it.
        for files, want in (
                ({"/usr/lib/tmpfiles.d/x.conf": "C /run/x - - - - //usr/share/pkg\n", "/usr/share/pkg/f": "x"},
                 "C line .*: its source is not absolute and normal"),
                ({"/usr/lib/tmpfiles.d/a.conf": "L //usr/share/pkg/lnk - - - - /run/agentos-x\n",
                  "/usr/lib/tmpfiles.d/x.conf": "C /run/x - - - - /usr/share/pkg\n", "/usr/share/pkg/f": "x"},
                 "L line .*: its path is not absolute and normal"),
                ({"/usr/lib/tmpfiles.d/a.conf": "L /usr/share/./pkg/lnk - - - - /run/agentos-x\n",
                  "/usr/lib/tmpfiles.d/x.conf": "C /run/x - - - - /usr/share/pkg\n", "/usr/share/pkg/f": "x"},
                 "L line .*: its path is not absolute and normal")):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, want):
                    r.boot_links(tree(d, files))

    def test_a_source_the_reader_cannot_read_fails_the_run(self):
        for line, want in (
                ("C /run/x - - - - /usr/share/%b/f", "holds a specifier, a quote or an escape"),
                ("C /run/x - - - - \"/usr/share/pkg\"", "holds a specifier, a quote or an escape"),
                ("C~ /run/x - - - - L3Vzci9zaGFyZQ==", "its source is encoded or a credential"),
                ("C^ /run/x - - - - cred", "its source is encoded or a credential"),
                ("C /run/x - - - - usr/share/pkg", "its source is not absolute and normal"),
                ("C /run/x - - - - /usr/share/../../run/udev", "its source is not absolute and normal"),
                ("C /run/x - - - - /run/pkg", "its source is under /run"),
                ("C /run/x - - - - /proc/self/root", "its source is under /proc"),
                ("C /run/x - - - - /tmp", "its source is under /tmp")):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                with self.assertRaisesRegex(SystemExit, "C line .*" + want):
                    self.run_line(d, line)

    def test_a_source_of_files_or_none_passes(self):
        for line, more in (("C /run/x - - - - /usr/share/pkg", {"/usr/share/pkg/a/f": "x", "/usr/share/pkg/g": "y"}),
                           ("C /run/x", {"/usr/share/factory/run/x": "x"}),
                           ("c /dev/x 0600 - - - 1:3", {})):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as d:
                got = self.run_line(d, line, more)
                self.assertNotIn("/run/x", got)


class LintTest(unittest.TestCase):
    """lint() refuses a run in which a generator failed (#4817, from #4767's harness)."""

    def test_a_failed_generator_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {ETC + "a.service": "[Service]\n"})  # View(view_root): no separate /usr
            stopped = []

            class Fake:
                def __init__(self, root, usr, cmdline, plant):
                    self.view_root = v.root

                def show(self, units, props):
                    return shown({u: ("loaded", ETC + "a.service", []) for u in units})

                def failed_generators(self):
                    return self.failed

                def stop(self):
                    stopped.append(1)
            real = offline_systemd.Manager
            offline_systemd.Manager = Fake
            try:
                for failed in ({"x-generator"}, {offline_systemd.GENERATOR_TIMEOUT}):
                    with self.subTest(failed=failed):
                        Fake.failed = failed
                        with self.assertRaisesRegex(SystemExit, "generators failed"):
                            r.lint(d, d, "", lambda view: lambda p: False)
                Fake.failed = set()
                self.assertEqual([u["unit"] for u in r.lint(d, d, "", lambda view: lambda p: False)["units"]],
                                 ["a.service"])
            finally:
                offline_systemd.Manager = real
            self.assertEqual(len(stopped), 3)


class NamesTest(unittest.TestCase):
    def test_no_file_may_be_the_lint_instance_s_own(self):
        # #4779 round 3: the lint's instance stands for every instance a boot may start
        for files in ({ETC + "t@agentos-unit-lint.service.d/u.conf": "u"}, {ETC + "t@agentos-unit-lint.service": "u"},
                      {ETC + "a.target.wants/t@agentos-unit-lint.service": "-> /dev/null"},
                      {ETC + "t@agentos-unit-lint.socket.d/u.conf": "u"}):  # #4779 L3 R1: any type
            with self.subTest(files=files), tempfile.TemporaryDirectory() as d:
                v = tree(d, dict(files, **{LIB + "t@.service": "t"}))
                with self.assertRaisesRegex(SystemExit, "lint's own instance"):
                    r.names(v, r.unit_dirs(v))

    def test_every_name_a_unit_directory_holds(self):
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {LIB + "a.service": "", LIB + "t@.service": "", ETC + "t@b.service.d/z.conf": "",
                         ETC + "multi-user.target.wants/getty@tty1.service": "-> " + LIB + "t@.service",
                         ETC + "service.d/z.conf": "", LIB + "README": ""})
            self.assertEqual(r.names(v, r.unit_dirs(v)),
                             ["a.service", "getty@tty1.service", "t@agentos-unit-lint.service",
                              "t@b.service", "t@tty1.service"])  # each template as every instance name

    def test_a_device_unit_file_and_its_drop_ins_are_named(self):
        # #5507: systemd loads a .device unit's file and drop-ins (device.c device_load), so a unit file of
        # ours for one, or a drop-in directory naming one, is asked about
        with tempfile.TemporaryDirectory() as d:
            v = tree(d, {ETC + "dev-x.device": "[Unit]\nWants=e.service\n",
                         ETC + "sys-subsystem-net-devices-y.device.d/50.conf": "[Unit]\nWants=e.service\n",
                         ETC + "dev-z.device.wants/e.service": "-> " + LIB + "e.service", LIB + "e.service": ""})
            self.assertEqual(r.names(v, r.unit_dirs(v)),
                             ["dev-x.device", "e.service", "sys-subsystem-net-devices-y.device"])
            dirs = r.unit_dirs(v)
            prov = r.Provenance(v, dirs, lambda p: p == LIB + "e.service")
            got = r.records(v, shown({"dev-x.device": ("loaded", ETC + "dev-x.device", []),
                                      "sys-subsystem-net-devices-y.device": (
                                          "loaded", "", [ETC + "sys-subsystem-net-devices-y.device.d/50.conf"]),
                                      "e.service": ("loaded", LIB + "e.service", [])}), dirs, prov)
            self.assertEqual([(u["unit"], u["alone"], [(f["path"], f["ours"]) for f in u["files"]]) for u in got["units"]],
                             [("dev-x.device", False, [(ETC + "dev-x.device", True)]),
                              ("e.service", False, [(LIB + "e.service", False)]),
                              ("sys-subsystem-net-devices-y.device", True,
                               [(ETC + "sys-subsystem-net-devices-y.device.d/50.conf", True)])])

    def test_shared_directories(self):
        # dropin.c unit_file_find_dirs reaches another name only through a template or a name whose part
        # before the @ or the type ends in -
        for n in (".service", "x-.service", "x@.service", "x-@.service", "x-@i.service", "-.slice", "x-.device",
                  "x.scope"):
            self.assertTrue(r.shared(n), n)
        for n in ("x.service", "x-y.service", "x@i.service", "x@i-.service", "x-y@i.service", "x.device"):
            self.assertFalse(r.shared(n), n)

    def test_a_name_systemctl_could_not_carry_is_refused(self):
        for p in (ETC + "a b.service", ETC + "x.service.d/z\n.conf", ETC + "x.wants/a\tb.service"):
            with self.subTest(p=p), tempfile.TemporaryDirectory() as d:
                v = tree(d, {p: ""})
                with self.assertRaisesRegex(SystemExit, "a name with a byte outside"):
                    r.names(v, r.unit_dirs(v))

    def test_the_control_is_a_drop_in_of_ours_on_a_packaged_root_unit(self):
        (p, text), = r.CONTROL.items()
        self.assertTrue(p.startswith("etc/systemd/system/systemd-tmpfiles-setup.service.d/"))
        self.assertIn("LD_PRELOAD", text)
        self.assertEqual(r.CONTROL_WANT, 'variable "LD_PRELOAD"')


if __name__ == "__main__":
    unittest.main()
