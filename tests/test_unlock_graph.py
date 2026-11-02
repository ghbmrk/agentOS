"""image/unlock_graph.py: the unlock step's reach, as the image's own systemd shows it (#4667), and the
offline_systemd harness it shares with the unit-rule lint (#4677).

REQ: STO-2c
"""
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "image"))
import offline_systemd  # noqa: E402
import unlock_graph as g  # noqa: E402

U = g.UNIT
NONE = [(a, "none") for a in g.ACTIONS]


def graph(spec):
    """graph()'s shape from {unit: ["Kind: target", ...]}."""
    return {name: {"edges": [tuple(e.split(": ")) for e in edges], "actions": list(NONE)} for name, edges in spec.items()}


SHIPPED = {U: ["Wants: agentos-link.service", "Requires: agentos-keeper.slice"],
           "agentos-link.service": ["BindsTo: link.device", "Requires: agentos-inbound.service",
                                    "Conflicts: shutdown.target"],
           "link.device": ["Wants: agentos-keeper-link-capture.service", "BoundBy: agentos-link.service"],
           "agentos-keeper-link-capture.service": [],
           "agentos-inbound.service": [],
           "agentos-keeper.slice": ["Requires: -.slice"],
           "-.slice": []}
FSTAB = "devtmpfs /dev devtmpfs nosuid,noexec 0 0\ntmpfs /run tmpfs mode=0755,nosuid,nodev,noexec 0 0\n"


def copy(spec):
    return {k: list(v) for k, v in spec.items()}


class FakeManager:
    """show() over a fixed graph, as offline_systemd.Manager answers it."""

    def __init__(self, spec):
        self.spec, self.asked = spec, []

    def show(self, units, props):
        self.asked.append(sorted(units))
        out = {}
        for u in units:
            p = {k: "" for k in props}
            p.update({a: "none" for a in g.ACTIONS})
            for e in self.spec.get(u, ()):
                k, t = e.split(": ")
                p[k] = (p[k] + " " + ('"%s"' % t.replace("\\", "\\\\") if "\\" in t else t)).strip()
            out[u] = p
        return out


class ReachTest(unittest.TestCase):
    def test_graph_walks_every_start_kind_and_stops_at_a_shutdown_unit(self):
        spec = copy(SHIPPED)
        spec["agentos-inbound.service"] = ["Wants: reboot.target", "Conflicts: agentosd.service"]
        spec["reboot.target"] = ["Requires: systemd-reboot.service"]
        got = g.graph(FakeManager(spec))
        self.assertEqual(set(got), set(SHIPPED) | {"reboot.target"})
        self.assertEqual(got["agentos-inbound.service"]["edges"],
                         [("Wants", "reboot.target"), ("Conflicts", "agentosd.service")])
        for kind in g.START_KINDS:
            with self.subTest(kind=kind):
                self.assertIn("x.service", g.graph(FakeManager({U: ["%s: x.service" % kind]})))
        for kind in g.STOP_KINDS:
            with self.subTest(kind=kind):
                self.assertNotIn("x.service", g.graph(FakeManager({U: ["%s: x.service" % kind]})))

    def test_a_quoted_name_is_unquoted_and_a_bad_one_refused(self):
        got = g.graph(FakeManager({U: ["Wants: sys-subsystem-net-devices-agentos\\x2dlink.device"]}))
        self.assertIn("sys-subsystem-net-devices-agentos\\x2dlink.device", got)
        for bad in ('a.service\nWants=reboot.target', '"a.service', "a b", "-> Unit x.service:"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                g.unit_names(U, "Wants", bad)

    def test_the_kinds_split_systemd_257s_list(self):
        # unit_dependency_to_string in systemd 257.13: these act on another unit; the rest only order,
        # reference or mirror them (PartOf acts on this unit, not another).
        acting = set(g.START_KINDS) | set(g.STOP_KINDS)
        self.assertEqual(acting, {"Requires", "Requisite", "Wants", "BindsTo", "Upholds", "OnSuccess", "OnFailure",
                                  "Triggers", "Conflicts", "ConflictedBy", "PropagatesStopTo", "BoundBy",
                                  "ConsistsOf"})
        self.assertEqual(g.SYSTEMD_MAJOR, "257")
        self.assertEqual(set(g.PROPS), acting | set(g.ACTIONS) | {"LoadState"})

    def test_facts_are_the_units_reached_their_stops_and_failed_generators(self):
        units = graph(SHIPPED)
        self.assertEqual(g.facts(units, {"systemd-gpt-auto-generator"}),
                         {"start " + u for u in SHIPPED}
                         | {"stop link.device BoundBy agentos-link.service",
                            "generator systemd-gpt-auto-generator failed"})


class ViolationsTest(unittest.TestCase):
    def v(self, spec, allowed=None, version="257.13-1~deb13u1", fstab=FSTAB, generators=()):
        allowed = g.facts(graph(SHIPPED), ()) if allowed is None else allowed
        return g.violations(graph(spec), set(generators), allowed, version, fstab)

    def test_the_shipped_shape_passes_against_its_own_list(self):
        self.assertEqual(self.v(SHIPPED), [])

    def test_every_route_to_a_shutdown_unit_is_refused(self):
        for kind in g.START_KINDS:
            for at in (U, "agentos-inbound.service"):
                for target in sorted(g.SHUTDOWN):
                    with self.subTest(kind=kind, at=at, target=target):
                        spec = copy(SHIPPED)
                        spec[at].append("%s: %s" % (kind, target))
                        spec[target] = []
                        v = self.v(spec)
                        self.assertIn("%s starts %s; %s" % (U, target, g.WHY), v)
                        self.assertIn("start %s: not on unlock.allow; review it and add the line there" % target, v)

    def test_a_shutdown_unit_is_refused_even_when_listed(self):
        spec = copy(SHIPPED)
        spec["agentos-inbound.service"].append("Wants: reboot.target")
        spec["reboot.target"] = ["Requires: systemd-reboot.service"]
        spec["systemd-reboot.service"] = []
        self.assertEqual(self.v(spec, g.facts(graph(SHIPPED), ()) | {"start reboot.target"}),
                         ["%s starts reboot.target; %s" % (U, g.WHY)])

    def test_a_reached_unit_with_an_action_is_refused(self):
        for name in g.ACTIONS:
            with self.subTest(name=name):
                units = graph(SHIPPED)
                units["agentos-link.service"]["actions"] = [(a, "reboot-force" if a == name else "none")
                                                            for a in g.ACTIONS]
                self.assertEqual(g.violations(units, set(), g.facts(graph(SHIPPED), ()), "257.13", FSTAB),
                                 ["agentos-link.service, which %s starts, has %s=reboot-force; %s" % (U, name, g.WHY)])

    def test_a_unit_outside_the_list_is_refused_and_a_stale_line_too(self):
        spec = copy(SHIPPED)
        spec["agentos-link.service"].append("Upholds: agentos-plant.service")
        spec["agentos-plant.service"] = ["Conflicts: agentosd.service"]
        self.assertEqual(self.v(spec), [
            "start agentos-plant.service: not on unlock.allow; review it and add the line there",
            "stop agentos-plant.service Conflicts agentosd.service: not on unlock.allow; review it and add the line there"])
        self.assertEqual(self.v(SHIPPED, g.facts(graph(SHIPPED), ()) | {"start gone.service"}),
                         ["start gone.service: on unlock.allow but no longer in the graph; remove the line"])

    def test_a_stop_of_a_shutdown_unit_is_not_listed(self):
        self.assertNotIn("stop agentos-link.service Conflicts shutdown.target", g.facts(graph(SHIPPED), ()))
        for kind in g.STOP_KINDS:
            with self.subTest(kind=kind):
                spec = copy(SHIPPED)
                spec[U].append("%s: agentosd.service" % kind)
                self.assertEqual(self.v(spec), ["stop %s %s agentosd.service: not on unlock.allow; review it and "
                                                "add the line there" % (U, kind)])

    def test_another_systemd_major_is_refused(self):
        self.assertEqual(self.v(SHIPPED, version="258.1"), [
            "the image's systemd is 258.1, but the dependency kinds this check follows were read from systemd 257; "
            "read them again for this version; " + g.WHY])

    def test_an_fstab_device_line_or_link_is_refused(self):
        # fstab-generator skips a device entry in a container, so its x-systemd.wants= would go unread.
        for line in ("/dev/sda3 /var ext4 x-systemd.wants=reboot.target 0 0", "LABEL=x /var ext4 defaults 0 0",
                     "UUID=1-2 /srv xfs defaults 0 0"):
            with self.subTest(line=line):
                self.assertEqual(self.v(SHIPPED, fstab=FSTAB + line + "\n"), [
                    "etc/fstab: %s names a device, which systemd in the check's container skips, so what it pulls "
                    "is unread; %s" % (line, g.WHY)])
        self.assertEqual(self.v(SHIPPED, fstab=FSTAB + "# /dev/sda1 / ext4\n"), [])
        self.assertEqual(self.v(SHIPPED, fstab=None), ["etc/fstab is a link, so what it holds is unread here; " + g.WHY])
        self.assertEqual(g.fstab_devices((ROOT / "image/mkosi/mkosi.extra/etc/fstab").read_text()), [])

    def test_a_new_failed_generator_is_refused_and_the_unlock_unit_must_load(self):
        self.assertEqual(self.v(SHIPPED, generators={"systemd-fstab-generator"}),
                         ["generator systemd-fstab-generator failed: not on unlock.allow; review it and add the line there"])
        self.assertIn("%s is not among the units systemd loaded; %s" % (U, g.WHY),
                      g.violations({}, set(), set(), "257", ""))


class OfflineSystemdTest(unittest.TestCase):
    def test_show_blocks_are_whole_and_exact(self):
        props = ("Id", "Names", "Wants")
        self.assertEqual(offline_systemd.parse_block("Id=a.service\nNames=a.service\nWants=b.service", props, "a"),
                         {"Id": "a.service", "Names": "a.service", "Wants": "b.service"})
        for bad in ("Id=a.service\nNames=a.service", "Id=a.service\nNames=a.service\nWants=\nWants=x.service",
                    "Id=a.service\nNames=a.service\nWants=b.service\nUser=root", "Id=a.service\nNames=a.service\nWants"):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                offline_systemd.parse_block(bad, props, "a")

    def test_list_values_split_as_shell_words(self):
        self.assertEqual(offline_systemd.shell_words('a.service "b\\\\x2dc.device"', "a"),
                         ["a.service", "b\\x2dc.device"])
        with self.assertRaises(SystemExit):
            offline_systemd.shell_words('"open', "a")

    def test_failed_generators_are_read_from_the_console(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log") as f:
            f.write("/usr/lib/systemd/system-generators/systemd-gpt-auto-generator failed with exit status 1.\n"
                    "Reached target sockets.target.\n")
            f.flush()
            m = offline_systemd.Manager.__new__(offline_systemd.Manager)
            m.log = f
            self.assertEqual(m.failed_generators(), {"systemd-gpt-auto-generator"})


class AllowFileTest(unittest.TestCase):
    def test_the_shipped_list_reads_and_holds_the_unlock_unit(self):
        allowed = g.read_allow()
        self.assertTrue(g.ALLOW.read_text().startswith(g.ALLOW_HEADER))
        self.assertIn("start " + U, allowed)
        self.assertFalse({"start " + s for s in g.SHUTDOWN} & allowed)
        for line in allowed:
            self.assertRegex(line, r"^(start \S+|stop \S+ (%s) \S+|generator \S+ failed)$" % "|".join(g.STOP_KINDS))

    def test_each_control_is_a_path_a_review_found(self):
        self.assertEqual(len(g.CONTROLS), 3)
        first = g.CONTROLS[next(iter(g.CONTROLS))]
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as dst:
            os.makedirs(os.path.join(root, "etc"))
            pathlib.Path(root, "etc/fstab").write_text(FSTAB)
            g.plant_tree(root, first, dst)
            self.assertEqual(pathlib.Path(dst, "etc/fstab").read_text(), FSTAB + first[g.FSTAB])
            self.assertEqual(os.stat(dst).st_mode & 0o777, 0o755)
            self.assertEqual(g.fstab_devices(FSTAB + first[g.FSTAB]), [])


@unittest.skipUnless(os.geteuid() == 0 and os.access("/usr/lib/systemd/systemd", os.X_OK)
                     and all(shutil.which(n) for n in ("unshare", "nsenter", "systemctl")),
                     "needs root and systemd; CI's image job runs the same path on the built image (--control)")
class HostSystemdTest(unittest.TestCase):
    """The harness against the host's own systemd, on a tree of the image's units."""

    def test_the_planted_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o755)
            root = pathlib.Path(d) / "root"
            for sub in ("usr", "proc", "sys", "dev", "run", "tmp", "var/tmp", "etc/systemd"):
                (root / sub).mkdir(parents=True)
            for n in ("bin", "lib", "lib64", "sbin"):
                (root / n).symlink_to("usr/" + n)
            shutil.copytree(ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/system", root / "etc/systemd/system",
                            symlinks=True)
            shutil.copy(ROOT / "image/mkosi/mkosi.extra/etc/fstab", root / "etc/fstab")
            (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
            wants = root / "etc/systemd/system" / (U + ".wants")
            wants.mkdir()
            (wants / "agentos-link.service").symlink_to("../agentos-link.service")
            m = offline_systemd.Manager(root, "/usr", "ro quiet")
            try:
                major = m.manager(("Version",))["Version"].split(".")[0]
                base = g.facts(g.graph(m), m.failed_generators())
            finally:
                m.stop()
            self.assertIn("start agentos-link.service", base)
            self.assertIn("start sys-subsystem-net-devices-agentos\\x2dlink.device", base)
            self.assertEqual(g.run(root, "/usr", "ro quiet", base, major=major)[2], [])
            for name, plant in g.CONTROLS.items():
                with self.subTest(name=name), tempfile.TemporaryDirectory() as p:
                    g.plant_tree(root, plant, p)
                    self.assertTrue(g.run(root, "/usr", "ro quiet", base, p, major=major)[2])


if __name__ == "__main__":
    unittest.main()
