"""image/unlock_graph.py: the unlock step's reach, read from systemd's own test-mode dump (#4667).

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


def dump(units):
    """A test-mode dump in systemd's layout: UNITS maps a name to its lines, each "Kind: target" (given an
    origin mask) or a "<X> Action: value" line."""
    out = ["-> By units:"]
    for name, lines in units.items():
        out.append("\t-> Unit %s:" % name)
        out.append("\t\tDescription: %s" % name)
        for l in lines:
            out.append("\t\t" + (l if " Action: " in l else l + " (origin-file)"))
    out += ["-> By jobs:", "\t-> Job 1:", "\t\tAction: %s -> start" % U]
    return "\n".join(out) + "\n"


SHIPPED = {U: ["Wants: agentos-link.service", "Requires: agentos-keeper.slice", "After: basic.target",
               "References: basic.target"],
           "agentos-link.service": ["BindsTo: link.device", "Requires: agentos-inbound.service",
                                    "Conflicts: shutdown.target"],
           "link.device": ["Wants: agentos-keeper-link-capture.service", "BoundBy: agentos-link.service"],
           "agentos-keeper-link-capture.service": [],
           "agentos-inbound.service": [],
           "agentos-keeper.slice": ["Requires: -.slice"],
           "-.slice": [],
           "basic.target": ["Wants: reboot.target"]}  # ordered, never started: not reached


def facts_of(units, stderr=""):
    return g.facts(g.parse_dump(dump(units)), stderr)


class ReachTest(unittest.TestCase):
    def test_the_walk_follows_every_start_kind_and_nothing_else(self):
        self.assertEqual(g.reached(g.parse_dump(dump(SHIPPED))),
                         {U, "agentos-link.service", "link.device", "agentos-keeper-link-capture.service",
                          "agentos-inbound.service", "agentos-keeper.slice", "-.slice"})
        for kind in sorted(g.START_KINDS):
            with self.subTest(kind=kind):
                self.assertIn("x.service", g.reached(g.parse_dump(dump({U: ["%s: x.service" % kind]}))))
        for kind in sorted(g.STOP_KINDS | g.OTHER_KINDS):
            with self.subTest(kind=kind):
                self.assertNotIn("x.service", g.reached(g.parse_dump(dump({U: ["%s: x.service" % kind]}))))

    def test_the_kind_classes_are_systemd_257s_whole_list(self):
        # unit_dependency_to_string in systemd 257.13's unit-dependency-atom.c / unit.c, plus the two
        # path lines unit_dump prints with a mask.
        kinds = {"Requires", "Requisite", "Wants", "BindsTo", "PartOf", "Upholds", "RequiredBy", "RequisiteOf",
                 "WantedBy", "BoundBy", "UpheldBy", "ConsistsOf", "Conflicts", "ConflictedBy", "Before", "After",
                 "OnSuccess", "OnSuccessOf", "OnFailure", "OnFailureOf", "Triggers", "TriggeredBy",
                 "PropagatesReloadTo", "ReloadPropagatedFrom", "PropagatesStopTo", "StopPropagatedFrom",
                 "JoinsNamespaceOf", "References", "ReferencedBy", "InSlice", "SliceOf"}
        self.assertEqual(g.START_KINDS | g.STOP_KINDS | g.OTHER_KINDS, kinds | {"RequiresMountsFor", "WantsMountsFor"})
        self.assertFalse(g.START_KINDS & g.STOP_KINDS or g.START_KINDS & g.OTHER_KINDS or g.STOP_KINDS & g.OTHER_KINDS)

    def test_facts_are_the_units_reached_their_stops_and_failed_generators(self):
        self.assertEqual(facts_of(SHIPPED, "/usr/lib/systemd/system-generators/systemd-gpt-auto-generator failed "
                                           "with exit status 1.\n"),
                         {"start " + u for u in g.reached(g.parse_dump(dump(SHIPPED)))}
                         | {"stop link.device BoundBy agentos-link.service",
                            "generator systemd-gpt-auto-generator failed"})


class ViolationsTest(unittest.TestCase):
    def v(self, units, allowed=None, status=0, stderr=""):
        text = dump(units)
        return g.violations(status, text, stderr, facts_of(SHIPPED) if allowed is None else allowed)

    def test_the_shipped_shape_passes_against_its_own_list(self):
        self.assertEqual(self.v(SHIPPED), [])

    def test_every_route_to_a_shutdown_unit_is_refused(self):
        # Each start kind, from the unlock unit or from a unit it reaches, and under each shutdown name.
        for kind in sorted(g.START_KINDS):
            for at in (U, "agentos-inbound.service"):
                for target in sorted(g.SHUTDOWN):
                    with self.subTest(kind=kind, at=at, target=target):
                        units = {k: list(v) for k, v in SHIPPED.items()}
                        units[at].append("%s: %s" % (kind, target))
                        units[target] = []
                        v = self.v(units)
                        self.assertIn("%s starts %s; %s" % (U, target, g.WHY), v)
                        self.assertIn("start %s: not on unlock.allow; review it and add the line there" % target, v)

    def test_a_shutdown_unit_is_refused_even_when_listed(self):
        units = {k: list(v) for k, v in SHIPPED.items()}
        units["agentos-inbound.service"].append("Wants: reboot.target")
        units["reboot.target"] = ["Requires: systemd-reboot.service"]
        units["systemd-reboot.service"] = []
        allowed = facts_of(SHIPPED) | {"start reboot.target"}
        # Reached, refused, and not walked past: systemd-reboot.service is not reached through it.
        self.assertEqual(self.v(units, allowed), ["%s starts reboot.target; %s" % (U, g.WHY)])

    def test_a_reached_unit_with_an_action_is_refused(self):
        for name in ("Failure Action", "Success Action", "Job Timeout Action", "Job Running Timeout Action",
                     "Start Limit Action"):
            with self.subTest(name=name):
                units = {k: list(v) for k, v in SHIPPED.items()}
                units["agentos-link.service"].append("%s: reboot-force" % name)
                self.assertEqual(self.v(units), ["agentos-link.service, which %s starts, has %s reboot-force; %s"
                                                 % (U, name, g.WHY)])
        units = {k: list(v) for k, v in SHIPPED.items()}
        units["basic.target"].append("Failure Action: reboot")  # not reached
        self.assertEqual(self.v(units), [])

    def test_a_unit_outside_the_list_is_refused_and_a_stale_line_too(self):
        units = {k: list(v) for k, v in SHIPPED.items()}
        units["agentos-link.service"].append("Upholds: agentos-plant.service")
        units["agentos-plant.service"] = ["Conflicts: agentosd.service"]
        self.assertEqual(self.v(units), [
            "start agentos-plant.service: not on unlock.allow; review it and add the line there",
            "stop agentos-plant.service Conflicts agentosd.service: not on unlock.allow; review it and add the line there"])
        self.assertEqual(self.v(SHIPPED, facts_of(SHIPPED) | {"start gone.service"}),
                         ["start gone.service: on unlock.allow but no longer in the graph; remove the line"])

    def test_a_stop_of_a_shutdown_unit_is_not_listed(self):
        # Every unit with default dependencies conflicts with shutdown.target; stopping it ends nothing.
        self.assertNotIn("stop agentos-link.service Conflicts shutdown.target", facts_of(SHIPPED))
        for kind in sorted(g.STOP_KINDS):
            with self.subTest(kind=kind):
                units = {k: list(v) for k, v in SHIPPED.items()}
                units[U].append("%s: agentosd.service" % kind)
                self.assertEqual(self.v(units), ["stop %s %s agentosd.service: not on unlock.allow; review it and "
                                                 "add the line there" % (U, kind)])

    def test_an_unknown_kind_is_refused(self):
        units = {k: list(v) for k, v in SHIPPED.items()}
        units["agentos-link.service"].append("PullsInLater: agentos-plant.service")
        self.assertEqual(self.v(units), ["agentos-link.service: dependency kind PullsInLater is not one this check "
                                         "knows, so where it leads is unread; %s" % g.WHY])

    def test_a_failed_run_a_dropped_job_or_a_new_failed_generator_is_refused(self):
        v = self.v(SHIPPED, status=1, stderr="Failed to start default target: Transaction contains conflicting jobs")
        self.assertTrue(v[0].startswith("systemd's test run for %s exited 1: Failed to start" % U), v)
        self.assertEqual(g.violations(1, "", "boom", facts_of(SHIPPED))[1:],
                         ["systemd's test run printed no unit list, so nothing it starts is known; " + g.WHY])
        line = "local-fs.target: Job ldconfig.service/start deleted to break ordering cycle starting with x/start"
        self.assertEqual(self.v(SHIPPED, stderr=line + "\n"),
                         ["systemd dropped a job from the unlock step's transaction (%s); %s" % (line, g.WHY)])
        self.assertEqual(self.v(SHIPPED, stderr="/usr/lib/systemd/system-generators/systemd-fstab-generator failed "
                                                "with exit status 1.\n"),
                         ["generator systemd-fstab-generator failed: not on unlock.allow; review it and add the "
                          "line there"])

    def test_the_unlock_unit_must_be_loaded(self):
        self.assertIn("%s is not among the units systemd loaded; %s" % (U, g.WHY),
                      g.violations(0, dump({"other.service": []}), "", set()))


class OfflineSystemdTest(unittest.TestCase):
    def test_units_splits_dependencies_from_settings_and_skips_job_lines(self):
        text = ("-> By units:\n\t-> Unit a.service:\n\t\tDescription: a: b\n\t\tUser: agentos-link\n"
                "\t\tWants: b.service (origin-file origin-default)\n\t\tRequiresMountsFor: /var (origin-implicit)\n"
                "\t\tFailure Action: reboot\n\t-> Job 4:\n\t\t\tAction: a.service -> start\n"
                "-> By jobs:\n\t-> Unit z.service:\n")
        self.assertEqual(offline_systemd.units(text), {"a.service": {
            "edges": [("Wants", "b.service"), ("RequiresMountsFor", "/var")],
            "settings": [("Description", "a: b"), ("User", "agentos-link"), ("Failure Action", "reboot")]}})
        self.assertEqual(offline_systemd.failed_generator(
            "/usr/lib/systemd/system-generators/systemd-gpt-auto-generator failed with exit status 1."),
            "systemd-gpt-auto-generator")
        self.assertIsNone(offline_systemd.failed_generator("Loaded units and determined initial transaction."))


class AllowFileTest(unittest.TestCase):
    def test_the_shipped_list_reads_and_holds_the_unlock_unit(self):
        allowed = g.read_allow()
        self.assertTrue(g.ALLOW.read_text().startswith(g.ALLOW_HEADER))
        self.assertIn("start " + U, allowed)
        self.assertFalse({"start " + s for s in g.SHUTDOWN} & allowed)
        for line in allowed:
            self.assertRegex(line, r"^(start \S+|stop \S+ (%s) \S+|generator \S+ failed)$" % "|".join(sorted(g.STOP_KINDS)))

    def test_each_control_is_a_path_a_review_found(self):
        self.assertEqual(len(g.CONTROLS), 3)
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as dst:
            os.makedirs(os.path.join(root, "etc"))
            pathlib.Path(root, "etc/fstab").write_text("tmpfs /run tmpfs nosuid 0 0\n")
            g.plant_tree(root, g.CONTROLS[next(iter(g.CONTROLS))], dst)
            self.assertEqual(pathlib.Path(dst, "etc/fstab").read_text(),
                             "tmpfs /run tmpfs nosuid 0 0\n" + g.CONTROLS[next(iter(g.CONTROLS))][g.FSTAB])
            self.assertEqual(os.stat(dst).st_mode & 0o777, 0o755)


@unittest.skipUnless(os.geteuid() == 0 and os.access("/usr/lib/systemd/systemd", os.X_OK) and shutil.which("unshare"),
                     "needs root and systemd; CI's image job runs the same path on the built image (--control)")
class HostSystemdTest(unittest.TestCase):
    """The namespace run and the dump reader against the host's own systemd, on a tree of the image's units."""

    def test_the_planted_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d) / "root"
            for sub in ("usr", "proc", "sys", "dev", "run", "tmp", "var/tmp", "etc/systemd"):
                (root / sub).mkdir(parents=True)
            for n in ("bin", "lib", "lib64", "sbin"):
                (root / n).symlink_to("usr/" + n)
            os.chmod(d, 0o755)
            shutil.copytree(ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/system", root / "etc/systemd/system",
                            symlinks=True)
            shutil.copy(ROOT / "image/mkosi/mkosi.extra/etc/fstab", root / "etc/fstab")
            (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
            wants = root / "etc/systemd/system" / (U + ".wants")
            wants.mkdir()
            (wants / "agentos-link.service").symlink_to("../agentos-link.service")
            status, out, err = g.systemd_test(root, "/usr", "ro quiet")
            self.assertEqual(status, 0, err[-2000:])
            base = g.facts(g.parse_dump(out), err)
            self.assertIn("start agentos-link.service", base)
            self.assertEqual(g.violations(status, out, err, base), [])
            for name, plant in g.CONTROLS.items():
                with self.subTest(name=name), tempfile.TemporaryDirectory() as p:
                    g.plant_tree(root, plant, p)
                    self.assertTrue(g.violations(*g.systemd_test(root, "/usr", "ro quiet", p), base))


if __name__ == "__main__":
    unittest.main()
