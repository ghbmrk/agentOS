"""image/unlock_graph.py: the unlock step's reach, as the image's own systemd shows it (#4667), and the
offline_systemd harness it shares with the unit-rule lint (#4677).

REQ: STO-2
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
    return {name: {"edges": [tuple(e.split(": ")) for e in edges], "actions": list(NONE), "load": "loaded",
                   "job_modes": [(m, "replace") for m in g.JOB_MODES]} for name, edges in spec.items()}


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
            p.update({a: "none" for a in g.ACTIONS}, LoadState="loaded", OnFailureJobMode="replace",
                     OnSuccessJobMode="fail")
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
                                  "RequiredBy", "RequisiteOf", "ConsistsOf"})
        self.assertEqual(g.SYSTEMD_MAJOR, "257")
        self.assertEqual(set(g.PROPS), acting | set(g.ACTIONS) | {"LoadState", "OnFailureJobMode", "OnSuccessJobMode"})

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

    def test_a_reached_unit_that_does_not_load_or_isolates_on_failure_is_refused(self):
        for load in ("not-found", "bad-setting", "error"):
            with self.subTest(load=load):
                units = graph(SHIPPED)
                units["agentos-inbound.service"]["load"] = load
                self.assertEqual(g.violations(units, set(), g.facts(graph(SHIPPED), ()), "257.13", FSTAB), [
                    "agentos-inbound.service, which %s starts, is %s in the check's container, so what it does on "
                    "the box is unread; %s" % (U, load, g.WHY)])
        units = graph(SHIPPED)
        units["agentos-inbound.service"]["load"] = "masked"
        units["agentosd.service"] = dict(units["agentos-inbound.service"], load="not-found")  # not reached
        self.assertEqual(g.violations(units, set(), g.facts(graph(SHIPPED), ()), "257.13", FSTAB), [])
        for mode in g.JOB_MODES:
            with self.subTest(mode=mode):
                units = graph(SHIPPED)
                units["agentos-link.service"]["job_modes"] = [(m, "isolate" if m == mode else "replace")
                                                              for m in g.JOB_MODES]
                self.assertEqual(g.violations(units, set(), g.facts(graph(SHIPPED), ()), "257.13", FSTAB), [
                    "agentos-link.service, which %s starts, has %s=isolate, which stops every unit outside its "
                    "%s= target; %s" % (U, mode, mode[:-len("JobMode")], g.WHY)])

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

    def test_every_form_of_a_generator_failure_is_read(self):
        # systemd 257: exec-util.c do_execute and process-util.c wait_for_terminate_and_check.
        d = "/usr/lib/systemd/system-generators/"
        for line, name in ((d + "systemd-gpt-auto-generator failed with exit status 1.", "systemd-gpt-auto-generator"),
                           (d + "a-generator failed with exit status 3, ignoring.", "a-generator"),
                           (d + "a-generator terminated by signal SEGV.", "a-generator"),
                           (d + "a-generator failed due to unknown reason.", "a-generator"),
                           ("/etc/systemd/system-generators/agentos plant-generator failed with exit status 3.",
                            "agentos plant-generator"),
                           ("'/etc/systemd/system-generators/x' is marked world-writable, which is a security risk",
                            "'/etc/systemd/system-generators/x' is marked world-writable, which is a security risk")):
            with self.subTest(line=line):
                self.assertEqual(offline_systemd.generator_failures("Detected architecture x86-64.\n%s\r\n"
                                                                    "Reached target sockets.target.\n" % line),
                                 {name})
        self.assertEqual(offline_systemd.generator_failures("Startup finished in 128ms.\n"), set())

    def test_failed_generators_drains_the_console_and_counts_a_timeout(self):
        master, slave = os.openpty()
        with tempfile.NamedTemporaryFile() as log:
            m = offline_systemd.Manager.__new__(offline_systemd.Manager)
            m.log, m.master, m.lock = log, master, __import__("threading").Lock()
            times = {}
            m.manager = lambda props: dict(times)
            os.write(slave, b"/etc/systemd/system-generators/g terminated by signal KILL.\n")
            for start, finish, want in ((5, 6, set()), (5, 5 + 79, set()),
                                        (5, 5 + 80, {offline_systemd.GENERATOR_TIMEOUT}),
                                        (5, 0, {offline_systemd.GENERATOR_TIMEOUT})):
                with self.subTest(start=start, finish=finish):
                    times.update(GeneratorsStartTimestampMonotonic=str(start * 1000000),
                                 GeneratorsFinishTimestampMonotonic=str(finish * 1000000))
                    self.assertEqual(m.failed_generators(), {"g"} | want)
        os.close(master)
        os.close(slave)

    def test_the_reader_is_not_starved_by_a_live_drain_thread(self):
        # Security 6596357788: the drain held the lock across its select, and Python 3.12's unfair lock let
        # it starve failed_generators() and stop().
        import threading
        import time
        master, slave = os.openpty()
        with tempfile.NamedTemporaryFile() as log:
            m = offline_systemd.Manager.__new__(offline_systemd.Manager)
            m.log, m.master, m.lock = log, master, threading.Lock()
            m.manager = lambda props: {"GeneratorsStartTimestampMonotonic": "1",
                                       "GeneratorsFinishTimestampMonotonic": "2"}
            drain = threading.Thread(target=m._drain, daemon=True)
            drain.start()
            seen = []

            def read():  # in a thread, so a starved reader fails the test instead of hanging it
                for i in range(20):
                    os.write(slave, b"/etc/systemd/system-generators/g%d failed with exit status 1.\n" % i)
                    end = time.monotonic() + 5  # the pty hands bytes to its reader asynchronously
                    while "g%d" % i not in m.failed_generators() and time.monotonic() < end:
                        time.sleep(0.01)
                    seen.append("g%d" % i in m.failed_generators())
            reader = threading.Thread(target=read, daemon=True)
            reader.start()
            reader.join(60)
            self.assertFalse(reader.is_alive(), "failed_generators() waited a minute for the drain thread's lock")
            self.assertEqual(seen, [True] * 20)
            os.close(slave)
            with m.lock:
                os.close(master)
                m.master = -1
            drain.join(5)
            self.assertFalse(drain.is_alive())


class AllowFileTest(unittest.TestCase):
    def test_the_shipped_list_reads_and_holds_the_unlock_unit(self):
        allowed = g.read_allow()
        self.assertTrue(g.ALLOW.read_text().startswith(g.ALLOW_HEADER))
        self.assertIn("start " + U, allowed)
        self.assertFalse({"start " + s for s in g.SHUTDOWN} & allowed)
        for line in allowed:
            self.assertRegex(line, r"^(start \S+|stop \S+ (%s) \S+|generator \S+ failed)$" % "|".join(g.STOP_KINDS))

    def test_each_control_is_a_path_a_review_found(self):
        self.assertEqual(len(g.CONTROLS), 5)
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
            # As the built root partition: no /usr (it is its own partition), /proc, /sys, /dev, /run or /tmp.
            for sub in ("var/tmp", "etc/systemd"):
                (root / sub).mkdir(parents=True)
            for n in ("bin", "lib", "lib64", "sbin"):
                (root / n).symlink_to("usr/" + n)
            shutil.copytree(ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/system", root / "etc/systemd/system",
                            symlinks=True)
            shutil.copy(ROOT / "image/mkosi/mkosi.extra/etc/fstab", root / "etc/fstab")
            (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
            if not pathlib.Path("/usr/lib/systemd/system/tmp.mount").exists():  # Ubuntu drops it; Debian ships it
                (root / "etc/systemd/system/tmp.mount").write_text("[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\n")
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
            for script, name in (("exit 3", "agentos-plant-generator"), ("kill -SEGV $$", "agentos-plant-generator"),
                                 ("exit 3", "agentos plant-generator")):
                with self.subTest(script=script, name=name), tempfile.TemporaryDirectory() as p:
                    g.plant_tree(root, {"etc/systemd/system-generators/" + name: "#!/bin/sh\n%s\n" % script,
                                        # the manager's own log level holds whatever the tree or command line asks
                                        "etc/systemd/system.conf.d/99-plant.conf": "[Manager]\nLogLevel=crit\n"}, p)
                    _, generators, v = g.run(root, "/usr", "ro quiet systemd.log_level=crit", base, p, major=major)
                    self.assertEqual(generators, {name})
                    self.assertIn("generator %s failed: not on unlock.allow; review it and add the line there" % name, v)
            # The manager cannot reach the runner's hostname or global sysctls (Security 6593364293 1).
            m = offline_systemd.Manager(root, "/usr", "ro quiet")
            try:
                for ns in ("uts", "ipc", "net", "pid", "mnt", "cgroup"):
                    self.assertNotEqual(os.readlink("/proc/%d/ns/%s" % (m.pid, ns)), os.readlink("/proc/self/ns/" + ns))
                mounts = pathlib.Path("/proc/%d/mountinfo" % m.pid).read_text().split("\n")
                self.assertIn("ro", [l for l in mounts if l.split()[4:5] == ["/proc/sys"]][-1].split()[5].split(","))
                self.assertIn("nodev", [l for l in mounts if l.split()[4:5] == ["/dev"]][-1].split()[5].split(","))
            finally:
                m.stop()

if __name__ == "__main__":
    unittest.main()
