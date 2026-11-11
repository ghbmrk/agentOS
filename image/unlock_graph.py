#!/usr/bin/env python3
"""What starting the unlock step can start, as the built image's own systemd computes it (#4667).

The unlock unit (agentos-keeper-kernel.service) has one reboot, ExecStopPost=KERNEL_REBOOT (#2897,
#2998). This checks that nothing it starts, directly or through any unit those start, can start a
shutdown unit, ask for a reboot or stop other units outside a reviewed list. It does not model how
systemd reads units (aliases, drop-ins, every section's keys, implicit and default dependencies, units
that generators write from etc/fstab or the kernel command line). It asks systemd instead: the image's
own systemd runs over the built tree with the boot entry's command line (offline_systemd.Manager), and
this asks it, unit by unit, for each dependency list and action. Each of those values is a list of unit
names or an enum, so no unit's text can pose as systemd's answer. Three rounds of review on #4696 each
found another way into a hand-written model. This one has no model to keep in step.

The walk starts at the unlock unit, which the step both starts and stops (its stop is the reboot), and
follows every dependency that starts another unit (START_KINDS); it lists every dependency from those that
stops another unit (STOP_KINDS). Starting a unit stops what it conflicts with (STOP_ON_START), so from each
stopped unit it follows the kinds that carry the stop on (PROPAGATE_STOP) and the units a stop can start
(STOP_STARTS: OnFailure= when ExecStop fails, OnSuccess= on a clean stop). A stopped unit is started again
by the units that trigger or uphold it (RESTART_KINDS), and a started service whose Restart= is not "no"
stops on its way back unless its RestartMode= is "direct" (restarts()). All of it runs to a fixed point
(closure()) (#4919). Each edge it takes, the unlock unit as the root and the generators that failed must
be exactly the lines of
image/mkosi/unlock.allow, which `unlock_graph.py --allowlist` prints for a built image, so a new path
onto a unit already listed is a new line for review (#4822). Whatever that list says, none of these may
happen: a unit started is a shutdown unit (SHUTDOWN); a unit started or stopped carries a failure,
success, start limit or timeout action, or isolates on failure or success (#4823); the manager is not
the systemd major the kinds were read from (SYSTEMD_MAJOR, so a new dependency kind cannot go unread);
the tree's etc/fstab names a device, which fstab-generator skips in the manager's container mode.

Not modelled here, each a release row: what a reached unit's commands do (a reboot word in an Exec=
line, #4766), units udev adds from SYSTEMD_WANTS (#4739), and units gpt-auto-generator writes from the
disk it boots on (#4738). A generator that fails in the check's container is named on the allowlist; the
manager's console, a pty, is where systemd says so.

Usage (as root): unlock_graph.py OUT VERSION checks build OUT; --allowlist OUT VERSION prints the
list; --control OUT VERSION requires that each planted path (CONTROLS) adds its own refusal."""
import os
import pathlib
import re
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import offline_systemd  # noqa: E402

UNIT = "agentos-keeper-kernel.service"
ALLOW = HERE / "mkosi" / "unlock.allow"
# The dependency kinds of systemd 257 (unit_dependency_to_string) that act on another unit, by the
# property systemctl shows for each: those that start it and those that stop it. The rest only order,
# reference or mirror these. SYSTEMD_MAJOR pins the version they were read from.
START_KINDS = ("Requires", "Requisite", "Wants", "BindsTo", "Upholds", "OnSuccess", "OnFailure", "Triggers")
STOP_KINDS = ("Conflicts", "ConflictedBy", "PropagatesStopTo", "BoundBy", "RequiredBy", "RequisiteOf", "ConsistsOf")
# When a unit stops, these of its kinds stop the other unit too (UNIT_ATOM_PROPAGATE_STOP and
# PROPAGATE_STOP_GRACEFUL in systemd 257); Conflicts= acts only when a unit starts. STOP_STARTS start the
# other unit when this one stops: OnSuccess= on a clean stop, OnFailure= when it stops failed (#4823).
# STOP_ON_START are the kinds by which starting a unit stops another. The other STOP_KINDS act when the
# unit itself stops, so they are walked only from a unit that stops: one stopped by these kinds, the unlock
# unit itself, and a started service that restarts (restarts()). From any other started unit they are listed
# one hop out: every unit it requires is required by most of the system (system.slice, sysinit.target).
PROPAGATE_STOP = ("PropagatesStopTo", "BoundBy", "RequiredBy", "RequisiteOf", "ConsistsOf")
STOP_ON_START = ("Conflicts", "ConflictedBy")
STOP_STARTS = ("OnSuccess", "OnFailure")
# A stopped unit is started again by the units in these lists: a trigger's next event (TriggeredBy=) and an
# upholding unit (UpheldBy=) while it stays up. Whether those are themselves stopped first is not read, so
# each counts (#4919).
RESTART_KINDS = ("TriggeredBy", "UpheldBy")
# A service's Restart= and RestartMode= (systemctl shows them for services only). Under RestartMode=normal,
# systemd 257's default, an automatic restart passes through the inactive or failed state, so the units that
# Requires=/BindsTo= the service stop and its OnSuccess=/OnFailure= run; RestartMode=direct skips that state.
RESTART = ("Restart", "RestartMode")
ACTIONS = ("FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction")
JOB_MODES = ("OnFailureJobMode", "OnSuccessJobMode")  # isolate stops every unit outside the target
PROPS = START_KINDS + STOP_KINDS + RESTART_KINDS + ACTIONS + JOB_MODES + ("LoadState",)
# A reached unit must load as it would on the box: a not-found unit may be a name whose specifier took the
# runner's value here (%H, %v, %m). Masked units load nowhere.
LOADED = ("loaded", "masked")
SYSTEMD_MAJOR = "257"
# Starting one of these ends the boot. Stopping one ends nothing, so stop edges to them are not listed
# (every unit with default dependencies conflicts with shutdown.target and umount.target).
SHUTDOWN = {"halt.target", "poweroff.target", "reboot.target", "kexec.target", "soft-reboot.target", "exit.target",
            "ctrl-alt-del.target", "shutdown.target", "final.target", "umount.target", "systemd-halt.service",
            "systemd-poweroff.service", "systemd-reboot.service", "systemd-kexec.service",
            "systemd-soft-reboot.service", "systemd-exit.service"}
WHY = "the unlock step's one reboot is ExecStopPost=KERNEL_REBOOT (#2897, #4667)"

def graph(manager, start=UNIT):
    """{unit: {"edges": [(kind, target)], "actions": [(name, value)], "load": LoadState, "job_modes":
    [(name, value)], "restart": (Restart, RestartMode) or None}} for START and every unit closure() reaches
    from it, as MANAGER's systemd shows them. Restart is None for a unit that is not a service."""
    units = {}
    while True:
        started, stopped, _ = closure(units, start)
        batch = sorted((started | stopped) - set(units))
        if not batch:
            return units
        services = manager.show([n for n in batch if n.endswith(".service")], RESTART)
        for name, p in manager.show(batch, PROPS).items():
            units[name] = {"edges": [(k, t) for k in START_KINDS + STOP_KINDS + RESTART_KINDS
                                     for t in unit_names(name, k, p[k])],
                           "actions": [(k, p[k]) for k in ACTIONS], "load": p["LoadState"],
                           "job_modes": [(k, p[k]) for k in JOB_MODES],
                           "restart": tuple(services[name][k] for k in RESTART) if name in services else None}


def restarts(unit):
    """Whether UNIT (a graph() entry) is a service whose automatic restart stops it on the way back: Restart=
    is not "no" and RestartMode= is not "direct". Each is an enum, so any other value counts."""
    r = unit.get("restart")
    return bool(r) and r[0] != "no" and r[1] != "direct"


UNIT_NAME = re.compile(r"[A-Za-z0-9:_.\\@-]+\.(service|socket|target|device|mount|automount|swap|timer|path|slice|scope)\Z")


def unit_names(unit, kind, value):
    """The unit names systemctl shows in UNIT's KIND list VALUE (offline_systemd.shell_words); anything that
    is not a valid unit name is refused."""
    names = offline_systemd.shell_words(value, unit)
    for n in names:
        if not UNIT_NAME.match(n):
            raise SystemExit("unlock graph: %s: %s= names %r, which is not a unit name" % (unit, kind, n))
    return names


def fstab_devices(text):
    """The etc/fstab lines (TEXT) that name a device, which fstab-generator skips when systemd runs in a
    container: a path, or a LABEL=, UUID=, PARTUUID= or PARTLABEL= tag. The image's fstab names none."""
    out = []
    for line in text.split("\n"):
        words = line.split()
        if words and not words[0].startswith("#") and (words[0].startswith("/") or "=" in words[0]):
            out.append(line.strip())
    return out


def closure(units, start=UNIT):
    """(started, stopped, edges) for START in UNITS (graph()): the units the unlock step can start, START
    included; the units it can stop, START included (its stop is the reboot); and each edge taken, as an
    allowlist line. A started unit's START_KINDS start the other unit ("start T KIND from U"); its STOP_KINDS
    are listed ("stop U KIND T") and its STOP_ON_START stop the other unit; a started service that restarts()
    is stopped too ("restart U Restart VALUE"). A stopped unit's PROPAGATE_STOP stop the other unit, its
    STOP_STARTS start it, and its RESTART_KINDS start it again ("restart U KIND T"). A shutdown unit is started
    but not walked past (it is refused where it is started), and stopping one is not followed or listed: every
    unit with default dependencies conflicts with shutdown.target and umount.target, and none is active."""
    started, stopped, edges, todo = set(), set(), {"start " + start}, [(False, start), (True, start)]
    while todo:
        up, u = todo.pop()
        if u in (started if up else stopped):
            continue
        (started if up else stopped).add(u)
        if u in SHUTDOWN:
            continue
        unit = units.get(u, {})
        if up and restarts(unit):
            edges.add("restart %s Restart %s" % (u, unit["restart"][0]))
            todo.append((False, u))
        for k, t in unit.get("edges", ()):
            if k in (START_KINDS if up else STOP_STARTS):
                edges.add("start %s %s from %s" % (t, k, u))
                todo.append((True, t))
            elif k in (STOP_KINDS if up else PROPAGATE_STOP) and t not in SHUTDOWN:
                edges.add("stop %s %s %s" % (u, k, t))
                if k in (STOP_ON_START if up else PROPAGATE_STOP):
                    todo.append((False, t))
            elif not up and k in RESTART_KINDS:
                edges.add("restart %s %s %s" % (u, k, t))
                todo.append((True, u))
    return started, stopped, edges


def reached(units, start=UNIT):
    """The units starting START can start, START included, in UNITS (graph())."""
    return closure(units, start)[0]


def facts(units, generators, start=UNIT):
    """The allowlist's lines for one run: "start START" as the root, each edge closure() takes ("start T
    KIND from U", "stop U KIND T", "restart U KIND T") and "generator G failed" for each of GENERATORS."""
    return closure(units, start)[2] | {"generator %s failed" % g for g in generators}


def violations(units, generators, allowed, version, fstab, start=UNIT, major=SYSTEMD_MAJOR):
    """Each refusal for one run: UNITS as graph() gives them, the failed GENERATORS, the ALLOWED lines, the
    manager's VERSION and the tree's etc/fstab text FSTAB (None when it is a link)."""
    out = []
    if version.split(".")[0] != major:
        out.append("the image's systemd is %s, but the dependency kinds this check follows were read from "
                   "systemd %s; read them again for this version; %s" % (version, major, WHY))
    if fstab is None:
        out.append("etc/fstab is a link, so what it holds is unread here; %s" % WHY)
    out += ["etc/fstab: %s names a device, which systemd in the check's container skips, so what it pulls is "
            "unread; %s" % (l, WHY) for l in fstab_devices(fstab or "")]
    if start not in units:
        out.append("%s is not among the units systemd loaded; %s" % (start, WHY))
    started, stopped, _ = closure(units, start)
    for u in sorted(started | stopped):
        verb = "starts" if u in started else "stops"
        if u in SHUTDOWN:
            if u in started:
                out.append("%s starts %s; %s" % (start, u, WHY))
            continue
        if u not in units:
            continue
        for name, value in units[u]["actions"]:
            if value != "none":
                out.append("%s, which %s %s, has %s=%s; %s" % (u, start, verb, name, value, WHY))
        # A unit only stopped need not load: one not found on the box is not running there either.
        if u in started and units[u]["load"] not in LOADED:
            out.append("%s, which %s starts, is %s in the check's container, so what it does on the box is unread; "
                       "%s" % (u, start, units[u]["load"], WHY))
        for name, value in units[u]["job_modes"]:
            if value == "isolate":
                out.append("%s, which %s %s, has %s=isolate, which stops every unit outside its %s= target; %s"
                           % (u, start, verb, name, name[:-len("JobMode")], WHY))
    have = facts(units, generators, start)
    out += ["%s: not on %s; review it and add the line there" % (f, ALLOW.name) for f in sorted(have - allowed)]
    out += ["%s: on %s but no longer in the graph; remove the line" % (f, ALLOW.name) for f in sorted(allowed - have)]
    return out


def run(root, usr, cmdline, allowed, plant="", major=SYSTEMD_MAJOR):
    """violations() for the tree at ROOT, with PLANT over it, under its own systemd."""
    m = offline_systemd.Manager(root, usr, cmdline, plant)
    try:
        version = m.manager(("Version",))["Version"]
        f = pathlib.Path(m.view_root, "etc/fstab")
        if f.is_symlink():  # a link would be followed from the runner's root, not the tree's
            fstab = None
        else:
            try:
                fstab = f.read_text()
            except FileNotFoundError:
                fstab = ""
        units = graph(m)
        generators = m.failed_generators()
        return units, generators, violations(units, generators, allowed, version, fstab, major=major)
    finally:
        m.stop()


def read_allow(path=ALLOW):
    """The allowlist's lines: blank lines and # comments are skipped."""
    return {l.strip() for l in path.read_text().split("\n") if l.strip() and not l.lstrip().startswith("#")}


# Each plant opens a path a reviewer found into the hand-written model on #4696; the check must refuse
# every one on the built image with the refusal named first (#4824). Paths are relative to the tree;
# FSTAB is appended to its etc/fstab.
FSTAB = "FSTAB"
NOT_LISTED = ": not on %s; review it and add the line there" % ALLOW.name
CONTROLS = {
    "fstab x-systemd.requires= on a mount the unlock step pulls (Security 6587814928)": (
        "%s starts reboot.target; %s" % (UNIT, WHY),
        {FSTAB: "tmpfs /var/tmp tmpfs nosuid,nodev,noexec,x-systemd.requires=reboot.target 0 0\n"}),
    "[Service] Sockets= on a unit the unlock step starts (Security 6587168736)": (
        "start agentos-plant.socket Wants from agentos-link.service" + NOT_LISTED,
        {"etc/systemd/system/agentos-link.service.d/99-plant.conf": "[Service]\nSockets=agentos-plant.socket\n",
         "etc/systemd/system/agentos-plant.socket":
             "[Unit]\nWants=reboot.target\n[Socket]\nListenStream=/run/agentos-plant\n"}),
    "an alias's drop-in on the unlock unit (Security 6586674844)": (
        "start agentos-plant.service BindsTo from %s%s" % (UNIT, NOT_LISTED),
        {"etc/systemd/system/agentos-keeper-.service.d/99-plant.conf": "[Unit]\nBindTo=agentos-plant.service\n",
         "etc/systemd/system/agentos-plant.service": "[Service]\nExecStart=/bin/true\n"}),
    "a generator that writes a unit and fails (L3 6593296481 1)": (
        "generator agentos-plant-generator failed" + NOT_LISTED,
        {"etc/systemd/system-generators/agentos-plant-generator":
             "#!/bin/sh\necho '[Unit]' >\"$1/agentos-plant.target\"\nexit 3\n"}),
    "a generator killed by a signal (L3 6595128762 1)": (
        "generator agentos-plant-generator failed" + NOT_LISTED,
        {"etc/systemd/system-generators/agentos-plant-generator": "#!/bin/sh\nkill -SEGV $$\n"}),
    # #4919: three ways the unlock step stops a unit that the walk once missed. Each planted unit is loaded
    # the way a shipped one would be, from a target the box starts, not from the unlock unit. The third's
    # units have no default dependencies, so the stop of sysinit.target that the emergency cascade reaches
    # does not stand in for the restart's own. On the built image the first is also reached through that cascade; the unit test
    # test_the_unlock_units_own_stop_is_walked holds the root's own stop without it.
    "PartOf= the unlock unit with SuccessAction=reboot (#4894 Security 6604961676 1, L3 6605070833 3)": (
        "agentos-plant.service, which %s stops, has SuccessAction=reboot; %s" % (UNIT, WHY),
        {"etc/systemd/system/agentos-plant.service":
             "[Unit]\nPartOf=%s\nSuccessAction=reboot\n[Service]\nExecStart=/bin/true\n" % UNIT,
         "etc/systemd/system/multi-user.target.d/99-plant.conf": "[Unit]\nWants=agentos-plant.service\n"}),
    "a unit the unlock unit's stop stops, started again by its socket (#4894 L3 6605070833 3)": (
        "%s starts reboot.target; %s" % (UNIT, WHY),
        {"etc/systemd/system/agentos-plant.service":
             "[Unit]\nPartOf=%s\nWants=reboot.target\n[Service]\nExecStart=/bin/true\n" % UNIT,
         "etc/systemd/system/agentos-plant.socket": "[Socket]\nListenStream=/run/agentos-plant\n",
         "etc/systemd/system/sockets.target.d/99-plant.conf": "[Unit]\nWants=agentos-plant.socket\n"}),
    "a service the unlock step starts with Restart=, required by one with SuccessAction=reboot (#4894 L3 "
    "6605070833 3)": (
        "agentos-plant-b.service, which %s stops, has SuccessAction=reboot; %s" % (UNIT, WHY),
        {"etc/systemd/system/%s.d/99-plant.conf" % UNIT: "[Unit]\nWants=agentos-plant.service\n",
         "etc/systemd/system/agentos-plant.service":
             "[Unit]\nDefaultDependencies=no\n[Service]\nExecStart=/bin/true\nRestart=always\n",
         "etc/systemd/system/agentos-plant-b.service": "[Unit]\nDefaultDependencies=no\nRequires=agentos-plant.service\n"
                                                       "SuccessAction=reboot\n[Service]\nExecStart=/bin/true\n",
         "etc/systemd/system/multi-user.target.d/99-plant.conf": "[Unit]\nWants=agentos-plant-b.service\n"}),
}


def control(base, planted, expect):
    """(added, seen) for one control: the refusals PLANTED adds to the unplanted run's BASE, and whether
    EXPECT, the refusal the plant exists to raise, is among them. Only added lines count, so a stale
    allowlist cannot make a blind check look sighted; and only the expected one, so a plant refused for
    another reason does not stand in for its own (#4824)."""
    base = set(base)
    added = [l for l in planted if l not in base]
    return added, expect in added


def controls(base, refusals, cases=None):
    """(report, blind) for --control: REFUSALS(plant) is the check's refusals with PLANT over the tree, BASE
    the unplanted run's; REPORT is the lines to print and BLIND the names of the CASES (CONTROLS) whose own
    refusal was not added. A non-empty BLIND fails the build."""
    report, blind = [], []
    for name, (expect, plant) in (CONTROLS if cases is None else cases).items():
        added, seen = control(base, refusals(plant), expect)
        report.append("unlock graph control: %s: %d refusal(s) added" % (name, len(added)))
        report += ["  " + l for l in added]
        if not seen:
            report.append("  missing: " + expect)
            blind.append(name)
    return report, blind


def plant_tree(root, plant, dst):
    """Write PLANT (a CONTROLS entry) under DST, to overlay ROOT. DST becomes the tree's root directory, so it
    gets the root's mode."""
    os.chmod(dst, 0o755)
    for rel, text in plant.items():
        if rel == FSTAB:
            rel = "etc/fstab"
            try:
                text = (pathlib.Path(root) / rel).read_text() + text
            except FileNotFoundError:
                pass
        p = pathlib.Path(dst) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        if p.parent.name.endswith("-generators"):
            p.chmod(0o755)


def main(argv):
    mode = argv[1] if argv[1:2] in (["--allowlist"], ["--control"]) else "check"
    args = argv[2:] if mode != "check" else argv[1:]
    if len(args) != 2 or os.geteuid() != 0:
        sys.exit(__doc__.rsplit("Usage", 1)[1].strip())
    root, usr, cmdline, cleanup = offline_systemd.built_tree(*args)
    try:
        allowed = read_allow()
        units, generators, v = run(root, usr, cmdline, allowed)
        if mode == "--control":
            # A plant counts only by the refusals it adds to the unplanted tree's, so a stale allowlist
            # cannot make a blind check look sighted.
            def refusals(plant):
                with tempfile.TemporaryDirectory() as p:
                    plant_tree(root, plant, p)
                    return run(root, usr, cmdline, allowed, p)[2]
            report, blind = controls(v, refusals)
            print("\n".join(report))
            if blind:
                sys.exit("unlock graph: the check passed planted paths, so a pass means nothing: %s" % "; ".join(blind))
            return
        if mode == "--allowlist":
            sys.stdout.write(ALLOW_HEADER + "".join(l + "\n" for l in sorted(facts(units, generators))))
            return
        for line in v:
            print("unlock graph: " + line)
        if v:
            sys.exit("unlock graph: %d problem(s), each named above; %s" % (len(v), WHY))
        print("unlock graph: clean (%d units reached)" % len(reached(units)))
    finally:
        cleanup()


ALLOW_HEADER = """# What the unlock step (agentos-keeper-kernel.service starting, then stopping) can start or stop, as
# the built image's own systemd computes it (image/unlock_graph.py, #4667). Each line is reviewed:
# "start T KIND from U" is an edge by which a unit the step starts or stops starts T, "stop U KIND T" one
# by which it stops T (#4822, #4823), "restart U KIND T" one by which a stopped U is started again
# (TriggeredBy, UpheldBy) or a started service U stops on its way back (Restart, T its value; #4919),
# "start agentos-keeper-kernel.service" the root, and "generator G failed" a generator that found nothing
# to read in the build's tree. Regenerate with, as root, after an image build:
#   python3 image/unlock_graph.py --allowlist OUT VERSION > image/mkosi/unlock.allow
"""

if __name__ == "__main__":
    main(sys.argv)
