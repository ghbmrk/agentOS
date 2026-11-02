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

The walk starts at the unlock unit and follows every dependency that starts another unit
(START_KINDS). The units it reaches, every dependency from them that stops another unit (STOP_KINDS),
and the generators that failed must be exactly the lines of image/mkosi/unlock.allow, which
`unlock_graph.py --allowlist` prints for a built image. Whatever that list says, none of these may
happen: a unit reached is a shutdown unit (SHUTDOWN); a unit reached carries a failure, success, start
limit or timeout action; the manager is not the systemd major the kinds were read from (SYSTEMD_MAJOR,
so a new dependency kind cannot go unread); the tree's etc/fstab names a device, which fstab-generator
skips in the manager's container mode.

Not modelled here, each a release row: what a reached unit's commands do (a reboot word in an Exec=
line, #4766), units udev adds from SYSTEMD_WANTS (#4739), and units gpt-auto-generator writes from the
disk it boots on (#4738). In the build's tree that generator finds no disk and fails, and the allowlist
names it.

Usage (as root): unlock_graph.py OUT VERSION checks build OUT; --allowlist OUT VERSION prints the
list; --control OUT VERSION requires that each planted path (CONTROLS) is refused."""
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
STOP_KINDS = ("Conflicts", "ConflictedBy", "PropagatesStopTo", "BoundBy", "ConsistsOf")
ACTIONS = ("FailureAction", "SuccessAction", "StartLimitAction", "JobTimeoutAction")
PROPS = START_KINDS + STOP_KINDS + ACTIONS + ("LoadState",)
SYSTEMD_MAJOR = "257"
# Starting one of these ends the boot. Stopping one ends nothing, so stop edges to them are not listed
# (every unit with default dependencies conflicts with shutdown.target and umount.target).
SHUTDOWN = {"halt.target", "poweroff.target", "reboot.target", "kexec.target", "soft-reboot.target", "exit.target",
            "ctrl-alt-del.target", "shutdown.target", "final.target", "umount.target", "systemd-halt.service",
            "systemd-poweroff.service", "systemd-reboot.service", "systemd-kexec.service",
            "systemd-soft-reboot.service", "systemd-exit.service"}
WHY = "the unlock step's one reboot is ExecStopPost=KERNEL_REBOOT (#2897, #4667)"

def graph(manager, start=UNIT):
    """{unit: {"edges": [(kind, target)], "actions": [(name, value)]}} for START and every unit it reaches,
    as MANAGER's systemd shows them. A shutdown unit is shown but not walked past."""
    units, todo = {}, [start]
    while todo:
        batch = sorted(set(todo) - set(units))
        todo = []
        for name, p in manager.show(batch, PROPS).items():
            units[name] = {"edges": [(k, t) for k in START_KINDS + STOP_KINDS for t in unit_names(name, k, p[k])],
                           "actions": [(k, p[k]) for k in ACTIONS]}
            if name not in SHUTDOWN:
                todo += [t for k, t in units[name]["edges"] if k in START_KINDS]
    return units


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


def reached(units, start=UNIT):
    """The units START reaches through START_KINDS, START included, in UNITS (graph()). A
    shutdown unit is reached but not walked past."""
    seen, todo = set(), [start]
    while todo:
        u = todo.pop()
        if u in seen:
            continue
        seen.add(u)
        if u not in SHUTDOWN:  # refused where it is reached; what it starts after that adds nothing
            todo += [t for k, t in units.get(u, {}).get("edges", ()) if k in START_KINDS]
    return seen


def facts(units, generators, start=UNIT):
    """The allowlist's lines for one run: "start U" for each unit reached, "stop U KIND T" for each stop
    dependency from one of them to a unit outside SHUTDOWN, and "generator G failed" for each of
    GENERATORS."""
    got = reached(units, start)
    out = {"start " + u for u in got}
    for u in got - SHUTDOWN:
        out |= {"stop %s %s %s" % (u, k, t) for k, t in units.get(u, {}).get("edges", ())
                if k in STOP_KINDS and t not in SHUTDOWN}
    return out | {"generator %s failed" % g for g in generators}


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
    for u in sorted(reached(units, start)):
        if u in SHUTDOWN:
            out.append("%s starts %s; %s" % (start, u, WHY))
            continue
        for name, value in units.get(u, {}).get("actions", ()):
            if value != "none":
                out.append("%s, which %s starts, has %s=%s; %s" % (u, start, name, value, WHY))
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
# every one on the built image. Paths are relative to the tree; FSTAB is appended to its etc/fstab.
FSTAB = "FSTAB"
CONTROLS = {
    "fstab x-systemd.requires= on a mount the unlock step pulls (Security 6587814928)": {
        FSTAB: "tmpfs /var/tmp tmpfs nosuid,nodev,noexec,x-systemd.requires=reboot.target 0 0\n"},
    "[Service] Sockets= on a unit the unlock step starts (Security 6587168736)": {
        "etc/systemd/system/agentos-link.service.d/99-plant.conf": "[Service]\nSockets=agentos-plant.socket\n",
        "etc/systemd/system/agentos-plant.socket": "[Unit]\nWants=reboot.target\n[Socket]\nListenStream=/run/agentos-plant\n"},
    "an alias's drop-in on the unlock unit (Security 6586674844)": {
        "etc/systemd/system/agentos-keeper-.service.d/99-plant.conf": "[Unit]\nBindTo=agentos-plant.service\n",
        "etc/systemd/system/agentos-plant.service": "[Service]\nExecStart=/bin/true\n"},
}


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
            base, blind = set(v), []
            for name, plant in CONTROLS.items():
                with tempfile.TemporaryDirectory() as p:
                    plant_tree(root, plant, p)
                    added = [l for l in run(root, usr, cmdline, allowed, p)[2] if l not in base]
                print("unlock graph control: %s: %d refusal(s) added" % (name, len(added)))
                for line in added:
                    print("  " + line)
                if not added:
                    blind.append(name)
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


ALLOW_HEADER = """# What starting agentos-keeper-kernel.service can start or stop, as the built image's own systemd
# computes it (image/unlock_graph.py, #4667). Each line is reviewed: "start U" is a unit the unlock
# step can start, "stop U KIND T" a unit one of those stops, "generator G failed" a generator that
# found nothing to read in the build's tree. Regenerate with, as root, after an image build:
#   python3 image/unlock_graph.py --allowlist OUT VERSION > image/mkosi/unlock.allow
"""

if __name__ == "__main__":
    main(sys.argv)
