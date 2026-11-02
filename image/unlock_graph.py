#!/usr/bin/env python3
"""What starting the unlock step can start, as the built image's own systemd computes it (#4667).

The unlock unit (agentos-keeper-kernel.service) has one reboot, ExecStopPost=KERNEL_REBOOT (#2897,
#2998). This checks that nothing it starts, directly or through any unit those start, can start a
shutdown unit, ask for a reboot or stop other units outside a reviewed list. Rather than modelling how
systemd reads units (aliases, drop-ins, every section's keys, implicit and default dependencies, units
that generators write from etc/fstab or the kernel command line), it asks systemd. It runs the image's
own /usr/lib/systemd/systemd in test mode (`--test --system`, which loads every unit, runs the
generators and prints each loaded unit's dependencies) inside the built tree, with the boot entry's
kernel command line, and walks the dependencies it prints. Three rounds of review on #4696 each found
another way into a hand-written model; this has none to keep in step.

The walk starts at the unlock unit and follows every dependency that starts another unit
(START_KINDS). The units it reaches, and every dependency from them that stops another unit
(STOP_KINDS), must be exactly the lines of image/mkosi/unlock.allow, which `unlock_graph.py --allowlist`
prints for a built image. Whatever that list says, no unit reached may be a shutdown unit (SHUTDOWN)
or carry a failure, success or timeout action, systemd's run must succeed with no job dropped, and a
dependency kind this file does not know is refused, so a newer systemd fails closed.

Not modelled here, each a release row: what a reached unit's commands do (a reboot word in an Exec=
line, #4493's direction), units udev adds from SYSTEMD_WANTS (#4739) and units gpt-auto-generator
writes from the disk it boots on (#4738); in the build's tree that generator finds no disk and fails,
and the allowlist names it.

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
# Every dependency kind systemd 257 prints (unit_dependency_to_string), in three classes.
START_KINDS = {"Requires", "Requisite", "Wants", "BindsTo", "Upholds", "OnSuccess", "OnFailure", "Triggers"}
STOP_KINDS = {"Conflicts", "ConflictedBy", "PropagatesStopTo", "BoundBy", "ConsistsOf"}
OTHER_KINDS = {"PartOf", "RequiredBy", "RequisiteOf", "WantedBy", "UpheldBy", "OnSuccessOf", "OnFailureOf",
               "TriggeredBy", "PropagatesReloadTo", "ReloadPropagatedFrom", "StopPropagatedFrom",
               "JoinsNamespaceOf", "References", "ReferencedBy", "InSlice", "SliceOf", "Before", "After",
               "RequiresMountsFor", "WantsMountsFor"}
# Starting one of these ends the boot. Stopping one ends nothing, so stop edges to them are not listed
# (every unit with default dependencies conflicts with shutdown.target and umount.target).
SHUTDOWN = {"halt.target", "poweroff.target", "reboot.target", "kexec.target", "soft-reboot.target", "exit.target",
            "ctrl-alt-del.target", "shutdown.target", "final.target", "umount.target", "systemd-halt.service",
            "systemd-poweroff.service", "systemd-reboot.service", "systemd-kexec.service",
            "systemd-soft-reboot.service", "systemd-exit.service"}
WHY = "the unlock step's one reboot is ExecStopPost=KERNEL_REBOOT (#2897, #4667)"

ACTION_RE = re.compile(r"^[A-Za-z ]+ Action$")

def parse_dump(text):
    """{unit: {"edges": [(kind, target)], "actions": [(name, value)], "unknown": [kind]}} from systemd's
    test-mode dump (offline_systemd.units): a dependency of a kind not in START_KINDS, STOP_KINDS or
    OTHER_KINDS goes under "unknown"."""
    out = {}
    for name, u in offline_systemd.units(text).items():
        known = START_KINDS | STOP_KINDS | OTHER_KINDS
        out[name] = {"edges": [(k, t) for k, t in u["edges"] if k in known],
                     "unknown": [k for k, _ in u["edges"] if k not in known],
                     "actions": [(k, v) for k, v in u["settings"] if ACTION_RE.match(k) and " " not in v]}
    return out


def systemd_test(root, usr, cmdline, plant="", unit=UNIT):
    """offline_systemd.run for the unlock unit."""
    return offline_systemd.run(root, usr, cmdline, unit, plant)


def reached(units, start=UNIT):
    """The units START reaches through START_KINDS, START included, in systemd's own dependency lists. A
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


def facts(units, stderr, start=UNIT):
    """The allowlist's lines for one run: "start U" for each unit reached, "stop U KIND T" for each stop
    dependency from one of them to a unit outside SHUTDOWN, and "generator G failed" for each generator
    that failed."""
    got = reached(units, start)
    out = {"start " + u for u in got}
    for u in got - SHUTDOWN:
        out |= {"stop %s %s %s" % (u, k, t) for k, t in units.get(u, {}).get("edges", ())
                if k in STOP_KINDS and t not in SHUTDOWN}
    for line in stderr.split("\n"):
        name = offline_systemd.failed_generator(line)
        if name:
            out.add("generator %s failed" % name)
    return out


def violations(status, stdout, stderr, allowed, start=UNIT):
    """Each refusal for one run of systemd_test against the ALLOWED lines."""
    out = []
    if status != 0:
        out.append("systemd's test run for %s exited %d: %s" % (start, status, stderr.strip()[-500:]))
    if "-> By units:" not in stdout:
        out.append("systemd's test run printed no unit list, so nothing it starts is known; %s" % WHY)
        return out
    for line in stderr.split("\n"):
        if "deleted to break ordering cycle" in line or "unmergeable" in line:
            out.append("systemd dropped a job from the unlock step's transaction (%s); %s" % (line.strip(), WHY))
    try:
        units = parse_dump(stdout)
    except ValueError as e:
        return out + ["%s; %s" % (e, WHY)]
    if start not in units:
        out.append("%s is not among the units systemd loaded; %s" % (start, WHY))
    got = reached(units, start)
    for u in sorted(got):
        for kind in sorted(set(units[u]["unknown"])) if u in units else ():
            out.append("%s: dependency kind %s is not one this check knows, so where it leads is unread; %s"
                       % (u, kind, WHY))
        if u in SHUTDOWN:
            out.append("%s starts %s; %s" % (start, u, WHY))
        for name, value in units.get(u, {}).get("actions", ()):
            if value != "none":
                out.append("%s, which %s starts, has %s %s; %s" % (u, start, name, value, WHY))
    have = facts(units, stderr, start)
    out += ["%s: not on %s; review it and add the line there" % (f, ALLOW.name) for f in sorted(have - allowed)]
    out += ["%s: on %s but no longer in the graph; remove the line" % (f, ALLOW.name) for f in sorted(allowed - have)]
    return out


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
        if mode == "--control":
            # A plant counts only by the refusals it adds to the unplanted tree's, so a stale allowlist
            # cannot make a blind check look sighted.
            allowed, blind = read_allow(), []
            base = set(violations(*systemd_test(root, usr, cmdline), allowed))
            for name, plant in CONTROLS.items():
                with tempfile.TemporaryDirectory() as p:
                    plant_tree(root, plant, p)
                    v = [l for l in violations(*systemd_test(root, usr, cmdline, p), allowed) if l not in base]
                print("unlock graph control: %s: %d refusal(s) added" % (name, len(v)))
                for line in v:
                    print("  " + line)
                if not v:
                    blind.append(name)
            if blind:
                sys.exit("unlock graph: the check passed planted paths, so a pass means nothing: %s" % "; ".join(blind))
            return
        status, stdout, stderr = systemd_test(root, usr, cmdline)
        if mode == "--allowlist":
            if status != 0 or "-> By units:" not in stdout:
                sys.exit("unlock graph: systemd's test run failed (%d): %s" % (status, stderr[-2000:]))
            sys.stdout.write(ALLOW_HEADER + "".join(l + "\n" for l in sorted(facts(parse_dump(stdout), stderr))))
            return
        v = violations(status, stdout, stderr, read_allow())
        for line in v:
            print("unlock graph: " + line)
        if v:
            sys.exit("unlock graph: %d problem(s), each named above; %s" % (len(v), WHY))
        print("unlock graph: clean (%d units reached)" % len(reached(parse_dump(stdout))))
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
