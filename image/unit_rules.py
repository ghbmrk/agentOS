#!/usr/bin/env python3
"""The files each unit of a built tree loads, as the tree's own systemd reads them, for the unit-rule
lint (#4677, Mark's option A on #4698).

Which file is a unit's, which drop-ins apply and in what order, which name is an alias and which
file a link or a mask hides are systemd's to decide, and two review rounds on #4737 each found
another place a hand-written copy of its precedence went wrong. So this file decides none of it. It
plants a target that Wants= every unit name the tree's lookup directories hold (an instance for each
template, and each instance a drop-in directory or a .wants link names), runs the tree's own systemd
in test mode on it once (image/offline_systemd.py, shared with image/unlock_graph.py), and reads, for
every unit loaded, its "Unit Load State", "Fragment Path" and "DropIn Path" lines: the files systemd
applies, in its order, after every mask.

What it adds is attribution: whether a file's lines are a package's or ours. A file is a package's
only when it is byte-identical to one a package installed (dpkg's md5sums and conffiles, which
mkosi.postinst copies out), and no link of ours brings it in. A link is ours, because no package
database lists a link's target: a unit file, drop-in or drop-in directory reached through a link,
or a parent directory reached through one, is ours. One link is not: a unit-directory entry whose own
target (read once, its directories resolved) is another unit-directory entry is an alias, and keeps
that entry's provenance. The rules themselves, and what a package's lines may do, are
broker/kernel/privfile's (unitCheck.unit, builtUnits): this prints records, it judges nothing.

A drop-in of ours that a transient or generated unit may read is also printed alone, to be read as
a root unit's: one in a type-wide (service.d) or prefix (a-.service.d) directory, one in a directory
no loaded unit has a name of, and every one of a unit whose fragment a generator wrote (systemd's
temporary generator directory is gone when it exits, so that fragment's text is not read; its main
input, /etc/fstab, is printed whole).

Usage (as root): unit_rules.py OUT VERSION prints build OUT's records as JSON; --control OUT VERSION
prints them with CONTROL planted, which the lint must refuse; --fixture ROOT PACKAGED prints a fixture
tree's records under the runner's systemd, with ROOT/usr over the runner's /usr (its unit directories
hidden) and PACKAGED a file listing, one per line, the tree's files that count as a package's.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import offline_systemd  # noqa: E402

LINT = "agentos-unit-lint.target"
INSTANCE = "agentos-unit-lint"
# The system manager's unit directories (systemd path-lookup.c, v255 to v257), highest first. A
# directory missed here makes an alias into it read as a link of ours, which holds more, never less.
UNIT_DIRS = ("/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient",
             "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached",
             "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator",
             "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
             "/run/systemd/generator.late")
TYPES = (".service", ".socket", ".mount", ".swap", ".target", ".path", ".timer", ".slice", ".automount")
DEP_DIRS = (".wants", ".requires", ".upholds")
# systemd will not start a bad-setting or error unit, but its files are held as a loaded one's: stricter.
STATES = ("loaded", "bad-setting", "error", "masked", "not-found")
# A drop-in of ours on a packaged root unit: the lint must refuse it, or a pass of the built tree
# means nothing (#4677 Security R-1's shape).
CONTROL = {"etc/systemd/system/systemd-journald.service.d/zz-agentos-unit-control.conf":
           "[Service]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n"}
CONTROL_WANT = 'variable "LD_PRELOAD"'


class View:
    """The tree as systemd in the namespace sees it: ROOT, with USR as /usr. Every path is absolute in
    the tree, and links resolve in it, never on the runner."""

    def __init__(self, root, usr):
        self.root, self.usr = str(root), str(usr)

    def host(self, p):
        if p == "/usr" or p.startswith("/usr/"):
            return self.usr + p[4:]
        return self.root + p

    def lstat(self, p):
        try:
            return os.lstat(self.host(p))
        except FileNotFoundError:
            return None

    def resolve(self, p, last=True):
        """(p resolved in the tree, [each link followed]). A link's target, absolute or not, is read in
        the tree, and .. stops at its root; from the first missing component on, p is kept as given.
        With last False, p's own last component is not followed."""
        links, done, rest = [], "/", [c for c in p.split("/") if c]
        while rest:
            c = rest.pop(0)
            if c == ".":
                continue
            if c == "..":
                done = os.path.dirname(done)
                continue
            nxt = os.path.join(done, c)
            st = self.lstat(nxt)
            if st is None:
                return os.path.join(nxt, *rest), links
            if not (st.st_mode & 0o170000 == 0o120000) or (not last and not rest):
                done = nxt
                continue
            links.append(nxt)
            if len(links) > 40:
                raise SystemExit("unit rules: %s: more than 40 links" % p)
            t = os.readlink(self.host(nxt))
            if t.startswith("/"):
                done = "/"
            rest = [x for x in t.split("/") if x] + rest
        return done, links

    def entries(self, d):
        try:
            return sorted(os.listdir(self.host(d)))
        except (FileNotFoundError, NotADirectoryError):
            return []

    def isdir(self, p):
        st = self.lstat(p)
        return st is not None and st.st_mode & 0o170000 == 0o040000

    def text(self, p):
        fd = os.open(self.host(p), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            return f.read().decode("utf-8", "surrogateescape")


def unit_dirs(view):
    """Each unit directory as resolved in the tree, once, in UNIT_DIRS' order."""
    out = []
    for d in UNIT_DIRS:
        r, _ = view.resolve(d)
        if view.isdir(r) and r not in out:
            out.append(r)
    return out


def names(view, dirs):
    """Every unit name the tree's unit directories hold: each unit file's (an instance for a template),
    each instance a drop-in directory names, and each unit a .wants, .requires or .upholds link names."""
    out = set()

    def add(n):
        if not n.endswith(TYPES) or n == LINT:
            return
        base, ext = os.path.splitext(n)
        out.add(base + INSTANCE + ext if base.endswith("@") else n)
    for d in dirs:
        for e in view.entries(d):
            if e.endswith(".d"):
                add(e[:-2])
            elif e.endswith(DEP_DIRS):
                for w in view.entries(view.resolve(d + "/" + e)[0]):
                    add(w)
            else:
                add(e)
    return sorted(out)


def plant_lint(plant, wanted):
    """Write LINT, wanting each of WANTED by a .wants link (a link's name is read as given, never
    unescaped), into the plant directory."""
    d = pathlib.Path(plant) / "etc/systemd/system"
    (d / (LINT + ".wants")).mkdir(parents=True, exist_ok=True)
    (d / LINT).write_text("[Unit]\nDescription=agentOS unit-rule lint (#4677)\nDefaultDependencies=no\n")
    for n in wanted:
        (d / (LINT + ".wants") / n).symlink_to("/dev/null/" + n)


class Provenance:
    """Whether a file systemd names is ours: see the module's docstring."""

    def __init__(self, view, dirs, packaged):
        self.view, self.dirs, self.packaged = view, set(dirs), packaged
        self.linked = set()  # files a link of ours reaches
        for d in dirs:
            for e in view.entries(d):
                p = d + "/" + e
                if e.endswith(".d"):
                    for c in view.entries(view.resolve(p)[0]):
                        self.mark(p + "/" + c)
                elif e.endswith(TYPES):
                    self.mark(p)

    def alias_target(self, p):
        """The unit-directory entry p, a link, names, if p is an alias; else None."""
        if os.path.dirname(p) not in self.dirs:
            return None
        st = self.view.lstat(p)
        if st is None or st.st_mode & 0o170000 != 0o120000:
            return None
        t = os.readlink(self.view.host(p))
        t = t if t.startswith("/") else os.path.dirname(p) + "/" + t
        d, _ = self.view.resolve(os.path.dirname(os.path.normpath(t)))
        if d in self.dirs and os.path.basename(t).endswith(TYPES):
            return d + "/" + os.path.basename(t)
        return None

    def mark(self, p):
        final, links = self.view.resolve(p)
        if links and self.alias_target(p) is None and final != "/dev/null":
            self.linked.add(final)

    def ours(self, p, depth=0):
        t = self.alias_target(p)
        if t is not None:
            if depth > 40:
                raise SystemExit("unit rules: %s: more than 40 aliases" % p)
            return self.ours(t, depth + 1)
        final, links = self.view.resolve(p)
        return bool(links) or final in self.linked or not self.packaged(final)


def records(view, out, err, status, dirs, prov, planted):
    """The records of one run: {"units": [{"unit", "alone", "files": [{"path", "ours", "text"}]}],
    "fstab": {"path", "text"} or None}. A run that failed, a unit systemd could not load, or a planted
    name it neither loaded nor knows as an alias fails the lint."""
    if status != 0:
        raise SystemExit("unit rules: systemd's test run failed (%d): %s" % (status, err[-2000:]))
    try:
        units = offline_systemd.units(out)
    except ValueError as e:
        raise SystemExit("unit rules: %s" % e)
    known = set(units)
    for u in units.values():
        known |= {v for k, v in u["settings"] if k == "Alias"}
    missing = sorted(set(planted) - known)
    if missing or LINT not in units:
        raise SystemExit("unit rules: systemd's dump lacks %s: its layout may have changed" % (missing or [LINT]))
    recs, listed, own = [], set(), set()
    for name in sorted(units):
        s = units[name]["settings"]
        state = [v for k, v in s if k == "Unit Load State"]
        frag = [v for k, v in s if k == "Fragment Path"]
        drop = [v for k, v in s if k == "DropIn Path"]
        if name == LINT:
            continue
        if len(state) != 1 or state[0] not in STATES or len(frag) > 1:
            raise SystemExit("unit rules: %s: load state %s, fragments %s; systemd cannot load it, or its "
                             "dump's layout changed" % (name, state, frag))
        if state[0] != "not-found":  # a name no unit loads under: its drop-ins are read alone below
            own |= {n + ".d" for n in [name] + [v for k, v in s if k == "Alias"]}
        if state[0] == "masked":
            continue
        if state[0] != "not-found" and name in planted and not frag and not drop:
            raise SystemExit("unit rules: %s is loaded with no Fragment Path or DropIn Path: the dump's "
                             "layout may have changed" % name)
        listed |= set(drop)
        generated = bool(frag) and "/systemd-temporary-" in frag[0]
        # A drop-in linked to /dev/null masks its name: systemd lists it and reads nothing from it.
        drop = [p for p in drop if view.resolve(p)[0] != "/dev/null"]
        if frag and not generated:
            files = [{"path": p, "ours": prov.ours(p), "text": view.text(view.resolve(p)[0])} for p in frag + drop]
            recs.append({"unit": name, "alone": False, "files": files})
            continue
        for p in drop:  # a generated, transient or fragment-less unit: each drop-in of ours, as root
            if prov.ours(p):
                recs.append({"unit": name, "alone": True,
                             "files": [{"path": p, "ours": True, "text": view.text(view.resolve(p)[0])}]})
    for d in dirs:
        for e in view.entries(d):
            if not e.endswith(".d"):
                continue
            n = e[:-2]
            base, ext = os.path.splitext(n)
            if "." not in n:  # a type-wide directory, service.d: no unit has its name
                n, base, ext = "." + n, "", "." + n
            if e in own or base.endswith("@") and any(u.startswith(base) and u.endswith(ext) for u in units):
                continue  # systemd listed what of it applies to the unit of that name or template
            for c in view.entries(view.resolve(d + "/" + e)[0]):
                p = d + "/" + e + "/" + c
                final, _ = view.resolve(p)
                if c.endswith(".conf") and final != "/dev/null" and prov.ours(p) and view.lstat(final):
                    recs.append({"unit": n, "alone": True,
                                 "files": [{"path": p, "ours": True, "text": view.text(final)}]})
    fstab = None
    final, _ = view.resolve("/etc/fstab")
    if view.lstat(final) and prov.ours("/etc/fstab"):
        fstab = {"path": "/etc/fstab", "text": view.text(final)}
    return {"units": recs, "fstab": fstab}


def lint(root, usr, cmdline, packaged, plant_files=None):
    """Plant LINT (and PLANT_FILES) over the tree, run its systemd once and return its records."""
    view = View(root, usr)
    dirs = unit_dirs(view)
    wanted = names(view, dirs)
    with tempfile.TemporaryDirectory() as plant:
        plant_lint(plant, wanted)
        for p, text in (plant_files or {}).items():
            f = pathlib.Path(plant) / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        os.chmod(plant, 0o755)
        status, out, err = offline_systemd.run(root, usr, cmdline, LINT, plant)
        if plant_files:  # read the planted files as systemd did: over the tree
            view = Planted(view, plant)
            dirs = unit_dirs(view)
        prov = Provenance(view, dirs, packaged)
        return records(view, out, err, status, dirs, prov, wanted)


class Planted(View):
    """A view with the plant directory over the tree, as the run's overlay has it."""

    def __init__(self, view, plant):
        super().__init__(view.root, view.usr)
        self.plant = str(plant)

    def host(self, p):
        q = self.plant + p
        if os.path.lexists(q):
            return q
        return super().host(p)

    def entries(self, d):
        out = set(super().entries(d))
        try:
            out |= set(os.listdir(self.plant + d))
        except (FileNotFoundError, NotADirectoryError):
            pass
        return sorted(out)


def dpkg_packaged(view, out):
    """Whether a file of build OUT is byte-identical to one a package installed: dpkg's md5sums
    (mkosi.postinst's agentos.dpkg-md5sums) and the conffiles in its status file, each path read as
    resolved in the tree."""
    want = {}
    for line in (pathlib.Path(out) / "agentos.dpkg-md5sums").read_text().splitlines():
        md5, _, p = line.partition("  ")
        if md5 and p:
            want.setdefault(view.resolve("/" + p)[0], set()).add(md5)
    conf = False
    for line in (pathlib.Path(out) / "agentos.dpkg-status").read_text().splitlines():
        if line.startswith("Conffiles:"):
            conf = True
        elif conf and line.startswith(" "):
            f = line.split()
            if len(f) >= 2 and f[0].startswith("/"):
                want.setdefault(view.resolve(f[0])[0], set()).add(f[1])
        else:
            conf = False
    if not want:
        raise SystemExit("unit rules: no package's files listed in %s" % out)

    def packaged(p):
        if p not in want:
            return False
        st = view.lstat(p)
        if st is None or st.st_mode & 0o170000 != 0o100000:
            return False
        with open(view.host(p), "rb") as f:
            return hashlib.md5(f.read()).hexdigest() in want[p]
    return packaged


def fixture(root, packaged_list):
    """Records of a fixture tree under the runner's systemd: ROOT/usr overlaid on the runner's /usr, with
    the runner's own unit directories hidden, so only the fixture's units load."""
    root = pathlib.Path(root)
    for sub in ("usr/lib/systemd/system", "usr/local/lib/systemd/system", "proc", "sys", "dev", "run", "tmp",
                "var/tmp", "etc/systemd/system"):
        if not any(os.path.islink(root / sub.rsplit("/", i)[0]) for i in range(sub.count("/") + 1)):
            (root / sub).mkdir(parents=True, exist_ok=True)
    for n in ("bin", "lib", "lib64", "sbin"):
        if not os.path.lexists(root / n):
            (root / n).symlink_to("usr/" + n)
    if not (root / "etc/machine-id").exists():
        (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    for d in ("usr/lib/systemd/system", "usr/local/lib/systemd/system"):
        os.setxattr(root / d, "trusted.overlay.opaque", b"y", follow_symlinks=False)
    os.chmod(root, 0o755)
    listed = {l for l in pathlib.Path(packaged_list).read_text().splitlines() if l}
    with tempfile.TemporaryDirectory() as m:
        subprocess.run(["mount", "-t", "overlay", "-o", "ro,lowerdir=%s:/usr" % (root / "usr"), "overlay", m],
                       check=True)
        try:
            return lint(root, m, "ro quiet", lambda p: p in listed)
        finally:
            subprocess.run(["umount", m], check=False)


def main(argv):
    control = argv[:1] == ["--control"]
    if len(argv) == 3 and argv[0] == "--fixture":
        recs = fixture(argv[1], argv[2])
    elif len(argv) == 2 + control:
        out, version = argv[control:]
        root, usr, cmdline, cleanup = offline_systemd.built_tree(out, version)
        try:
            recs = lint(root, usr, cmdline, dpkg_packaged(View(root, usr), out), CONTROL if control else None)
        finally:
            cleanup()
        recs["want"] = CONTROL_WANT if control else ""
    else:
        sys.exit(__doc__)
    json.dump(recs, sys.stdout, indent=0, sort_keys=True)


if __name__ == "__main__":
    main(sys.argv[1:])
