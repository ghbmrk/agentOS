#!/usr/bin/env python3
"""The files each unit of a built tree loads, as the tree's own systemd reads them, for the unit-rule
lint (#4677, Mark's option A on #4698).

Which file is a unit's, which drop-ins apply and in what order, which name is an alias and which
file a link or a mask hides are systemd's to decide, and two review rounds on #4737 each found
another place a hand-written copy of its precedence went wrong. So this file decides none of it. It
boots the tree's own /usr/lib/systemd/systemd as PID 1 of a container namespace (MANAGER: its own
mount, PID, network and cgroup namespaces, over an overlay of the tree, starting nothing), so its generators run and their output stays readable. It then asks that manager, over
its private bus with the runner's own systemctl, for each unit name the tree's unit directories
hold: `systemctl show -p Id,Names,LoadState,FragmentPath,DropInPaths`. That is a structured reply
of one block per name, never a dump of unit values (#4779 Security 1: an Environment= value can
hold newlines). Unit names cannot hold a space or a control byte, and every name in a unit or
drop-in directory is held to SAFE first, so no path in the reply can either; each path is then
checked to be one the tree holds.

What it adds is attribution: whether a file's lines are a package's or ours. A file is a package's
only when it is byte-identical to one a package installed (dpkg's md5sums and conffiles, which
mkosi.postinst copies out), keyed by its path resolved through the merged-/usr top links alone,
and no link brings it in. A link is ours, because no package database lists a link's target: a
unit file, drop-in or drop-in directory reached through a link is ours. One link is not: a
unit-directory entry whose own target, resolved in the tree with its last component unfollowed, is
an entry of a unit directory is an alias, and keeps that entry's provenance. The rules themselves,
and what a package's lines may do, are broker/kernel/privfile's (unitCheck.unit, builtUnits): this
prints records, it judges nothing.

A drop-in of ours that a transient or later unit may read is also printed alone, to be read as a
root unit's: one in a type-wide (service.d) or prefix (a-.service.d) directory, and one in a
directory whose name no loaded unit, alias or loaded template instance has. /etc/fstab is printed
whole when it is ours; the units its generator writes are read like any other.

Usage (as root): unit_rules.py OUT VERSION prints build OUT's records as JSON; --control OUT VERSION
prints them with CONTROL planted, which the lint must refuse; --fixture ROOT PACKAGED prints a fixture
tree's records under the runner's systemd, with ROOT/usr over the runner's /usr (its unit directories
hidden) and PACKAGED a file listing, one per line, the tree's files that count as a package's.
"""
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import offline_systemd  # noqa: E402

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
# Every name in a unit directory, a drop-in directory or a dependency directory: the bytes a unit
# name may hold (unit-name.c) and a drop-in's. A name with any other byte (a space, a newline) could
# not be told apart in systemctl's reply, so the tree is refused.
SAFE = re.compile(r"[A-Za-z0-9:_.@\\+-]+\Z")
PROPS = ("Id", "Names", "LoadState", "FragmentPath", "DropInPaths")
# systemd will not start a bad-setting or error unit, but its files are held as a loaded one's: stricter.
STATES = ("loaded", "bad-setting", "error", "masked", "not-found")
# The top links of a merged /usr: the only links a dpkg path may be resolved through.
MERGED = {"/bin", "/sbin", "/lib", "/lib64"}
# A drop-in of ours on a packaged root unit: the lint must refuse it, or a pass of the built tree
# means nothing (#4677 Security R-1's shape).
CONTROL = {"etc/systemd/system/systemd-journald.service.d/zz-agentos-unit-control.conf":
           "[Service]\nEnvironment=LD_PRELOAD=/var/lib/agentos-x/x.so\n"}
CONTROL_WANT = 'variable "LD_PRELOAD"'


class View:
    """A tree at ROOT (optionally with USR as its /usr), every path absolute in the tree, links
    resolved in it, never on the runner."""

    def __init__(self, root, usr=None):
        self.root, self.usr = str(root), usr and str(usr)

    def host(self, p):
        if self.usr and (p == "/usr" or p.startswith("/usr/")):
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

    def kind(self, p):
        st = self.lstat(p)
        return st and st.st_mode & 0o170000

    def text(self, p):
        fd = os.open(self.host(p), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            return f.read().decode("utf-8", "surrogateescape")


def unit_dirs(view):
    """Each unit directory as resolved in the tree, once, in UNIT_DIRS' order."""
    out = []
    for d in UNIT_DIRS:
        r, _ = view.resolve(d)
        if view.kind(r) == 0o040000 and r not in out:
            out.append(r)
    return out


def safe(name, where):
    if not SAFE.match(name):
        raise SystemExit("unit rules: %s/%r: a name with a byte outside [A-Za-z0-9:_.@\\+-], which "
                         "systemctl's reply could not carry unambiguously" % (where, name))


def names(view, dirs):
    """Every unit name the tree's unit directories hold: each unit file's (an instance for a template),
    each instance a drop-in directory names, and each unit a .wants, .requires or .upholds link names.
    Every name met is held to SAFE."""
    out = set()

    def add(n):
        if not n.endswith(TYPES):
            return
        base, ext = os.path.splitext(n)
        out.add(base + INSTANCE + ext if base.endswith("@") else n)
    for d in dirs:
        for e in view.entries(d):
            safe(e, d)
            sub = view.resolve(d + "/" + e)[0]
            if e.endswith(".d") or e.endswith(DEP_DIRS):
                for c in view.entries(sub):
                    safe(c, d + "/" + e)
                    if not e.endswith(".d"):
                        add(c)
                add(e[:-2] if e.endswith(".d") else "")
            else:
                add(e)
    return sorted(out)


def template_of(name):
    """x@.service for an instance x@a.service, else None."""
    base, ext = os.path.splitext(name)
    at = base.find("@")
    return base[:at + 1] + ext if 0 < at < len(base) - 1 else None


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
        """The unit-directory entry that p, a unit-directory link, names, if p is an alias; else None.
        The link's own target is read once and resolved in the tree, its last component unfollowed
        (#4779 L3 1: never folded by spelling)."""
        d, _ = self.view.resolve(os.path.dirname(p))
        if d not in self.dirs or self.view.kind(d + "/" + os.path.basename(p)) != 0o120000:
            return None
        t = os.readlink(self.view.host(d + "/" + os.path.basename(p)))
        r, _ = self.view.resolve(t if t.startswith("/") else d + "/" + t, last=False)
        if os.path.dirname(r) in self.dirs and os.path.basename(r).endswith(TYPES):
            return r
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


# The tree's own systemd as PID 1 of a container: an overlay of the tree (writable, so nothing needs
# a mount over it), its own /usr, a private /proc, a /sys with only a cgroup2 tree in its own cgroup
# namespace, five character devices and a console file, an empty /run, no network. It starts only
# -.slice, which every manager has and which starts nothing, so nothing is planted (a planted
# directory would hide a link of the tree's). Its argv after --unit= is the boot entry's command
# line, which systemd in a container reads as the kernel's.
MANAGER = r'''set -eu
R=$1 USR=$2 PLANT=$3 CONSOLE=$4
shift 4
W=$(mktemp -d)
mount -t tmpfs -o mode=755 tmpfs "$W"
mkdir "$W/upper" "$W/work" "$W/root"
[ -z "$PLANT" ] || cp -a "$PLANT/." "$W/upper/"
mount -t overlay -o "lowerdir=$R,upperdir=$W/upper,workdir=$W/work" overlay "$W/root"
N=$W/root
mount --rbind "$USR" "$N/usr"
mount -t proc -o nosuid,nodev,noexec proc "$N/proc"
mount -t tmpfs -o mode=755 tmpfs "$N/sys"
mkdir -p "$N/sys/fs/cgroup"
mount -t cgroup2 cgroup2 "$N/sys/fs/cgroup"
mount -t tmpfs -o mode=755 tmpfs "$N/dev"
for n in null zero full random urandom; do : >"$N/dev/$n"; mount --bind "/dev/$n" "$N/dev/$n"; done
: >"$N/dev/console"; mount --bind "$CONSOLE" "$N/dev/console"
mount -t tmpfs -o mode=755 tmpfs "$N/run"
mkdir -p "$N/tmp" && chmod 1777 "$N/tmp"
exec env -i container=agentos-unit-lint "$(command -v chroot)" "$N" /usr/lib/systemd/systemd --unit=-.slice "$@"
'''
# The runner's systemctl, in the manager's PID namespace (systemd refuses a bus peer it cannot see),
# reaching its private bus through /proc/PID/root.
CTL = r'''set -eu
S=$1; shift
mount -t tmpfs -o mode=755 tmpfs /run
mkdir -p /run/systemd/system
ln -s "$S" /run/systemd/private
exec systemctl "$@"
'''


class Manager:
    """The tree's systemd, running (see MANAGER). view is the tree exactly as it sees it."""

    def __init__(self, root, usr, cmdline, plant):
        self.log = tempfile.NamedTemporaryFile(prefix="unit-rules-console-")
        wrap = []
        if os.path.isdir("/run/systemd/system"):  # a runner booted by systemd: a delegated scope of our own
            wrap = ["systemd-run", "--scope", "--quiet", "-p", "Delegate=yes", "--"]
        self.proc = subprocess.Popen(wrap + ["unshare", "-m", "-p", "-f", "-n", "-C", "--propagation", "private",
                                             "sh", "-c", MANAGER, "unit-rules", str(root), str(usr), str(plant),
                                             self.log.name] + cmdline.split(),
                                     stdout=subprocess.DEVNULL, stderr=self.log)
        self.pid = None
        try:
            self.wait()
        except BaseException:
            self.stop()
            raise
        self.view = View("/proc/%d/root" % self.pid)

    def wait(self, timeout=120):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                break
            try:
                kids = open("/proc/%d/task/%d/children" % (self.proc.pid, self.proc.pid)).read().split()
            except OSError:
                kids = []
            if kids:
                self.pid = int(kids[0])
                r = self.ctl(["show", "-p", "SystemState", "--value"], check=False)
                if r.returncode == 0 and r.stdout.strip() in ("running", "degraded"):
                    return
            time.sleep(0.2)
        raise SystemExit("unit rules: the tree's systemd did not start: %s" % self.console())

    def console(self):
        try:
            return pathlib.Path(self.log.name).read_text(errors="replace")[-3000:]
        except OSError:
            return ""

    def ctl(self, args, check=True):
        r = subprocess.run(["nsenter", "-t", str(self.pid), "-p", "--", "unshare", "-m", "--propagation", "private",
                            "sh", "-c", CTL, "unit-rules-ctl", "/proc/%d/root/run/systemd/private" % self.pid] + args,
                           capture_output=True, text=True, timeout=300)
        if check and r.returncode != 0:
            raise SystemExit("unit rules: systemctl %s: %s" % (" ".join(args[:3]), r.stderr[-2000:]))
        return r

    def show(self, units):
        """{name: {prop: value}} for each of UNITS, one systemctl reply block each, in order."""
        out = {}
        for i in range(0, len(units), 200):
            batch = units[i:i + 200]
            text = self.ctl(["show", "--all", "-p", ",".join(PROPS), "--"] + batch).stdout
            blocks = text.rstrip("\n").split("\n\n") if text.strip() else []
            if len(blocks) != len(batch):
                raise SystemExit("unit rules: systemctl gave %d blocks for %d units" % (len(blocks), len(batch)))
            for name, block in zip(batch, blocks):
                props = {}
                for line in block.split("\n"):
                    k, sep, v = line.partition("=")
                    if not sep or k not in PROPS or k in props:
                        raise SystemExit("unit rules: %s: systemctl line %r" % (name, line))
                    props[k] = v
                if set(props) != set(PROPS) or name not in props["Names"].split():
                    raise SystemExit("unit rules: %s: systemctl gave %s" % (name, props))
                out[name] = props
        return out

    def stop(self):
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.proc.kill()
        self.proc.wait()
        self.log.close()


def tree_path(view, p):
    """p, a path systemd named, as the tree holds it: absolute, every byte SAFE or /, resolving to a
    regular file or to /dev/null. Else the run fails."""
    if not p.startswith("/") or not all(SAFE.match(c) for c in p.split("/")[1:]):
        raise SystemExit("unit rules: systemd named %r, not an absolute path of safe names" % p)
    final, _ = view.resolve(p)
    if final != "/dev/null" and view.kind(final) != 0o100000:
        raise SystemExit("unit rules: systemd named %s, which the tree does not hold as a file" % p)
    return final


def records(view, shown, dirs, prov):
    """The records of one run: {"units": [{"unit", "alone", "files": [{"path", "ours", "text"}]}],
    "fstab": {"path", "text"} or None}, from SHOWN, systemctl's reply for every name names() found."""
    recs, own, done, instances = [], set(), set(), set()
    for name in sorted(shown):
        s = shown[name]
        if s["LoadState"] not in STATES:
            raise SystemExit("unit rules: %s: load state %r; systemd cannot load it" % (name, s["LoadState"]))
        if s["LoadState"] == "not-found":
            continue  # a name no unit loads under: its drop-ins are read alone below
        own |= {n + ".d" for n in s["Names"].split()}
        instances |= {template_of(n) for n in s["Names"].split()} - {None}
        if s["LoadState"] == "masked" or s["Id"] in done:
            continue
        done.add(s["Id"])
        frag = [s["FragmentPath"]] if s["FragmentPath"] else []
        files = []
        for p in frag + s["DropInPaths"].split():
            final = tree_path(view, p)
            if final != "/dev/null":  # a drop-in linked to /dev/null masks its name; nothing is read
                files.append({"path": p, "ours": prov.ours(p), "text": view.text(final)})
        if frag:
            recs.append({"unit": s["Id"], "alone": False, "files": files})
        else:  # loaded with no fragment: each drop-in of ours, as root
            recs += [{"unit": s["Id"], "alone": True, "files": [f]} for f in files if f["ours"]]
    for d in dirs:
        for e in view.entries(d):
            if not e.endswith(".d"):
                continue
            n = e[:-2]
            if "." not in n:  # a type-wide directory, service.d: no unit has its name
                n = "." + n
            if e in own or n in instances:
                continue  # systemd gave what of it applies to the unit, alias or instance of that name
            for c in view.entries(view.resolve(d + "/" + e)[0]):
                p = d + "/" + e + "/" + c
                final, _ = view.resolve(p)
                if c.endswith(".conf") and final != "/dev/null" and view.kind(final) == 0o100000 and prov.ours(p):
                    recs.append({"unit": n, "alone": True,
                                 "files": [{"path": p, "ours": True, "text": view.text(final)}]})
    fstab = None
    final, _ = view.resolve("/etc/fstab")
    if view.kind(final) == 0o100000 and prov.ours("/etc/fstab"):
        fstab = {"path": "/etc/fstab", "text": view.text(final)}
    return {"units": recs, "fstab": fstab}


def lint(root, usr, cmdline, packaged, plant_files=None):
    """Boot the tree's systemd (with PLANT_FILES over the tree), ask it for every unit name and return
    the records."""
    with tempfile.TemporaryDirectory() as plant:
        for p, text in (plant_files or {}).items():
            f = pathlib.Path(plant) / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        os.chmod(plant, 0o755)
        m = Manager(root, usr, cmdline, plant)
        try:
            dirs = unit_dirs(m.view)
            shown = m.show(names(m.view, dirs))
            return records(m.view, shown, dirs, Provenance(m.view, dirs, packaged(m.view)))
        finally:
            m.stop()


def dpkg_packaged(out):
    """For a view, whether a file of build OUT is byte-identical to one a package installed: dpkg's
    md5sums (mkosi.postinst's agentos.dpkg-md5sums) and the conffiles in its status file. A listed path
    counts only resolved through MERGED links alone: any other link on it may be ours (#4779 Security 2)."""
    listed = []
    for line in (pathlib.Path(out) / "agentos.dpkg-md5sums").read_text().splitlines():
        md5, _, p = line.partition("  ")
        if md5 and p:
            listed.append(("/" + p, md5))
    conf = False
    for line in (pathlib.Path(out) / "agentos.dpkg-status").read_text().splitlines():
        if line.startswith("Conffiles:"):
            conf = True
        elif conf and line.startswith(" "):
            f = line.split()
            if len(f) >= 2 and f[0].startswith("/"):
                listed.append((f[0], f[1]))
        else:
            conf = False
    if not listed:
        raise SystemExit("unit rules: no package's files listed in %s" % out)

    def for_view(view):
        want = {}
        for p, md5 in listed:
            final, links = view.resolve(p)
            if set(links) <= MERGED:
                want.setdefault(final, set()).add(md5)

        def packaged(p):
            if p not in want or view.kind(p) != 0o100000:
                return False
            with open(view.host(p), "rb") as f:
                return hashlib.md5(f.read()).hexdigest() in want[p]
        return packaged
    return for_view


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
            return lint(root, m, "", lambda view: lambda p: p in listed)
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
            recs = lint(root, usr, cmdline, dpkg_packaged(out), CONTROL if control else None)
        finally:
            cleanup()
        recs["want"] = CONTROL_WANT if control else ""
    else:
        sys.exit(__doc__)
    json.dump(recs, sys.stdout, indent=0, sort_keys=True)


if __name__ == "__main__":
    main(sys.argv[1:])
