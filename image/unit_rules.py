#!/usr/bin/env python3
"""The files each unit of a built tree loads, as the tree's own systemd reads them, for the unit-rule
lint (#4677, Mark's option A on #4698).

Which file is a unit's, which drop-ins apply and in what order, which name is an alias and which
file a link or a mask hides are systemd's to decide, and two review rounds on #4737 each found
another place a hand-written copy of its precedence went wrong. So this file decides none of it. It
boots the tree's own /usr/lib/systemd/systemd as PID 1 of a container namespace (offline_systemd.Manager: its own
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

A drop-in of ours is also printed alone, to be read in the worst context (unitCheck.unit: as a root
unit's, with no line that changes how unseen lines read), wherever a unit the tree does not list may
read it. systemd (dropin.c unit_file_find_dirs) reads a directory for other names only through a
template or a name whose part before the @ or the type ends in -, so every drop-in of ours in a
shared directory (type-wide, a-.service.d, x@.service.d, a-@i.service.d) is printed alone,
whatever loaded. One in any other directory is read only by the unit of that name, so it is
printed alone only when no unit loads under that name. So is each file of ours in a unit that did
not finish loading as the lint's instance (bad-setting), which may stop before its drop-ins while an
instance under another name does not (a unit under any other name loads as it would at boot). A lint
instance in error (systemd could not read its template's files) fails the run, and so does a
generator that failed: either hides files a boot reads. A name masked or in error is taken not to
load at boot, which holds only for units no generator writes, or while the generators' output in the
container matches a boot's. /etc/fstab is printed whole when it is ours; the units its generator
writes are read like any other.

Usage (as root): unit_rules.py OUT VERSION prints build OUT's records as JSON; --control OUT VERSION
prints them with CONTROL planted, which the lint must refuse; --fixture ROOT PACKAGED prints a fixture
tree's records under the runner's systemd, with ROOT/usr over the runner's /usr (its unit directories
hidden) and PACKAGED a file listing, one per line, the tree's files that count as a package's, and as
"listed PATH" a path a package lists that the tree no longer holds as installed.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

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
# Every type whose units load a unit file or drop-in (unit_load_fragment_and_dropin; .device too, #5507).
# .scope does not: scope_load refuses any unit not made at runtime, so no file of the tree loads one.
TYPES = (".service", ".socket", ".device", ".mount", ".swap", ".target", ".path", ".timer", ".slice", ".automount")
DEP_DIRS = (".wants", ".requires", ".upholds")
# Every name in a unit directory, a drop-in directory or a dependency directory: the bytes a unit
# name may hold (unit-name.c) and a drop-in's. A name with any other byte (a space, a newline) could
# not be told apart in systemctl's reply, so the tree is refused.
SAFE = re.compile(r"[A-Za-z0-9:_.@\\+-]+\Z")
PROPS = ("Id", "Names", "LoadState", "FragmentPath", "DropInPaths", "Triggers", "TriggeredBy")
# systemd will not start a bad-setting or error unit, but its files are held as a loaded one's: stricter.
STATES = ("loaded", "bad-setting", "error", "masked", "not-found")
# Every template is loaded as one instance of each instance name the tree holds (so a-@i.service.d is
# read with every a-x@i that reads it), and as the lint's own instance (INSTANCE), which no file in the
# tree may name (safe()), so it loads from the template's files alone, as an instance a boot starts
# under any other name does. Its drop-ins are printed alone besides (shared()), so whether it loads
# decides nothing.
# The top links of a merged /usr: the only links a dpkg path may be resolved through.
MERGED = {"/bin", "/sbin", "/lib", "/lib64"}
# A drop-in of ours on a packaged root unit that no package's socket feeds (systemd's own oneshot), so the
# Environment= rule refuses it rather than the fed-service one (#5072: journald, fed by its sockets, was
# refused first): the lint must refuse it, or a pass of the built tree means nothing (#4677 Security R-1).
CONTROL = {"etc/systemd/system/systemd-tmpfiles-setup.service.d/zz-agentos-unit-control.conf":
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
    if "@" + INSTANCE + "." in name:
        raise SystemExit("unit rules: %s/%s: a name of the lint's own instance, which stands for every "
                         "instance a boot may start, so no file may be its own" % (where, name))


def names(view, dirs):
    """Every unit name the tree's unit directories hold: each unit file's, each instance a drop-in
    directory names, and each unit a .wants, .requires or .upholds link names; and each template as an
    instance of INSTANCE and of every instance name met with its type. Every name met is held to SAFE."""
    out = set()

    def add(n):
        if n.endswith(TYPES):
            out.add(n)
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
    # n = pre@inst.type; a template has an empty inst
    split = [(b[:b.index("@") + 1], b[b.index("@") + 1:], e) for b, e in map(os.path.splitext, out) if "@" in b]
    for pre, inst, ext in split:
        if not inst:
            out.discard(pre + ext)
            out |= {pre + i + ext for _, i, e in split if e == ext and i} | {pre + INSTANCE + ext}
    return sorted(out)


def shared(n):
    """Whether a drop-in directory n.d may be read by a unit of another name (see the docstring): any
    name but a unit name whose part before the @ or the type does not end in -, with a nonempty
    instance after an @."""
    base, ext = os.path.splitext(n)
    pre, at, inst = base.partition("@")
    return ext not in TYPES or not pre or pre.endswith("-") or (at and not inst)


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


def tree_path(view, p):
    """p, a path systemd named, as the tree holds it: absolute, every byte SAFE or /, resolving to a
    regular file or to /dev/null. Else the run fails."""
    if not p.startswith("/") or not all(SAFE.match(c) for c in p.split("/")[1:]):
        raise SystemExit("unit rules: systemd named %r, not an absolute path of safe names" % p)
    final, _ = view.resolve(p)
    if final != "/dev/null" and view.kind(final) != 0o100000:
        raise SystemExit("unit rules: systemd named %s, which the tree does not hold as a file" % p)
    return final


def words(s, prop):
    """A list property of one reply block, split as systemctl quotes it (offline_systemd.shell_words)."""
    return offline_systemd.shell_words(s[prop], "%s %s" % (s["Id"], prop))


def packaged_names(view, dirs, prov):
    """Every unit name a package ships a unit file for, in any unit directory: whether or not a file of
    ours hides it."""
    out = set()
    for d in dirs:
        for e in view.entries(d):
            final, _ = view.resolve(d + "/" + e)
            if e.endswith(TYPES) and final != "/dev/null" and view.kind(final) == 0o100000 and not prov.ours(d + "/" + e):
                out.add(e)
    return out


def package_sockets(shown, pkg):
    """The sockets whose endpoint is a package's: one whose name, or a name of the unit it activates
    (Triggers, or the template an Accept=yes socket starts), a package ships, and one a package's service takes (TriggeredBy, Sockets=). Who may
    connect to such a socket is the package's (#5072 Security 1)."""
    def shipped(n):
        base, ext = os.path.splitext(n)
        names = words(shown[n], "Names") if n in shown else [n]
        return any(x in pkg or "@" in base and x.split("@")[0] + "@" + ext in pkg for x in names)
    out = set()
    for n, s in shown.items():
        if s["LoadState"] != "loaded":
            continue
        if n.endswith(".socket"):
            # the service it activates: Triggers, or, with Accept=yes (no Triggers), its name's template
            feeds = words(s, "Triggers") + [n[:-len(".socket")] + "@.service"]
            if shipped(n) or any(shipped(t) for t in feeds):
                out.add(s["Id"])
        if shipped(n):
            out |= {t for t in words(s, "TriggeredBy") if t.endswith(".socket")}
    return out


def fed_services(shown, pkgsock):
    """Whether a unit name is a service a package's socket (PKGSOCK) hands its connections or listening
    fds to: read from each such socket's side (its Triggers, its implicit same-name service and every
    instance of its <prefix>@.service, which Accept=yes starts), since the lint's manager drops an
    inactive service between show calls and with it the TriggeredBy those edges add (#5072 Security
    round 3), and from the service's own TriggeredBy (Sockets=). Every name of such a unit counts."""
    feeds, prefixes = set(), set()
    for n, s in shown.items():
        if n.endswith(".socket") and s["LoadState"] == "loaded" and s["Id"] in pkgsock:
            feeds |= set(words(s, "Triggers"))
            for x in words(s, "Names"):
                feeds.add(x[:-len(".socket")] + ".service")
                prefixes.add(x[:-len(".socket")].split("@")[0] + "@")
    for n, s in shown.items():
        if set(words(s, "TriggeredBy")) & pkgsock:
            feeds.add(n)
    fed = set(feeds)
    for n, s in shown.items():
        names = set(words(s, "Names"))
        if names & feeds:
            fed |= names
    # an instance's template is fed too: the lint's manager shows only the lint's instance of it, and
    # files of ours in the template's directories reach every instance (#5072 round 4)
    prefixes |= {u.split("@")[0] + "@" for u in fed if "@" in u}

    def is_fed(u):
        return u.endswith(".service") and (u in fed or u.startswith(tuple(prefixes)))
    is_fed.names, is_fed.prefixes = {u for u in fed if u.endswith(".service")}, prefixes
    return is_fed


def unread(view, shown, dirs, packaged):
    """A mask for each unit file or drop-in a package lists (packaged.listed) that systemd does not read as
    installed: changed, no longer a regular file, reached by a link, or gone while a unit still loads under
    its name or its directory is shared. Provenance by current bytes alone makes a changed one ours
    (#5072 round 5), so this holds it from the package's side. A unit removed whole, fragment and
    drop-ins, with nothing loading under its name (drop.py's dpkg-db-backup), hides nothing."""
    loads = set()
    for s in shown.values():
        if s["LoadState"] in ("loaded", "bad-setting", "error"):
            for n in words(s, "Names"):
                base, ext = os.path.splitext(n)
                loads.add(n)
                if "@" in base:
                    loads.add(base.split("@")[0] + "@" + ext)  # any instance loads its template's files
    top, out = set(dirs) | set(UNIT_DIRS), []  # listed paths are as dpkg laid them out (dpkg_packaged)
    for p in sorted(getattr(packaged, "listed", ())):
        parent, base = os.path.split(p)
        if parent in top and base.endswith(TYPES):
            name = base
        elif os.path.dirname(parent) in top and parent.endswith(".d") and base.endswith(".conf"):
            name = os.path.basename(parent)[:-2]
        else:
            continue
        # a link of ours anywhere on it (a unit directory, a parent, a drop-in directory) is a mask too,
        # since its files then read as ours (#5072 Security round 6)
        final, links = view.resolve(p)
        if view.lstat(final) is None:  # gone, whatever link led there
            n = name if "." in name else "." + name
            if name not in loads and (parent in top or not shared(n)):
                continue
        elif not links and view.kind(final) == 0o100000 and packaged(final):
            continue
        out.append({"path": p, "hides": p})
    return out


def tree_links(view):
    """{link: its target resolved in the tree} for every link of the tree (/proc and /sys aside) that does
    not resolve to a file other than a directory: one an endpoint path's directory may pass through, a
    dangling one included (#5620 R-c, R-i). A loop, or a link the reader cannot follow (into /proc), maps to
    itself."""
    out, todo = {}, ["/"]
    while todo:
        d = todo.pop()
        for e in view.entries(d):
            p = os.path.join(d, e)
            kind = view.kind(p)
            if p in ("/proc", "/sys"):
                continue
            if kind == 0o040000:
                todo.append(p)
            elif kind == 0o120000:
                try:
                    final, _ = view.resolve(p)
                except (SystemExit, OSError):  # a loop, or a link into /proc (/dev/fd)
                    final = p
                if view.kind(final) in (None, 0o040000) or final == p:
                    out[p] = final
    return out


def records(view, shown, dirs, prov):
    """The records of one run: {"units": [{"unit", "alone", "package", "fed", "files": [{"path", "ours",
    "text"}]}], "fstab": {"path", "text"} or None, "masks": [{"path", "hides"}], "links": tree_links()}, from SHOWN, systemctl's
    reply for every name names() found. package marks a socket whose endpoint is a package's
    (package_sockets), fed a service such a socket hands its connections to (fed_services); a mask is a
    file of ours that hides a package's drop-in."""
    recs, own, done = [], set(), set()
    pkgsock = package_sockets(shown, packaged_names(view, dirs, prov))
    for name in sorted(shown):
        s = shown[name]
        if s["LoadState"] not in STATES:
            raise SystemExit("unit rules: %s: load state %r; systemd cannot load it" % (name, s["LoadState"]))
        if s["LoadState"] == "not-found":
            continue  # a name no unit loads under: its drop-ins are read alone below
        # A masked or error name stands for its own directory: no other unit loads under that name.
        own |= {n + ".d" for n in words(s, "Names")}
        if s["LoadState"] == "masked" or s["Id"] in done:
            continue
        if s["LoadState"] == "error" and "@" + INSTANCE + "." in s["Id"]:
            # systemd could not read the template's files, so which drop-ins its instances read (one of
            # ours may mask a package's User= line) and what a package's lines run cannot be seen (#4821
            # Security R1)
            raise SystemExit("unit rules: %s: load state error; the lint's instance stands for every instance "
                             "a boot may start, so its template must load" % s["Id"])
        done.add(s["Id"])
        frag = [s["FragmentPath"]] if s["FragmentPath"] else []
        files = []
        for p in frag + words(s, "DropInPaths"):
            final = tree_path(view, p)
            if final != "/dev/null":  # a drop-in linked to /dev/null masks its name; nothing is read
                files.append({"path": p, "ours": prov.ours(p), "text": view.text(final)})
        if frag:
            recs.append({"unit": s["Id"], "alone": False, "files": files})
        if not frag or s["LoadState"] != "loaded" and "@" + INSTANCE + "." in s["Id"]:
            # no fragment, or the lint's instance did not finish loading (it may have stopped before the
            # drop-ins, and an instance under another name may not): each file of ours alone too
            recs += [{"unit": s["Id"], "alone": True, "files": [f]} for f in files if f["ours"]]
    for d in dirs:
        for e in view.entries(d):
            if not e.endswith(".d"):
                continue
            n = e[:-2]
            if "." not in n:  # a type-wide directory, service.d: no unit has its name
                n = "." + n
            if e in own and not shared(n):
                continue  # read only under that name, and systemd gave it to the unit of that name
            for c in view.entries(view.resolve(d + "/" + e)[0]):
                p = d + "/" + e + "/" + c
                final, _ = view.resolve(p)
                if c.endswith(".conf") and final != "/dev/null" and view.kind(final) == 0o100000 and prov.ours(p):
                    recs.append({"unit": n, "alone": True,
                                 "files": [{"path": p, "ours": True, "text": view.text(final)}]})
    # A .conf of ours (a /dev/null link, an empty file, any file) named as a package's drop-in of its type
    # hides that file's lines, say SocketMode= or User= (#5072 round 4); a unit file a package lists and
    # systemd does not read as installed is unread() below
    masks, pkgdrop, ourdrop = [], {}, []
    for d in dirs:
        for e in (e for e in view.entries(d) if e.endswith(".d")):
            ext = os.path.splitext(e[:-2])[1] or "." + e[:-2]  # service.d: .service
            for c in (c for c in view.entries(view.resolve(d + "/" + e)[0]) if c.endswith(".conf")):
                p = d + "/" + e + "/" + c
                final, links = view.resolve(p)
                if prov.ours(p):
                    ourdrop.append((ext, c, p))
                elif view.kind(final) == 0o100000:
                    pkgdrop.setdefault((ext, c), []).append(p)
    masks += [{"path": p, "hides": q} for ext, c, p in ourdrop for q in pkgdrop.get((ext, c), [])]
    masks += unread(view, shown, dirs, prov.packaged)
    fed = fed_services(shown, pkgsock)
    for rec in recs:
        rec["package"] = rec["unit"] in pkgsock
        rec["fed"] = fed(rec["unit"])
    # every name a package's socket or a service it feeds goes by, for a [Unit] line of ours in any unit
    # that names one (JoinsNamespaceOf=, Conflicts=: systemd adds the edge on both units, #5072 round 5)
    held = set(fed.names)
    for s in shown.values():
        if s["Id"] in pkgsock:
            held |= set(words(s, "Names"))
    fstab = None
    final, _ = view.resolve("/etc/fstab")
    if view.kind(final) == 0o100000 and not prov.ours("/etc/fstab"):
        for line in view.text(final).split("\n"):
            w = line.split()
            if w and not w[0].startswith("#") and (w[0].startswith("/") or "=" in w[0]):
                # fstab-generator skips a device line in the manager's container mode, so the unit a boot
                # writes from a package's line would go unread (an fstab of ours is printed whole below)
                raise SystemExit("unit rules: a package's /etc/fstab names a device, which systemd in a "
                                 "container skips: %r" % line.strip())
    if view.kind(final) == 0o100000 and prov.ours("/etc/fstab"):
        fstab = {"path": "/etc/fstab", "text": view.text(final)}
    return {"units": recs, "fstab": fstab, "masks": masks, "links": tree_links(view),
            "held": {"names": sorted(held), "prefixes": sorted(fed.prefixes)}}


def lint(root, usr, cmdline, packaged, plant_files=None):
    """Boot the tree's systemd (with PLANT_FILES over the tree), ask it for every unit name and return
    the records."""
    with tempfile.TemporaryDirectory() as plant:
        for p, text in (plant_files or {}).items():
            f = pathlib.Path(plant) / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        os.chmod(plant, 0o755)
        m = offline_systemd.Manager(root, usr, cmdline, plant)
        try:
            view = View(m.view_root)
            dirs = unit_dirs(view)
            shown = m.show(names(view, dirs), PROPS)
            failed = m.failed_generators()
            if failed:
                # a failed generator wrote none or only some of its units, which a boot may write and start
                raise SystemExit("unit rules: generators failed, so their units are not all in the tree: %s"
                                 % ", ".join(sorted(failed)))
            return records(view, shown, dirs, Provenance(view, dirs, packaged(view)))
        finally:
            m.stop()


def merged(view, link):
    """Whether LINK is a merged-/usr top link as a package lays it out: one of MERGED, resolving in the
    tree to /usr/<its name> (#4779 Security R-b: /lib -> etc made our /etc files a
    package's)."""
    return link in MERGED and view.resolve(link)[0] == "/usr" + link


def dpkg_packaged(out):
    """For a view, whether a file of build OUT is byte-identical to one a package installed: dpkg's
    md5sums (mkosi.postinst's agentos.dpkg-md5sums) and the conffiles in its status file. A listed path
    counts only resolved through MERGED links alone, each to /usr/<its name> (merged()): any other link on
    it may be ours (#4779 Security 2)."""
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
            if all(merged(view, l) for l in links):
                want.setdefault(final, set()).add(md5)

        def packaged(p):
            if p not in want or view.kind(p) != 0o100000:
                return False
            with open(view.host(p), "rb") as f:
                return hashlib.md5(f.read()).hexdigest() in want[p]
        # every path a package installed, whatever its links or bytes now: as dpkg laid it out, through a
        # merged top link to /usr/<its name> only (#5072 Security round 6: a link of ours took a listed
        # path out of want, so out of listed too)
        packaged.listed = {"/usr" + p if p.split("/")[1:2] and "/" + p.split("/")[1] in MERGED
                           and merged(view, "/" + p.split("/")[1]) else p for p, _ in listed}
        return packaged
    return for_view


def fixture(root, packaged_list):
    """Records of a fixture tree under the runner's systemd: ROOT/usr overlaid on the runner's /usr, with
    the runner's own unit and generator directories hidden, so only the fixture's units load. Of the
    runner's generators only systemd's fstab one runs (a package's, snapd's, writes units of its own)."""
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
    gen = root / "usr/lib/systemd/system-generators"
    gen.mkdir(parents=True, exist_ok=True)
    shutil.copy2(os.path.realpath("/usr/lib/systemd/system-generators/systemd-fstab-generator"),
                 gen / "systemd-fstab-generator")
    (root / "usr/local/lib/systemd/system-generators").mkdir(parents=True, exist_ok=True)
    for d in ("usr/lib/systemd/system", "usr/local/lib/systemd/system", "usr/lib/systemd/system-generators",
              "usr/local/lib/systemd/system-generators"):
        os.setxattr(root / d, "trusted.overlay.opaque", b"y", follow_symlinks=False)
    os.chmod(root, 0o755)
    lines = [l for l in pathlib.Path(packaged_list).read_text().splitlines() if l]
    listed = {l for l in lines if not l.startswith("listed ")}
    packaged = lambda p: p in listed  # noqa: E731
    packaged.listed = listed | {l[len("listed "):] for l in lines if l.startswith("listed ")}
    with tempfile.TemporaryDirectory() as m:
        subprocess.run(["mount", "-t", "overlay", "-o", "ro,lowerdir=%s:/usr" % (root / "usr"), "overlay", m],
                       check=True)
        try:
            return lint(root, m, "", lambda view: packaged)
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
