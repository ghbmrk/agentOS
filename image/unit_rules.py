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
    resolved in it, never on the runner: each public reader (lstat, kind, entries, text, data, readlink)
    resolves every component of its path through resolve() first. Only five calls touch the host, each
    at a path resolve() gave and _lstat found, so no tree link is left in its directory: _lstat, _list,
    resolve's own readlink, readlink()'s os.readlink and data()'s os.open (O_NOFOLLOW) (#5703)."""

    def __init__(self, root, usr=None):
        self.root, self.usr = str(root), usr and str(usr)

    def host(self, p):
        if self.usr and (p == "/usr" or p.startswith("/usr/")):
            return self.usr + p[4:]
        return self.root + p

    def _lstat(self, q):
        """The lstat of Q, a path resolve() gave, so no tree link is left in its directory."""
        try:
            return os.lstat(self.host(q))
        except (FileNotFoundError, NotADirectoryError):
            return None

    def _list(self, q):
        """The names in Q, a path resolve() gave with its last component followed."""
        if self._lstat(q) is None:
            return []
        try:
            return sorted(os.listdir(self.host(q)))
        except (FileNotFoundError, NotADirectoryError):
            return []

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
            st = self._lstat(nxt)
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

    def lstat(self, p):
        return self._lstat(self.resolve(p, last=False)[0])

    def entries(self, d):
        return self._list(self.resolve(d)[0])

    def kind(self, p):
        st = self.lstat(p)
        return st and st.st_mode & 0o170000

    def readlink(self, p):
        """P's own link target, None when P is not a link (its directory resolved in the tree)."""
        q = self.resolve(p, last=False)[0]
        st = self._lstat(q)
        return os.readlink(self.host(q)) if st and st.st_mode & 0o170000 == 0o120000 else None

    def data(self, p):
        """P's bytes, P's directory resolved in the tree; a link at P itself is refused (O_NOFOLLOW)."""
        q = self.resolve(p, last=False)[0]
        if self._lstat(q) is None:
            raise FileNotFoundError(p)
        fd = os.open(self.host(q), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as f:
            return f.read()

    def text(self, p):
        return self.data(p).decode("utf-8", "surrogateescape")


# #5703: what is mounted over the tree before systemd-tmpfiles-setup runs, so nothing the tree holds there
# is boot state. systemd's mount_table (src/shared/mount-setup.c, v255 to v257) mounts every API file
# system at or under /proc, /sys, /dev or /run; tmp.mount mounts /tmp (its 50-agentos-noexec.conf
# drop-in). Nothing rests on the list being whole (package .mount units may add more): a mount it
# misses leaves a tree link that is not there at boot in the records, or fails the run (tmpfiles_lines,
# tmpfiles_links), never drops a link. The link readers (tree_links, tmpfiles_links) read through BootView.
BOOT_MOUNTS = ("/dev", "/proc", "/sys", "/run", "/tmp")


class BootView(View):
    """VIEW as the box finds it when systemd-tmpfiles runs: each of BOOT_MOUNTS is a directory holding
    nothing, whatever the tree has there (the run's container mounts its own /run too, but a reader
    called on a plain tree must not read the tree's mounts as boot state). The hiding sits in the host
    primitives, so every path, however its links lead there, is hidden once it resolves under one."""

    def __init__(self, view):
        super().__init__(view.root, view.usr)

    @staticmethod
    def hidden(p):
        return any(p.startswith(m + "/") for m in BOOT_MOUNTS)

    def _lstat(self, q):
        if q in BOOT_MOUNTS:
            return super()._lstat("/")  # a directory, as the mount is, whatever the tree has there
        return None if self.hidden(q) else super()._lstat(q)

    def _list(self, q):
        return [] if self.hidden(q) or q in BOOT_MOUNTS else super()._list(q)


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
        t = self.view.readlink(d + "/" + os.path.basename(p))
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


def tree_links(view, usr_view=None):
    """{link: its target resolved in the tree} for every link of the tree (/proc and /sys aside) that does
    not resolve to a file other than a directory: one an endpoint path's directory may pass through, a
    dangling one included (#5620 R-c, R-i). A loop, or a link the reader cannot follow (into /proc), maps to
    itself. With USR_VIEW (a fixture's own tree), /usr is listed there, not in the view's /usr, which is
    the fixture over the runner's whole /usr: walking that took the privfile tests past 10 minutes (#5652 L3).
    Each link is still resolved in the view."""
    out, todo = {}, ["/"]
    while todo:
        d = todo.pop()
        lister = usr_view if usr_view and (d == "/usr" or d.startswith("/usr/")) else view
        for e in lister.entries(d):
            p = os.path.join(d, e)
            kind = (usr_view if usr_view and p == "/usr" else lister).kind(p)
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


# Where systemd-tmpfiles reads its files, highest first: a name in a higher one hides it in a lower one.
TMPFILES_DIRS = ("/etc/tmpfiles.d", "/run/tmpfiles.d", "/usr/local/lib/tmpfiles.d", "/usr/lib/tmpfiles.d")


def tmpfiles_lines(view, usr_view=None):
    """[(file, line)] for every line of the tree's tmpfiles.d files, each name read once from the highest
    directory holding it (one linked to /dev/null, or not a regular file, masks it), in name order. With
    USR_VIEW, /usr's directories are listed there (tree_links). #5703 Security delta 2: a link anywhere
    on the way to a file, but a file's own link to exactly /dev/null, fails the run, so no file is read
    from where the tree's content is not the box's at boot (BOOT_MOUNTS, or a mount the list misses).
    mkosi.finalize refuses every link under tmpfiles.d in the built image, so the image needs none."""
    chosen = {}
    for d in TMPFILES_DIRS:
        lister = usr_view if usr_view and d.startswith("/usr/") else view
        _, via = lister.resolve(d)
        if via:
            raise SystemExit("unit rules: %s: a tmpfiles.d directory reached through a link (%s), which "
                             "the reader does not read" % (d, via[0]))
        for e in lister.entries(d):
            t = lister.readlink(os.path.join(d, e))
            if t is not None and t != "/dev/null":
                raise SystemExit("unit rules: %s/%s: a tmpfiles.d file that is a link to %s, not a /dev/null "
                                 "mask, which the reader does not read" % (d, e, t))
            if e.endswith(".conf"):
                chosen.setdefault(e, os.path.join(d, e))
    out = []
    for e in sorted(chosen):
        final, _ = view.resolve(chosen[e])
        if final == "/dev/null" or view.kind(final) != 0o100000:
            continue
        for line in view.text(final).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append((chosen[e], line))
    return out


def through(p, links):
    """P with each directory component, and its last one, read through LINKS, until none is a link."""
    for _ in range(41):
        cur, comps = "/", [c for c in p.split("/") if c]
        for i, c in enumerate(comps):
            cur = os.path.join(cur, c)
            if cur in links and links[cur] != cur:
                p = os.path.join(links[cur], *comps[i + 1:])
                break
        else:
            return p
    raise SystemExit("unit rules: %s: more than 40 links" % p)


def tmpfiles_links(view, links, usr_view=None, mounts=()):
    """LINKS (tree_links) with each link a tmpfiles.d L line makes at boot (#5651, KRN-2): tmpfiles.allow
    gates these lines by review alone. VIEW is a BootView (boot_links). #5703 re-plan: nothing here rests
    on knowing what is mounted at boot, which package .mount units leave open. Every L line counts, with
    any modifier; a tree entry at a plain L line's path fails the run, unless it is a link resolving to
    the line's target, since that L leaves the entry (L+ removes it). An L line, any modifier, whose path
    is at, under or above one of MOUNTS (mount_points), or whose target is at or under one, fails the
    run: at boot the mounted file system, not the tree, holds what is there, and L+ cannot replace a
    mount point, remove a directory holding one, or write to a read-only mount (#5725). Its path's
    directory and its target (the factory copy when it gives none) are resolved in the tree, and a tree
    link on either way fails the run, since it may sit under a mount the tree does not show; the target
    is then read through the other L lines' links, and every value again through them. An L line
    holding a specifier, quote or escape, an encoded (~) or credential (^) target, a path not absolute
    and normal, a path another tmpfiles.d line also names (which one applies is systemd-tmpfiles' to
    decide), or one whose directory passes through another L line's link fails the run too."""
    lines, named = tmpfiles_lines(view, usr_view), {}
    for f, line in lines:
        w = line.split()
        if len(w) > 1:
            named.setdefault(w[1], []).append(w[0])
    found, found_mod = {}, {}
    for f, line in lines:
        w = line.split(None, 6)
        if not w[0].startswith("L"):
            continue
        if any(ch in line for ch in "%\"\'\\"):
            raise SystemExit("unit rules: %s: L line %r holds a specifier, a quote or an escape, which the "
                             "unit lint does not read" % (f, line))
        if "~" in w[0] or "^" in w[0]:
            raise SystemExit("unit rules: %s: L line %r: its target is encoded or a credential, which the "
                             "unit lint does not read" % (f, line))
        p = w[1] if len(w) > 1 else ""
        if not p.startswith("/") or p.startswith("//") or os.path.normpath(p) != p:  # normpath keeps a leading //
            raise SystemExit("unit rules: %s: L line %r: its path is not absolute and normal" % (f, line))
        if len(named[p]) > 1:
            raise SystemExit("unit rules: %s: a tmpfiles.d L line and another line name it, and which "
                             "applies is not read" % p)
        m = covering(p, mounts)
        if m:
            raise SystemExit("unit rules: %s: L line %r: its path is at, under or above %s, where a mount puts a "
                             "file system the unit lint does not see, and no L line, L+ included, can replace "
                             "what it holds; move the line off the mount" % (f, line, m))
        _, via = view.resolve(os.path.dirname(p))
        if via:
            raise SystemExit("unit rules: %s: L line %r: its path's directory passes through a link in the "
                             "tree (%s), which may not be there at boot" % (f, line, via[0]))
        arg = w[6].strip() if len(w) > 6 else "-"
        target = "/usr/share/factory" + p if arg in ("", "-") else os.path.join(os.path.dirname(p), arg)
        # #5725 Security 6876826072: a target at or under a mount resolves in its file system at boot, not in
        # the tree; one above it resolves in the tree, and a path read on through it is read as any other.
        t = os.path.normpath(target)
        m = next((m for m in mounts if t == m or t.startswith(m + "/")), None)
        if m:
            raise SystemExit("unit rules: %s: L line %r: its target is at or under %s, where a mount puts a file "
                             "system the unit lint does not see; point the line at a path no mount covers"
                             % (f, line, m))
        found[p], found_mod[p] = (f, line, target), w[0]
    if not found:
        return links
    out = dict(links)
    for key, (f, line, target) in found.items():
        final, via = view.resolve(target)
        if via:
            raise SystemExit("unit rules: %s: L line %r: its target passes through a link in the tree (%s), "
                             "which may not be there at boot" % (f, line, via[0]))
        # #5703 L3 6872965749: a plain L leaves whatever the tree has at its path, so a tree entry there
        # fails the run unless it is a link that resolves where the line's does (debian's /etc/mtab);
        # L+ removes the entry first. Which of the two is there at boot rests on mounts; neither is picked.
        if "+" not in found_mod[key] and view.lstat(key) is not None and (
                view.readlink(key) is None or view.resolve(key)[0] != final):
            raise SystemExit("unit rules: %s: L line %r: the tree already has an entry there, which a plain L "
                             "leaves in place; use L+, remove the entry, or make it a link to the same target"
                             % (f, line))
        if view.kind(final) in (None, 0o040000) or final == key:
            out[key] = final
        else:
            out.pop(key, None)  # a link to a file no endpoint's directory passes through
    for key in found:
        if through(os.path.dirname(key), out) != os.path.dirname(key):
            raise SystemExit("unit rules: %s: a tmpfiles.d L line's path passes through another link, "
                             "which the unit lint does not read" % key)
    return {k: (v if v == k else through(v, {a: b for a, b in out.items() if a != k})) for k, v in out.items()}


def tmpfiles_copies(view, links, usr_view=None, mounts=()):
    """#5707 (KRN-2): systemd-tmpfiles copies a link as a link for a C line (copy_tree_at), so a C line
    whose source is a link, or a directory holding one anywhere below it, would make a link at boot that
    LINKS (boot_links) do not hold: the run fails. VIEW is a BootView. Its source (the factory copy when it
    names none) is read like an L line's target: a specifier, quote or escape, an encoded (~) or credential
    (^) source, one not absolute and normal, one under a boot mount (empty in VIEW, filled at boot), or one
    passing through a link, the tree's or one in LINKS, fails the run too, as does one at, under or above
    any L line's path or one of MOUNTS (mount_points: its file system, not the tree, is the source at boot),
    or one outside /usr (#5715: no exception; the image drops systemd's /.extra lines)."""
    lines = tmpfiles_lines(view, usr_view)
    ls = [w[1] for w in (line.split() for _, line in lines) if w[0].startswith("L") and len(w) > 1]
    for f, line in lines:
        w = line.split(None, 6)
        if not w[0].startswith("C"):
            continue
        if any(ch in line for ch in "%\"\'\\"):
            raise SystemExit("unit rules: %s: C line %r holds a specifier, a quote or an escape, which the "
                             "unit lint does not read" % (f, line))
        if "~" in w[0] or "^" in w[0]:
            raise SystemExit("unit rules: %s: C line %r: its source is encoded or a credential, which the "
                             "unit lint does not read" % (f, line))
        arg = w[6].strip() if len(w) > 6 else "-"
        src = "/usr/share/factory" + (w[1] if len(w) > 1 else "") if arg in ("", "-") else arg
        if not src.startswith("/") or src.startswith("//") or os.path.normpath(src) != src:
            raise SystemExit("unit rules: %s: C line %r: its source is not absolute and normal" % (f, line))
        if any(src == m or src.startswith(m + "/") for m in BOOT_MOUNTS):
            raise SystemExit("unit rules: %s: C line %r: its source is under %s, whose content at boot the "
                             "unit lint does not see; copy from /usr" % (f, line, "/" + src.split("/")[1]))
        m = covering(src, mounts)
        if m:
            raise SystemExit("unit rules: %s: C line %r: its source is at, under or above %s, where a mount puts "
                             "a file system the unit lint does not see; copy from a path under /usr that no "
                             "mount covers" % (f, line, m))
        todo = [src]
        while todo:
            p = todo.pop()
            kind = view.kind(p)
            if kind == 0o120000:
                raise SystemExit("unit rules: %s: C line %r: its source is or holds a link, %s, which "
                                 "systemd-tmpfiles copies as a link" % (f, line, p))
            if kind == 0o040000:
                todo += [os.path.join(p, e) for e in view.entries(p)]
        _, via = view.resolve(src)
        via += [k for k, v in links.items() if v != k and (src == k or src.startswith(k + "/"))]
        if via:
            raise SystemExit("unit rules: %s: C line %r: its source passes through a link (%s), which the "
                             "unit lint does not read" % (f, line, via[0]))
        # #5715 L3 6874735402, Security 6874738412: an L line's link at or under the source is made at boot
        # (and stays in a persistent /etc or /var), not in the tree the walk reads, and tmpfiles_links drops
        # some L keys (a link to a file, a loop), so every L line counts, at, under or above the source.
        under = src.rstrip("/") + "/"
        for k in ls:
            if k == src or k.startswith(under) or src.startswith(k.rstrip("/") + "/"):
                raise SystemExit("unit rules: %s: C line %r: an L line makes a link at, under or above its "
                                 "source, %s, which systemd-tmpfiles may copy as a link; drop the L line or "
                                 "move the source" % (f, line, k))
        # A source in persistent writable state copies what a running service left there between boots,
        # which no lint of the tree sees: only read-only /usr (verity, I4) is a source. #5715 L3 6874919503,
        # Security 6874914212: a /.extra exception compared path text, which //, /./ or a link on the way
        # bypassed; the image drops systemd's /.extra lines (mkosi.conf RemoveFiles), so none is kept.
        if not (src == "/usr" or src.startswith("/usr/")):
            raise SystemExit("unit rules: %s: C line %r: its source is not under /usr, the one tree no service "
                             "writes between boots and the image holds whole (a /.extra source is neither); "
                             "copy from /usr" % (f, line))


# #5725 Security 6876826072: systemd-gpt-auto-generator mounts the ESP at /boot or /efi from the boot disk, and
# exits in the lint's container, so no unit name shows it. finish_image.py (REPART_TYPES, #5289) holds the
# disk to the ESP, /usr, its verity and root, so these are the only points gpt-auto mounts.
GPT_AUTO_MOUNTS = ("/boot", "/efi")


def mount_points(view):
    """#5708: the Where= of every .mount and .automount unit name in the tree's unit directories, generators'
    included (systemd loads such a unit only under the name its Where= escapes to), and GPT_AUTO_MOUNTS,
    but / and BOOT_MOUNTS, which BootView already reads as the tree or as empty. Ours count with a
    package's: what a mounted file system holds at a path is not in the tree, whoever ships the unit."""
    out = set(GPT_AUTO_MOUNTS)
    for n in names(view, unit_dirs(view)):
        base, ext = os.path.splitext(n)
        if ext not in (".mount", ".automount") or "@" in base or base == "-":
            continue
        w = os.path.normpath("/" + re.sub(r"\\x([0-9a-fA-F]{2})", lambda x: chr(int(x.group(1), 16)),
                                          base.replace("-", "/")))
        if w != "/" and w not in BOOT_MOUNTS:
            out.add(w)
    return sorted(out)


def covering(p, mounts):
    """The first of MOUNTS at, under or above P (a mount below P puts its directories on P's way), or None."""
    for m in mounts:
        if p == m or p.startswith(m + "/") or m.startswith(p.rstrip("/") + "/"):
            return m
    return None


# #5703 L3 6872796820: the kernel's own links under /proc, /sys and /dev (/proc/self/root, /proc/<pid>/root,
# /proc/thread-self, /dev/fd) lead back into /, and the reader cannot follow them, so a link whose target
# resolves at or under one fails the run, but at exactly these: none is a directory a path steps through
# into / (/dev/shm is a plain tmpfs). /dev/null masks; /dev/shm and /proc/self/mounts are debian.conf's
# /run/shm and /etc/mtab lines.
API_MOUNTS = ("/proc", "/sys", "/dev")
API_TARGETS = ("/dev/null", "/dev/shm", "/proc/self/mounts")


def boot_links(view, usr_view=None):
    """The links a path may pass through at boot: the tree's and tmpfiles.d's, read at BootView. A link
    into an API mount but API_TARGETS, or one whose resolved target keeps a . or .. component, fails the run,
    and so does a tmpfiles.d C line that may copy a link (tmpfiles_copies). The mount points are read from
    VIEW, not the BootView, since generators write their units under /run."""
    boot, mounts = BootView(view), mount_points(view)
    out = tmpfiles_links(boot, tree_links(boot, usr_view), usr_view, mounts)
    tmpfiles_copies(boot, out, usr_view, mounts)
    for k, v in sorted(out.items()):
        if v != k and os.path.normpath(v) != v:  # #5703 Security 6872976172: resolve keeps .. past a missing
            raise SystemExit("unit rules: %s: a link (the tree's, or a tmpfiles.d L line's at that path) "
                             "resolving to %s, which keeps a . or .. component the unit lint does not follow; "
                             "write the target without . or .." % (k, v))  # the kernel follows links before ..
        if v != k and v not in API_TARGETS and any(v == m or v.startswith(m + "/") for m in API_MOUNTS):
            raise SystemExit("unit rules: %s: a link to %s, under %s, whose own links the unit lint does not "
                             "follow" % (k, v, "/" + v.split("/")[1]))
    return out


def records(view, shown, dirs, prov, usr_view=None):
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
    return {"units": recs, "fstab": fstab, "masks": masks, "links": boot_links(view, usr_view),
            "held": {"names": sorted(held), "prefixes": sorted(fed.prefixes)}}


def lint(root, usr, cmdline, packaged, plant_files=None, own_usr=False):
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
            return records(view, shown, dirs, Provenance(view, dirs, packaged(view)), View(root) if own_usr else None)
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
            return hashlib.md5(view.data(p)).hexdigest() in want[p]
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
            return lint(root, m, "", lambda view: packaged, own_usr=True)
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
