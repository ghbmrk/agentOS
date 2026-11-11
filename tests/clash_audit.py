#!/usr/bin/env python3
"""No two unit-test modules that run at the same time write one path or bind one address (CI-par-clash).

tools/unit_tests.py runs the tests/test*.py modules several at a time, each under `strace -f -y`
into its own `<module>.trace`, and a run strace cut short into `<module>.trace.cut` (CI-PATHS).
`clash_audit.py DIR` reads both, as one module's, and fails when two modules, neither of them in
unit_tests.SERIAL, each
  - open one path for writing or creating (O_WRONLY, O_RDWR or O_CREAT; the file the open
    reached, else the path it asked for, so a create that failed because the other module's
    file was there counts), or unlink, rename (either name) or truncate it, whatever the result, or
  - bind one fixed address: an IP port other than 0 (any address, either protocol), or a Unix
    socket name, abstract or a path.
A path the kernel did not resolve for us (a failed or cut-off open, a socket path) is resolved as
the kernel walked it when the trace was taken: from the directory fd or the process's cwd, `..`
and symlinks followed in each parent component, and in the final one unless the call makes that
name (O_EXCL, O_NOFOLLOW, bind, unlink, rename), through the links the module's own tree made before that call
(symlink and symlinkat, traced), then through links on disk for names the tree never made a link
at. A failed create through a symlinked directory so names the real file.
It names both modules and the path, and points at unit_tests.SERIAL. The check reads every
pair, whether or not the two happened to overlap on this run, so it does not depend on timing.
A unique temporary path (tempfile's random names, an ephemeral port) never matches another
module's, so it needs no exception; shared() lists the paths built to be written by many
processes at once (devices, Python's bytecode cache, Go's build and module caches and telemetry
counters). tools/unit_tests.py turns off git's optional index lock, so the shared worktree's
.git/index.lock is written only by a git command that changes the index.
Not seen: a clash through something other than open or bind (a fixed directory made by mkdir
and only listed, a lock taken with flock on a file opened read-only,
a connect to a server another module started), by a process outside the module's tree (a
daemon), or between the tests of one SPLIT module, whose workers share one trace (CI-par-3).
Not resolved: a link that is gone by the audit and was made outside the module's tree or put in
place by rename, a link name removed and reused in the same tree, and a relative name from a
process whose cwd its trace never showed (a forked child before its first call with AT_FDCWD).
A thread's cwd is the last one its own lines showed: a chdir by another thread of its process
reaches it at its next AT_FDCWD call. Each unresolved call also counts its path as asked, `..`
folded, so a stale or reused link name can add a name but never drop the one main read.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir, "tools"))
import unit_tests  # noqa: E402

# One strace -f -y line: pid, call, rest. A call split by another process's ends
# `<unfinished ...>`; its result is on a later `<... call resumed>` line of the same pid.
_CALLS = "open|openat|openat2|bind|symlink|symlinkat|chdir|fchdir|unlink|unlinkat|rename|renameat|renameat2|truncate"
_LINE = re.compile(rf'^(\d+)\s+({_CALLS})\((.*)$')
_RESUMED = re.compile(rf'^(\d+)\s+<\.\.\. ({_CALLS}) resumed>(.*)$')
_STR = r'"((?:[^"\\]|\\.)*)"'
_DIRFD = r'[A-Z_\d]+<([^>]*)>'
_OPEN_ARGS = re.compile(rf'^(?:{_DIRFD}, )?{_STR}, (.*)$')
_SYMLINK_ARGS = re.compile(rf'^{_STR}, (?:{_DIRFD}, )?{_STR}')
# unlink and truncate's one name, rename's two, each after its directory fd if the call takes one.
_NAMES_ARGS = re.compile(rf'^(?:{_DIRFD}, )?{_STR}(?:, (?:{_DIRFD}, )?{_STR})?')
_CHDIR_ARGS = re.compile(rf'^(?:{_STR}|\d+<([^>]*)>)')
# The cwd strace shows as a call's AT_FDCWD: openat's first argument, symlinkat's second.
_CWD = re.compile(rf'^(?:{_STR}, )?AT_FDCWD<([^>]*)>')
_OK = re.compile(r'\)\s+= 0$')
# strace pads a short result to a column: `)             = 3</path>`, on every resumed line.
_REACHED = re.compile(r'\)\s+= \d+<([^>]*)>$')
_RESULT = re.compile(r'\)\s+= ')
_WRITE = re.compile(r'\bO_(?:WRONLY|RDWR|CREAT)\b')
_NOFOLLOW = re.compile(r'\bO_(?:EXCL|NOFOLLOW)\b')
_PORT = re.compile(r'sa_family=AF_INET6?, sin6?_port=htons\((\d+)\)')
_UNIX = re.compile(r'sa_family=AF_UNIX, sun_path=(@?)"((?:[^"\\]|\\.)*)"')
_UNFINISHED = " <unfinished ...>"


_ESC = {"n": b"\n", "t": b"\t", "r": b"\r", "v": b"\v", "f": b"\f"}


def _decode(s):
    r"""A path as strace prints it, quoted or after -y's `<`, back to the name: `\\`, `\"`, `\n`
    and the like, `\ooo` octal (-y writes `<` and `>` as `\74` and `\76`) and `\xHH`. The asked
    path and the reached one must decode alike, or one file reads as two names."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n in "01234567":
                j = i + 1
                while j < len(s) and j < i + 4 and s[j] in "01234567":
                    j += 1
                out.append(int(s[i + 1:j], 8) & 0xFF)
                i = j
                continue
            if n == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 2:i + 4]):
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            out += _ESC.get(n, n.encode("utf-8", "surrogateescape"))
            i += 2
            continue
        out += c.encode("utf-8", "surrogateescape")
        i += 1
    return out.decode("utf-8", "surrogateescape")


def _flags(rest):
    """The flags argument and anything before the result: what follows the path."""
    return _RESULT.split(rest)[0].split(_UNFINISHED)[0]


def shared(path, home=None):
    """Whether path is built to be written by many processes at once."""
    home = home if home is not None else os.path.expanduser("~")
    if path in ("/dev/null", "/dev/tty", "/dev/full", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/ptmx"):
        return True
    if path.startswith(("/proc/", "/dev/pts/", "/dev/fd/")):
        return True
    # Python's bytecode cache: importlib's own names, written to a temporary name and renamed
    # (_write_atomic); any other file a test writes there is not exempt.
    if re.search(r"/__pycache__/[^/.]+\.cpython-\d+(\.opt-\d)?\.pyc(\.\d+)?$", path):
        return True
    # Go's build and module caches (content-addressed, locked for concurrent go commands) and its
    # telemetry counters (memory-mapped files every go command adds to at once).
    config = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    for cache in (os.environ.get("GOCACHE"), os.path.join(home, ".cache", "go-build"),
                  os.environ.get("GOMODCACHE"), os.path.join(home, "go", "pkg", "mod"),
                  os.path.join(config, "go", "telemetry")):
        if cache and (path == cache or path.startswith(cache.rstrip("/") + "/")):
            return True
    return False


def _ondisk(path):
    """The target of the symlink at path on disk now, or None. /proc's links name the
    auditing process's own fds and pid, not the traced one's, so they are not followed."""
    if path == "/proc" or path.startswith("/proc/"):
        return None
    try:
        return os.readlink(path)
    except OSError:
        return None


def walk(path, link_of, last=False):
    """path (absolute) as the kernel walks it: `.` and `..` taken in order, and every parent
    component that link_of(name) gives a target for replaced by it (relative to its directory),
    up to the kernel's 40 links. The final component is followed only if last: an open without
    O_EXCL or O_NOFOLLOW, and chdir, follow it; an O_EXCL create, a bind and a symlink make that
    name. Past 40 links the call failed with ELOOP, and the name is as asked."""
    done, todo, hops = "/", [c for c in reversed(path.split("/")) if c], 0
    while todo:
        c = todo.pop()
        if c == ".":
            continue
        if c == "..":
            done = os.path.dirname(done)
            continue
        name = os.path.join(done, c)
        target = link_of(name) if todo or last else None
        if target is None:
            done = name
            continue
        hops += 1
        if hops > 40:
            return os.path.normpath(path)
        if target.startswith("/"):
            done = "/"
        todo.extend(c for c in reversed(target.split("/")) if c)
    return done


def writes(trace, ondisk=_ondisk):
    """The set of ('path', p) written or created and ('bind', name) bound in one strace -f -y log.
    ondisk(name) gives a symlink's target on disk, read only for a name the trace's own symlink
    calls never make: a link the tree made after a call was not there when the call walked it.
    One pass reads the trace; only if it read from disk a name the tree made (before or after)
    does a second pass read it again, with no disk read for those names."""
    out, tree = _scan(trace, _Tree(ondisk))
    if not tree.links.keys() & tree.from_disk.keys():
        return out
    made = set(tree.links)
    return _scan(trace, _Tree(lambda name: None if name in made else ondisk(name)))[0]


def as_main(path, base):
    """The name main's audit read for an open: joined only to a dirfd, `..` folded only if
    absolute (a relative name with no dirfd stays as asked; every module runs from the root)."""
    if not os.path.isabs(path) and base is not None:
        path = os.path.join(base, path)
    return os.path.normpath(path) if os.path.isabs(path) else path


class _Tree:
    """One module's process tree as its trace showed it up to the line read: each pid's working
    directory, and the links (resolved name -> target) its symlink calls made, in order."""

    def __init__(self, ondisk):
        self.ondisk, self.links, self.cwd, self.from_disk = ondisk, {}, {}, {}

    def link_of(self, name):
        if name in self.links:
            return self.links[name]
        if name not in self.from_disk:
            self.from_disk[name] = self.ondisk(name)
        return self.from_disk[name]

    def resolve(self, pid, path, base=None, last=False):
        """The name path (decoded) reaches, from base (a dirfd's path), else the pid's cwd. A
        relative path with neither is returned as is."""
        base = base if base is not None else self.cwd.get(pid)
        if not os.path.isabs(path):
            if base is None:
                return path
            path = os.path.join(base, path)
        return walk(path, self.link_of, last)

    def asked(self, pid, path, base, last, main):
        """The names an unresolved call may have reached: the walk, and main, the name main's
        audit read for it, so a stale link or a cwd the trace showed wrongly can add a name but
        never lose that one."""
        return {("path", self.resolve(pid, path, base, last)), ("path", main)}

    def made(self, pid, call, rest):
        """The effect of a symlink, symlinkat, chdir or fchdir line, once its result is 0."""
        if call.startswith("symlink"):
            m = _SYMLINK_ARGS.match(rest)
            if m:
                base = m.group(2) and _decode(m.group(2))
                name = self.resolve(pid, _decode(m.group(3)), base)
                if os.path.isabs(name):
                    self.links[name] = _decode(m.group(1))
            return
        m = _CHDIR_ARGS.match(rest)
        if m and m.group(1) is not None:
            to = self.resolve(pid, _decode(m.group(1)), last=True)
            if os.path.isabs(to):
                self.cwd[pid] = to
        elif m:
            self.cwd[pid] = _decode(m.group(2))


def _write_open(tree, pid, rest):
    """The names a write open asked for, walked, or None for an open that writes nothing. Only
    an open the kernel gave no file for is walked; a resolved one is its reached file. The result
    is read only after the quoted path, since a name can hold `) = 3<` (a split line has none)."""
    m = _OPEN_ARGS.match(rest)
    if not m or not _WRITE.search(_flags(m.group(3))):
        return None
    reached = _REACHED.search(m.group(3))
    if reached:
        return {("path", os.path.normpath(_decode(reached.group(1))))}
    base, path = m.group(1) and _decode(m.group(1)), _decode(m.group(2))
    return tree.asked(pid, path, base, not _NOFOLLOW.search(_flags(m.group(3))), as_main(path, base))


def _named(tree, pid, call, rest):
    """The names an unlink, rename or truncate changes, asked for and walked: truncate follows
    its final component, the others act on the name itself. A call with no directory fd shows
    no cwd, so its name as asked joins the cwd the pid's own lines last showed."""
    m = _NAMES_ARGS.match(rest)
    out = set()
    for base, path in ((m.group(1), m.group(2)), (m.group(3), m.group(4))) if m else ():
        if path is not None:
            base, path = base and _decode(base), _decode(path)
            main = as_main(path, base if base is not None else tree.cwd.get(pid))
            out |= tree.asked(pid, path, base, call == "truncate", main)
    return out


def _bound(tree, pid, args):
    port = _PORT.search(args)
    if port and port.group(1) != "0":
        return {("bind", f"port {port.group(1)}")}
    unix = _UNIX.search(args)
    if unix and unix.group(2):
        name = _decode(unix.group(2))
        if unix.group(1):
            return {("bind", f"unix @{name}")}
        return tree.asked(pid, name, None, False, os.path.normpath(name))
    return set()


def _scan(trace, tree):
    """(writes, tree), reading trace in order into tree."""
    out = set()
    pending = {}  # pid -> (call, rest) of a symlink or chdir, or (call, None) of a write open, split
    for line in trace.splitlines():
        m = _LINE.match(line)
        if m:
            pid, call, rest = m.groups()
            at = _CWD.match(rest)
            if at:
                tree.cwd[pid] = _decode(at.group(2))
            if call in ("symlink", "symlinkat", "chdir", "fchdir"):
                if rest.endswith(_UNFINISHED):
                    pending[pid] = (call, rest)
                elif _OK.search(rest):
                    tree.made(pid, call, rest)
            elif call == "bind":
                out |= _bound(tree, pid, rest)
            elif not call.startswith("open"):
                out |= _named(tree, pid, call, rest)
            else:
                names = _write_open(tree, pid, rest)
                if names is not None:
                    # A split open's asked path counts even if the call never resumes (the process
                    # was killed mid-open); the resumed line adds the file it reached.
                    out |= names
                    if rest.endswith(_UNFINISHED):
                        pending[pid] = (call, None)
            continue
        r = _RESUMED.match(line)
        if r and r.group(1) in pending:
            call, rest = pending.pop(r.group(1))
            if rest is not None:
                if _OK.search(r.group(3)):
                    tree.made(r.group(1), call, rest)
                continue
            reached = _REACHED.search(r.group(3))
            if reached:
                out.add(("path", os.path.normpath(_decode(reached.group(1)))))
    return out, tree


def clashes(traces, serial=None, is_shared=shared, cut=None):
    """traces: {module: strace text}; cut: {module: the trace of its attempt strace cut short},
    whose writes are the module's too (#5413). [(kind, name, module_a, module_b)] for every name
    two modules outside serial both wrote or bound, in name order."""
    serial = unit_tests.SERIAL if serial is None else serial
    cut = cut or {}
    seen = {}
    for unit in sorted(traces):
        if unit in serial:
            continue
        for kind, name in writes(traces[unit]) | writes(cut.get(unit, "")):
            if kind == "path" and is_shared(name):
                continue
            seen.setdefault((kind, name), []).append(unit)
    out = []
    for (kind, name), who in sorted(seen.items()):
        for i, a in enumerate(who):
            for b in who[i + 1:]:
                out.append((kind, name, a, b))
    return out


def main(argv):
    d = argv[1]
    traces, cut = {}, {}
    for name in sorted(os.listdir(d)):
        for suffix, into in ((".trace", traces), (unit_tests.CUT, cut)):
            if name.endswith(suffix):
                with open(os.path.join(d, name), errors="surrogateescape") as f:
                    into[name[:-len(suffix)]] = f.read()
    missing = [m for m in unit_tests.modules() if m not in traces]
    for m in missing:
        print(f"::error::{m} has no trace in {d}: nothing to check it against")
    go = os.path.normpath(os.path.abspath(unit_tests.go_dir(d))) + "/"  # the Go caches every module's user shares (unit_tests.env)
    found = clashes(traces, cut=cut, is_shared=lambda path: shared(path) or os.path.normpath(path).startswith(go))
    for kind, name, a, b in found:
        print(f"::error::{a} and {b} both {'write' if kind == 'path' else 'bind'} {name}")
    if found:
        print("Modules that run at the same time must not share a path or address: make each use its "
              "own (a tempfile directory, port 0), or put the module in tools/unit_tests.py SERIAL "
              "with its reason.", file=sys.stderr)
    return 1 if found or missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
