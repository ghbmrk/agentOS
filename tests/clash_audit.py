#!/usr/bin/env python3
"""No two unit-test units that run at the same time write one path or bind one address (CI-par-clash).

tools/unit_tests.py runs the tests/test*.py modules (and a split module's shards) several at a
time, each under `strace -f -y` into its own `<unit>.trace` (CI-PATHS). `clash_audit.py DIR`
reads those traces and fails when two units, neither of them in unit_tests.SERIAL, each
  - open one path for writing or creating (O_WRONLY, O_RDWR or O_CREAT; the file the open
    reached, else the path it asked for, so a create that failed because the other unit's file
    was there counts), or
  - bind one fixed address: an IP port other than 0 (any address, either protocol), or a Unix
    socket name, abstract or a path.
It names both units and the path, and points at unit_tests.SERIAL. The check reads every pair,
whether or not the two happened to overlap on this run, so it does not depend on timing.
A unique temporary path (tempfile's random names, an ephemeral port) never matches another
unit's, so it needs no exception; SHARED lists the paths built to be written by many processes
at once (devices, Python's bytecode cache, Go's build and module caches and telemetry
counters). tools/unit_tests.py turns off git's optional index lock, so the shared worktree's
.git/index.lock is written only by a git command that changes the index.
Not seen: a clash through something other than open or bind (a fixed directory made by mkdir
and only listed, a rename onto a fixed name, a lock taken with flock on a file opened read-only,
a connect to a server another unit started) or by a process outside the unit's tree (a daemon).
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir, "tools"))
import unit_tests  # noqa: E402

# One strace -f -y line: pid, call, rest. A call split by another process's ends
# `<unfinished ...>`; its result is on a later `<... call resumed>` line of the same pid.
_LINE = re.compile(r'^(\d+)\s+(open|openat|openat2|bind)\((.*)$')
_RESUMED = re.compile(r'^(\d+)\s+<\.\.\. (open|openat|openat2|bind) resumed>(.*)$')
_OPEN_ARGS = re.compile(r'^(?:[A-Z_\d]+<([^>]*)>, )?"((?:[^"\\]|\\.)*)", (.*)$')
_REACHED = re.compile(r'\) = \d+<([^>]*)>$')
_WRITE = re.compile(r'\bO_(?:WRONLY|RDWR|CREAT)\b')
_PORT = re.compile(r'sa_family=AF_INET6?, sin6?_port=htons\((\d+)\)')
_UNIX = re.compile(r'sa_family=AF_UNIX, sun_path=(@?)"((?:[^"\\]|\\.)*)"')
_UNFINISHED = " <unfinished ...>"


def _unquote(s):
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _flags(rest):
    """The flags argument and anything before the result: what follows the path."""
    return rest.split(") = ")[0].split(_UNFINISHED)[0]


def shared(path, home=None):
    """Whether path is built to be written by many processes at once."""
    home = home if home is not None else os.path.expanduser("~")
    if path in ("/dev/null", "/dev/tty", "/dev/full", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/ptmx"):
        return True
    if path.startswith(("/proc/", "/dev/pts/", "/dev/fd/", "/dev/shm/sem.")):
        return True
    # Python's bytecode cache: written to a temporary name, then renamed (importlib's _write_atomic).
    if re.search(r"/__pycache__/[^/]+\.pyc(\.\d+)?$", path):
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


def writes(trace):
    """The set of ('path', p) written or created and ('bind', name) bound in one strace -f -y log."""
    out = set()
    pending = {}

    def open_target(rest):
        m = _OPEN_ARGS.match(rest)
        if not m:
            return None, False
        base, path = m.group(1), _unquote(m.group(2))
        if not os.path.isabs(path) and base is not None:
            path = os.path.join(base, path)
        return os.path.normpath(path) if os.path.isabs(path) else path, bool(_WRITE.search(_flags(m.group(3))))

    def bound(args):
        port = _PORT.search(args)
        if port and port.group(1) != "0":
            return ("bind", f"port {port.group(1)}")
        unix = _UNIX.search(args)
        if unix and unix.group(2):
            name = _unquote(unix.group(2))
            return ("bind", f"unix @{name}") if unix.group(1) else ("path", os.path.normpath(name))
        return None
    for line in trace.splitlines():
        m = _LINE.match(line)
        if m:
            pid, call, rest = m.groups()
            if call == "bind":
                b = bound(rest)
                if b:
                    out.add(b)
                continue
            path, write = open_target(rest)
            if path is None or not write:
                continue
            if rest.endswith(_UNFINISHED):
                pending[pid] = path
                continue
            reached = _REACHED.search(rest)
            out.add(("path", os.path.normpath(reached.group(1)) if reached else path))
            continue
        r = _RESUMED.match(line)
        if r and r.group(2) != "bind" and r.group(1) in pending:
            asked = pending.pop(r.group(1))
            reached = _REACHED.search(r.group(3))
            out.add(("path", os.path.normpath(reached.group(1)) if reached else asked))
    return out


def clashes(traces, serial=None, is_shared=shared):
    """traces: {unit: strace text}. [(kind, name, unit_a, unit_b)] for every name two units
    outside serial both wrote or bound, units in name order."""
    serial = unit_tests.SERIAL if serial is None else serial
    seen = {}
    for unit in sorted(traces):
        if unit_tests.module_of(unit) in serial:
            continue
        for kind, name in writes(traces[unit]):
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
    traces = {}
    for name in sorted(os.listdir(d)):
        if name.endswith(".trace"):
            with open(os.path.join(d, name), errors="surrogateescape") as f:
                traces[name[:-len(".trace")]] = f.read()
    found = clashes(traces)
    for kind, name, a, b in found:
        print(f"::error::{a} and {b} both {'write' if kind == 'path' else 'bind'} {name}")
    if found:
        print("Units that run at the same time must not share a path or address: make each use its "
              "own (a tempfile directory, port 0), or put the module in tools/unit_tests.py SERIAL "
              "with its reason.", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
