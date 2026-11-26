#!/usr/bin/env python3
"""The tracked files the broker's Go tests read, measured, against ci_scope's RACE_READ (CI-race-scope).

broker-race skips its steps on a pull request whose every change is a record, or a modification
of a file outside ci_scope.RACE_READ and NEVER_BLIND (the base commit's copy decides). That is
sound only while no broker test, nor anything a test runs, touches a tracked file outside them.
This tool is the measurement: each shard runs its `go test` under `strace -f -y` (every file
syscall of every process, exec'd children included), and `audit` fails on a tracked file reached
outside RACE_READ and NEVER_BLIND, on a path it cannot place, on any read of git's object store
(it holds every file), and on a trace that ran no test binary or was cut short (fail closed).

Only tracked files count: a change can modify nothing else, and a modification leaves every
directory's listing and every file's type as they were (an addition, deletion or type change is
never race-blind), so a directory opened or a missing path probed reads nothing a race-blind
change alters. Paths outside the repository are not the tree's.

Usage:
  tools/race_reads.py run --trace FILE -- CMD...   CMD under strace, as the invoking user (see run())
  tools/race_reads.py audit --root DIR [--reads-out FILE] TRACE...
                                                   fail on a read outside the read set, printing each;
                                                   FILE gets every tracked file read, one per line
Standard library only.
"""
import argparse
import gzip
import os
import posixpath
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_scope  # noqa: E402

# The two git commands go's VCS stamp runs on a binary a test builds (cmd/go/internal/vcs), whose
# child go a test may start with an environment of its own, so GOFLAGS=-buildvcs=false misses it.
# Their output rests on no committed file's content: `status --porcelain` lists the worktree's
# differences from HEAD (none for a file as committed, whatever it holds), and `log -1` prints HEAD's
# id and time. So the reads of a process running exactly one of them, and of its threads, are not
# the tree's; any other git command that reads the object store fails the audit.
VCS_STAMP = ('["git", "status", "--porcelain"]', '["git", "-c", "log.showsignature=false", "log", "-1", "--format=%H:%ct"]')
_STAMP = re.compile(r'^"(?:[^"\\]|\\.)*/git", (?:' + "|".join(re.escape(v) for v in VCS_STAMP) + r')(?:, |\)| <unfinished)')
# The pseudo-syscall accesses() yields when the first process exits: its status is the raw field.
EXITED = "+++ exited"
# Clones that do not pass CLONE_FS give the child its own copy of the working directory.
CLONES = frozenset({"clone", "clone3", "fork", "vfork"})

_LINE = re.compile(r"^(\d+) +(?:(\w+)\((.*)|<\.\.\. (\w+) resumed>(.*))$")
_EXIT = re.compile(r"^(\d+) +\+\+\+ (?:exited with (\d+)|killed by .*) \+\+\+$")
_STR = r'"((?:[^"\\]|\\.)*)"'
_DIRFD = re.compile(r"^(AT_FDCWD|-?\d+)(?:<((?:[^>\\]|\\.)*)>)?, " + _STR)
_FIRST = re.compile(r"^" + _STR)
_RET = re.compile(r"\) += (-?\d+)")
# --decode-pids=pidns: a clone in a pid namespace returns that namespace's pid, and strace adds
# the one it prints the child under.
_CHILD = re.compile(r"\) += (\d+)(?: /\* (\d+) in strace's PID NS \*/)?$")
_RETFD = re.compile(r"\) += (\d+)<((?:[^>\\]|\\.)*)>$")
_FDDIR = re.compile(r"^-?\d+<((?:[^>\\]|\\.)*)>")


def _unescape(s):
    """strace's C-style escapes back to the path's bytes, as text (surrogateescape)."""
    out = bytearray()
    i = 0
    raw = s.encode("utf-8", "surrogateescape")
    simple = {ord("n"): 10, ord("t"): 9, ord("r"): 13, ord("v"): 11, ord("f"): 12, ord("\\"): 92, ord('"'): 34}
    while i < len(raw):
        c = raw[i]
        if c == 92 and i + 1 < len(raw):
            n = raw[i + 1]
            if n == ord("x") and i + 3 < len(raw) + 1:
                out.append(int(raw[i + 2:i + 4], 16))
                i += 4
                continue
            if 48 <= n <= 55:
                j = i + 1
                while j < len(raw) and j < i + 4 and 48 <= raw[j] <= 55:
                    j += 1
                out.append(int(raw[i + 1:j], 8))
                i = j
                continue
            if n in simple:
                out.append(simple[n])
                i += 2
                continue
        out.append(c)
        i += 1
    return out.decode("utf-8", "surrogateescape")


class Cwd:
    """A working directory that threads sharing CLONE_FS share; None when not yet known."""
    def __init__(self, path):
        self.path = path


def _events(lines):
    """(pid, syscall, args, resumed) for each whole call, an unfinished call joined to its resumed
    half (resumed True), and (pid, EXITED, status or None, False) for each process's exit (None:
    killed by a signal)."""
    pending = {}  # pid -> (syscall, args so far) of an <unfinished ...> line
    for line in lines:
        line = line.rstrip("\n")
        m = _LINE.match(line)
        if not m:
            e = _EXIT.match(line)
            if e:
                pending.pop(int(e.group(1)), None)
                yield int(e.group(1)), EXITED, e.group(2), False
            continue
        pid = int(m.group(1))
        if m.group(2):
            name, args = m.group(2), m.group(3)
            if args.endswith(" <unfinished ...>"):
                pending[pid] = (name, args[:-len(" <unfinished ...>")])
                continue
            yield pid, name, args, False
        else:
            prev = pending.pop(pid, (m.group(4), ""))
            yield pid, prev[0], prev[1] + m.group(5), True


def accesses(lines, start_cwd):
    """Yield (pid, syscall, absolute path or None, raw path) for each path a traced syscall named,
    and (first pid, EXITED, None, status) when the first process exits.

    lines are `strace -f -y -q` output with pids; start_cwd is the first process's working
    directory. A relative path is resolved against its dirfd's decoration, or against the
    process's working directory as the trace tracked it; None when neither is known (unresolved).
    A new process's calls wait until its parent's clone returns its pid (a vfork child chdirs
    and execs before that line), then run with the parent's working directory and descriptors."""
    cwds = {}  # pid -> Cwd, shared by processes that share CLONE_FS
    fds = {}  # pid -> {fd: path}, shared by processes that share CLONE_FILES
    stamp = set()  # pids running go's VCS-stamp git (VCS_STAMP), and their threads
    unborn = {}  # pid -> its events, until a clone returns it
    first = None

    def orphan(pid, evs):
        """A process no clone can be shown to have made: from an unknown working directory."""
        cwds[pid], fds[pid] = Cwd(None), {}
        stamp.discard(pid)
        for ev in evs:
            yield from run(pid, *ev)

    def segments(evs):
        """The events split after each exit: one process's life per part."""
        out, cur = [], []
        for ev in evs:
            cur.append(ev)
            if ev[0] == EXITED:
                out.append(cur)
                cur = []
        return out, cur

    def run(pid, name, args, resumed=False):
        if name == EXITED:
            # The pid is free again: a later process given it starts from its own clone.
            cwds.pop(pid, None)
            fds.pop(pid, None)
            stamp.discard(pid)
            if pid == first and args is not None:
                yield pid, EXITED, None, args
            return
        cell, table = cwds[pid], fds[pid]
        if name == "execve":
            if _STAMP.match(args):
                stamp.add(pid)
            else:
                stamp.discard(pid)
        if name in CLONES:
            r = _CHILD.search(args)
            if r and int(r.group(r.lastindex)) > 0 and int(r.group(r.lastindex)) not in cwds:
                # A live pid is never a new child.
                child = int(r.group(r.lastindex))
                lives, rest = segments(unborn.pop(child, []))
                if not resumed:
                    # A clone printed whole was made after every buffered life of its pid ended.
                    for life in lives:
                        yield from orphan(child, life)
                    lives = []
                # Unfinished across the child's first calls (vfork): the first buffered life is
                # this clone's child, which may already have exited; later lives wait for theirs.
                mine = lives[0] if lives else rest
                later = [ev for life in lives[1:] for ev in life] + (rest if lives else [])
                if later:
                    unborn[child] = later
                if pid in stamp:
                    stamp.add(child)
                clone = name in ("clone", "clone3")
                fds[child] = table if clone and "CLONE_FILES" in args else dict(table)
                cwds[child] = cell if clone and "CLONE_FS" in args else Cwd(cell.path)
                for ev in mine:
                    yield from run(child, *ev)
            return
        if name == "fchdir":
            d = _FDDIR.match(args)
            r = _RET.search(args)
            if r and r.group(1) == "0":
                cell.path = _unescape(d.group(1)) if d else table.get(int(args.split(",")[0].split("<")[0].strip(") ")))
            return
        if pid in stamp or name in ("symlink", "symlinkat"):
            return  # a link's first string is its content, not a path the call reaches
        d = _DIRFD.match(args)
        if d and (name.endswith("at") or name.endswith("at2") or name in ("statx", "execveat", "name_to_handle_at", "open_tree")):
            fd, base, raw = d.group(1), d.group(2), _unescape(d.group(3))
            if base is not None:
                base = _unescape(base)
                if fd == "AT_FDCWD":
                    cell.path = base
            elif fd == "AT_FDCWD":
                base = cell.path
            else:
                # -y prints no path for a directory whose path is past PATH_MAX: the path the
                # process opened that descriptor at, as this trace resolved it.
                base = table.get(int(fd))
        else:
            f = _FIRST.match(args)
            if not f:
                return
            raw, base = _unescape(f.group(1)), cell.path
        if raw.startswith("/"):
            path = posixpath.normpath(raw)
        elif base is not None:
            path = posixpath.normpath(posixpath.join(base, raw))
        else:
            path = None
        yield pid, name, path, raw
        # The file an open reached, links resolved: a link elsewhere in the tree that points
        # at a tracked file reads it under the link's own name.
        got = _RETFD.search(args)
        if got:
            real = posixpath.normpath(_unescape(got.group(2)))
            table[int(got.group(1))] = real
            if real != path:
                yield pid, name, real, raw
        elif name.startswith("open") or name == "creat":
            r = _RET.search(args)
            if r and int(r.group(1)) >= 0 and path is not None:
                table[int(r.group(1))] = path
        if name == "chdir":
            r = _RET.search(args)
            if r and r.group(1) == "0":
                cell.path = path

    for pid, name, args, resumed in _events(lines):
        if first is None:
            first = pid
            cwds[pid], fds[pid] = Cwd(start_cwd), {}
        if pid not in cwds or pid in unborn:
            unborn.setdefault(pid, []).append((name, args, resumed))
            continue
        yield from run(pid, name, args, resumed)
    # A process no traced clone returned: its calls run from an unknown working directory, which
    # an AT_FDCWD decoration later fills; a relative path before that is unresolved.
    while unborn:
        pid = next(iter(unborn))
        lives, rest = segments(unborn.pop(pid))
        for life in lives + ([rest] if rest else []):
            yield from orphan(pid, life)


def read_lines(paths):
    for p in paths:
        opener = gzip.open if p.endswith(".gz") else open
        with opener(p, "rt", encoding="utf-8", errors="surrogateescape") as f:
            yield from f


def tracked(root):
    """The repository's tracked paths (git ls-files), relative to root."""
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True, capture_output=True).stdout
    return {p for p in out.decode("utf-8", "surrogateescape").split("\0") if p}


def covered(rel, read=None):
    """Whether a tracked file read is one a race-blind change cannot touch."""
    read = ci_scope.RACE_READ if read is None else read
    return any(rel == e or e.endswith("/") and rel.startswith(e) for e in (*read, *ci_scope.NEVER_BLIND))


def audit(traces, root, read=None, files=None, start_cwd=None):
    """Return (problems, reads): problems are lines naming each failure; reads the tracked files
    the traces reached, relative to root. Each trace is one traced command, read on its own."""
    root = posixpath.normpath(root)
    files = tracked(root) if files is None else files
    problems, reads = [], set()
    for trace in traces:
        n = execs = 0
        exited = False
        for pid, name, path, raw in accesses(read_lines([trace]), start_cwd or posixpath.join(root, "broker")):
            if name == EXITED:
                exited = True
                continue
            n += 1
            if name == "execve" and raw.endswith(".test"):
                execs += 1
            if path is None:
                problems.append(f"unresolved: {name}({raw!r}) in process {pid}: its working directory is unknown")
                continue
            if path != root and not path.startswith(root + "/"):
                continue
            rel = posixpath.relpath(path, root)
            if rel == ".git" or rel.startswith(".git/"):
                if rel.startswith(".git/objects/"):
                    problems.append(f"git object store read: {name}({rel}): it holds every file")
                continue
            if rel not in files:
                continue
            reads.add(rel)
            if not covered(rel, read):
                problems.append(f"read outside RACE_READ: {name}({rel}); add it to tools/ci_scope.py RACE_READ")
        if not execs:
            problems.append(f"{trace}: no test binary ran ({n} path accesses): not a test trace")
        if not exited:
            problems.append(f"{trace}: the traced command's first process never exited in it: the trace was cut short")
    return problems, reads


def run(trace, cmd):
    """Run cmd under strace, writing the trace to `trace`; return its exit code.

    strace runs through sudo as root and runs cmd as the invoking user (-u), so setuid helpers
    the tests run (newuidmap, for the canary sandbox) keep their privilege under the trace, which
    a tracer of the same user would take away. The environment passes through whole."""
    strace = shutil.which("strace")
    if not strace:
        print("race_reads: strace is not installed", file=sys.stderr)
        return 2
    # -q, not -qq: the first process's exit line is the audit's proof the trace is whole. As in
    # tools/unit_tests.py: --kill-on-exit, so nothing runs on untraced if strace gives up (#5364).
    base = [strace, "-f", "-y", "-q", "--kill-on-exit", "--seccomp-bpf", "--decode-pids=pidns", "-e", "signal=none",
            "-e", "trace=%file,chdir,fchdir,clone,clone3,fork,vfork", "-o", trace]
    if os.geteuid() != 0:
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
        env = [f"{k}={v}" for k, v in os.environ.items()]
        full = ["sudo", "-n", "--", "env", "-i", *env, *base, "-u", user, "--", *cmd]
    else:
        full = [*base, "--", *cmd]
    return subprocess.call(full)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--trace", required=True)
    r.add_argument("command", nargs=argparse.REMAINDER)
    a = sub.add_parser("audit")
    a.add_argument("--root", required=True)
    a.add_argument("--cwd", help="the traced command's working directory (default ROOT/broker)")
    a.add_argument("--reads-out")
    a.add_argument("traces", nargs="+")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
        if not cmd:
            ap.error("run needs a command after --")
        return run(a.trace, cmd)
    root = os.path.realpath(a.root)
    problems, reads = audit(a.traces, root, start_cwd=os.path.realpath(a.cwd) if a.cwd else None)
    if a.reads_out:
        with open(a.reads_out, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.writelines(p + "\n" for p in sorted(reads))
    for p in sorted(set(problems)):
        print(p)
    print(f"race_reads: {len(reads)} repository paths read; {len(set(problems))} problems", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
