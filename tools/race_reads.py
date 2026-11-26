#!/usr/bin/env python3
"""The tracked files the broker's Go tests read, measured, against ci_scope's RACE_READ (CI-race-scope).

broker-race skips its steps on a pull request whose every change is a record, or a modification
of a file outside ci_scope.RACE_READ and NEVER_BLIND (the base commit's copy decides). That is
sound only while no broker test, nor anything a test runs, touches a tracked file outside them.
This tool is the measurement: each shard runs its `go test` with a bpftrace program attached to
the kernel's LSM hooks (program()), which logs every open, exec, stat, readlink and symlink
followed of a file under the repository and outside broker/, by any process of the command's
tree. `audit` fails on a tracked file reached outside RACE_READ and NEVER_BLIND, on any read of
git's object store (it holds every file), and on a trace that is not whole: one that did not run
from start to end, lost an event, missed a control access of each kind, or ran no test binary
(fail closed).

Only tracked files count: a change can modify nothing else, and a modification leaves every
directory's listing and every file's type and mode as they were (an addition, deletion, type or
mode change is never race-blind), so a directory opened or a missing path probed reads nothing a
race-blind change alters. Paths outside the repository are not the tree's.

Usage:
  tools/race_reads.py run --out FILE --root DIR -- CMD...   CMD with the tracer attached (sudo)
  tools/race_reads.py audit --root DIR [--reads-out FILE] TRACE...
                                       fail on a read outside the read set, printing each;
                                       FILE gets every tracked file read, one per line
Standard library only.
"""
import argparse
import gzip
import os
import posixpath
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_scope  # noqa: E402

# The hooks traced, by the kind letter a trace line carries, with the dentry each names. Every
# open goes through security_file_open (do_dentry_open: open, openat2, io_uring, exec's own open,
# an overlay's open of its real file); every stat through security_inode_getattr (vfs_getattr);
# readlink and each symlink a path walk follows through the other two. They are called across
# compilation units, so unlike vfs_getattr (which fentry saw no call of on the runner) no caller
# inlines them. A kernel probe makes no ptrace stop: strace's stops doubled broker-race's time.
HOOKS = (("o", "open", "security_file_open", "args->file->f_path.dentry"),
         ("s", "stat", "security_inode_getattr", "args->path->dentry"),
         ("l", "readlink", "security_inode_readlink", "args->dentry"),
         ("f", "follow_link", "security_inode_follow_link", "args->dentry"))
KINDS = {k: name for k, name, _, _ in HOOKS}
# run() makes one access of each kind once the tracer is attached: the audit's proof that each
# hook fires. The link is untracked and made fresh; the audit needs only its name.
CONTROL = "tools/race_reads.py"
CONTROL_LINK = ".race-reads-control/link"
CONTROLS = {("o", CONTROL), ("s", CONTROL), ("l", CONTROL_LINK), ("f", CONTROL_LINK)}
LEVELS = 16  # how far up from a file the probe looks for root; deeper tracked files fail the audit
NAMELEN = 64  # bpftrace's string length for one path part; a part this long may be cut short
RB_PAGES = 2048  # each CPU's output buffer, 8 MiB: a lost event fails the trace
TREE_KEYS = 1 << 18  # room for the command's processes; an insert that does not fit fails the trace

# The two git commands go's VCS stamp runs on a binary a test builds (cmd/go/internal/vcs), whose
# child go a test may start with an environment of its own, so GOFLAGS=-buildvcs=false misses it.
# Their output rests on no committed file's content: `status --porcelain` lists the worktree's
# differences from HEAD (none for a file as committed, whatever it holds), and `log -1` prints HEAD's
# id and time. So the accesses of a process a go process execs as exactly one of them are not the
# tree's (program() marks it at the exec); any other git that reads the object store fails.
VCS_STAMP = (("git", "status", "--porcelain"),
             ("git", "-c", "log.showsignature=false", "log", "-1", "--format=%H:%ct"))


def _argv_is(argv):
    """The new image's argv is exactly these strings, read where exec laid them out: one after
    another from mm->arg_start, each ending in a NUL, arg_end just past the last. The total length
    is tested first, so every string read lies inside the argument area."""
    tests, off = [f"$n == {sum(len(a) + 1 for a in argv)}"], 0
    for a in argv:
        tests.append(f'str(uptr($a + {off}), {len(a) + 1}) == "{a}"')
        off += len(a) + 1
    return " && ".join(tests)


def program(ino, dev, seed):
    """The bpftrace program: for each hook, a file under the directory with inode `ino` on the
    filesystem with (kernel) device `dev`, outside its broker/, reached by a process descended from
    pid `seed`. The probe walks d_parent from the file to root and prints the path's parts, leaf
    first, one line each ("C tid i name"), then "E kind tid pid parts"; the dentry walk gives the
    file's place in its filesystem, so a bind mount or a sandbox's root does not hide it. Each exec
    in the tree prints "X pid stamped parent-comm argv-bytes filename". Go's VCS-stamp git (VCS_STAMP) prints nothing."""
    ino, dev, seed = int(ino), int(dev), int(seed)
    walk = "\n".join(f"  $d{i + 1} = $d{i}->d_parent;" for i in range(LEVELS))
    find = "\n  else ".join(f"if ($d{i}->d_inode->i_ino == {ino} && $d{i}->d_sb->s_dev == {dev}) {{ $k = {i}; }}"
                            for i in range(1, LEVELS + 1))
    top = "\n    ".join(f"if ($k == {i + 1}) {{ $top = $d{i}; }}" for i in range(LEVELS))
    parts = "\n      ".join(f'if ($k > {i}) {{ printf("C %d {i} %s\\n", tid, str($d{i}->d_name.name, {NAMELEN})); }}'
                            for i in range(LEVELS))
    stamp = " ||\n       ".join(f"({_argv_is(v)})" for v in VCS_STAMP)
    probes = "".join(f"""
fentry:{fn} /@tree[pid] && @stamp[pid] == 0/ {{
  $d0 = {dentry};
{walk}
  $k = 0;
  {find}
  if ($k > 0) {{
    $top = $d0;
    {top}
    if (str($top->d_name.name, {NAMELEN}) != "broker") {{
      {parts}
      printf("E {k} %d %d %d\\n", tid, pid, $k);
    }}
  }}
}}""" for k, _, fn, dentry in HOOKS)
    return f"""
BEGIN {{ @tree[{seed}] = 1; printf("START\\n"); }}
tracepoint:task:task_newtask /@tree[pid] && (args->clone_flags & 0x10000) == 0/ {{
  @tree[args->pid] = 1;
  if (@tree[args->pid] == 0) {{ printf("FULL\\n"); }}
}}
tracepoint:sched:sched_process_exec /@tree[pid]/ {{
  $a = curtask->mm->arg_start;
  $n = curtask->mm->arg_end - $a;
  if (curtask->real_parent->comm == "go" &&
      ({stamp})) {{
    @stamp[pid] = 1;
  }} else {{
    delete(@stamp[pid]);
  }}
  printf("X %d %d %s %d %s\\n", pid, @stamp[pid], curtask->real_parent->comm, $n, str(args->filename));
}}
tracepoint:sched:sched_process_exit /pid == tid/ {{ delete(@stamp[pid]); }}{probes}
END {{ clear(@tree); clear(@stamp); printf("END\\n"); }}
"""


def kernel_dev(st_dev):
    """A stat's st_dev as the kernel's s_dev holds it (MKDEV: major << 20 | minor)."""
    return os.major(st_dev) << 20 | os.minor(st_dev)


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


def judge(name, path, root, files, read, problems, reads):
    """Record one access of an absolute path: a tracked file outside the read set, or any read of
    git's object store, is a problem."""
    if path != root and not path.startswith(root + "/"):
        return
    rel = posixpath.relpath(path, root)
    if rel == ".git" or rel.startswith(".git/"):
        if rel.startswith(".git/objects/"):
            problems.append(f"git object store read: {name}({rel}): it holds every file")
        return
    if rel not in files:
        return
    reads.add(rel)
    if not covered(rel, read):
        problems.append(f"read outside RACE_READ: {name}({rel}); add it to tools/ci_scope.py RACE_READ")


def events(lines):
    """("access", kind, rel), ("exec", filename) or ("problem", text) for each event of one trace;
    rel is the path below root. A trace that did not start or end, lost events, filled its process
    map, or has a path whose parts did not all arrive or may be cut short yields a problem."""
    started = ended = False
    parts = {}  # tid -> {index: name}
    for line in lines:
        line = line.rstrip("\n")
        if not started:  # bpftrace's own messages before BEGIN; nothing is traced yet
            started = line == "START"
            continue
        if line == "END" and not ended:
            ended = True
        elif ended and line:
            yield "problem", f"trace: a line after END: {line!r}"
        elif line.startswith("C "):
            f = line.split(" ", 3)
            if len(f) == 4 and f[1].isdigit() and f[2].isdigit() and f[3]:
                parts.setdefault(f[1], {})[int(f[2])] = f[3]
            else:
                yield "problem", f"trace: unreadable line {line!r}"
        elif line.startswith("E "):
            f = line.split(" ")
            if not (len(f) == 5 and f[1] in KINDS and all(x.isdigit() for x in f[2:])):
                yield "problem", f"trace: unreadable line {line!r}"
                continue
            got, k = parts.pop(f[2], {}), int(f[4])
            if sorted(got) != list(range(k)):
                yield "problem", f"trace: process {f[3]} reached a path whose parts did not all arrive ({sorted(got)} of {k})"
            elif any(len(n.encode("utf-8", "surrogateescape")) >= NAMELEN - 1 for n in got.values()):
                yield "problem", f"trace: a path part may be cut short at {NAMELEN} bytes: {got}"
            else:
                yield "access", f[1], "/".join(got[i] for i in reversed(range(k)))
        elif (line.startswith("X ") and len(f := line.split(" ", 5)) == 6 and f[1].isdigit()
              and f[2] in ("0", "1") and f[4].isdigit()):
            yield "exec", f[5]
        elif line == "FULL":
            yield "problem", f"trace: the process map is full ({TREE_KEYS} keys): a process went untraced"
        elif line:
            yield "problem", f"trace: unexpected line {line!r} (lost events, or an error)"
    if parts:
        yield "problem", f"trace: path parts with no end line, from threads {sorted(parts)}"
    if not started or not ended:
        yield "problem", "trace: the tracer did not run from start to end"


def too_deep(files):
    """Tracked files outside broker/ deeper than the probe looks: their accesses would go unseen."""
    return sorted(f for f in files if not f.startswith("broker/") and f.count("/") + 1 >= LEVELS)


def audit(traces, root, read=None, files=None):
    """Return (problems, reads): problems are lines naming each failure; reads the tracked files
    the traces reached, relative to root. Each trace is one traced command, read on its own."""
    root = posixpath.normpath(root)
    files = tracked(root) if files is None else files
    problems, reads = [], set()
    for f in too_deep(files):
        problems.append(f"tracked file deeper than the probe looks ({LEVELS} parts): {f}")
    for trace in traces:
        seen, tests = set(), 0
        for ev in events(read_lines([trace])):
            if ev[0] == "problem":
                problems.append(f"{trace}: {ev[1]}")
            elif ev[0] == "exec":
                tests += ev[1].endswith(".test")
            else:
                seen.add(ev[1:])
                judge(KINDS[ev[1]], posixpath.join(root, ev[2]), root, files, read, problems, reads)
        for kind, rel in sorted(CONTROLS - seen):
            problems.append(f"{trace}: the control {KINDS[kind]} of {rel} is missing: the tracer did not see that hook")
        if not tests:
            problems.append(f"{trace}: no test binary ran: not a test trace")
    return problems, reads


def controls(root):
    """One access of each traced kind, of the files CONTROLS names."""
    with open(os.path.join(root, CONTROL), "rb") as f:
        f.read(1)
    os.stat(os.path.join(root, CONTROL))
    link = os.path.join(root, CONTROL_LINK)
    shutil.rmtree(os.path.dirname(link), ignore_errors=True)
    os.mkdir(os.path.dirname(link))
    try:
        os.symlink("missing", link)
        os.readlink(link)
        os.path.exists(link)  # follows the link to its missing target
    finally:
        shutil.rmtree(os.path.dirname(link), ignore_errors=True)


def run(out, root, cmd, wait=120):
    """Run cmd with the tracer attached, writing the trace to `out`; return cmd's exit code, or 2
    when the tracer never started. bpftrace runs as root (sudo unless already root) and cmd as
    this process, untraced by ptrace, so setuid helpers the tests run keep their privilege. The
    tracer's own messages go to `out` too, so the audit sees a lost event."""
    bpftrace = shutil.which("bpftrace")
    if not bpftrace:
        print("race_reads: bpftrace is not installed", file=sys.stderr)
        return 2
    root = os.path.realpath(root)
    sudo = [] if os.geteuid() == 0 else ["sudo", "-n", "--"]
    st = os.stat(root)
    prog = program(st.st_ino, kernel_dev(st.st_dev), os.getpid())
    with open(out, "wb") as f:
        tracer = subprocess.Popen([*sudo, "env", f"BPFTRACE_MAX_MAP_KEYS={TREE_KEYS}", f"BPFTRACE_PERF_RB_PAGES={RB_PAGES}", bpftrace, "-e", prog],
                                  stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        deadline = time.monotonic() + wait
        while True:
            with open(out, "rb") as f:
                if b"START\n" in f.read():
                    break
            if tracer.poll() is not None or time.monotonic() > deadline:
                with open(out, "rb") as f:
                    said = f.read()[-4000:].decode("utf-8", "replace")
                print(f"race_reads: the tracer did not start; it said:\n{said}", file=sys.stderr)
                return 2
            time.sleep(0.2)
        controls(root)
        return subprocess.call(cmd)
    finally:
        if tracer.poll() is None:
            # SIGINT runs the program's END block; sudo passes it on to bpftrace.
            if sudo:
                subprocess.call([*sudo, "kill", "-INT", str(tracer.pid)])
            else:
                os.kill(tracer.pid, signal.SIGINT)
        try:
            tracer.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            tracer.kill()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", required=True)
    r.add_argument("--root", required=True, help="the repository root the tracer keeps")
    r.add_argument("command", nargs=argparse.REMAINDER)
    a = sub.add_parser("audit")
    a.add_argument("--root", required=True)
    a.add_argument("--reads-out")
    a.add_argument("traces", nargs="+")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
        if not cmd:
            ap.error("run needs a command after --")
        return run(a.out, a.root, cmd)
    root = os.path.realpath(a.root)
    problems, reads = audit(a.traces, root)
    if a.reads_out:
        with open(a.reads_out, "w", encoding="utf-8", errors="surrogateescape") as f:
            f.writelines(p + "\n" for p in sorted(reads))
    for p in sorted(set(problems)):
        print(p)
    print(f"race_reads: {len(reads)} repository paths read; {len(set(problems))} problems", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
