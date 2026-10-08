#!/usr/bin/env python3
"""Dependency audit harness (spec A9, DEP-1–4).

run     Run each registered scenario (boot, take STOP/STATUS, recover) with every
        optional dependency removed: a fresh network namespace with only
        loopback, DNS answered NXDOMAIN by a logging sink, and every connect /
        send syscall of the scenario's process tree logged by strace. The run
        fails if the scenario fails offline, or if it attempts any non-loopback
        traffic, any DNS lookup, any host-wide Unix socket (which would carry
        traffic out of the namespace), or anything matching a forbidden pattern.
static  Every network endpoint literal in shipping code (broker/, src/) must be
        declared in assurance/dependencies.json with its spec §2 class, and none
        may match a forbidden (AgentOS-operated) pattern.

Usage:
  depaudit.py static [--manifest F]
  depaudit.py run --targets assurance/dep-targets.json [--manifest F] [--report F]
"""
import argparse
import collections
import contextlib
import errno
import fnmatch
import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "assurance" / "dependencies.json"
CLASSES = ("inherent", "commodity", "optional")
PROFILES = {"offline": frozenset(), "full": frozenset(CLASSES)}
# Socket calls, plus every way to make a path inside the work directory lead
# somewhere else (links, mounts). '?' tolerates names an older strace lacks.
_LINKS = ("symlink", "symlinkat", "link", "linkat")
_MOUNTS = ("mount", "umount2", "open_tree", "move_mount", "fsopen", "fsmount", "pivot_root")
TRACED = ",".join(("connect", "sendto", "sendmsg", "sendmmsg") + tuple("?" + n for n in _LINKS + _MOUNTS))

SHIPPING_DIRS = ("broker", "src")
CODE_SUFFIXES = {".go", ".py", ".rs", ".c", ".h", ".ts", ".js", ".sh", ".toml", ".json", ".yaml", ".yml", ".conf"}
URL = re.compile(r"\b(https?|wss?|ftps?|grpcs?|tcp|udp|ntp)://[^\s\"'`<>()\[\]{}\\,]+", re.I)
COMMENT_STARTS = ("//", "#", "*", "/*", "--", ";")
LOCAL_NAMES = ("localhost", "*.localhost", "*.local", "*.home.arpa")
DOC_NAMES = ("example.com", "example.net", "example.org", "*.example.com", "*.example.net",
             "*.example.org", "*.example", "*.test", "*.invalid")

Event = collections.namedtuple("Event", "pid syscall family addr port")
Manifest = collections.namedtuple("Manifest", "forbidden endpoints inert", defaults=((),))

_LINE = re.compile(r"^(?:(\d+)\s+)?(\w+)\(")
_SOCKADDR = re.compile(r"\{sa_family=AF_(\w+)([^{}]*)\}")
_V4 = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
_V6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
_UNIX = re.compile(r'sun_path=(@?)"((?:[^"\\]|\\.)*)"')
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


# ---- parsing ------------------------------------------------------------------

# Families that stay inside the sandbox's network namespace. Anything else
# (AF_VSOCK is not namespaced, AF_PACKET, ...) is a violation: fail closed.
_NAMESPACED = {"NETLINK", "UNSPEC"}


def parse_strace(text):
    events = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        pid, syscall = m.group(1), m.group(2)
        if syscall in _MOUNTS:
            events.append(Event(pid, syscall, "mount", syscall, None))
            continue
        if syscall in _LINKS:
            # symlink*: first string is the link's target; link*: the existing path.
            strings = _QUOTED.findall(line)
            src = strings[0] if strings else "?"
            if syscall == "linkat" and not line[m.end():].startswith("AT_FDCWD"):
                src = "<dirfd>/" + src if not src.startswith("/") else src
            events.append(Event(pid, syscall, "link", src, None))
            continue
        found = _SOCKADDR.findall(line)
        for fam, body in found:
            v4, v6, unix = _V4.search(body), _V6.search(body), _UNIX.search(body)
            if fam == "INET" and v4:
                events.append(Event(pid, syscall, "inet", v4.group(2), int(v4.group(1))))
            elif fam == "INET6" and v6:
                events.append(Event(pid, syscall, "inet6", v6.group(2), int(v6.group(1))))
            elif fam == "UNIX" and unix:
                events.append(Event(pid, syscall, "abstract" if unix.group(1) else "unix", unix.group(2), None))
            elif fam in _NAMESPACED:
                continue
            elif fam in ("INET", "INET6", "UNIX"):
                events.append(Event(pid, syscall, "unparsed", "AF_" + fam, None))
            else:
                events.append(Event(pid, syscall, "other", "AF_" + fam, None))
        if line.count("sa_family=") > len(found):
            events.append(Event(pid, syscall, "unparsed", "sockaddr", None))
    return events


def _question(q):
    i, labels = 12, []
    while i < len(q) and q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode(errors="replace"))
        i += 1 + q[i]
    qtype = int.from_bytes(q[i + 1:i + 3], "big") if i + 3 <= len(q) else 0
    return ".".join(labels).lower(), qtype, i + 5


def dns_qname(q):
    return _question(q)[:2]


# ---- policy -------------------------------------------------------------------

def _match(host, patterns):
    host = host.lower().rstrip(".")
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns)


def load_manifest(data):
    forbidden = tuple(data.get("forbidden_host_patterns", ()))
    endpoints = []
    for e in data.get("endpoints", ()):
        for k in ("host", "class", "dependency"):
            if not e.get(k):
                raise ValueError("endpoint missing %r: %r" % (k, e))
        if e["class"] not in CLASSES:
            raise ValueError("endpoint %s: class %r is not one of %s" % (e["host"], e["class"], CLASSES))
        if _match(e["host"], forbidden):
            raise ValueError("endpoint %s matches a forbidden pattern (DEP-2)" % e["host"])
        endpoints.append(e)
    # Inert literals: a URL in third-party vendored code that names a host but
    # is never contacted (e.g. a metadata string). Each is one exact file and
    # host with a reason; it exempts nothing else, and the runtime scan still
    # catches any real contact.
    inert = []
    for e in data.get("inert_literals", ()):
        for k in ("file", "host", "why"):
            if not e.get(k):
                raise ValueError("inert literal missing %r: %r" % (k, e))
        # Only a shipping directory's own Go vendor tree: a "vendor" folder
        # deeper in our code (broker/x/vendor/) is not third-party.
        if not any(e["file"].startswith(d + "/vendor/") for d in SHIPPING_DIRS) or ".." in e["file"].split("/"):
            raise ValueError("inert literal %s: only vendored third-party files may be exempted" % e["file"])
        if _match(e["host"], forbidden):
            raise ValueError("inert literal %s matches a forbidden pattern (DEP-2)" % e["host"])
        inert.append((e["file"], e["host"].lower()))
    return Manifest(forbidden, tuple(endpoints), tuple(inert))


def _allowed(host, manifest, profile):
    classes = PROFILES[profile]
    return any(e["class"] in classes and _match(host, [e["host"]]) for e in manifest.endpoints)


def _is_local_ip(addr):
    ip = ipaddress.ip_address(addr)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_loopback or ip.is_unspecified


def _plainly_under(path, work):
    return (path.startswith("/") and os.path.normpath(path) == path.rstrip("/")
            and (path + os.sep).startswith(work))


def unix_realpaths(events):
    """Resolve each filesystem socket path seen; call inside the sandbox."""
    return {e.addr: os.path.realpath(e.addr) for e in events if e.family == "unix" and e.addr.startswith("/")}


def evaluate(events, names, manifest, profile, workdir, realpaths=None):
    realpaths = realpaths or {}
    found = collections.OrderedDict()

    def add(kind, target, detail):
        v = found.setdefault((kind, target), {"kind": kind, "target": target, "count": 0, "first": detail})
        v["count"] += 1

    work = os.path.realpath(workdir) + os.sep
    for e in events:
        how = "%s by pid %s" % (e.syscall, e.pid)
        if e.family in ("inet", "inet6"):
            target = ("[%s]:%d" if e.family == "inet6" else "%s:%d") % (e.addr, e.port)
            if _is_local_ip(e.addr):
                if e.port == 53:
                    add("dns", "loopback:53", how)  # a lookup, even if the name was not logged
                continue
            if _match(e.addr, manifest.forbidden):
                add("forbidden", target, how)
            elif not _allowed(e.addr, manifest, profile):
                add("ipv6" if e.family == "inet6" else "ipv4", target, how)
        elif e.family == "abstract":
            continue  # abstract sockets live in the network namespace
        elif e.family == "unix":
            # Filesystem sockets reach host services unless they are plainly
            # inside the work directory: absolute, no '.'/'..' components, and
            # resolving (symlinks followed, inside the sandbox) to the same place.
            if not _plainly_under(e.addr, work) or not _plainly_under(realpaths.get(e.addr, e.addr), work):
                add("host-socket", e.addr, how)
        elif e.family == "link":
            # A link whose source could lie outside the work directory could make
            # a work path lead to a host socket; fail closed.
            src = e.addr
            relative_ok = not src.startswith(("/", "<dirfd>")) and ".." not in src.split("/")
            if not relative_ok and not _plainly_under(src, work):
                add("link", src, how)
        elif e.family == "mount":
            add("mount", e.addr, how)
        elif e.family == "other":
            add("unknown-family", e.addr, how)
        else:
            add("unparsed", e.addr, how)
    for name in names:
        if _match(name, manifest.forbidden):
            add("forbidden", name, "DNS lookup")
        elif not _allowed(name, manifest, profile):
            add("dns", name, "DNS lookup")
    return list(found.values())


# ---- static scan -----------------------------------------------------------------

def _is_test_path(rel):
    parts = rel.parts
    return ("testdata" in parts or "tests" in parts or rel.name.endswith("_test.go")
            or rel.name.startswith("test_") or rel.name.endswith("_test.py"))


def _host_class(host):
    try:
        ip = ipaddress.ip_address(host)
        return "local" if (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified) else "ip"
    except ValueError:
        pass
    if _match(host, LOCAL_NAMES):
        return "local"
    return "name"


def static_scan(root, manifest, dirs=SHIPPING_DIRS):
    out = []
    for d in dirs:
        base = root / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            rel = f.relative_to(root)
            if not f.is_file() or f.suffix not in CODE_SUFFIXES or _is_test_path(rel):
                continue
            for n, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if line.lstrip().startswith(COMMENT_STARTS):
                    continue
                for m in URL.finditer(line):
                    host = (urllib.parse.urlsplit(m.group(0)).hostname or "").rstrip(".")
                    if not host or _host_class(host) == "local":
                        continue
                    loc = "%s:%d" % (rel.as_posix(), n)
                    if _match(host, manifest.forbidden):
                        out.append({"kind": "forbidden", "target": host, "location": loc})
                    elif _match(host, DOC_NAMES) or (rel.as_posix(), host.lower()) in manifest.inert:
                        continue
                    elif not _allowed(host, manifest, "full"):
                        out.append({"kind": "undeclared", "target": host, "location": loc})
    return out


# ---- offline sandbox ----------------------------------------------------------------

def _unshare_flags():
    # A PID namespace: when its first process exits or is killed, the kernel kills every
    # process in it, including one that left the process group (setsid) or strace let go of.
    pid = ["--pid", "--fork", "--kill-child", "--mount-proc"]
    return (["-n", "-m"] if os.geteuid() == 0 else ["-r", "-n", "-m"]) + pid


_SANDBOX = None


def sandbox_available():
    global _SANDBOX
    if _SANDBOX is None:
        _SANDBOX = False
        if shutil.which("unshare") and shutil.which("strace"):
            try:
                p = subprocess.run(["unshare"] + _unshare_flags() + ["--", "strace", "-o", os.devnull, "true"],
                                   capture_output=True, timeout=30)
                _SANDBOX = p.returncode == 0
            except (OSError, subprocess.SubprocessError):
                pass
    return _SANDBOX


def _loopback_up():
    import fcntl
    import struct
    siocgifflags, siocsifflags, iff_up = 0x8913, 0x8914, 0x1
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flags = struct.unpack("16sH14s", fcntl.ioctl(s, siocgifflags, struct.pack("16sH14s", b"lo", 0, b"")))[1]
    fcntl.ioctl(s, siocsifflags, struct.pack("16sH14s", b"lo", flags | iff_up, b""))
    s.close()


# Host directories that hold or could hold filesystem sockets (systemd-resolved,
# nscd, D-Bus, docker, X11, agents, anything under /var or a home directory). Each is hidden under an empty tmpfs inside the sandbox,
# so the egress block is enforced, not only detected; anything the scenario
# needs from them (its work directory, the repository) is bound back in.
MASKED_DIRS = ("/run", "/tmp", "/var", "/home", "/root", "/srv", "/mnt", "/media")


def _mount(*args):
    subprocess.run(["mount"] + list(args), check=True)


def _under(path, base):
    return (os.path.realpath(path) + os.sep).startswith(os.path.realpath(base) + os.sep)


def _mask_host_sockets(keep, writable=()):
    """Masks MASKED_DIRS and binds each kept path back; a kept path not in writable
    is mounted read-only, so a scenario cannot change what a later run executes."""
    fds = {k: os.open(k, os.O_PATH | os.O_DIRECTORY) for k in keep}
    masked, ro = [], []
    for d in MASKED_DIRS:
        if os.path.isdir(d) and not os.path.islink(d):
            _mount("-t", "tmpfs", "-o", "mode=1777,nosuid,nodev", "tmpfs", d)
            masked.append(d)
    for k in sorted(fds):  # a parent before a path kept inside it
        if k not in writable or any(_under(k, d) for d in masked + ro):
            if not os.path.isdir(k):
                os.makedirs(k)
            _mount("--no-canonicalize", "--rbind", "/proc/%d/fd/%d" % (os.getpid(), fds[k]), k)
        if k not in writable:
            _mount("--no-canonicalize", "-o", "remount,bind,ro", k)
            ro.append(k)
        os.close(fds[k])
    if os.path.lexists("/dev/log") and not os.path.exists("/dev/log"):
        pass  # symlink into a masked directory: already gone
    elif os.path.exists("/dev/log") and not os.path.isfile("/dev/log"):
        _mount("--bind", "/dev/null", "/dev/log")
    return masked


def _place(content, dest, work, masked):
    """Make dest read as content inside the sandbox."""
    if not os.path.lexists(dest):
        return
    real = os.path.realpath(dest)
    if any(_under(real, d) for d in masked):
        os.makedirs(os.path.dirname(real), exist_ok=True)
        pathlib.Path(real).write_text(content)
    else:
        src = work / ("etc-" + os.path.basename(dest))
        src.write_text(content)
        _mount("--bind", str(src), dest)


def _dns_sink(sock, names):
    while True:
        try:
            q, addr = sock.recvfrom(512)
        except OSError:
            return
        name, _, end = _question(q)
        names.append(name)
        flags = (0x8180 | 3) | (q[2] & 1) << 8  # response, NXDOMAIN, keep RD
        sock.sendto(q[:2] + flags.to_bytes(2, "big") + q[4:6] + b"\0" * 6 + q[12:end], addr)


def _io_uring_disabled():
    try:
        return pathlib.Path("/proc/sys/kernel/io_uring_disabled").read_text().strip()
    except OSError:
        return None


def _drain_into(fd, chunks):
    with open(fd, "rb", buffering=0) as f:
        for chunk in iter(lambda: f.read(65536), b""):
            chunks.append(chunk)


def _reader(fd):
    chunks = []
    t = threading.Thread(target=_drain_into, args=(fd, chunks), daemon=True)
    t.start()
    return t, chunks


def _inner(work, timeout, cmd, extra_keep=(), writable=()):
    """Runs inside the fresh user, network, and mount namespaces. The evidence
    (strace's trace and its stderr) arrives over pipes this process holds, and the
    result leaves on its stdout, so nothing the verdict reads is a file the scenario
    could truncate or rewrite: the trace pipe is not even inherited by the scenario
    (strace opens it close-on-exec), and stderr, which strace shares with the
    scenario, can only be appended to."""
    work = pathlib.Path(work)
    result = os.fdopen(os.dup(1), "w")  # only this process writes its result
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.close(null)
    _loopback_up()
    writable = {os.path.realpath(work)} | {os.path.realpath(w) for w in writable}
    keep = {str(ROOT), os.path.realpath(sys.prefix), *(os.path.realpath(k) for k in extra_keep),
            os.path.dirname(os.path.realpath(sys.executable))} | writable
    masked = _mask_host_sockets(sorted(keep), writable)
    _place("nameserver 127.0.0.1\n", "/etc/resolv.conf", work, masked)
    if os.path.exists("/etc/nsswitch.conf"):
        lines = [l for l in pathlib.Path("/etc/nsswitch.conf").read_text().splitlines()
                 if not l.startswith("hosts:")]
        _place("\n".join(lines + ["hosts: files dns"]) + "\n", "/etc/nsswitch.conf", work, masked)
    names = []
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 53))
    threading.Thread(target=_dns_sink, args=(sink, names), daemon=True).start()
    for d in ("tmp", "home"):
        (work / d).mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(work / "tmp"), HOME=str(work / "home"))
    trace_r, trace_w = os.pipe()
    err_r, err_w = os.pipe()
    trace_t, trace = _reader(trace_r)
    err_t, err = _reader(err_r)
    with open(work / "stdout", "wb") as out:
        proc = subprocess.Popen(["strace", "-f", "-qq", "-e", "trace=" + TRACED,
                                 "-o", "/proc/%d/fd/%d" % (os.getpid(), trace_w), "--"] + cmd,
                                env=env, cwd=ROOT, stdout=out, stderr=err_w)
        os.close(err_w)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            rc = "timeout"
    os.close(trace_w)
    # A tracee strace let go of may still hold stderr; take what has arrived.
    trace_t.join(10)
    err_t.join(2)
    text = b"".join(list(trace)).decode(errors="replace")
    events = parse_strace(text)
    result.write(json.dumps({"rc": rc, "dns": names, "masked": masked, "realpaths": unix_realpaths(events),
                             "io_uring_disabled": _io_uring_disabled(), "trace": text,
                             "stderr": b"".join(list(err)).decode("latin-1")}) + "\n")
    result.close()
    return 0


# strace's own failure, as opposed to a scenario that failed: strace prints e.g.
# "strace: ptrace(PTRACE_LISTEN,pid:42,sig:0): Input/output error", lets its tracees go on
# untraced, and its exit status may still be the main tracee's 0, so the trace is partial.
# Unanchored: tracees share strace's stderr, so the message can follow a partial line.
STRACE_FAULT = re.compile(rb"strace: .*(?:Input/output error|PTRACE_)")
STRACE_ATTEMPTS = 3


@contextlib.contextmanager
def _scratch_dir(prefix, tries=50, pause=0.2, stats=None):
    """TemporaryDirectory whose removal outlasts a straggler still writing into it
    (a go-build dir 'not empty' as rmtree reaches it). Only ENOTEMPTY is retried, and
    a directory that never empties still raises. run_target kills the sandbox before
    this runs, so the retry covers only writes already in flight, not a live process.
    Each retry is counted in stats["cleanup_retries"], for the report."""
    path = tempfile.mkdtemp(prefix=prefix)
    try:
        yield path
    finally:
        for left in range(tries, 0, -1):
            try:
                shutil.rmtree(path)
                break
            except OSError as e:
                if e.errno != errno.ENOTEMPTY or left == 1:
                    raise
                if stats is not None:
                    stats["cleanup_retries"] += 1
                time.sleep(pause)


def _run_sandboxed(cmd, env, timeout):
    """Runs the sandbox in its own process group and kills what is left of it; killing
    unshare also ends its PID namespace (--kill-child), so nothing outlives the run."""
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        proc.wait()
    return proc.returncode, out, err


_RESULT_KEYS = {"rc", "dns", "masked", "realpaths", "io_uring_disabled", "trace", "stderr"}


def _result(stdout):
    """The sandbox's one result line, or None if its stdout is anything else."""
    lines = stdout.splitlines()
    try:
        res = json.loads(lines[0]) if len(lines) == 1 else None
    except ValueError:
        return None
    return res if isinstance(res, dict) and _RESULT_KEYS <= set(res) else None


def _attempt(target, manifest, timeout, stats=None):
    """One sandboxed run in a fresh work directory: (result, whether strace faulted)."""
    profile = target.get("profile", "offline")
    with _scratch_dir("depaudit-", stats=stats) as work:
        os.chmod(work, 0o755)
        cmd = ["unshare"] + _unshare_flags() + ["--", sys.executable, str(pathlib.Path(__file__).resolve()),
                                                "_inner", "--work", work, "--timeout", str(timeout)]
        cmd += sum((["--keep", k] for k in target.get("keep", ())), [])
        cmd += sum((["--writable", w] for w in target.get("writes", ())), []) + ["--"]
        env = dict(os.environ, **target.get("env", {}))
        rc, stdout, stderr = _run_sandboxed(cmd + list(target["cmd"]), env, timeout + 60)
        res = _result(stdout)
        if rc != 0 or res is None:
            return {"name": target["name"], "outcome": "error", "violations": [],
                    "detail": "sandbox exit %s, %s\n%s" % (
                        rc, "result present" if res is not None else "no single result line",
                        stderr.decode(errors="replace")[-2000:])}, False
        events = parse_strace(res["trace"])
        violations = evaluate(events, res["dns"], manifest, profile, work, res["realpaths"])
        err = res["stderr"].encode("latin-1")
        out = {"name": target["name"], "profile": profile, "exit": res["rc"], "events": len(events),
               "logged": sorted({"%s %s" % (e.family, e.addr) for e in events}),
               "violations": violations, "masked": res["masked"], "io_uring_disabled": res["io_uring_disabled"]}
        fault = STRACE_FAULT.search(err) is not None
        if fault:
            out["outcome"] = "error"
            out["detail"] = "strace failed itself (not a scenario result):\n" + err[-2000:].decode(errors="replace")
        elif res["rc"] != 0:
            out["outcome"] = "scenario-failed"
            out["stderr_tail"] = err[-2000:].decode(errors="replace")
        else:
            out["outcome"] = "violation" if violations else "pass"
        return out, fault


def run_target(target, manifest, timeout=600):
    """Reruns a scenario strace faulted on, up to STRACE_ATTEMPTS; what a faulted attempt
    saw is kept, so a fault can hide neither a leak nor (all faulting) pass."""
    if target.get("profile", "offline") != "offline":
        raise ValueError("%s: only offline scenarios run in the sandbox" % target["name"])
    carried = []  # violations from attempts strace itself cut short
    stats = {"attempts": 0, "faults": 0, "cleanup_retries": 0}
    for attempt in range(1, STRACE_ATTEMPTS + 1):
        stats["attempts"] += 1
        out, fault = _attempt(target, manifest, timeout, stats)
        if not fault:
            break
        stats["faults"] += 1
        carried += out["violations"]
    else:
        out["detail"] = "on all %d attempts: %s" % (STRACE_ATTEMPTS, out["detail"])
        out["violations"] = carried
        out.update(stats)
        return out
    out["violations"] = carried + out["violations"]
    if out["outcome"] == "pass" and carried:
        out["outcome"] = "violation"
    out.update(stats)
    return out


# ---- controls and CLI -------------------------------------------------------------------

def _ipv6_available():
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
        return True
    except OSError:
        return False


def _control(mode):
    """Planted scenarios against the harness's own defences (DEP-2), run as
    `depaudit.py _control MODE` inside the sandbox.
      tamper-evidence  connects to a documentation address, then truncates or rewrites
                       every evidence file the harness once read from its work directory
      write-kept       exits nonzero unless every write to ROOT (tools/depaudit.py too),
                       sys.prefix and $DEPAUDIT_KEEP_RO fails read-only, and a write to
                       $DEPAUDIT_KEEP_RW (declared in the target's writes) succeeds"""
    if mode == "tamper-evidence":
        with contextlib.suppress(OSError):
            socket.create_connection(("192.0.2.10", 443), timeout=2).close()
        work = os.path.dirname(os.environ["TMPDIR"])
        forged = json.dumps({"rc": 0, "dns": [], "masked": list(MASKED_DIRS), "realpaths": {},
                             "io_uring_disabled": "2", "trace": "", "stderr": ""})
        for name, text in (("net.strace", ""), ("stderr", ""), ("result.json", forged)):
            with contextlib.suppress(OSError):
                pathlib.Path(work, name).write_text(text)
        return 0
    if mode != "write-kept":
        raise ValueError(mode)
    wrong = []
    for d in (str(ROOT), os.path.realpath(sys.prefix), os.environ["DEPAUDIT_KEEP_RO"]):
        probe = os.path.join(d, ".depaudit-write-%d" % os.getpid())
        try:
            os.close(os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            os.unlink(probe)
            wrong.append("wrote " + d)
        except OSError as e:
            if e.errno != errno.EROFS:
                wrong.append("%s: %s, not read-only" % (d, e))
    try:
        os.close(os.open(__file__, os.O_WRONLY | os.O_APPEND))
        wrong.append("opened %s for writing" % __file__)
    except OSError as e:
        if e.errno != errno.EROFS:
            wrong.append("%s: %s, not read-only" % (__file__, e))
    probe = os.path.join(os.environ["DEPAUDIT_KEEP_RW"], ".depaudit-write-%d" % os.getpid())
    try:
        os.close(os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        os.unlink(probe)
    except OSError as e:
        wrong.append("declared writable, yet %s" % e)
    # One logged loopback call, so the control is seen to have run under strace.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("127.0.0.1", 9))
    if wrong:
        sys.exit("; ".join(wrong))
    return 0


def control_targets(masked_probe, visible_probe, writable_dir):
    """Built-in controls, hard-coded so that removing one cannot keep CI green.
    masked_probe listens in /tmp (hidden in the sandbox); visible_probe listens in
    a directory bound back into the sandbox (reachable), so path tricks must be
    caught by the audit. Each control names the calls it must have made, so it
    cannot pass vacuously (e.g. a path too long to connect at all)."""
    cmd = [sys.executable, str(ROOT / "tools" / "depaudit_controls.py")]
    v6 = _ipv6_available()
    home = ["dns", "forbidden", "host-socket", "ipv4"] + (["ipv6"] if v6 else [])
    probes = {"DEPAUDIT_PROBE": masked_probe, "DEPAUDIT_PROBE_VISIBLE": visible_probe}
    keep = [os.path.dirname(visible_probe)]
    probe_name = os.path.basename(visible_probe)
    own = [sys.executable, str(pathlib.Path(__file__).resolve()), "_control"]
    return [
        {"name": "control-offline-clean", "cmd": cmd + ["clean"], "expect": "pass",
         "must_log": [("inet", "127.0.0.1"), ("unix", "/ctl.sock")]},
        {"name": "control-phones-home", "cmd": cmd + ["phones-home"], "expect": "violation", "expect_kinds": home,
         "must_log": [("inet", "192.0.2.10"), ("unix", "/run/systemd/resolve")] + ([("inet6", "2001:db8::1")] if v6 else [])},
        {"name": "control-needs-network", "cmd": cmd + ["needs-network"], "expect": "scenario-failed",
         "must_log": [("inet", "192.0.2.10")]},
        # Exits nonzero if it can reach the live socket left listening in /tmp.
        {"name": "control-host-socket-masked", "cmd": cmd + ["host-socket"], "expect": "violation",
         "expect_kinds": ["host-socket"], "env": probes, "keep": keep, "must_log": [("unix", masked_probe)]},
        {"name": "control-host-socket-dotdot", "must_reach": True, "cmd": cmd + ["host-socket-dotdot"], "expect": "violation",
         "expect_kinds": ["host-socket"], "env": probes, "keep": keep, "must_log": [("unix", "/../")]},
        {"name": "control-host-socket-symlink", "must_reach": True, "cmd": cmd + ["host-socket-symlink"], "expect": "violation",
         "expect_kinds": ["host-socket", "link"], "env": probes, "keep": keep,
         "must_log": [("link", os.path.dirname(visible_probe)), ("unix", "/l/" + probe_name)]},
        {"name": "control-symlink-removed", "must_reach": True, "cmd": cmd + ["host-socket-symlink-removed"], "expect": "violation",
         "expect_kinds": ["link"], "env": probes, "keep": keep,
         "must_log": [("link", os.path.dirname(visible_probe)), ("unix", "/l/" + probe_name)]},
        # DEP-2: evidence the scenario rewrites after a connect, and writes to kept paths.
        {"name": "control-evidence-tamper", "cmd": own + ["tamper-evidence"], "expect": "violation",
         "expect_kinds": ["ipv4"], "must_log": [("inet", "192.0.2.10")]},
        {"name": "control-kept-read-only", "cmd": own + ["write-kept"], "expect": "pass", "keep": keep,
         "writes": [writable_dir], "env": {"DEPAUDIT_KEEP_RO": keep[0], "DEPAUDIT_KEEP_RW": writable_dir},
         "must_log": [("inet", "127.0.0.1")]},
    ]


def _judge(target, res):
    expect = target.get("expect", "pass")
    if res["outcome"] != expect:
        return False, "expected %s, got %s" % (expect, res["outcome"])
    missing = [f + " " + sub for f, sub in target.get("must_log", ())
               if not any(l.startswith(f + " ") and sub in l for l in res.get("logged", ()))]
    if missing:
        return False, "control's own calls were not logged: %s" % missing
    want = target.get("expect_kinds")
    got = sorted({v["kind"] for v in res["violations"]})
    if want is not None and sorted(want) != got:
        return False, "expected violation kinds %s, got %s" % (sorted(want), got)
    return True, expect


def load_registry(path):
    targets = json.loads(pathlib.Path(path).read_text())["targets"]
    for t in targets:
        if set(t) - {"name", "cmd", "expect", "note"} or t.get("expect", "pass") != "pass":
            raise ValueError("%s: product scenarios must expect pass; controls are built in" % t.get("name"))
    return targets


def _drain(sock):
    n = 0
    while True:
        try:
            sock.accept()[0].close()
            n += 1
        except BlockingIOError:
            return n


def cmd_static(args):
    manifest = load_manifest(json.loads(pathlib.Path(args.manifest).read_text()))
    found = static_scan(ROOT, manifest)
    for v in found:
        print("FAIL %s endpoint %s at %s" % (v["kind"], v["target"], v["location"]))
    print("static endpoint scan: %d finding(s) in %s" % (len(found), ", ".join(SHIPPING_DIRS)))
    return 1 if found else 0


def cmd_run(args):
    if not sandbox_available():
        print("FAIL sandbox unavailable: needs strace and unprivileged user+network namespaces", file=sys.stderr)
        return 2
    try:
        product = load_registry(args.targets)
    except ValueError as e:
        print("FAIL registry: %s" % e, file=sys.stderr)
        return 2
    manifest = load_manifest(json.loads(pathlib.Path(args.manifest).read_text()))
    report, ok_all = {"targets": []}, True
    with tempfile.TemporaryDirectory(prefix="depaudit-probe-", dir="/tmp") as masked_dir, \
            tempfile.TemporaryDirectory(prefix="dpv-", dir="/tmp") as visible_dir, \
            tempfile.TemporaryDirectory(prefix="dpw-", dir="/tmp") as writable_dir:
        os.chmod(writable_dir, 0o755)
        probes = []
        for d in (masked_dir, visible_dir):
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(os.path.join(d, "p"))
            probe.listen(16)
            probes.append(probe)
            os.chmod(d, 0o755)
        probes[1].setblocking(False)
        for t in control_targets(os.path.join(masked_dir, "p"), os.path.join(visible_dir, "p"), writable_dir) + product:
            res = run_target(t, manifest, timeout=args.timeout)
            ok, why = _judge(t, res)
            reached = _drain(probes[1])
            if ok and t.get("must_reach") and not reached:
                ok, why = False, "never reached the visible probe, so the control tested nothing"
            ok_all &= ok
            res.update(control=t not in product, passed=ok)
            report["targets"].append(res)
            print("%s %-28s %s (%s; %d socket events, %d violation(s); "
                  "%d attempt(s), %d strace fault(s), %d cleanup retr(ies))" % (
                      "PASS" if ok else "FAIL", t["name"], "scenario" if t in product else "control",
                      why, res.get("events", 0), len(res["violations"]),
                      res.get("attempts", 0), res.get("faults", 0), res.get("cleanup_retries", 0)))
            if not ok:
                for v in res["violations"]:
                    print("    %s %s (%dx, first: %s)" % (v["kind"], v["target"], v["count"], v["first"]))
                for k in ("detail", "stderr_tail"):
                    if res.get(k):
                        print("    %s:\n%s" % (k, res[k]))
        for probe in probes:
            probe.close()
    uring = {r.get("io_uring_disabled") for r in report["targets"]}
    report["io_uring_disabled"] = sorted(str(u) for u in uring)
    if args.require_io_uring_disabled and uring != {"2"}:
        print("FAIL io_uring is not disabled (kernel.io_uring_disabled=%s); its socket calls bypass strace"
              % ",".join(report["io_uring_disabled"]))
        ok_all = False
    report["real_targets"] = [t["name"] for t in product]
    if not product:
        print("note: no product scenarios registered yet; only controls ran (see assurance/README.md)")
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps(report, indent=1) + "\n")
    return 0 if ok_all else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("static")
    s.add_argument("--manifest", default=str(MANIFEST))
    r = sub.add_parser("run")
    r.add_argument("--targets", required=True)
    r.add_argument("--manifest", default=str(MANIFEST))
    r.add_argument("--timeout", type=int, default=600)
    r.add_argument("--require-io-uring-disabled", action="store_true",
                   help="fail unless kernel.io_uring_disabled=2 (set in CI)")
    r.add_argument("--report")
    i = sub.add_parser("_inner")
    i.add_argument("--work", required=True)
    i.add_argument("--timeout", type=int, required=True)
    i.add_argument("--keep", action="append", default=[])
    i.add_argument("--writable", action="append", default=[])
    i.add_argument("subject", nargs=argparse.REMAINDER)
    c = sub.add_parser("_control")
    c.add_argument("mode")
    args = ap.parse_args(argv)
    if args.cmd == "_inner":
        return _inner(args.work, args.timeout, args.subject[1:] if args.subject[:1] == ["--"] else args.subject,
                      args.keep, args.writable)
    if args.cmd == "_control":
        return _control(args.mode)
    return cmd_static(args) if args.cmd == "static" else cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
