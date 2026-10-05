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
import fnmatch
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
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
        if "/vendor/" not in "/" + e["file"]:
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
    return ["-n", "-m"] if os.geteuid() == 0 else ["-r", "-n", "-m"]


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


def _mask_host_sockets(keep):
    fds = {k: os.open(k, os.O_PATH | os.O_DIRECTORY) for k in keep}
    masked = []
    for d in MASKED_DIRS:
        if os.path.isdir(d) and not os.path.islink(d):
            _mount("-t", "tmpfs", "-o", "mode=1777,nosuid,nodev", "tmpfs", d)
            masked.append(d)
    for k, fd in fds.items():
        if any(_under(k, d) for d in masked):
            os.makedirs(k, exist_ok=True)
            _mount("--no-canonicalize", "--bind", "/proc/%d/fd/%d" % (os.getpid(), fd), k)
        os.close(fd)
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


def _inner(work, timeout, cmd, extra_keep=()):
    """Runs inside the fresh user, network, and mount namespaces."""
    work = pathlib.Path(work)
    _loopback_up()
    keep = {str(work), str(ROOT), os.path.realpath(sys.prefix), *extra_keep,
            os.path.dirname(os.path.realpath(sys.executable))}
    masked = _mask_host_sockets(sorted(keep))
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
    with open(work / "stdout", "wb") as out, open(work / "stderr", "wb") as err:
        try:
            rc = subprocess.run(["strace", "-f", "-qq", "-e", "trace=" + TRACED, "-o", str(work / "net.strace"),
                                 "--"] + cmd, env=env, cwd=ROOT, stdout=out, stderr=err, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
    trace = work / "net.strace"
    events = parse_strace(trace.read_text(errors="replace") if trace.exists() else "")
    (work / "result.json").write_text(json.dumps({"rc": rc, "dns": names, "masked": masked,
                                                  "realpaths": unix_realpaths(events),
                                                  "io_uring_disabled": _io_uring_disabled()}))
    return 0


def run_target(target, manifest, timeout=600):
    profile = target.get("profile", "offline")
    if profile != "offline":
        raise ValueError("%s: only offline scenarios run in the sandbox" % target["name"])
    with tempfile.TemporaryDirectory(prefix="depaudit-") as work:
        os.chmod(work, 0o755)
        cmd = ["unshare"] + _unshare_flags() + ["--", sys.executable, str(pathlib.Path(__file__).resolve()),
                                                "_inner", "--work", work, "--timeout", str(timeout)]
        cmd += sum((["--keep", k] for k in target.get("keep", ())), []) + ["--"]
        env = dict(os.environ, **target.get("env", {}))
        p = subprocess.run(cmd + list(target["cmd"]), env=env, capture_output=True, timeout=timeout + 60)
        res_file = pathlib.Path(work, "result.json")
        if p.returncode != 0 or not res_file.exists():
            return {"name": target["name"], "outcome": "error", "violations": [],
                    "detail": "sandbox exit %s, %s\n%s" % (
                        p.returncode, "result present" if res_file.exists() else "no result",
                        p.stderr.decode(errors="replace")[-2000:])}
        res = json.loads(res_file.read_text())
        trace = pathlib.Path(work, "net.strace")
        events = parse_strace(trace.read_text(errors="replace") if trace.exists() else "")
        violations = evaluate(events, res["dns"], manifest, profile, work, res["realpaths"])
        out = {"name": target["name"], "profile": profile, "exit": res["rc"], "events": len(events),
               "logged": sorted({"%s %s" % (e.family, e.addr) for e in events}),
               "violations": violations, "masked": res["masked"], "io_uring_disabled": res["io_uring_disabled"]}
        if res["rc"] != 0:
            out["outcome"] = "scenario-failed"
            out["stderr_tail"] = pathlib.Path(work, "stderr").read_bytes()[-2000:].decode(errors="replace")
        else:
            out["outcome"] = "violation" if violations else "pass"
        return out


# ---- controls and CLI -------------------------------------------------------------------

def _ipv6_available():
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
        return True
    except OSError:
        return False


def control_targets(masked_probe, visible_probe):
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
            tempfile.TemporaryDirectory(prefix="dpv-", dir="/tmp") as visible_dir:
        probes = []
        for d in (masked_dir, visible_dir):
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(os.path.join(d, "p"))
            probe.listen(16)
            probes.append(probe)
            os.chmod(d, 0o755)
        probes[1].setblocking(False)
        for t in control_targets(os.path.join(masked_dir, "p"), os.path.join(visible_dir, "p")) + product:
            res = run_target(t, manifest, timeout=args.timeout)
            ok, why = _judge(t, res)
            reached = _drain(probes[1])
            if ok and t.get("must_reach") and not reached:
                ok, why = False, "never reached the visible probe, so the control tested nothing"
            ok_all &= ok
            res.update(control=t not in product, passed=ok)
            report["targets"].append(res)
            print("%s %-28s %s (%s; %d socket events, %d violation(s))" % (
                "PASS" if ok else "FAIL", t["name"], "scenario" if t in product else "control",
                why, res.get("events", 0), len(res["violations"])))
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
    i.add_argument("subject", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    if args.cmd == "_inner":
        return _inner(args.work, args.timeout, args.subject[1:] if args.subject[:1] == ["--"] else args.subject,
                      args.keep)
    return cmd_static(args) if args.cmd == "static" else cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
