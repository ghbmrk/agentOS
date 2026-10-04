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
TRACED = "connect,sendto,sendmsg,sendmmsg"

SHIPPING_DIRS = ("broker", "src")
CODE_SUFFIXES = {".go", ".py", ".rs", ".c", ".h", ".ts", ".js", ".sh", ".toml", ".json", ".yaml", ".yml", ".conf"}
URL = re.compile(r"\b(https?|wss?|ftps?|grpcs?|tcp|udp|ntp)://[^\s\"'`<>()\[\]{}\\,]+", re.I)
COMMENT_STARTS = ("//", "#", "*", "/*", "--", ";")
LOCAL_NAMES = ("localhost", "*.localhost", "*.local", "*.home.arpa")
DOC_NAMES = ("example.com", "example.net", "example.org", "*.example.com", "*.example.net",
             "*.example.org", "*.example", "*.test", "*.invalid")

Event = collections.namedtuple("Event", "pid syscall family addr port")
Manifest = collections.namedtuple("Manifest", "forbidden endpoints")

_LINE = re.compile(r"^(?:(\d+)\s+)?(\w+)\(")
_SOCKADDR = re.compile(r"\{sa_family=AF_(\w+)([^{}]*)\}")
_V4 = re.compile(r'sin_port=htons\((\d+)\), sin_addr=inet_addr\("([^"]+)"\)')
_V6 = re.compile(r'sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6, "([^"]+)"')
_UNIX = re.compile(r'sun_path=(@?)"((?:[^"\\]|\\.)*)"')


# ---- parsing ------------------------------------------------------------------

def parse_strace(text):
    events = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        pid, syscall = m.group(1), m.group(2)
        for fam, body in _SOCKADDR.findall(line):
            if fam == "INET" and _V4.search(body):
                port, addr = _V4.search(body).groups()
                events.append(Event(pid, syscall, "inet", addr, int(port)))
            elif fam == "INET6" and _V6.search(body):
                port, addr = _V6.search(body).groups()
                events.append(Event(pid, syscall, "inet6", addr, int(port)))
            elif fam == "UNIX" and _UNIX.search(body):
                at, path = _UNIX.search(body).groups()
                events.append(Event(pid, syscall, "unix", at + path, None))
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
    return Manifest(forbidden, tuple(endpoints))


def _allowed(host, manifest, profile):
    classes = PROFILES[profile]
    return any(e["class"] in classes and _match(host, [e["host"]]) for e in manifest.endpoints)


def _is_local_ip(addr):
    ip = ipaddress.ip_address(addr)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_loopback or ip.is_unspecified


def evaluate(events, names, manifest, profile, workdir):
    found = collections.OrderedDict()

    def add(kind, target, detail):
        v = found.setdefault((kind, target), {"kind": kind, "target": target, "count": 0, "first": detail})
        v["count"] += 1

    work = os.path.realpath(workdir) + os.sep
    for e in events:
        if e.family in ("inet", "inet6"):
            if _is_local_ip(e.addr):
                continue
            target = ("[%s]:%d" if e.family == "inet6" else "%s:%d") % (e.addr, e.port)
            if _match(e.addr, manifest.forbidden):
                add("forbidden", target, "%s by pid %s" % (e.syscall, e.pid))
            elif not _allowed(e.addr, manifest, profile):
                add("ip", target, "%s by pid %s" % (e.syscall, e.pid))
        elif e.family == "unix":
            # Abstract sockets live in the network namespace; filesystem sockets
            # outside the scenario's own directory reach host services.
            if e.addr.startswith("@") or (e.addr + os.sep).startswith(work):
                continue
            add("host-socket", e.addr, "%s by pid %s" % (e.syscall, e.pid))
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
                    elif _match(host, DOC_NAMES):
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


def _bind_over(src, dest):
    if os.path.exists(dest):
        subprocess.run(["mount", "--bind", str(src), dest], check=True)


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


def _inner(work, timeout, cmd):
    """Runs inside the fresh user, network, and mount namespaces."""
    work = pathlib.Path(work)
    _loopback_up()
    (work / "resolv.conf").write_text("nameserver 127.0.0.1\n")
    _bind_over(work / "resolv.conf", "/etc/resolv.conf")
    if os.path.exists("/etc/nsswitch.conf"):
        lines = [l for l in pathlib.Path("/etc/nsswitch.conf").read_text().splitlines()
                 if not l.startswith("hosts:")]
        (work / "nsswitch.conf").write_text("\n".join(lines + ["hosts: files dns"]) + "\n")
        _bind_over(work / "nsswitch.conf", "/etc/nsswitch.conf")
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
    (work / "result.json").write_text(json.dumps({"rc": rc, "dns": names}))
    return 0


def run_target(target, manifest, timeout=600):
    profile = target.get("profile", "offline")
    if profile != "offline":
        raise ValueError("%s: only offline scenarios run in the sandbox" % target["name"])
    with tempfile.TemporaryDirectory(prefix="depaudit-") as work:
        os.chmod(work, 0o755)
        cmd = ["unshare"] + _unshare_flags() + ["--", sys.executable, str(pathlib.Path(__file__).resolve()),
                                                "_inner", "--work", work, "--timeout", str(timeout), "--"]
        p = subprocess.run(cmd + list(target["cmd"]), capture_output=True, timeout=timeout + 60)
        res_file = pathlib.Path(work, "result.json")
        if p.returncode != 0 or not res_file.exists():
            return {"name": target["name"], "outcome": "error", "violations": [],
                    "detail": p.stderr.decode(errors="replace")[-2000:]}
        res = json.loads(res_file.read_text())
        trace = pathlib.Path(work, "net.strace")
        events = parse_strace(trace.read_text(errors="replace") if trace.exists() else "")
        violations = evaluate(events, res["dns"], manifest, profile, work)
        out = {"name": target["name"], "profile": profile, "exit": res["rc"], "events": len(events),
               "violations": violations}
        if res["rc"] != 0:
            out["outcome"] = "scenario-failed"
            out["stderr_tail"] = pathlib.Path(work, "stderr").read_bytes()[-2000:].decode(errors="replace")
        else:
            out["outcome"] = "violation" if violations else "pass"
        return out


# ---- CLI ---------------------------------------------------------------------------

def _judge(target, res):
    expect = target.get("expect", "pass")
    if res["outcome"] != expect:
        return False, "expected %s, got %s" % (expect, res["outcome"])
    want = target.get("expect_kinds")
    got = sorted({v["kind"] for v in res["violations"]})
    if want is not None and sorted(want) != got:
        return False, "expected violation kinds %s, got %s" % (sorted(want), got)
    return True, expect


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
    manifest = load_manifest(json.loads(pathlib.Path(args.manifest).read_text()))
    targets = json.loads(pathlib.Path(args.targets).read_text())["targets"]
    report, ok_all = {"targets": []}, True
    for t in targets:
        res = run_target(t, manifest, timeout=args.timeout)
        ok, why = _judge(t, res)
        ok_all &= ok
        res.update(control=bool(t.get("control")), passed=ok)
        report["targets"].append(res)
        print("%s %-26s %s (%s; %d socket events, %d violation(s))" % (
            "PASS" if ok else "FAIL", t["name"], "control" if t.get("control") else "scenario",
            why, res.get("events", 0), len(res["violations"])))
        if not ok:
            for v in res["violations"]:
                print("    %s %s (%dx, first: %s)" % (v["kind"], v["target"], v["count"], v["first"]))
            for k in ("detail", "stderr_tail"):
                if res.get(k):
                    print("    %s:\n%s" % (k, res[k]))
    real = [t["name"] for t in targets if not t.get("control")]
    report["real_targets"] = real
    if not real:
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
    r.add_argument("--report")
    i = sub.add_parser("_inner")
    i.add_argument("--work", required=True)
    i.add_argument("--timeout", type=int, required=True)
    i.add_argument("subject", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    if args.cmd == "_inner":
        return _inner(args.work, args.timeout, args.subject[1:] if args.subject[:1] == ["--"] else args.subject)
    return cmd_static(args) if args.cmd == "static" else cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
