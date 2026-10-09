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
import grp
import ipaddress
import json
import os
import pathlib
import pwd
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
# somewhere else (links, mounts). Every name must be one strace knows, or the sandbox
# is unavailable (DEP-4b); '?' marks only the names the architecture has no syscall for
# (the generic table has symlinkat and linkat but no symlink or link). An architecture
# not listed gets no '?': if it lacks a name, the run fails loudly until it is listed.
_LINKS = ("symlink", "symlinkat", "link", "linkat")
_MOUNTS = ("mount", "umount2", "open_tree", "move_mount", "fsopen", "fsmount", "pivot_root")
_ABSENT = {"aarch64": ("symlink", "link")}


def _traced(machine):
    """The strace -e trace= list for machine: '?' on exactly the names _ABSENT lists for it (D12)."""
    return ",".join(("?" if n in _ABSENT.get(machine, ()) else "") + n
                    for n in ("connect", "sendto", "sendmsg", "sendmmsg") + _LINKS + _MOUNTS)


TRACED = _traced(os.uname().machine)

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
    """Raises OSError without a subordinate uid and gid range (DEP-3a)."""
    # A PID namespace: when its first process exits or is killed, the kernel kills every
    # process in it, including one that left the process group (setsid) or strace let go of.
    pid = ["--pid", "--fork", "--kill-child", "--mount-proc"]
    # A user namespace even as root: the capabilities setpriv keeps then act only inside it.
    # Without one, real root keeps CAP_DAC_READ_SEARCH (open_by_handle_at), CAP_SYS_MODULE and
    # others on the host, each a way past a read-only bind (B2, Security re-sign 2 on #437).
    # Its maps hold the runner as uid 0 (_inner, strace) and SCENARIO_ID as the first id of
    # its subordinate range; unshare sets both through newuidmap and newgidmap, and fails if
    # either refuses (DEP-3a). No fallback to -r's single-id map.
    uid_map, gid_map = _id_maps()
    users = ["--map-user=0", "--map-group=0", "--map-users=%d:%d:%d" % uid_map[1],
             "--map-groups=%d:%d:%d" % gid_map[1]]
    return users + ["-n", "-m"] + pid


# The scenario runs as this uid and gid inside the sandbox's user namespace, mapped to the
# first id of the runner's subordinate range; _inner and strace stay uid 0 there, mapped to
# the runner's own ids. A different uid closes /proc/1/* and ptrace of either to the scenario
# by DAC alone, with or without the capability drop (DEP-3a, D9).
SCENARIO_ID = 1000
SUBUID, SUBGID = "/etc/subuid", "/etc/subgid"
# DEP-8: a range is usable only if it maps the scenario onto an id no one else owns (D13).
# The floor keeps every id systemd reserves below it; login.defs can raise it, never lower it.
LOGIN_DEFS = "/etc/login.defs"
SUB_FLOOR = 100000
_ID_LAST = 4294967294  # 4294967295 is (uid_t)-1
_NSS_BUF_MAX = 1 << 20
# shadow reads START and COUNT with base 0 (lib/subordinateio.c): ASCII decimal with no sign,
# space, base prefix or leading 0 reads the same in base 0 and base 10 (DEP-8c).
_SUBID_LINE = re.compile(r"([^:\s]+):(0|[1-9][0-9]*):(0|[1-9][0-9]*)")


class UnusableRange(OSError):
    """The runner has a subordinate range, but it breaks a DEP-8 rule."""


def _sub_floor(kind):
    """max(SUB_FLOOR, SUB_UID_MIN or SUB_GID_MIN from LOGIN_DEFS); a missing file or key is
    SUB_FLOOR. Raises ValueError for a value that is not a plain decimal (DEP-8a)."""
    key = "SUB_%s_MIN" % kind.upper()
    try:
        lines = pathlib.Path(LOGIN_DEFS).read_text(errors="surrogateescape").split("\n")
    except FileNotFoundError:
        return SUB_FLOOR
    except OSError as e:
        raise ValueError("%s cannot be read: %s" % (LOGIN_DEFS, e))
    floor = SUB_FLOOR
    for line in lines:
        f = line.split()
        if f and f[0] == key:
            if len(f) != 2 or not re.fullmatch(r"0|[1-9][0-9]*", f[1]):
                raise ValueError("%s %s %r is not a decimal number" % (LOGIN_DEFS, key, " ".join(f[1:])))
            floor = max(floor, int(f[1]))
    return floor


def _nss_lookup(call, ident):
    """(rc, found) from glibc's getpwuid_r or getgrgid_r of ident, through nsswitch. The buffer
    grows on ERANGE up to _NSS_BUF_MAX; past it, ERANGE is returned. What rc means is the
    caller's: CPython's pwd.getpwuid reads every NSS error as KeyError (DEP-8b)."""
    import ctypes
    fn = getattr(ctypes.CDLL(None, use_errno=True), call)
    fn.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                   ctypes.POINTER(ctypes.c_void_p)]
    fn.restype = ctypes.c_int
    entry = ctypes.create_string_buffer(256)  # struct passwd is 48 bytes and struct group 32 on LP64
    size = 1024
    while True:
        buf, result = ctypes.create_string_buffer(size), ctypes.c_void_p()
        rc = fn(ident, entry, buf, size, ctypes.byref(result))
        if rc != errno.ERANGE or size >= _NSS_BUF_MAX:
            return rc, bool(result.value)
        size *= 2


def _subordinate(path):
    """The first line path grants the effective user (by name or uid) as (owner, start, count),
    with every other owner's line as (line, start, count), or (None, []) without one. Raises
    UnusableRange for a non-blank line that does not parse strictly (DEP-8c)."""
    me = {str(os.geteuid())}
    with contextlib.suppress(KeyError):
        me.add(pwd.getpwuid(os.geteuid()).pw_name)
    try:
        lines = pathlib.Path(path).read_text(errors="surrogateescape").split("\n")
    except OSError:
        return None, []
    mine, others = None, []
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        m = _SUBID_LINE.fullmatch(line)
        if not m:
            raise UnusableRange("line %d of %s, %r, does not parse as NAME:START:COUNT in ASCII decimal "
                                "(no sign, space, base prefix or leading 0), so the overlap check cannot "
                                "read it" % (n, path, line))
        owner, start, count = m.group(1), int(m.group(2)), int(m.group(3))
        if owner not in me:
            others.append((line, start, count))
        elif mine is None:
            mine = (owner, start, count)
    return mine, others


def _range_problem(kind, path, mine, others):
    """The first DEP-8 rule the runner's range breaks, as text, or "" if it breaks none."""
    _, start, count = mine
    end = start + count  # exclusive
    try:
        floor = _sub_floor(kind)
    except ValueError as e:
        return str(e)
    if start < floor:
        return "start %d is below the floor %d (SUB_%s_MIN)" % (start, floor, kind.upper())
    if count < 1:
        return "count 0 grants no id"
    if end - 1 > _ID_LAST:
        return "the range ends at %d, past %d (4294967295 is (%s_t)-1)" % (end - 1, _ID_LAST, kind)
    for line, o_start, o_count in others:
        if o_start < end and start < o_start + o_count:
            return "overlaps %s" % line
    own = os.geteuid() if kind == "uid" else os.getegid()
    if start <= own < end:
        return "%s %d (the runner) is in the range" % (kind, own)
    try:
        if kind == "uid":
            known = [(e.pw_uid, e.pw_name) for e in pwd.getpwall()]
        else:
            known = [(e.gr_gid, e.gr_name) for e in grp.getgrall()]
    except Exception as e:  # noqa: BLE001 - any failure leaves the range unchecked
        return "%s failed: %r" % ("getpwall()" if kind == "uid" else "getgrall()", e)
    for ident, name in known:
        if start <= ident < end:
            return "%s %d (%s) is in the range" % (kind, ident, name)
    call = "getpwuid_r" if kind == "uid" else "getgrgid_r"
    rc, found = _nss_lookup(call, start)
    if rc:
        return "%s(%d) failed with %s" % (call, start, errno.errorcode.get(rc, str(rc)))
    if found:
        return "%s %d has an entry (%s) and is in the range" % (kind, start, call)
    return ""


def _id_maps():
    """The exact uid_map and gid_map lines the sandbox sets, as (inside, outside, count)
    triples: uid 0 is the runner, SCENARIO_ID the first subordinate id (DEP-3c). Raises
    OSError without a subordinate range, and UnusableRange for one that breaks a DEP-8 rule:
    the sandbox is then unavailable (DEP-3a). Only the first line counts (DEP-8d)."""
    (uid, uid_others), (gid, gid_others) = _subordinate(SUBUID), _subordinate(SUBGID)
    if uid is None or gid is None:
        raise OSError("no subordinate uid and gid range for uid %d in %s and %s" % (os.geteuid(), SUBUID, SUBGID))
    for kind, path, mine, others in (("uid", SUBUID, uid, uid_others), ("gid", SUBGID, gid, gid_others)):
        why = _range_problem(kind, path, mine, others)
        if why:
            raise UnusableRange("range %d:%d for %s in %s is not usable: %s" % (mine[1], mine[2], mine[0], path, why))
    return ([(0, os.geteuid(), 1), (SCENARIO_ID, uid[1], 1)], [(0, os.getegid(), 1), (SCENARIO_ID, gid[1], 1)])


def _map_text(triples):
    return "\n".join("%d %d %d" % t for t in triples)


_SANDBOX = None
SANDBOX_WHY = ""  # why sandbox_available() is false, with the remedy (DEP-6d, DEP-6e)
# Each binary the sandbox runs, and the package that ships it.
_NEEDS = (("unshare", "util-linux"), ("setpriv", "util-linux"), ("strace", "strace"),
          ("newuidmap", "uidmap"), ("newgidmap", "uidmap"))


def _has_mount_setattr():
    """Whether the kernel has mount_setattr (Linux 5.12+), asked with no side effect: a NULL
    attr of size 0 is refused before any lookup, and any errno but ENOSYS means the call
    exists (DEP-6c). It only predicts: a seccomp filter may answer EPERM for any call, and
    then _inner's own refusal stays the check (D10)."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.syscall(_SYS_MOUNT_SETATTR, -1, None, 0, None, 0) == 0 or ctypes.get_errno() != errno.ENOSYS


def _tail(stderr, lines=5, chars=500):
    text = " | ".join(stderr.decode(errors="replace").strip().splitlines()[-lines:])
    return text[-chars:] or "(no stderr)"


def _sandbox_missing():
    """The first need the sandbox lacks, named with its remedy, or "" if it has them all.
    Every branch can only find a reason: none makes the sandbox available."""
    if not _has_mount_setattr():
        return ("the kernel has no mount_setattr (ENOSYS), which makes each kept path read-only with every "
                "mount under it (tools/ASSUMPTIONS.md D10); needs Linux 5.12 or later")
    missing = [n for n, _ in _NEEDS if not shutil.which(n)]
    if missing:
        return "missing on PATH: %s; install them (apt-get install %s)" % (
            ", ".join(missing), " ".join(sorted({pkg for n, pkg in _NEEDS if n in missing})))
    try:
        flags = _unshare_flags()
    except OSError as e:
        try:
            user = pwd.getpwuid(os.geteuid()).pw_name
        except KeyError:
            user = str(os.geteuid())
        # No fixed range: one that overlaps another user's would share their ids. The rules are
        # the ones _range_problem checks, and only those (DEP-8e, D13).
        floors = []
        for kind in ("uid", "gid"):
            try:
                floors.append("%d (SUB_%s_MIN in /etc/login.defs, never below 100000)" % (_sub_floor(kind), kind.upper()))
            except ValueError as err:
                floors.append("max(100000, SUB_%s_MIN), which cannot be computed: %s" % (kind.upper(), err))
        verb = "replace it: sudo usermod --del-subuids/--del-subgids the old range, then" \
            if isinstance(e, UnusableRange) else "add one:"
        return ("%s; %s sudo usermod --add-subuids START-END --add-subgids START-END %s, with a 65536-id "
                "START-END: START at least %s for uids and %s for gids; containing no uid or gid that "
                "getent passwd, getent group or a lookup by id returns, and not the runner's own; and that "
                "overlaps no other owner's line in /etc/subuid or /etc/subgid (tools/ASSUMPTIONS.md D13)"
                % (e, verb, user, floors[0], floors[1]))
    try:
        # The same -e as the run: an strace that cannot name a traced syscall exits
        # nonzero ("invalid system call") instead of skipping it unseen (DEP-4b).
        # The same maps and uid drop too: without a subordinate range, newuidmap or
        # the drop to SCENARIO_ID, the run fails loudly, never with the old map (DEP-3a).
        p = subprocess.run(["unshare"] + flags + ["--", "strace", "-e", "trace=" + TRACED,
                                                  "-o", os.devnull] + AS_SCENARIO + ["true"],
                           capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        return "the sandbox probe did not run: %s" % e
    if p.returncode == 0:
        return ""
    return ("the sandbox probe (unshare, strace, setpriv) exited %s: %s; it needs unprivileged user+network "
            "namespaces, newuidmap and newgidmap that accept the range, and an strace that names every "
            "traced syscall (%s)" % (p.returncode, _tail(p.stderr), TRACED))


def sandbox_available():
    global _SANDBOX, SANDBOX_WHY
    if _SANDBOX is None:
        SANDBOX_WHY = _sandbox_missing()
        _SANDBOX = not SANDBOX_WHY
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


# x86_64 and the generic table (arm64) share these numbers.
_SYS_MOUNT_SETATTR, _SYS_OPEN_TREE_ATTR = 442, 467
_MOUNT_ATTR_RDONLY, _OPEN_TREE_CLONE, _AT_RECURSIVE = 0x1, 0x1, 0x8000


def _set_read_only(path):
    """Makes the mount at path and every mount under it read-only (mount_setattr with
    AT_RECURSIVE): `remount,bind,ro` reaches the top mount only, and `ro=recursive` left a
    submount writable (D10). No fallback: without the call (ENOSYS, Linux < 5.12) the
    attempt is a sandbox error, never a run with an unchecked submount (DEP-4a)."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    attr = (ctypes.c_uint64 * 4)(_MOUNT_ATTR_RDONLY, 0, 0, 0)  # set, clr, propagation, userns_fd
    if libc.syscall(_SYS_MOUNT_SETATTR, -100, path.encode(), _AT_RECURSIVE, attr, ctypes.sizeof(attr)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, "mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY) failed with %s (%s) on %s" % (
            errno.errorcode.get(err, err), os.strerror(err), path))


def _mask_host_sockets(keep, writable=()):
    """Masks MASKED_DIRS and binds each kept path back; a kept path not in writable
    is mounted read-only with every mount under it, so a scenario cannot change what a
    later run executes. A writes path inside one is bound after it and stays writable."""
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
            _set_read_only(k)
            ro.append(k)
        os.close(fds[k])
    if os.path.lexists("/dev/log") and not os.path.exists("/dev/log"):
        pass  # symlink into a masked directory: already gone
    elif os.path.exists("/dev/log") and not os.path.isfile("/dev/log"):
        _mount("--bind", "/dev/null", "/dev/log")
    return masked


def _mask_or_refuse(keep, writable):
    """_mask_host_sockets, or one line naming the path and errno and exit 1, before any
    command runs: a failed mount_setattr is a sandbox error, never a traceback (DEP-6c)."""
    try:
        return _mask_host_sockets(keep, writable)
    except OSError as e:
        sys.exit("depaudit: sandbox not run, %s" % e)


_OCTAL = re.compile(r"\\([0-7]{3})")


def _reaches_rw(path):
    """Whether path lookup of a mount point lands on a writable mount. A mount point that no
    longer resolves (ENOENT) is under a mount that hides it; any other error fails closed."""
    try:
        return not os.statvfs(path).f_flag & os.ST_RDONLY
    except FileNotFoundError:
        return False
    except OSError:
        return True


def writable_mounts(mountinfo, read_only, writable, reaches_rw=_reaches_rw):
    """Mount points in mountinfo text at or under a read-only kept path that are mounted rw,
    unless a writes path at or under that kept path covers them (DEP-4a). An rw entry the
    path no longer reaches (overmounted, or under a masking tmpfs) is hidden: the mount the
    path does reach is judged by its own entry, so reaches_rw (statvfs) settles it."""
    declared = [(p, True) for p in read_only] + [(p, False) for p in writable]
    wrong = []
    for line in mountinfo.splitlines():
        f = line.split(" ")
        if len(f) < 6 or not f[4].startswith("/"):
            wrong.append("unparsed mountinfo line: %r" % line)
            continue
        mp = _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), f[4])
        covering = [(len(p), ro) for p, ro in declared if mp == p or mp.startswith(p.rstrip("/") + "/")]
        if (covering and max(covering)[1] and "ro" not in f[5].split(",") and mp not in wrong
                and reaches_rw(mp)):
            wrong.append(mp)
    return wrong


def _unescape_field(field):
    """A /proc/self/mounts field: the kernel writes space, tab, newline and backslash as
    \\ooo. Anything else after a backslash raises ValueError."""
    head, *rest = field.split("\\")
    out = [head]
    for part in rest:
        if len(part) < 3 or not all(c in "01234567" for c in part[:3]):
            raise ValueError(field)
        out.append(chr(int(part[:3], 8)) + part[3:])
    return "".join(out)


def kept_rw_mounts(mounts, read_only, writable, statvfs=os.statvfs):
    """control-kept-read-only's own mount check, from a second source (DEP-6b): it shares
    no code with _inner's check, so one bug cannot blind both. mounts is /proc/self/mounts text (field 4 says ro if the mount or its
    superblock is read-only). A mount point at or under a declared path is judged by the
    closest declared path, as D10: under a read-only one, a mount that is rw there and rw
    by statvfs on its mount point is reported; ENOENT means hidden (D10), any other error
    counts as writable. An unparsable line is reported too."""
    declared = [(p, True) for p in read_only] + [(p, False) for p in writable]
    found = []
    for line in mounts.splitlines():
        fields = line.split(" ")
        try:
            if len(fields) < 4 or not fields[1].startswith("/"):
                raise ValueError(line)
            point = _unescape_field(fields[1])
        except ValueError:
            found.append("unparsed /proc/self/mounts line: %r" % line)
            continue
        closest = max(((len(p), ro) for p, ro in declared if os.path.commonpath([point, p]) == p), default=None)
        if closest is None or not closest[1] or "ro" in fields[3].split(",") or point in found:
            continue
        try:
            if statvfs(point).f_flag & os.ST_RDONLY:
                continue
        except FileNotFoundError:
            continue
        except OSError:
            pass
        found.append(point)
    return found


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


# The scenario runs as (userns) root with CAP_SYS_ADMIN over the sandbox's mount
# namespace, where the kept paths' ro flag is not locked: it could clear it with
# mount_setattr or open_tree_attr, neither traced. Without the capability, in its
# bounding and inheritable sets, no exec can get it back, so ro holds (DEP-2b).
# CAP_SYS_PTRACE goes too: with it the scenario could attach to _inner or strace, which
# keep CAP_SYS_ADMIN, and make the call through them. Without it, an ancestor holding
# capabilities it lacks is out of its reach (cap_ptrace_access_check, and Yama scope 1).
DROP_CAPS = ["setpriv", "--bounding-set", "-sys_admin,-sys_ptrace", "--inh-caps", "-sys_admin,-sys_ptrace", "--"]
# Then the command leaves uid 0 for SCENARIO_ID (after DROP_CAPS, which needs uid 0's
# CAP_SETPCAP). A non-root uid keeps no capability across exec, and ptrace_may_access closes
# /proc/1/fd, /proc/1/mem and a ptrace attach of _inner or strace to it without any cap
# (DEP-3, D9). no_new_privs keeps a setuid or file-capability binary from handing it
# capabilities back, so this holds even without DROP_CAPS (DEP-3b). Not setpriv --reuid:
# it looks the number up as a user name first, and glibc's lookup tries nscd's socket, a
# host-socket connect in every run. Python with -I -S makes no lookup; a failed step exits 1.
_AS_SCENARIO = """import ctypes, os, sys
os.setgroups([])
os.setresgid(%(id)d, %(id)d, %(id)d)
os.setresuid(%(id)d, %(id)d, %(id)d)
if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
    sys.exit("depaudit: no_new_privs: " + os.strerror(ctypes.get_errno()))
if os.getresuid() != (%(id)d,) * 3 or os.getresgid() != (%(id)d,) * 3 or os.getgroups():
    sys.exit("depaudit: still holds another id")
os.execvp(sys.argv[1], sys.argv[1:])
""" % {"id": SCENARIO_ID}
AS_SCENARIO = [sys.executable, "-I", "-S", "-c", _AS_SCENARIO]


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


def _chown_tree(path, ident):
    """Gives path and everything under it to uid and gid ident, following no symlink."""
    os.lchown(path, ident, ident)
    for base, dirs, files in os.walk(path):
        for name in dirs + files:
            os.lchown(os.path.join(base, name), ident, ident)


def _end_namespace():
    """As the PID namespace's init, kills every other process in it and reaps them all, so
    nothing the scenario started still writes when its files go back to uid 0 (DEP-3)."""
    if os.getpid() != 1:
        raise RuntimeError("_inner is not its PID namespace's init")
    with contextlib.suppress(ProcessLookupError):
        os.kill(-1, signal.SIGKILL)  # from init: every process in the namespace but this one
    with contextlib.suppress(ChildProcessError):
        while True:
            os.waitpid(-1, 0)


def _hand_back(paths):
    """Ends the namespace, then gives paths back to uid 0 (the runner outside) so the runner
    can remove the work directory. In this order only: nothing the scenario started may
    still write once its files are root's (DEP-3, DEP-7g)."""
    _end_namespace()
    for path in paths:
        _chown_tree(path, 0)


def _inner(work, timeout, cmd, extra_keep=(), writable=(), drop_caps=True):
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
    masked = _mask_or_refuse(sorted(keep), writable)
    _place("nameserver 127.0.0.1\n", "/etc/resolv.conf", work, masked)
    if os.path.exists("/etc/nsswitch.conf"):
        lines = [l for l in pathlib.Path("/etc/nsswitch.conf").read_text().splitlines()
                 if not l.startswith("hosts:")]
        _place("\n".join(lines + ["hosts: files dns"]) + "\n", "/etc/nsswitch.conf", work, masked)
    # Checked last, after every mount the sandbox makes: no rw mount at or under a
    # read-only kept path, or the command never runs (DEP-4a).
    wrong = writable_mounts(pathlib.Path("/proc/self/mountinfo").read_text(), sorted(keep - writable), writable)
    if wrong:
        sys.exit("depaudit: sandbox not run, rw mount under a read-only kept path: %s; bind it read-only, "
                 "or drop the keep entry (tools/ASSUMPTIONS.md D10)" % ", ".join(wrong))
    names = []
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 53))
    threading.Thread(target=_dns_sink, args=(sink, names), daemon=True).start()
    scenario_owned = [work / d for d in ("tmp", "home", "stdout")]
    for d in scenario_owned[:2]:
        (work / d).mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(work / "tmp"), HOME=str(work / "home"))
    trace_r, trace_w = os.pipe()
    err_r, err_w = os.pipe()
    trace_t, trace = _reader(trace_r)
    err_t, err = _reader(err_r)
    with open(work / "stdout", "wb") as out:
        # The work directory is the scenario's; kept paths stay root-owned and read-only.
        for path in scenario_owned:
            _chown_tree(path, SCENARIO_ID)
        proc = subprocess.Popen(["strace", "-f", "-qq", "-e", "trace=" + TRACED,
                                 "-o", "/proc/%d/fd/%d" % (os.getpid(), trace_w), "--"]
                                + (DROP_CAPS if drop_caps else []) + AS_SCENARIO + cmd,
                                env=env, cwd=ROOT, stdout=out, stderr=err_w)
        os.close(err_w)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            rc = "timeout"
    os.close(trace_w)
    # A tracee strace let go of may still hold stderr; take what has arrived, then end it.
    trace_t.join(10)
    err_t.join(2)
    _hand_back(scenario_owned)
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


def _attempt(target, manifest, timeout, stats=None, drop_caps=True):
    """One sandboxed run in a fresh work directory: (result, whether strace faulted)."""
    profile = target.get("profile", "offline")
    with _scratch_dir("depaudit-", stats=stats) as work:
        os.chmod(work, 0o755)
        cmd = ["unshare"] + _unshare_flags() + ["--", sys.executable, str(pathlib.Path(__file__).resolve()),
                                                "_inner", "--work", work, "--timeout", str(timeout)]
        cmd += [] if drop_caps else ["--no-drop-caps"]
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


def run_target(target, manifest, timeout=600, drop_caps=True):
    """Reruns a scenario strace faulted on, up to STRACE_ATTEMPTS; what a faulted attempt
    saw is kept, so a fault can hide neither a leak nor (all faulting) pass. drop_caps=False
    is for tests only: it runs the scenario without DROP_CAPS, to show the uid boundary holds
    alone (DEP-3b). No registry entry or environment variable reaches it."""
    if target.get("profile", "offline") != "offline":
        raise ValueError("%s: only offline scenarios run in the sandbox" % target["name"])
    carried = []  # violations from attempts strace itself cut short
    stats = {"attempts": 0, "faults": 0, "cleanup_retries": 0}
    for attempt in range(1, STRACE_ATTEMPTS + 1):
        stats["attempts"] += 1
        out, fault = _attempt(target, manifest, timeout, stats, drop_caps)
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


def _clear_read_only(path):
    """What a scenario holding CAP_SYS_ADMIN over its mount namespace could do to a kept
    path without a traced call: clear MOUNT_ATTR_RDONLY in place (mount_setattr), or on a
    detached clone of the same mount (open_tree_attr, Linux 6.15+) and write through it."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    attr = (ctypes.c_uint64 * 4)(0, _MOUNT_ATTR_RDONLY, 0, 0)  # set, clr, propagation, userns_fd
    wrong = []
    if libc.syscall(_SYS_MOUNT_SETATTR, -100, path.encode(), _AT_RECURSIVE, attr, ctypes.sizeof(attr)) == 0:
        wrong.append("mount_setattr cleared read-only on " + path)
    fd = libc.syscall(_SYS_OPEN_TREE_ATTR, -100, path.encode(), _OPEN_TREE_CLONE | os.O_CLOEXEC | _AT_RECURSIVE,
                      attr, ctypes.sizeof(attr))
    if fd >= 0:
        wrong.append("open_tree_attr cloned %s writable" % path)
        probe = ".depaudit-write-%d" % os.getpid()
        try:
            os.close(os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, dir_fd=fd))
            os.unlink(probe, dir_fd=fd)
            wrong.append("wrote %s through the clone" % path)
        except OSError:
            pass
        os.close(fd)
    return wrong


_PTRACE_SEIZE = 0x4206


def _ptrace_denied(pid, comm, seize):
    """Tries to attach to an ancestor that keeps CAP_SYS_ADMIN, into which a tracer could
    inject mount_setattr (DEP-2b). With seize, a real PTRACE_SEIZE: it does not stop the
    target, and the kernel detaches it when this process exits. strace cannot be seized
    that way: once its own tracee traces it, the next stop of either deadlocks the pair. So
    for strace this opens /proc/PID/mem, which the kernel allows only after the same check
    PTRACE_ATTACH runs (ptrace_may_access in attach mode, Yama included)."""
    import ctypes
    try:
        got = pathlib.Path("/proc/%d/comm" % pid).read_text().strip()
    except OSError as e:
        return ["pid %d: %s" % (pid, e)]
    if not got.startswith(comm):
        return ["pid %d is %s, not %s: nothing was tried" % (pid, got, comm)]
    if seize:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
        if libc.ptrace(_PTRACE_SEIZE, pid, None, None) == 0:
            return ["ptrace attached to %s (pid %d)" % (got, pid)]
        err = ctypes.get_errno()
    else:
        try:
            os.close(os.open("/proc/%d/mem" % pid, os.O_RDONLY))
            return ["opened the memory of %s (pid %d) for ptrace" % (got, pid)]
        except OSError as e:
            err = e.errno
    if err in (errno.EPERM, errno.EACCES):
        return []
    return ["ptrace %s (pid %d): %s, not denied" % (got, pid, os.strerror(err))]


def _ids(pid):
    """The Uid: and Gid: fields of /proc/PID/status (real, effective, saved, fs)."""
    found = {}
    for line in pathlib.Path("/proc/%d/status" % pid).read_text().splitlines():
        k, _, v = line.partition(":")
        if k in ("Uid", "Gid"):
            found[k] = set(v.split())
    return found["Uid"], found["Gid"]


def _evidence_fds():
    """The fds of _inner (PID 1) to try. If its fd table is readable, the evidence pipes: a
    pipe it holds both ends of (the trace pipe), or the one this process's stderr writes to
    (strace's stderr). Its result pipe is left alone, so a breach shows as a lost connect,
    not as a torn result. If the table is unreadable, every fd below 64 is tried blind."""
    try:
        links = {int(n): os.readlink("/proc/1/fd/" + n) for n in os.listdir("/proc/1/fd")}
    except OSError:
        return list(range(64))
    mine = os.readlink("/proc/self/fd/2")
    held = collections.Counter(links.values())
    return sorted(n for n, l in links.items() if l.startswith("pipe:") and (held[l] > 1 or l == mine))


def _tracer_channels(strace):
    """Through the tracer's own /proc entry, so ptrace_may_access on strace is tried as well
    as the pipe's DAC: reopen strace's stderr to drain fault lines (DEP-7b), and signal strace
    and _inner (DEP-7c). Signal 0 runs kill's permission check and delivers nothing, so one
    that is allowed stops neither. Only a PermissionError is a refusal: a target that is not
    there was not denied by the uid. Returns each that was not refused."""
    wrong = []
    path = "/proc/%d/fd/2" % strace
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except PermissionError:
        pass
    except OSError as e:
        wrong.append("%s (strace's stderr): %s, not denied" % (path, e.strerror))
    else:
        with contextlib.suppress(OSError):
            os.read(fd, 1 << 20)
        os.close(fd)
        wrong.append("opened %s (strace's stderr) to read" % path)
    for who, pid in (("strace", strace), ("_inner", 1)):
        try:
            os.kill(pid, 0)
        except PermissionError:
            continue
        except OSError as e:
            wrong.append("signal 0 to %s (pid %d): %s, not denied" % (who, pid, e.strerror))
        else:
            wrong.append("signalled %s (pid %d)" % (who, pid))
    return wrong


def _evidence_channels():
    """What a tracee sharing _inner's uid could do to the evidence without a traced call
    (D9): drain the trace or stderr pipe's read end, write a partial line into its write end
    so strace's next line no longer parses, PTRACE_SEIZE _inner, and reopen strace's stderr
    or signal strace and _inner (_tracer_channels). Returns each that worked."""
    import ctypes
    wrong = []
    strace = os.getppid()
    try:
        comm = pathlib.Path("/proc/%d/comm" % strace).read_text().strip()
    except OSError as e:
        comm = str(e)
    if comm.startswith("strace"):
        wrong += _tracer_channels(strace)
    else:
        wrong.append("parent pid %d is %s, not strace: its stderr and signals were not tried" % (strace, comm))
    for n in _evidence_fds():
        path = "/proc/1/fd/%d" % n
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        except OSError:
            pass
        else:
            with contextlib.suppress(OSError):
                os.read(fd, 1 << 20)
            os.close(fd)
            wrong.append("opened %s to read" % path)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            continue
        with contextlib.suppress(OSError):
            os.write(fd, b"depaudit partial line, no newline ")
        os.close(fd)
        wrong.append("opened %s to write" % path)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    if libc.ptrace(_PTRACE_SEIZE, 1, None, None) == 0:
        wrong.append("ptrace attached to pid 1 (_inner)")
    return wrong


def _loopback_call():
    """One logged loopback call, so a control is seen to have run under strace."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"x", ("127.0.0.1", 9))


def _id_triples(text):
    return sorted(tuple(int(x) for x in line.split()) for line in text.splitlines() if line.strip())


def _refused_read_only(err, path):
    """A write refused because path's mount is read-only. As SCENARIO_ID the kernel may check
    file permissions first and say EACCES (DEP-3); that counts only on a read-only mount."""
    if err.errno == errno.EROFS:
        return True
    return err.errno == errno.EACCES and bool(os.statvfs(path).f_flag & os.ST_RDONLY)


def _control(mode):
    """Planted scenarios against the harness's own defences (DEP-2), run as
    `depaudit.py _control MODE` inside the sandbox.
      tamper-evidence  connects to a documentation address, then truncates or rewrites
                       every evidence file the harness once read from its work directory
      write-kept       exits nonzero unless every write to ROOT (tools/depaudit.py too),
                       sys.prefix and $DEPAUDIT_KEEP_RO fails read-only, and a write to
                       $DEPAUDIT_KEEP_RW (declared in the target's writes) succeeds; first it
                       tries to clear read-only with the untraced mount_setattr and
                       open_tree_attr (a mount(2) remount is traced: a violation by itself)
      ptrace-ancestors exits nonzero unless a ptrace attach to the sandbox's PID 1 (_inner)
                       and to its strace parent is denied: either still holds CAP_SYS_ADMIN
      own-user-namespace exits nonzero unless the scenario's uid_map and gid_map are exactly
                       $DEPAUDIT_UID_MAP and $DEPAUDIT_GID_MAP, the maps the harness sets (DEP-3c)
      distinct-uid     exits nonzero if its uid or gid shares a value with _inner's (PID 1) or
                       its strace parent's (DEP-3a), or no_new_privs is not set (DEP-7d)
      evidence-channels connects to a documentation address, drains and writes a partial line
                       into _inner's evidence pipes through /proc/1/fd, PTRACE_SEIZEs _inner,
                       reopens strace's stderr through /proc/<strace>/fd/2, signals strace and
                       _inner with signal 0, connects again, and exits nonzero if any of that
                       worked (DEP-3b, DEP-7b, DEP-7c)"""
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
    if mode == "ptrace-ancestors":
        wrong = _ptrace_denied(1, "python", True) + _ptrace_denied(os.getppid(), "strace", False)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"x", ("127.0.0.1", 9))
        if wrong:
            sys.exit("; ".join(wrong))
        return 0
    if mode == "own-user-namespace":
        _loopback_call()
        wrong = []
        for name in ("uid_map", "gid_map"):
            got = pathlib.Path("/proc/self/" + name).read_text()
            want = os.environ["DEPAUDIT_" + name.upper()]
            if _id_triples(got) != _id_triples(want):
                wrong.append("%s is %r, not %r" % (name, " / ".join(" ".join(l.split()) for l in got.splitlines()),
                                                   " / ".join(want.splitlines())))
        if wrong:
            sys.exit("; ".join(wrong))
        return 0
    if mode == "distinct-uid":
        _loopback_call()
        ppid = os.getppid()
        if not pathlib.Path("/proc/%d/comm" % ppid).read_text().startswith("strace"):
            sys.exit("parent pid %d is not strace: nothing was compared" % ppid)
        uid, gid = _ids(os.getpid())
        wrong = []
        # no_new_privs, set by AS_SCENARIO, keeps a setuid or file-capability binary from
        # handing the scenario capabilities back (DEP-3b, DEP-7d).
        if "NoNewPrivs:\t1" not in pathlib.Path("/proc/self/status").read_text().splitlines():
            wrong.append("no_new_privs is not set (no 'NoNewPrivs:\\t1' in /proc/self/status)")
        for who, pid in (("_inner", 1), ("strace", ppid)):
            ouid, ogid = _ids(pid)
            if uid & ouid or gid & ogid:
                wrong.append("uid %s gid %s shares an id with %s's uid %s gid %s" % (
                    sorted(uid), sorted(gid), who, sorted(ouid), sorted(ogid)))
        if wrong:
            sys.exit("; ".join(wrong))
        return 0
    if mode == "evidence-channels":
        with contextlib.suppress(OSError):
            socket.create_connection(("192.0.2.10", 443), timeout=2).close()
        wrong = _evidence_channels()
        with contextlib.suppress(OSError):
            socket.create_connection(("192.0.2.10", 443), timeout=2).close()
        if wrong:
            sys.exit("; ".join(wrong))
        return 0
    if mode != "write-kept":
        raise ValueError(mode)
    wrong = []
    for d in (str(ROOT), os.path.realpath(sys.prefix), os.environ["DEPAUDIT_KEEP_RO"]):
        wrong += _clear_read_only(d)
        probe = os.path.join(d, ".depaudit-write-%d" % os.getpid())
        try:
            os.close(os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            os.unlink(probe)
            wrong.append("wrote " + d)
        except OSError as e:
            if not _refused_read_only(e, d):
                wrong.append("%s: %s, not read-only" % (d, e))
    ro_kept = [str(ROOT), os.path.realpath(sys.prefix), os.environ["DEPAUDIT_KEEP_RO"]]
    wrong += ["rw mount under a read-only kept path: " + m for m in kept_rw_mounts(
        pathlib.Path("/proc/self/mounts").read_text(), ro_kept, [os.environ["DEPAUDIT_KEEP_RW"]])]
    try:
        os.close(os.open(__file__, os.O_WRONLY | os.O_APPEND))
        wrong.append("opened %s for writing" % __file__)
    except OSError as e:
        if not _refused_read_only(e, __file__):
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
        {"name": "control-no-ptrace-ancestors", "cmd": own + ["ptrace-ancestors"], "expect": "pass",
         "must_log": [("inet", "127.0.0.1")]},
        {"name": "control-own-user-namespace", "cmd": own + ["own-user-namespace"], "expect": "pass",
         "env": _expected_maps_env(), "must_log": [("inet", "127.0.0.1")]},
        # DEP-3: the scenario's uid is not _inner's or strace's, so the evidence pipes and a
        # ptrace of _inner are closed to it by uid alone.
        {"name": "control-distinct-uid", "cmd": own + ["distinct-uid"], "expect": "pass",
         "must_log": [("inet", "127.0.0.1")]},
        {"name": "control-evidence-channels", "cmd": own + ["evidence-channels"], "expect": "violation",
         "expect_kinds": ["ipv4"], "must_log": [("inet", "192.0.2.10")]},
    ]


def _expected_maps_env():
    """The maps control-own-user-namespace compares against; empty if there is no range (the
    sandbox is then unavailable and no control runs)."""
    try:
        uid_map, gid_map = _id_maps()
    except OSError:
        return {"DEPAUDIT_UID_MAP": "", "DEPAUDIT_GID_MAP": ""}
    return {"DEPAUDIT_UID_MAP": _map_text(uid_map), "DEPAUDIT_GID_MAP": _map_text(gid_map)}


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
        print("FAIL sandbox unavailable: %s" % SANDBOX_WHY, file=sys.stderr)
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
        os.chmod(writable_dir, 0o777)  # the scenario runs as SCENARIO_ID (DEP-3)
        probes = []
        for d in (masked_dir, visible_dir):
            probe = socket.socket(socket.AF_UNIX)
            probe.bind(os.path.join(d, "p"))
            probe.listen(16)
            probes.append(probe)
            # Connecting needs write permission on the socket; the scenario is not its owner.
            os.chmod(os.path.join(d, "p"), 0o666)
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
    i.add_argument("--no-drop-caps", action="store_true", help=argparse.SUPPRESS)  # tests only (DEP-3b)
    i.add_argument("subject", nargs=argparse.REMAINDER)
    c = sub.add_parser("_control")
    c.add_argument("mode")
    args = ap.parse_args(argv)
    if args.cmd == "_inner":
        return _inner(args.work, args.timeout, args.subject[1:] if args.subject[:1] == ["--"] else args.subject,
                      args.keep, args.writable, not args.no_drop_caps)
    if args.cmd == "_control":
        return _control(args.mode)
    return cmd_static(args) if args.cmd == "static" else cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
