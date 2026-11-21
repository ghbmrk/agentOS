#!/usr/bin/env python3
"""Every static ELF file the built image ships is declared with what it links (VULN-static-elf part b,
#5885, EVL-5).

tools/vulncheck.py image scans dpkg statuses. A file that carries a C library or C++ runtime in its own
bytes is scanned only when something records where that code came from, so this lists every such file
and holds it to image/static_elf.allow:

  static_elf.py OUT VERSION [ALLOW]      the build in OUT (as root: offline_systemd.built_tree mounts it):
                                         the main tree (root partition and verified /usr, the guests'
                                         roots under /usr/lib/agentos/images/ included) and each initrd
  static_elf.py --tree DIR OUT [ALLOW]   a plain directory read as the main tree, with OUT's lists

A file is listed (SEL-5) when it is an x86 executable or shared object (ET_EXEC or ET_DYN, EM_X86_64 or
EM_386; relocatable objects and other machines' firmware run nothing here) and either names no
interpreter and no NEEDED library (import_sweep.read_elf's "static"), or is dynamic, needs no libstdc++
or libc++, and carries a C++ runtime: it defines one of CXX_DEFS or holds one of CXX_MARKS.

Each listed file must match exactly one entry of ALLOW, a line "GLOB KIND [ARG]", GLOB an absolute
fnmatch pattern on the file's path (an initrd's members by their path inside it). Kinds (SEL-6):
  go             a Go binary built without cgo, read from the file: its build info says CGO_ENABLED=0, or
                 records no setting and the file holds none of runtime/cgo's C code (go_cgo): no C library
  linked LIST    a build step recorded the file's link inputs (image/guest-shipped.sh with SHIPPED_FOR):
                 OUT/LIST/agentos.inputs names the packages its link loaded, by the file's SHA-256, and
                 each must be in OUT/LIST/agentos.dpkg-status, the status the scan reads for LIST
                 ("linked": the main tree's, "guest": the guests')
  package PKG    PKG, installed in the file's tree's status, ships it: the main tree's (and there the file
                 must match dpkg's md5sum at its path, agentos.dpkg-md5sums), the guests' for a file under
                 the guests' roots, the initrd's own for an initrd member. vulncheck.py also queries each
                 source a package's Built-Using names, so a Debian static build's sources are scanned.
  bundled HOLDER a pinned download's binary: assurance/vulncheck.json "bundled" names HOLDER
  sha256 HEX     a pinned download's binary reviewed as linking no library (raw system calls), held to
                 those exact bytes, so a new release fails until it is read again
A listed file matching no entry or two, an entry matching no listed file, an unknown kind, and any
kind's check that fails are refusals. Control (SEL-7): the main tree must list each of REQUIRED, and
a file the check cannot read fails, so a clean result is not a walk that read nothing. Exit 1 on any.
"""
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ALLOW = HERE / "static_elf.allow"
CONFIG = HERE.parent / "assurance" / "vulncheck.json"
sys.path.insert(0, str(HERE))
import import_sweep  # noqa: E402  (the tree walk and ELF reader; #5889 holds that file, so it is imported, not edited)

ET_EXEC, ET_DYN = 2, 3
MACHINES = (3, 62)  # EM_386, EM_X86_64
# The main tree always lists these (SEL-7): llama-server (static libstdc++ and glibc), runsc (Go),
# agentos-camdecode (static glibc and libavcodec) and Debian's static ldconfig.
REQUIRED = ("/usr/lib/agentos/infer/llama-server", "/usr/lib/agentos/runsc",
            "/usr/lib/agentos/images/camdecode/agentos-camdecode", "/usr/sbin/ldconfig")
GUEST_ROOTS = "/usr/lib/agentos/images/"
LISTS = ("linked", "guest")
INPUTS, STATUS, MD5SUMS = "agentos.inputs", "agentos.dpkg-status", "agentos.dpkg-md5sums"
INITRD_STATUS = "/usr/share/agentos/initrd.dpkg-status"
# A C++ runtime's own code: the ABI entry points libsupc++ and libc++abi define, and the strings they
# hold (the verbose terminate handler's message; __class_type_info's type name, which only the runtime
# defines, NUL on each side so the tail of an imported symbol's name in .dynstr does not count).
CXX_DEFS = {"__cxa_throw", "__cxa_begin_catch", "__gxx_personality_v0", "_ZSt9terminatev"}
CXX_MARKS = (b"terminate called after throwing an instance of '", b"\0N10__cxxabiv117__class_type_infoE\0",
             b"terminating due to uncaught exception of type ")
CXX_NEEDED = re.compile(r"^lib(std)?c\+\+\.so")
SYM = re.compile(r"^[0-9a-f]+\s.{7}\s(\S+)\s+[0-9a-f]+\s+(?:\S+\s+)?(\S+)$")
BUILDINFO = b"\xff Go buildinf:"
# A Go binary's section names, for one whose build info is missing.
GO_SECTIONS = (b"\0.gopclntab\0", b"\0.go.buildinfo\0")
# runtime/cgo's C code (gcc_libinit.c _cgo_try_pthread_create's message): in every cgo binary, static or
# dynamic, glibc or musl, and in no binary built with cgo off.
CGO_MARK = b"pthread_create failed"


class Unread(Exception):
    """A file the check cannot read."""


def header(data):
    """(e_type, e_machine) of ELF bytes DATA; Unread when too short or of an unknown class or order."""
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] != 1:
        raise Unread("not a little-endian ELF file of a known class")
    return struct.unpack_from("<HH", data, 16)


def go_cgo(data):
    """A Go binary's cgo state, read from DATA: "0" or "1" from its build info's CGO_ENABLED; for a Go
    binary whose build info records no setting (Bazel's rules_go, as gVisor's release is built) or that
    has none (a .gopclntab section but no .go.buildinfo, as esbuild's release), "cgo" when it holds
    runtime/cgo's C code (CGO_MARK) and "none" when it does not; None when DATA is no Go binary. Unread
    when the build info is of a form this cannot read (pre-1.18, by pointer)."""
    i = data.find(BUILDINFO)
    while i >= 0 and i % 16:
        i = data.find(BUILDINFO, i + 1)
    if i < 0:
        if not any(m in data for m in GO_SECTIONS):
            return None
        return "cgo" if CGO_MARK in data else "none"
    if len(data) < i + 32 or not data[i + 15] & 2:
        raise Unread("Go build info is not inline (Go before 1.18?)")
    j, out = i + 32, []
    for _ in range(2):
        n = shift = 0
        while True:
            if j >= len(data):
                raise Unread("Go build info is truncated")
            b = data[j]
            j += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        out.append(data[j:j + n])
        j += n
    m = re.search(rb"(?m)^build\tCGO_ENABLED=(\d)$", out[1])
    if m:
        return m.group(1).decode()
    return "cgo" if CGO_MARK in data else "none"


def go_shown(go):
    return {"0": "Go CGO_ENABLED=0", "1": "Go CGO_ENABLED=1", "none": "Go, no cgo setting, no cgo code",
            "cgo": "Go, no cgo setting, cgo code"}[go]


def cxx_defined(path):
    """Whether the file at PATH defines (not imports) one of CXX_DEFS in its symbol tables."""
    r = subprocess.run(["objdump", "-tT", str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       text=True, errors="replace")
    for line in r.stdout.splitlines():
        m = SYM.match(line)
        if m and m.group(1) != "*UND*" and m.group(2).split("@")[0] in CXX_DEFS:
            return True
    return False


def classify(path):
    """None when the ELF file at PATH is not listed (SEL-5); else {"why": "static" or "c++ runtime",
    "sha256", "go": go_cgo's answer}. Unread when objdump or the header cannot read it."""
    try:
        data = pathlib.Path(path).read_bytes()
    except OSError as e:
        raise Unread(str(e))
    e_type, machine = header(data)
    if e_type not in (ET_EXEC, ET_DYN) or machine not in MACHINES:
        return None
    _syms, needed, _soname, read, how = import_sweep.read_elf(path)
    if not read:
        raise Unread("objdump cannot read it")
    if how == "static":
        why = "static"
    elif any(CXX_NEEDED.match(n) for n in needed):
        return None
    elif any(m in data for m in CXX_MARKS) or cxx_defined(path):
        why = "c++ runtime"
    else:
        return None
    return {"why": why, "sha256": hashlib.sha256(data).hexdigest(), "go": go_cgo(data)}


def listed(files):
    """({shown: classify} of the listed files among FILES, {shown: reason} of those it cannot read)."""
    out, unread = {}, {}
    for shown, real in sorted(files.items()):
        try:
            c = classify(real)
        except Unread as e:
            unread[shown] = str(e)
            continue
        if c:
            out[shown] = c
    return out, unread


def installed(text):
    """The name of each installed package in a dpkg status text (as tools/vulncheck.py dpkg_installed reads it)."""
    out = set()
    for stanza in re.split(r"\n\s*\n", text):
        f = dict(m.groups() for m in re.finditer(r"(?m)^([A-Za-z-]+):[ \t]*(.*)$", stanza))
        if f.get("Status", "").endswith(" installed") and f.get("Package"):
            out.add(f["Package"])
    return out


def read_text(p):
    try:
        return pathlib.Path(p).read_text()
    except OSError:
        return None


def context(out, config=CONFIG):
    """What the kinds are checked against, from build OUT: each LIST's inputs and status, the main tree's
    status and md5sums, and the bundled holders."""
    out = pathlib.Path(out)
    lists = {}
    for name in LISTS:
        inputs = {}
        for line in (read_text(out / name / INPUTS) or "").splitlines():
            parts = line.split()
            if len(parts) == 2:
                inputs.setdefault(parts[0], set()).add(parts[1])
        status = read_text(out / name / STATUS)
        lists[name] = {"inputs": inputs, "status": installed(status) if status else None}
    md5 = {}
    for line in (read_text(out / MD5SUMS) or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            md5["/" + parts[1].strip().lstrip("/")] = parts[0]
    main = read_text(out / STATUS)
    try:
        holders = {b["holder"] for b in json.loads(pathlib.Path(config).read_text()).get("bundled", [])}
    except (OSError, ValueError, KeyError, TypeError):
        holders = set()
    return {"lists": lists, "md5": md5, "status": {"tree": installed(main) if main else None,
                                                   "guest": lists["guest"]["status"]},
            "holders": holders}


def read_allow(path):
    """[(line number, glob, kind, arg)] of ALLOW; ValueError naming a line it cannot read."""
    entries = []
    for n, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if not parts[0].startswith("/") or parts[1:2] not in (["go"], ["linked"], ["package"], ["bundled"], ["sha256"]) \
                or len(parts) != (2 if parts[1] == "go" else 3) \
                or (parts[1] == "sha256" and not re.fullmatch(r"[0-9a-fA-F]{64}", parts[2])):
            raise ValueError("%s:%d: not \"GLOB go\" or \"GLOB linked|package|bundled|sha256 ARG\": %r" % (path, n, line))
        entries.append((n, parts[0], parts[1], parts[2] if len(parts) == 3 else None))
    return entries


def kind_refusal(shown, place, info, kind, arg, ctx, place_status):
    """Why the listed file SHOWN of PLACE fails its entry's KIND, or None."""
    if kind == "go":
        if info["go"] in ("0", "none"):
            return None
        return "not a Go binary" if info["go"] is None else "a Go binary with cgo (%s)" % go_shown(info["go"])
    if kind == "sha256":
        return None if info["sha256"] == arg.lower() else "its SHA-256 is %s, not the reviewed %s" % (info["sha256"], arg)
    if kind == "linked":
        lst = ctx["lists"].get(arg)
        if lst is None:
            return "linked names no list %r (one of %s)" % (arg, ", ".join(LISTS))
        pkgs = lst["inputs"].get(info["sha256"])
        if not pkgs:
            return "no link inputs recorded for its SHA-256 %s in %s/%s" % (info["sha256"], arg, INPUTS)
        if lst["status"] is None:
            return "%s/%s is missing or empty" % (arg, STATUS)
        missing = sorted(pkgs - lst["status"])
        return "its link inputs %s are not in %s/%s" % (missing, arg, STATUS) if missing else None
    if kind == "package":
        if place_status is None:
            return "its tree has no dpkg status to own it"
        if arg not in place_status:
            return "package %s is not installed in its tree's status" % arg
        if place == "tree" and not shown.startswith(GUEST_ROOTS):
            want = ctx["md5"].get(shown) or ctx["md5"].get(shown[4:] if shown.startswith("/usr/") else None)
            with open(info["real"], "rb") as f:
                got = hashlib.md5(f.read()).hexdigest()
            if want != got:
                return "its bytes are not the ones dpkg installed at that path (%s)" % MD5SUMS
        return None
    if arg not in ctx["holders"]:
        return "assurance/vulncheck.json \"bundled\" names no holder %r" % arg
    return None


def refusals(places, entries, ctx, statuses):
    """Each refusal (module docstring) of PLACES ({place: {shown: info}}) against ENTRIES."""
    errs, used = [], set()
    for place, files in sorted(places.items()):
        for shown, info in sorted(files.items()):
            hits = [e for e in entries if fnmatch.fnmatchcase(shown, e[1])]
            used.update(e[0] for e in hits)
            where = shown if place == "tree" else "%s %s" % (place, shown)
            if not hits:
                errs.append("%s (%s%s): no entry in static_elf.allow declares it" % (
                    where, info["why"], "" if info["go"] is None else ", " + go_shown(info["go"])))
                continue
            if len(hits) > 1:
                errs.append("%s: matches %d entries (lines %s)" % (where, len(hits), ", ".join(str(e[0]) for e in hits)))
                continue
            status = statuses.get(place)
            if place == "tree":
                status = ctx["status"]["guest" if shown.startswith(GUEST_ROOTS) else "tree"]
            why = kind_refusal(shown, place, info, hits[0][2], hits[0][3], ctx, status)
            if why:
                errs.append("%s: %s %s: %s" % (where, hits[0][2], hits[0][3] or "", why))
    errs += ["static_elf.allow:%d: %s matches no listed file" % (n, g) for n, g, _k, _a in entries if n not in used]
    return errs


def control(places, unread):
    errs = ["%s: cannot read %s: %s" % (place, shown, why) for place, u in sorted(unread.items())
            for shown, why in sorted(u.items())]
    tree = places.get("tree", {})
    errs += ["tree: %s is not listed, so the walk did not read what it should have (control)" % p
             for p in REQUIRED if p not in tree]
    return errs


def tree_files(root, usr=None):
    files = import_sweep.tree_files(root, skip=("usr",) if usr else ())
    if usr:
        files.update(import_sweep.tree_files(usr, "/usr"))
    return files


def initrd_places(out, places, unread, statuses):
    import finish_image
    initrds = pathlib.Path(out) / "initrd"
    for p in sorted(pathlib.Path(d, n) for d, _, names in import_sweep.walk(initrds) for n in names
                    if import_sweep.is_file(os.path.join(d, n))):
        key = "initrd:" + str(p.relative_to(initrds))
        files, status = {}, None
        with tempfile.TemporaryDirectory() as scratch:
            for i, (name, mode, body, _link) in enumerate(finish_image.cpio_members(p.read_bytes())):
                shown = "/" + name.lstrip("/")
                if stat.S_ISREG(mode) and shown == INITRD_STATUS:
                    status = installed(body.decode("utf-8", "replace"))
                if stat.S_ISREG(mode) and body[:4] == b"\x7fELF":
                    f = os.path.join(scratch, "%d" % i)
                    pathlib.Path(f).write_bytes(body)
                    files[shown] = f
            places[key], unread[key] = listed(files)
            for shown, info in places[key].items():
                info["real"] = None  # md5 is read only for the main tree
        statuses[key] = status


def run(root, usr, out, allow):
    files = tree_files(root, usr)
    places, unread, statuses = {}, {}, {}
    places["tree"], unread["tree"] = listed(files)
    for shown, info in places["tree"].items():
        info["real"] = files[shown]
    if usr is not None:
        initrd_places(out, places, unread, statuses)
    entries = read_allow(allow)
    return places, control(places, unread) + refusals(places, entries, context(out), statuses)


def main(argv):
    if len(argv) in (3, 4) and argv[0] == "--tree":
        places, errs = run(argv[1], None, argv[2], argv[3] if len(argv) == 4 else ALLOW)
    elif len(argv) in (2, 3) and not argv[0].startswith("-"):
        import offline_systemd
        root, usr, _cmdline, cleanup = offline_systemd.built_tree(argv[0], argv[1])
        try:
            places, errs = run(root, usr, argv[0], argv[2] if len(argv) == 3 else ALLOW)
        finally:
            cleanup()
    else:
        sys.exit(__doc__)
    for place, files in sorted(places.items()):
        for shown, info in sorted(files.items()):
            print("%s %s: %s%s sha256=%s" % (place, shown, info["why"], "" if info["go"] is None else ", " + go_shown(info["go"]),
                                             info["sha256"]))
    for e in errs:
        print("::error title=static ELF check::" + e.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
