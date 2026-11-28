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
interpreter and no NEEDED library (import_sweep.read_elf's STATIC), or is dynamic, needs no libstdc++
or libc++, and holds one of CXX_MARKS, a C++ runtime's own strings (a shipped file is stripped, so its
symbols say nothing).

Each listed file must match exactly one entry of ALLOW, a line "GLOB KIND [ARG]", GLOB an absolute
pattern on the file's path (an initrd's members by their path inside it) matched segment by segment, so
"*" never crosses "/" (matches). Kinds (SEL-6):
  go             a Go binary built without cgo, read from the file (go_cgo): its section headers name
                 .gopclntab; the build info at .go.buildinfo says CGO_ENABLED=0, or there is none or it records
                 no setting; the file holds none of runtime/cgo's C code; and its function table lists no
                 function without a line table (C code an internal link took from a .syso): no C library
  linked LIST    a build step recorded the file's link inputs (image/guest-shipped.sh with SHIPPED_FOR):
                 OUT/LIST/agentos.inputs names the packages its link loaded, by the file's SHA-256, and
                 each must be in OUT/LIST/agentos.dpkg-status, the status the scan reads for LIST
                 ("linked": the main tree's, "guest": the guests')
  package PKG    PKG, installed in the file's tree's status, ships these bytes: in the main tree, dpkg's
                 md5sum at its path (agentos.dpkg-md5sums); under the guests' roots, the guests' status and
                 an MD5 image/guest-userland.sh recorded for PKG as it copied the file (guest/agentos.md5sums);
                 in an initrd, its own status, PKG at the main tree's version, and the main tree's md5sum at
                 its path. vulncheck.py also queries each source a package's Built-Using names, so a Debian
                 static build's sources are scanned.
  bundled HOLDER a pinned download's binary: assurance/vulncheck.json "bundled" names HOLDER
  sha256 HEX     a pinned download's binary reviewed as linking no library (raw system calls), held to
                 those exact bytes, so a new release fails until it is read again; only a static file of
                 at most SHA256_MAX bytes, too small to hold a C library
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
INITRD_REQUIRED = "/usr/sbin/ldconfig"
LISTS = ("linked", "guest")
INPUTS, STATUS, MD5SUMS = "agentos.inputs", "agentos.dpkg-status", "agentos.dpkg-md5sums"
# "MD5 PACKAGE" for each file image/guest-userland.sh copied into a guest (guest-shipped.sh SHIPPED_BYTES).
COPIED = "agentos.md5sums"
INITRD_STATUS = "/usr/share/agentos/initrd.dpkg-status"
# A C++ runtime's own code: strings libsupc++ and libc++abi hold (the verbose terminate handlers'
# messages; __class_type_info's type name, which only the runtime defines, NUL on each side so the tail of
# an imported symbol's name in .dynstr does not count).
CXX_MARKS = (b"terminate called after throwing an instance of '", b"\0N10__cxxabiv117__class_type_infoE\0",
             b"terminating due to uncaught exception of type ")
CXX_NEEDED = re.compile(r"^lib(std)?c\+\+\.so")
BUILDINFO = b"\xff Go buildinf:"
SHT_NOBITS = 8
# The function table formats read (Go 1.18 and 1.20 onward); an older one is unread.
PCLN_MAGICS = (0xFFFFFFF0, 0xFFFFFFF1)
# The largest file the sha256 kind may declare: gVisor's sidecars are 1.4 KiB; a static libc is far larger.
SHA256_MAX = 16384
# runtime/cgo's C code (gcc_libinit.c _cgo_try_pthread_create's message): in every cgo binary, static or
# dynamic, glibc or musl, and in no binary built with cgo off. An external link, the one way C reaches a
# Go binary outside its function table, needs cgo (Go refuses -linkmode=external with cgo off).
CGO_MARK = b"pthread_create failed"


class Unread(Exception):
    """A file the check cannot read."""


def header(data):
    """(e_type, e_machine) of ELF bytes DATA; Unread when too short or of an unknown class or order."""
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] != 1:
        raise Unread("not a little-endian ELF file of a known class")
    return struct.unpack_from("<HH", data, 16)


def sections(data):
    """{name: (file offset, size)} of ELF bytes DATA's section header table ({} when it has none);
    Unread when the table or a section lies outside the file (L3 7068815628 point 4a)."""
    try:
        if data[4] == 2:
            shoff, = struct.unpack_from("<Q", data, 40)
            entsize, num, strndx = struct.unpack_from("<HHH", data, 58)
            form, want = "<IIQQQQ", 64
        else:
            shoff, = struct.unpack_from("<I", data, 32)
            entsize, num, strndx = struct.unpack_from("<HHH", data, 46)
            form, want = "<IIIIII", 40
        if num == 0:
            return {}
        if entsize != want or shoff + num * want > len(data) or strndx >= num:
            raise Unread("its section header table is not inside the file")
        heads = [struct.unpack_from(form, data, shoff + k * want) for k in range(num)]
        out = {}
        for name, typ, _flags, _addr, off, size in heads:
            if typ != SHT_NOBITS and off + size > len(data):
                raise Unread("a section lies past the end of the file")
            out[name] = (off, size) if typ != SHT_NOBITS else (off, 0)
        names = data[heads[strndx][4]:heads[strndx][4] + heads[strndx][5]]
        return {names[n:names.index(b"\0", n)].decode("latin-1"): v for n, v in out.items()}
    except (struct.error, IndexError, ValueError) as e:
        raise Unread("its section header table cannot be read (%s)" % e)


def no_line_funcs(table):
    """The functions of Go function table bytes TABLE (.gopclntab) that have no line table, the linker's own
    "go:" markers aside: code an internal link took from a host object (a .syso), which has no Go
    source (L3 7068815628 point 4b). Unread for a format this cannot read."""
    try:
        magic, = struct.unpack_from("<I", table, 0)
        if magic not in PCLN_MAGICS or table[7] != 8:
            raise Unread("its Go function table is of a format this cannot read (magic %#x)" % magic)
        nfunc, _files, _text, names, _cu, _filetab, _pctab, funcs = struct.unpack_from("<8Q", table, 8)
        out = []
        for k in range(nfunc):
            _entry, off = struct.unpack_from("<II", table, funcs + 8 * k)
            # _func: entryOff, nameOff, args, deferreturn, pcsp, pcfile, pcln (the same in both formats).
            _e, name, _a, _d, _sp, _file, pcln = struct.unpack_from("<IiIIIII", table, funcs + off)
            start = names + name
            shown = table[start:table.index(b"\0", start)].decode("latin-1")
            if pcln == 0 and not shown.startswith("go:"):
                out.append(shown)
        return out
    except (struct.error, IndexError, ValueError) as e:
        raise Unread("its Go function table cannot be read (%s)" % e)


def go_cgo(data):
    """A Go binary's cgo state, read from DATA: None when its section headers name no .gopclntab (no Go
    binary, whatever bytes it holds). Else the build info's CGO_ENABLED, read at .go.buildinfo, "0" or
    "1", or "none" when there is no build info (esbuild's release) or it records no setting (Bazel's
    rules_go, as gVisor's release is built); suffixed "-cgo" ("cgo" for none) when the file holds
    runtime/cgo's C code (CGO_MARK), or "-c" ("c" for none) when its function table lists a function
    with no line table (no_line_funcs). Unread when the headers, the table or the build info cannot be
    read (build info before Go 1.18 is by pointer)."""
    secs = sections(data)
    if ".gopclntab" not in secs:
        return None
    off, size = secs[".gopclntab"]
    setting = "none"
    if ".go.buildinfo" in secs:
        i, n = secs[".go.buildinfo"]
        if data[i:i + len(BUILDINFO)] != BUILDINFO:
            raise Unread(".go.buildinfo does not start with Go's build info")
        if n < 32 or not data[i + 15] & 2:
            raise Unread("Go build info is not inline (Go before 1.18?)")
        j, end, out = i + 32, i + n, []
        for _ in range(2):
            m = shift = 0
            while True:
                if j >= end:
                    raise Unread("Go build info is truncated")
                b = data[j]
                j += 1
                m |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            out.append(data[j:j + m])
            j += m
        found = re.search(rb"(?m)^build\tCGO_ENABLED=(\d)$", out[1])
        if found:
            setting = found.group(1).decode()
    # Build info saying cgo off is held to the code too (Security 7068790342 R2).
    if setting != "1" and CGO_MARK in data:
        return "cgo" if setting == "none" else "0-cgo"
    if setting != "1" and no_line_funcs(data[off:off + size]):
        return "c" if setting == "none" else "0-c"
    return setting


def go_shown(go):
    return {"0": "Go CGO_ENABLED=0", "1": "Go CGO_ENABLED=1", "none": "Go, no cgo setting, no cgo code",
            "cgo": "Go, no cgo setting, cgo code", "0-cgo": "Go CGO_ENABLED=0 but cgo code",
            "c": "Go, no cgo setting, C functions with no line table",
            "0-c": "Go CGO_ENABLED=0 but C functions with no line table"}[go]


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
    _syms, needed, _soname, read, _lookup, static = import_sweep.read_elf(path)
    if not read:
        raise Unread("objdump cannot read it")
    if static:
        why = "static"
    elif any(CXX_NEEDED.match(n) for n in needed):
        return None
    elif any(m in data for m in CXX_MARKS):
        why = "c++ runtime"
    else:
        return None
    return {"why": why, "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
            "go": go_cgo(data), "size": len(data)}


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
    """{name: version} of each installed package in a dpkg status text (as tools/vulncheck.py
    dpkg_installed reads it)."""
    out = {}
    for stanza in re.split(r"\n\s*\n", text):
        f = dict(m.groups() for m in re.finditer(r"(?m)^([A-Za-z-]+):[ \t]*(.*)$", stanza))
        if f.get("Status", "").endswith(" installed") and f.get("Package"):
            out[f["Package"]] = f.get("Version")
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
    copied = {}
    for line in (read_text(out / "guest" / COPIED) or "").splitlines():
        parts = line.split()
        if len(parts) == 2:
            copied.setdefault(parts[0], set()).add(parts[1])
    main = read_text(out / STATUS)
    try:
        holders = {b["holder"] for b in json.loads(pathlib.Path(config).read_text()).get("bundled", [])}
    except (OSError, ValueError, KeyError, TypeError):
        holders = set()
    return {"lists": lists, "md5": md5, "status": {"tree": installed(main) if main else None,
                                                   "guest": lists["guest"]["status"]},
            "holders": holders, "copied": copied}


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
        if info["go"] is None:
            return "not a Go binary"
        return "a Go binary with %s (%s)" % ("C code" if info["go"] in ("c", "0-c") else "cgo", go_shown(info["go"]))
    if kind == "sha256":
        # Bounded by what the check reads (Security 7068790342 R1): only a static file too small to hold a
        # C library can be declared by review alone.
        if info["why"] != "static" or info["size"] > SHA256_MAX:
            return "the sha256 kind takes only a static file of at most %d bytes (this: %s, %d bytes)" % (
                SHA256_MAX, info["why"], info["size"])
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
        missing = sorted(pkgs - set(lst["status"]))
        return "its link inputs %s are not in %s/%s" % (missing, arg, STATUS) if missing else None
    if kind == "package":
        if place_status is None:
            return "its tree has no dpkg status to own it"
        if arg not in place_status:
            return "package %s is not installed in its tree's status" % arg
        if place == "tree" and shown.startswith(GUEST_ROOTS):
            # Bound to the bytes guest-userland.sh copied (Potency 7068815856 point 4).
            if arg not in ctx["copied"].get(info["md5"], ()):
                return "its bytes (MD5 %s) are not a copy guest-userland.sh recorded from %s (guest/%s)" % (
                    info["md5"], arg, COPIED)
            return None
        if place != "tree":
            # An initrd keeps no md5sums; it installs from the main tree's pinned sources, so PKG at the
            # main tree's version ships the main tree's bytes at this path.
            main = (ctx["status"]["tree"] or {}).get(arg)
            if main is None or place_status[arg] != main:
                return "package %s is at version %s here and %s in the main tree, so its bytes cannot be held to %s" % (
                    arg, place_status[arg], main, MD5SUMS)
        want = ctx["md5"].get(shown) or ctx["md5"].get(shown[4:] if shown.startswith("/usr/") else None)
        if want != info["md5"]:
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
            hits = [e for e in entries if matches(shown, e[1])]
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


def matches(path, glob):
    """Whether PATH matches GLOB segment by segment (fnmatch within each), so "*" never crosses "/"
    (L3 7068815628 point 3)."""
    p, g = path.split("/"), glob.split("/")
    return len(p) == len(g) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(p, g))


def control(places, unread, statuses=None):
    """The control (SEL-7): unreadable files, the main tree's REQUIRED, and in each initrd that holds a
    dpkg status (the one Debian initrd; a modules initrd holds no program) Debian's static ldconfig
    (L3 7068815628 point 2, Potency 7068815856 point 5)."""
    errs = ["%s: cannot read %s: %s" % (place, shown, why) for place, u in sorted(unread.items())
            for shown, why in sorted(u.items())]
    tree = places.get("tree", {})
    errs += ["tree: %s is not listed, so the walk did not read what it should have (control)" % p
             for p in REQUIRED if p not in tree]
    errs += ["%s: %s is not listed, so the initrd's walk did not read what it should have (control)" % (k, INITRD_REQUIRED)
             for k, st in sorted((statuses or {}).items()) if st is not None and INITRD_REQUIRED not in places.get(k, {})]
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
        statuses[key] = status


def run(root, usr, out, allow):
    files = tree_files(root, usr)
    places, unread, statuses = {}, {}, {}
    places["tree"], unread["tree"] = listed(files)
    if usr is not None:
        initrd_places(out, places, unread, statuses)
    entries = read_allow(allow)
    return places, control(places, unread, statuses) + refusals(places, entries, context(out), statuses)


def escaped(line):
    return line.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


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
            # Escaped as the errors are (Security 7068790342 R3): a path cannot start a workflow command.
            print(escaped("%s %s: %s%s sha256=%s" % (place, shown, info["why"],
                                                     "" if info["go"] is None else ", " + go_shown(info["go"]), info["sha256"])))
    for e in errs:
        print("::error title=static ELF check::" + escaped(e))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
