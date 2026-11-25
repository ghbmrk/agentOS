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
or libc++, and holds one of CXX_MARKS, a C++ runtime's own strings (a shipped file is stripped, so its
symbols say nothing).

Each listed file must match exactly one entry of ALLOW, a line "GLOB KIND [ARG]", GLOB an absolute
pattern on the file's path (an initrd's members by their path inside it) matched segment by segment, so
"*" never crosses "/" (matches). Kinds (SEL-6):
  go             a Go binary built without cgo, read from the file (go_cgo): its section headers name
                 .gopclntab; the build info at .go.buildinfo says CGO_ENABLED=0, or there is none or it records
                 no setting; the file holds none of runtime/cgo's C code; its function table lists no
                 function without a line table (C code an internal link took from a .syso) but the linker's
                 GO_MARKERS; and it runs only code that table lists (go_outside: an external link, which
                 cmd/link takes with cgo off, puts C there outside it): no C library
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
SHF_EXECINSTR, PT_LOAD, PF_X = 4, 1, 1
# The function table formats read (Go 1.18 and 1.20 onward); an older one is unread.
PCLN_MAGICS = (0xFFFFFFF0, 0xFFFFFFF1)
# The text symbols cmd/link makes itself, with no line table: the FIPS 140 module's bounds (Go 1.24 onward;
# the only "go:" text symbols in cmd/link/internal of go1.22.12 to go1.26.8 a static executable holds, and
# the only functions without one in gVisor release-20260928.0's and esbuild 0.28.2's tables, #6563).
GO_MARKERS = ("go:textfipsstart", "go:textfipsend")
# .text past the table's end entry: runtime.etext, at most one 32-byte function alignment on, plus MinLC's
# one byte (cmd/link data.go); 16 bytes in the pinned releases, 1 in go1.22.12's.
TEXT_SLACK = 33
# The largest file the sha256 kind may declare: gVisor's sidecars are 1.4 KiB; a static libc is far larger.
SHA256_MAX = 16384
# runtime/cgo's C code (gcc_libinit.c _cgo_try_pthread_create's message): in every cgo binary, static or
# dynamic, glibc or musl, and in no binary built with cgo off. go build refuses -linkmode=external with cgo
# off, but cmd/link takes it with a warning, so an external link with no runtime/cgo is go_outside's to see.
CGO_MARK = b"pthread_create failed"


class Unread(Exception):
    """A file the check cannot read."""


def header(data):
    """(e_type, e_machine) of ELF bytes DATA; Unread when too short or of an unknown class or order."""
    if len(data) < 20 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] != 1:
        raise Unread("not a little-endian ELF file of a known class")
    return struct.unpack_from("<HH", data, 16)


def sections(data):
    """{name: (file offset, size, address, flags)} of ELF bytes DATA's section header table ({} when it has none);
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
        for name, typ, flags, addr, off, size in heads:
            if typ != SHT_NOBITS and off + size > len(data):
                raise Unread("a section lies past the end of the file")
            out[name] = (off, size if typ != SHT_NOBITS else 0, addr, flags)
        names = data[heads[strndx][4]:heads[strndx][4] + heads[strndx][5]]
        return {names[n:names.index(b"\0", n)].decode("latin-1"): v for n, v in out.items()}
    except (struct.error, IndexError, ValueError) as e:
        raise Unread("its section header table cannot be read (%s)" % e)


def pcln_funcs(table):
    """(text start, [(entry offset from it, name, has a line table)], end offset) of Go function table bytes
    TABLE (.gopclntab), functions in address order; text start is 0 from Go 1.26, which no longer stores it.
    Unread for a format this cannot read."""
    try:
        magic, = struct.unpack_from("<I", table, 0)
        if magic not in PCLN_MAGICS or table[7] != 8:
            raise Unread("its Go function table is of a format this cannot read (magic %#x)" % magic)
        nfunc, _files, text, names, _cu, _filetab, _pctab, funcs = struct.unpack_from("<8Q", table, 8)
        out = []
        for k in range(nfunc):
            entry, off = struct.unpack_from("<II", table, funcs + 8 * k)
            # _func: entryOff, nameOff, args, deferreturn, pcsp, pcfile, pcln (the same in both formats).
            _e, name, _a, _d, _sp, _file, pcln = struct.unpack_from("<IiIIIII", table, funcs + off)
            start = names + name
            out.append((entry, table[start:table.index(b"\0", start)].decode("latin-1"), pcln != 0))
        end, = struct.unpack_from("<I", table, funcs + 8 * nfunc)
        if any(a[0] >= b[0] for a, b in zip(out, out[1:] + [(end,)])):
            raise Unread("its Go function table is not in address order")
        return text, out, end
    except (struct.error, IndexError, ValueError) as e:
        raise Unread("its Go function table cannot be read (%s)" % e)


def no_line_funcs(table):
    """The functions of Go function table bytes TABLE that have no line table, GO_MARKERS aside: code an
    internal link took from a host object (a .syso), which has no Go source (L3 7068815628 point 4b; an
    exact list, not a "go:" prefix any assembler can name, #6563 item 3). Unread as pcln_funcs."""
    return [name for _e, name, lines in pcln_funcs(table)[1] if not lines and name not in GO_MARKERS]


def go_outside(data):
    """Why the Go binary DATA (section headers naming .gopclntab) may run code its function table does not
    list, or None (#6563 items 1 and 2): the table lists a function; .text is the only executable section;
    the table starts at .text's start and ends within TEXT_SLACK of its end; every executable segment ends
    at .text's end and starts at or before its start; and the entry point lies in a listed function with a
    line table. An external link adds _start, .init, .plt and .fini and puts the C library in .text outside
    the table; a .gopclntab added to a C binary lists no function or not its code. Unread when the headers
    or the table cannot be read."""
    if data[4] != 2:
        raise Unread("a 32-bit file with a Go function table")
    secs = sections(data)
    o, n = secs[".gopclntab"][:2]
    stored, funcs, end = pcln_funcs(data[o:o + n])
    if not funcs:
        return "its function table lists no function"
    execs = sorted(k for k, v in secs.items() if v[3] & SHF_EXECINSTR)
    if execs != [".text"]:
        return "its executable sections are %s, not .text alone" % ", ".join(execs)
    _o, size, addr, _f = secs[".text"]
    if stored not in (0, addr):
        return "its function table's text start %#x is not .text's %#x" % (stored, addr)
    if funcs[0][0] != 0 or not 0 <= addr + size - (addr + end) <= TEXT_SLACK:
        return "its function table spans %#x to %#x, not .text's %#x to %#x" % (
            addr + funcs[0][0], addr + end, addr, addr + size)
    try:
        entry, phoff = struct.unpack_from("<QQ", data, 24)
        phsize, phnum = struct.unpack_from("<HH", data, 54)
        if phsize != 56:
            raise Unread("its program headers are not ELF64's")
        segs = [struct.unpack_from("<IIQQQQQQ", data, phoff + 56 * k) for k in range(phnum)]
    except struct.error as e:
        raise Unread("its program headers cannot be read (%s)" % e)
    run = [(s[3], s[3] + s[6]) for s in segs if s[0] == PT_LOAD and s[1] & PF_X]
    if not run:
        return "no executable segment holds .text"
    for lo, hi in run:
        if lo > addr or hi != addr + size:
            return "an executable segment spans %#x to %#x, not up to .text's end %#x" % (lo, hi, addr + size)
    bounds = [e for e, _n, _l in funcs] + [end]
    for k, (e, _name, lines) in enumerate(funcs):
        if addr + e <= entry < addr + bounds[k + 1]:
            if lines:
                return None
            break
    return "its entry point %#x is in no function its table lists with a line table" % entry


def go_cgo(data):
    """A Go binary's cgo state, read from DATA: None when its section headers name no .gopclntab (no Go
    binary, whatever bytes it holds). Else the build info's CGO_ENABLED, read at .go.buildinfo, "0" or
    "1", or "none" when there is no build info (esbuild's release) or it records no setting (Bazel's
    rules_go, as gVisor's release is built); suffixed "-cgo" ("cgo" for none) when the file holds
    runtime/cgo's C code (CGO_MARK), "-c" ("c" for none) when its function table lists a function
    with no line table (no_line_funcs), or "-o" ("o" for none) when it may run code outside that table
    (go_outside). Unread when the headers, the table or the build info cannot be
    read (build info before Go 1.18 is by pointer)."""
    secs = sections(data)
    if ".gopclntab" not in secs:
        return None
    off, size = secs[".gopclntab"][:2]
    setting = "none"
    if ".go.buildinfo" in secs:
        i, n = secs[".go.buildinfo"][:2]
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
    if setting != "1" and go_outside(data):
        return "o" if setting == "none" else "0-o"
    return setting


def go_shown(go):
    return {"0": "Go CGO_ENABLED=0", "1": "Go CGO_ENABLED=1", "none": "Go, no cgo setting, no cgo code",
            "cgo": "Go, no cgo setting, cgo code", "0-cgo": "Go CGO_ENABLED=0 but cgo code",
            "c": "Go, no cgo setting, C functions with no line table",
            "0-c": "Go CGO_ENABLED=0 but C functions with no line table",
            "o": "Go, no cgo setting, code outside its function table",
            "0-o": "Go CGO_ENABLED=0 but code outside its function table"}[go]


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
        what = {"c": "C code", "o": "code outside its function table"}.get(info["go"].split("-")[-1], "cgo")
        return "a Go binary with %s (%s)" % (what, go_shown(info["go"]))
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
