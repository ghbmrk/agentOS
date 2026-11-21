#!/usr/bin/env python3
"""Which ELF files in a built image import glibc's POSIX regex, glob() or wide scanf functions (#5697,
#6285, EVL-5).

The image's glibc records (assurance/vulncheck.json, DEBIAN-CVE-2026-100290, -126765 and -115819) accept
the advisories on the grounds that no long-lived or network-facing process calls the affected functions
on input from the network or a guest.
This reads that from the tree CI builds, not from another distribution's builds: every ELF file's
dynamic imports (objdump -pT), in the main tree (the root partition and the verified /usr) and in each
initrd of the boot entry (OUT/initrd/, every cpio member).

  import_sweep.py OUT VERSION     the build in OUT (as root: offline_systemd.built_tree mounts it)
  import_sweep.py --tree DIR      a plain directory, read as a main tree
  import_sweep.py --summary FILE [ALLOW]
                                  the JSON the two forms print, as lines and as ::notice annotations,
                                  held to ALLOW (default image/import_sweep.allow)

It also reads, for the openssl records (#5341), which files hold the name of a by-name OpenSSL cipher
selector or spell GCM-SIV or KRB5KDF, as selecting AES-GCM-SIV takes one of its names (see CIPHER_NAMES
and SPELT), and counts their references to each selector and their spellings.

The JSON maps each place ("tree", and "initrd:<path>" for each initrd) to: "scanned", the ELF files read;
"imports", each file importing an affected glibc symbol and those symbols; "lookups", each file that holds
an affected function's name at the end of a string and imports glibc's dlsym or dlvsym or has a library in its
NEEDED closure that does (a wrapper; #6299), and those names; "carries", each file but a glibc whose bytes
hold a mark of glibc's glob, regex or wide scanf code (CARRIES: a static copy, or embedded objects), and
the function each mark stands for (#6298, #6299); each of these three counts as importing the function.
"via", each ELF file whose NEEDED closure (by SONAME or file name, within that place) holds an importing
library other than itself, and those libraries, whether or not the file imports a symbol itself (#6297: a
file importing one group's symbols can reach another group's through a library); "glibc", each glibc
(SONAME libc.so.6 at GLIBC_PATH) and the marks it holds; "unresolved", each file with a NEEDED name no
file of the place answers to, and those names; "packed", each file whose code is not in its bytes as stored,
and why (packed()); "cipher", each file whose bytes hold a CIPHER_NAMES or SPELT name and its references
to each (cipher_sites); "sha256", the SHA-256 of each file reaching a group or held under "cipher";
"unread", each ELF file objdump failed on; and, for an initrd, "others", its executable members that are not ELF files. Only symbols bound to a GLIBC_ version count, so a library's own
re_* names do not.

--summary exits 1 when a claim the glibc records rest on stops holding: any file, in any place, imports
or reaches a wide scanf function, or imports or reaches a regex function and is not accepted by ALLOW's
regex entries (the image -100290 record), or imports or reaches glob() and is not accepted by its [glob]
section (the -126765 records). A file is accepted by an entry naming it (a glob) that pins its SHA-256
(#6299), or, when no such glob names it and it imports none of the group's functions itself, by "via"
entries naming every library it reaches them through, each of which has an entry naming it (#6297): a
reviewed library's dependents need no entry each, and a new direct caller or new bytes still fail. An
entry that accepts nothing, or a pin no accepted file holds, also fails, so each list stays its record's.
It also exits 1 when a file holding a selector name or a SPELT name matches no [cipher] entry of ALLOW or
more than one, or holds other sites or other bytes (SHA-256) than the counted entry it matches, or an
entry matches nothing; on any packed file or unresolved NEEDED name; and on an ALLOW it cannot read (read_allow). The control is the
scan itself: it also exits 1 when objdump failed on a file, the main tree or an initrd with executable
members read no ELF file, the main tree has no importer of regcomp (bash and grep always import it), or no
call site of EVP_CIPHER_fetch (libcryptsetup and libcrypto always hold one), no glibc, or no file carrying
glob() (Debian's static ldconfig always does), or a glibc lacks a mark, so a clean result is not a scan
that read nothing.
"""
import collections
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
ALLOW = HERE / "import_sweep.allow"
sys.path.insert(0, str(HERE))

# DEBIAN-CVE-2026-100290 (regcomp/regexec and the GNU re_* interface over the same engine) and
# DEBIAN-CVE-2026-115819 (the wide scanf family, with the C99/C23 aliases glibc's headers bind them to).
# glibc's own callers of the regex engine count as it: rpmatch (stdlib/rpmatch.c, the locale's
# YESEXPR) and the compat step/advance (misc/regexp.c). The wide scanf family has none.
# DEBIAN-CVE-2026-126765 (#6285): glob() and glob64, every version (posix/glob.c is the one engine), and
# wordexp, glibc's one shared-library caller of it (posix/wordexp.c do_parse_glob, 2.41); its other
# caller, ldconfig's include patterns (elf/ldconfig.c), is static and reads root-owned configuration.
GROUPS = {
    "regex": re.compile(r"(regcomp|regexec|re_\w+|rpmatch|step|advance)$"),
    "glob": re.compile(r"(glob(64)?|wordexp)$"),
    "wscanf": re.compile(r"(__isoc(99|23)_)?v?(sw|fw|w)scanf$"),
}
# #5341: the openssl records (DEBIAN-CVE-2026-88823 and -95692 among them, AES-GCM-SIV) rest on no file
# passing a name read from data to an OpenSSL cipher fetch. AES-GCM-SIV has no OID or NID
# (crypto/objects/objects.txt, 3.5.7), so only a selector given one of its names picks it: EVP_CIPHER_fetch,
# or systemd's openssl_cipher_many (src/shared/openssl-util.c, v257), which formats "%s-%zu-%s" from its
# caller's arguments and fetches that. EVP_get_cipherbyname cannot return it (crypto/evp/names.c reads only
# the legacy table) but is counted, as it hands a name to the same table. Every ELF file whose bytes hold one of these
# names (an importer, the library defining it, or a dlsym caller's string) is disassembled and its
# references to each counted, for image/import_sweep.allow's [cipher] section.
# Security 6899468190: a provider cipher can also be picked by name through EVP_CIPHER_do_all_provided
# with EVP_CIPHER_is_a, or OSSL_ENCODER_CTX_set_cipher, so those count too.
CIPHER_NAMES = ("EVP_CIPHER_fetch", "EVP_get_cipherbyname", "openssl_cipher_many", "EVP_CIPHER_do_all_provided",
                "EVP_CIPHER_is_a", "OSSL_ENCODER_CTX_set_cipher")
# And a file whose bytes spell one of these, in any case, is held under it with the number of times it
# does. The cipher: a name passed some other way (an OSSL_PARAM "cipher" to a MAC, KDF or DRBG) still has
# to be spelt. KRB5KDF: of the algorithms taking a "cipher" parameter, CMAC, GMAC, KBKDF (through CMAC) and
# CTR-DRBG refuse GCM-SIV by its mode, and KRB5KDF does not check the mode (#5861), so its callers are
# recorded too: a caller selects it by spelling its name.
SPELT = ("GCM-SIV", "KRB5KDF")
# A reference: any instruction naming the start of a function, <name>, <name@plt>, <name@@VERSION> or
# a GOT slot (# <name@VERSION>), so a call, a jump and an instruction taking its address all count
# (L3 6899461135). <name+0x..> is a place inside it, and "addr <name>:" a label, neither a reference.
SITE = re.compile(r"^\s*[0-9a-f]+:\s.*<([A-Za-z_]\w*)(?:@[\w.@]*)?>\s*$")
# A dynamic relocation against the name: one in data (a function-pointer table, R_X86_64_64) or a GOT
# slot (GLOB_DAT) is a reference no instruction shows; JUMP_SLOT is the PLT's, already counted at its calls.
RELOC = re.compile(r"^[0-9a-f]+\s+(R_\w+)\s+([A-Za-z_]\w*)(?:@[\w.@]*)?(?:[+-]0x[0-9a-f]+)?\s*$")
UND = re.compile(r"\*UND\*\s+\S+\s+(?:Base\s+)?\((GLIBC_[^)]*)\)\s+(\S+)$")
DYNAMIC = re.compile(r"^\s+(NEEDED|SONAME)\s+(\S+)$")
# #6298: two ways to reach a group's code that no import shows.
# A run-time lookup: a file whose own imports or NEEDED closure (within its place) import glibc's dlsym or
# dlvsym can resolve any function whose name it holds, itself or through a library's wrapper around them
# (libltdl, libuv and the like; #6299, L3 on #6339). dlopen alone runs only the opened file's code, which the
# sweep reads as a file of its own. Such a file holding a group function's name at the end of a string (a
# NUL after it, as a C string literal is stored; the linker stores "glob" as the tail of "safe_glob" when a
# file holds both, so no NUL need precede it: Security on #6382) counts as importing that function, except
# a COMPAT_ONLY name when nothing in reach imports dlvsym. The openssl group needs no such rule: [cipher] already
# holds every file whose bytes hold a selector's name, a dlsym caller's string included (#5341).
LOOKUP_FUNCS = ("dlsym", "dlvsym")
# glibc exports these only under a hidden compat version (misc/regexp.c, compat_symbol since 2.23), and
# dlsym never returns a hidden version (elf/dl-lookup.c check_match), so only dlvsym can reach them.
COMPAT_ONLY = ("step", "advance")
# glibc's exported re_* names, for LOOKUP: as a string's tail, the group's re_\w+ would match any string
# holding "re_" (store_value).
RE_NAMES = ("re_comp", "re_compile_fastmap", "re_compile_pattern", "re_exec", "re_match", "re_match_2",
            "re_max_failures", "re_search", "re_search_2", "re_set_registers", "re_set_syntax", "re_syntax_options")
LOOKUP = re.compile(b"(?:%s)(?=\0)" % b"|".join(
    rx.pattern.rstrip("$").replace("re_\\w+", "|".join(RE_NAMES)).encode() for rx in GROUPS.values()))
# A carried copy: a file can run glibc code it carries in its own bytes, with no symbol to read once
# stripped: a static file (llama-server and agentos-camdecode link libc.a; Debian's ldconfig is static), or
# a dynamic one embedding glibc's objects or a copy of their source (libc_pic, gnulib's glob and regex;
# Security on #6339). A string glibc's own code holds marks each group's code: glob_in_dir's name
# (posix/glob.c's assertions), the wide scanf engine's name (__vfwscanf_internal,
# stdio-common/vfscanf-internal.c's assertions), and one of the regex engine's error messages
# (posix/regcomp.c's table, which regcomp's object carries), each at the end of a string, as a merged
# string can hold it (LOOKUP). Any file but a glibc (GLIBC) holding one counts
# as importing the function named beside it. Every glibc in the image must hold every mark, which is the
# control that the marks are those of the glibc the image ships (problems()); the main tree's static
# ldconfig must carry glob(), the control that a carried copy is read.
CARRIES = {b"glob_in_dir\0": "glob", b"__vfwscanf_internal\0": "vfwscanf",
           b"Invalid preceding regular expression\0": "regcomp"}
# glibc's shared library, the one file whose marks are the functions it exports, not a copy: its SONAME,
# at the path Debian installs it, in the main tree or initrd or a guest root (Security R2 on #6382: a
# SONAME alone would let any file named so skip the carried-copy rule).
GLIBC = "libc.so.6"
GLIBC_PATH = re.compile(r"^(/usr/lib/agentos/images/[^/]+)?/usr/lib/x86_64-linux-gnu/libc\.so\.6$")


def group_of(sym):
    return next((g for g, rx in GROUPS.items() if rx.match(sym)), None)


def read_elf(path):
    """(affected glibc symbols imported, NEEDED names, SONAME or None, read, lookup) of the ELF file at PATH.
    READ is False when objdump fails on it for any reason but its having no dynamic section (a static or
    relocatable file, which imports nothing), so a file objdump cannot parse is never counted clean. LOOKUP
    is the set of glibc run-time lookups (LOOKUP_FUNCS) it imports."""
    r = subprocess.run(["objdump", "-pT", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, errors="replace")
    read = r.returncode == 0 or "not a dynamic object" in r.stderr
    syms, needed, soname, dl = set(), [], None, set()
    for line in r.stdout.splitlines():
        m = UND.search(line)
        if m and group_of(m.group(2)):
            syms.add(m.group(2))
        if m and m.group(2) in LOOKUP_FUNCS:
            dl.add(m.group(2))
        m = DYNAMIC.match(line)
        if m and m.group(1) == "NEEDED":
            needed.append(m.group(2))
        elif m:
            soname = m.group(2)
    return sorted(syms), needed, soname, read, dl


# ELF header fields (#6299): by class (32 or 64-bit), the offsets of e_phoff, e_shoff, e_phentsize and
# e_phnum, and each program header's p_type, p_flags, p_filesz and p_memsz.
ELF_HEADER = {1: ("I", 0x1C, 0x20, 0x2A, 0x2C, 0, 24, 16, 20), 2: ("Q", 0x20, 0x28, 0x36, 0x38, 0, 4, 32, 40)}
PT_LOAD, PF_X, PF_W = 1, 1, 2


def packed(data):
    """Why the code of the ELF file DATA is not in its bytes as stored, so no import, lookup or mark of it
    can be read (#6299, Security on #6339): it loads segments and has no section table (UPX and its like
    drop it), or it maps a segment both writable and executable, or executable memory past the bytes the
    file holds for it (code written at run time); or its headers do not parse, so neither can be read.
    "" for none of these."""
    try:
        word, phoff, shoff, phentsize, phnum, *at = ELF_HEADER[data[4]]
        order = {1: "<", 2: ">"}[data[5]]
        field = lambda fmt, off: struct.unpack_from(order + fmt, data, off)[0]
        loads = []
        for i in range(field("H", phnum)):
            h = field(word, phoff) + i * field("H", phentsize)
            typ, flags, filesz, memsz = (field("I" if n < 2 else word, h + o) for n, o in enumerate(at))
            if typ == PT_LOAD:
                loads.append((flags, filesz, memsz))
        no_sections = field(word, shoff) == 0
    except (KeyError, IndexError, struct.error):
        return "headers that do not parse"
    if loads and no_sections:
        return "no section table"
    if any(f & PF_X and f & PF_W for f, _, _ in loads):
        return "a writable and executable segment"
    if any(f & PF_X and memsz > filesz for f, filesz, memsz in loads):
        return "executable memory past its file bytes"
    return ""


def cipher_sites(path):
    """({name: references} in the ELF file at PATH for each CIPHER_NAMES name its bytes hold, or None when
    they hold none; read). A reference is an instruction outside the PLT naming the function (SITE) or a
    dynamic relocation against it other than the PLT's JUMP_SLOT (RELOC), so a pointer to the fetch, in
    code or in a table, changes the count as a call does. A name held with no reference (a dlsym caller's
    string) maps to 0. READ is False when objdump fails, so a file it cannot read is never counted clean."""
    with open(path, "rb") as f:
        data = f.read()
    held = [n for n in CIPHER_NAMES if n.encode() in data]
    low = data.lower()
    spelt = {n: low.count(n.lower().encode()) for n in SPELT}
    spelt = {n: c for n, c in spelt.items() if c}
    if not held and not spelt:
        return None, True
    r = subprocess.run(["objdump", "-d", "--no-show-raw-insn", str(path)], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, text=True, errors="replace")
    sites, plt = dict.fromkeys(held, 0), False
    sites.update(spelt)
    for line in r.stdout.splitlines():
        if line.startswith("Disassembly of section "):
            plt = line.split()[-1].startswith(".plt")  # a PLT stub's own jump through the GOT is no call site
        m = not plt and SITE.search(line)
        if m and m.group(1) in sites:
            sites[m.group(1)] += 1
    rel = subprocess.run(["objdump", "-R", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, errors="replace")
    for line in rel.stdout.splitlines():
        m = RELOC.match(line)
        if m and m.group(1) != "R_X86_64_JUMP_SLOT" and m.group(2) in sites:
            sites[m.group(2)] += 1
    # A static or relocatable file has no dynamic relocations; any other failure is a file not read.
    rel_ok = rel.returncode == 0 or "not a dynamic object" in rel.stderr
    return sites, r.returncode == 0 and rel_ok


def is_elf(path):
    """Whether PATH starts with the ELF magic. A file gone since the walk listed it is not one; any other
    read error fails the run, so a /usr block that dm-verity refuses (EIO) is a failed check, not a file
    skipped (#5988)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except FileNotFoundError:
        return False
    except OSError as e:
        sys.exit("import sweep: cannot read %s: %s" % (path, e))


def own(v, p):
    """The group functions file P of place V imports itself: by import, by a run-time lookup of a name it
    holds, or as a copy of glibc's code it carries (#6298, #6299)."""
    return set(v["imports"].get(p, [])) | set(v.get("lookups", {}).get(p, [])) | set(v.get("carries", {}).get(p, []))


def sweep(files):
    """FILES maps a shown path to a readable path. Returns the place's record (module docstring)."""
    imports, needed, by_name, unread, cipher, digest = {}, {}, {}, [], {}, {}
    dl, names, carries, glibc, opaque = {}, {}, {}, {}, {}
    for shown, real in files.items():
        syms, needed[shown], soname, read, dl[shown] = read_elf(real)
        with open(real, "rb") as f:
            data = f.read()
        digest[shown] = hashlib.sha256(data).hexdigest()
        names[shown] = {m.group().decode() for m in LOOKUP.finditer(data)}
        marks = sorted({name for mark, name in CARRIES.items() if mark in data})
        if soname == GLIBC and GLIBC_PATH.match(shown):
            glibc[shown] = marks
        elif marks:
            carries[shown] = marks
        why = packed(data)
        if why:
            opaque[shown] = why
        sites, disassembled = cipher_sites(real)
        if sites is not None:
            cipher[shown] = sites
        if not (read and disassembled):
            unread.append(shown)
        if syms:
            imports[shown] = syms
        # A NEEDED entry names a library's SONAME, which on disk is a symbolic link to the file read.
        for n in {os.path.basename(shown), soname} - {None}:
            by_name.setdefault(n, []).append(shown)

    def closure(shown):
        """The files of this place in SHOWN's NEEDED closure, itself excluded."""
        seen, todo, libs = set(), list(needed[shown]), set()
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            for lib in by_name.get(n, []):
                libs.add(lib)
                todo += needed.get(lib, [])
        return libs - {shown}
    reached = {shown: closure(shown) for shown in files}
    # A NEEDED name no file of the place answers to hides that library's imports, dlsym among them, from
    # every rule above (Security R4 on #6382).
    unresolved = {shown: sorted(set(n for n in needed[shown] if n not in by_name)) for shown in files}
    lookups = {}
    for shown in files:
        how = dl[shown].union(*(dl[lib] for lib in reached[shown]))
        held = names[shown] if "dlvsym" in how else names[shown] - set(COMPAT_ONLY)
        if how and held:
            lookups[shown] = sorted(held)
    importers = set(imports) | set(lookups) | set(carries)
    via = {shown: sorted(reached[shown] & importers) for shown in files if reached[shown] & importers}
    # Each reaching or [cipher] file's SHA-256, for the pinned allow entries (#5861, #6299).
    pinned = importers | set(via) | set(cipher)
    return {"scanned": len(files), "imports": dict(sorted(imports.items())), "via": dict(sorted(via.items())),
            "lookups": dict(sorted(lookups.items())), "carries": dict(sorted(carries.items())),
            "glibc": dict(sorted(glibc.items())), "packed": dict(sorted(opaque.items())),
            "unresolved": {p: n for p, n in sorted(unresolved.items()) if n},
            "unread": sorted(unread), "cipher": dict(sorted(cipher.items())),
            "sha256": {p: d for p, d in sorted(digest.items()) if p in pinned}}


def cannot_read(e):
    sys.exit("import sweep: cannot read %s: %s" % (e.filename, e.strerror or e))


def walk(top):
    """os.walk(TOP), except that a directory it cannot list (EIO from a verity-refused block, a missing
    TOP) fails the run instead of dropping that subtree from the scan (#5988)."""
    return os.walk(top, onerror=cannot_read)


def is_file(path, follow=True):
    """Whether PATH (links followed unless FOLLOW is false) is a regular file. One gone since the walk listed
    it is not; any other stat error (a link loop, EIO) fails the run instead of skipping the entry (#6073)."""
    try:
        return stat.S_ISREG(os.stat(path, follow_symlinks=follow).st_mode)
    except FileNotFoundError:
        return False
    except OSError as e:
        cannot_read(e)


def tree_files(top, prefix="/", skip=()):
    """Every regular ELF file under TOP (symbolic links not followed), as {prefix + relative path: path}."""
    files = {}
    for d, dirs, names in walk(top):
        rel = os.path.relpath(d, top)
        if rel == ".":
            dirs[:] = [x for x in dirs if x not in skip]
        for n in names:
            p = os.path.join(d, n)
            if is_file(p, follow=False) and is_elf(p):
                files[os.path.normpath(os.path.join(prefix, rel, n))] = p
    return files


def initrd_place(path, scratch):
    """The record of the initrd at PATH: each regular ELF member written under SCRATCH and read."""
    import finish_image
    files, others = {}, 0
    for i, (name, mode, body, _link) in enumerate(finish_image.cpio_members(pathlib.Path(path).read_bytes())):
        if stat.S_ISREG(mode) and body[:4] == b"\x7fELF":
            f = os.path.join(scratch, "%d" % i)
            pathlib.Path(f).write_bytes(body)
            files["/" + name.lstrip("/")] = f
        elif stat.S_ISREG(mode) and mode & 0o111:
            others += 1
    # "others": executable regular members that are not ELF files (problems()). A modules initrd's
    # modules, indexes and firmware are not executable.
    return dict(sweep(files), others=others)


def run_tree(root, usr=None):
    files = tree_files(root, skip=("usr",) if usr else ())
    if usr:
        files.update(tree_files(usr, "/usr"))
    return {"tree": sweep(files)}


def run_build(out, version):
    import offline_systemd
    root, usr, _cmdline, cleanup = offline_systemd.built_tree(out, version)
    try:
        places = run_tree(root, usr)
    finally:
        cleanup()
    initrds = pathlib.Path(out) / "initrd"
    for p in sorted(pathlib.Path(d, n) for d, _, names in walk(initrds) for n in names
                    if is_file(os.path.join(d, n))):
        with tempfile.TemporaryDirectory() as scratch:
            places["initrd:" + str(p.relative_to(initrds))] = initrd_place(p, scratch)
    return places


def problems(places):
    # An initrd of only kernel modules (compressed .ko files, their indexes, firmware) holds no ELF
    # file; one with executable members must hold one, as its records rest on what was read in it.
    errs = [] if places.get("tree", {}).get("scanned") else ["tree: no ELF file read"]
    errs += ["%s: no ELF file read among %d executable files" % (k, v.get("others", 0)) for k, v in places.items()
             if k.startswith("initrd:") and not v["scanned"] and v.get("others", 1)]
    errs += ["%s: objdump could not read %s" % (k, p) for k, v in places.items() for p in v.get("unread", [])]
    if "regcomp" not in {s for syms in places.get("tree", {}).get("imports", {}).values() for s in syms}:
        errs.append("tree: no file imports regcomp, so the scan read nothing it should have (control)")
    # libcryptsetup and libcrypto always call EVP_CIPHER_fetch: none found is a disassembly that read nothing.
    if not any(v.get("EVP_CIPHER_fetch") for v in places.get("tree", {}).get("cipher", {}).values()):
        errs.append("tree: no call site of EVP_CIPHER_fetch, so the cipher scan read nothing it should have (control)")
    # #6299: every glibc read holds every mark (CARRIES), so the marks are checked against the glibc the image
    # ships, not only the runner's libc.a; and the main tree holds one. A missing mark would let that
    # group's carried copies pass unread.
    errs += ["%s: the glibc %s holds no %s mark, so carried copies of that code would pass unread (control)"
             % (k, p, name) for k, v in places.items() for p, held in v.get("glibc", {}).items()
             for name in sorted(set(CARRIES.values()) - set(held))]
    if not places.get("tree", {}).get("glibc"):
        errs.append("tree: no glibc (%s) read, so the marks are checked against none (control)" % GLIBC)
    # #6298: Debian's static ldconfig always carries glob() (its include patterns): none found is a carried
    # copy the scan no longer reads.
    if "glob" not in {s for names in places.get("tree", {}).get("carries", {}).values() for s in names}:
        errs.append("tree: no file carries glob() (Debian's static ldconfig always does), so the scan reads no "
                    "carried copy (control)")
    # #6299: a file whose code is not in its bytes as stored can hide any import, lookup or copy.
    errs += ["%s: %s is packed (%s): its code cannot be read for imports, lookups or carried copies"
             % (k, p, why) for k, v in places.items() for p, why in v.get("packed", {}).items()]
    errs += ["%s: %s needs %s, which no file there answers to, so what it imports is not read"
             % (k, p, " ".join(n)) for k, v in places.items() for p, n in v.get("unresolved", {}).items()]
    return errs


def reach(places):
    """{(group, path): {place: (imports one itself, [the importing libraries it reaches one through])}} of
    every file that imports or reaches a function of the group."""
    out = {}
    for place, v in places.items():
        for p in set(v["imports"]) | set(v.get("lookups", {})) | set(v.get("carries", {})) | set(v["via"]):
            mine = {group_of(x) for x in own(v, p)}
            libs = v["via"].get(p, [])
            for g in mine | {group_of(x) for lib in libs for x in own(v, lib)}:
                out.setdefault((g, p), {})[place] = (g in mine, sorted(
                    lib for lib in libs if g in {group_of(x) for x in own(v, lib)}))
    return out


def load_allow(path):
    """The regex entries of ALLOW: one per line, after any '#' comment, up to its first section line."""
    return read_allow(path)[0]


# A [regex] or [glob] entry: GLOB and the SHA-256 of each file reviewed under it, which accepts the files
# it names whose bytes are one of those (#6299: as [cipher] entries are keyed, so a new version, or another
# file the glob matches, is read before it is accepted), or "via GLOB", which accepts a file reaching the
# group only through libraries it names (refusals), whose own GLOB entries pin them.
Entry = collections.namedtuple("Entry", "glob via sha256", defaults=(False, ()))


def shown(e):
    return ("via " if e.via else "") + e.glob


def entry(e):
    """E as an Entry; a plain string is a GLOB entry pinning no bytes, which accepts no file."""
    return e if isinstance(e, Entry) else Entry(e)


def parse_entry(line):
    """The Entry a [regex] or [glob] line gives, or why it is none (ENTRY_FORMAT)."""
    t = line.split()
    if t[0] == "via":
        return Entry(t[1], True) if len(t) == 2 else "%s is not an entry" % line
    pins = [w[len("sha256="):].lower() for w in t[1:] if DIGEST.match(w)]
    if t[0].startswith("sha256=") or len(pins) < len(t) - 1:
        return "%s is not an entry" % line
    if not pins:
        return "%s pins no SHA-256" % line
    if len(set(pins)) < len(pins):
        return "%s gives a SHA-256 twice" % line
    return Entry(t[0], False, tuple(sorted(pins)))


ENTRY_FORMAT = "GLOB sha256=HEX ... (the SHA-256 of each file reviewed) or via GLOB"


# A [cipher] entry's tokens: the SHA-256 of the file reviewed (hex in either case, kept lowercased), and
# each site count.
DIGEST = re.compile(r"^sha256=([0-9a-fA-F]{64})$")
COUNT = re.compile(r"^([A-Za-z_][\w-]*)=([0-9]+)$")
FORMAT = "GLOB sha256=HEX NAME=COUNT ... (NAME from CIPHER_NAMES or SPELT) or GLOB *"
# What every [cipher] refusal asks for, as the allow file's header does: % "add" or "update".
REVIEW = ("review where its names come from, then %s the [cipher] entry and the openssl records' "
          "reach note in assurance/vulncheck.json")


def read_allow(path):
    """(the regex entries, the [cipher] entries, the [glob] entries) of ALLOW. The regex entries come first,
    one per line, then each section once, opened by its line ([glob] or [cipher]); a regex or [glob] entry
    is an Entry (ENTRY_FORMAT), each given once. A [cipher] entry is a glob, then either "*" (not
    counted) or the SHA-256 of the file reviewed and the sites it holds exactly (FORMAT), read as
    {"sha256": hex, "sites": {name: count}}: a new package version changes the bytes, so the source is
    read again even when the counts hold (#5861). Exits naming the line on any other entry, a glob given
    twice, or a name or the digest given twice in one entry, and on a section line it does not know or
    has read already."""
    regex, cipher, globs, section, seen = [], {}, [], None, set()
    for n, l in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        l = l.split("#", 1)[0].strip()

        def bad(why):
            sys.exit("import sweep: %s:%d: %s; a [cipher] entry is %s" % (path, n, why, FORMAT))
        if l.startswith("["):
            section = l[1:-1] if l.endswith("]") else l
            if section not in ("glob", "cipher") or section in seen:
                sys.exit("import sweep: %s:%d: %s is %s; the sections are [glob] and [cipher], each once"
                         % (path, n, l, "given again" if section in seen else "no section"))
            seen.add(section)
        elif l and section in (None, "glob"):
            e, into = parse_entry(l), regex if section is None else globs
            if not isinstance(e, Entry) or (e.glob, e.via) in {(x.glob, x.via) for x in into}:
                sys.exit("import sweep: %s:%d: %s; a%s entry is %s, each given once" % (
                    path, n, e if not isinstance(e, Entry) else "%s is given again" % l,
                    " [glob]" if section else " regex", ENTRY_FORMAT))
            into.append(e)
        elif l:
            glob, *want = l.split()
            if glob in cipher:
                bad("%s has an entry already" % glob)
            if want == ["*"]:
                cipher[glob] = "*"
                continue
            if not want or "*" in want:
                bad("%s names %s" % (glob, "nothing" if not want else "'*' with other tokens"))
            digests = [w[len("sha256="):].lower() for w in want if DIGEST.match(w)]
            if len(digests) != 1:
                bad("%s gives %d sha256=HEX tokens, not one" % (glob, len(digests)))
            sites = {}
            for w in want:
                m = COUNT.match(w)
                if DIGEST.match(w):
                    continue
                if not m or m.group(1) not in CIPHER_NAMES + SPELT:
                    bad("%s: %s is not NAME=COUNT with a NAME from CIPHER_NAMES or SPELT" % (glob, w))
                if m.group(1) in sites:
                    bad("%s gives %s twice" % (glob, m.group(1)))
                sites[m.group(1)] = int(m.group(2))
            if not sites:
                bad("%s counts no site" % glob)
            cipher[glob] = {"sha256": digests[0], "sites": sites}
    return regex, cipher, globs


def entry_line(p, sha, sites):
    return " ".join([p, "sha256=" + (sha or "MISSING")] + ["%s=%d" % kv for kv in sorted(sites.items())])


def cipher_refusals(places, entries):
    """Each file of PLACES holding a selector name or a SPELT name that matches no [cipher] entry or more
    than one, or whose sites or SHA-256 differ from the counted entry it matches; each such file the
    scan gives no SHA-256 for (a broken scan: sweep digests every file it counts); and each entry matching
    no such file."""
    errs, used = [], set()
    for place, v in places.items():
        for p, sites in v.get("cipher", {}).items():
            hit = [g for g in entries if fnmatch.fnmatchcase(p, g)]
            used.update(hit)
            sha = v.get("sha256", {}).get(p)
            got = " ".join("%s=%d" % kv for kv in sorted(sites.items()))
            if not sha:
                errs.append("%s: %s holds cipher sites (%s) but the scan gives no SHA-256 for it; the scan "
                            "is broken: run the sweep again, not an allow edit" % (place, p, got))
            elif not hit:
                errs.append("%s: %s holds a by-name cipher selector or spells %s (%s) and is not in "
                            "import_sweep.allow [cipher]; %s, adding: %s"
                            % (place, p, " or ".join(SPELT), got, REVIEW % "add", entry_line(p, sha, sites)))
            elif len(hit) > 1:
                errs.append("%s: %s matches %d [cipher] entries (%s); keep one, so no entry hides another's "
                            "review" % (place, p, len(hit), " ".join(hit)))
            elif entries[hit[0]] != "*" and entries[hit[0]] != {"sha256": sha, "sites": sites}:
                want = entries[hit[0]]
                what = ["cipher references %s, not the %s reviewed" % (got, " ".join(
                    "%s=%d" % kv for kv in sorted(want["sites"].items())))] if want["sites"] != sites else []
                what += ["other bytes (a new version?) than the ones reviewed"] if want["sha256"] != sha else []
                errs.append("%s: %s holds %s; %s, as: %s" % (place, p, " and ".join(what), REVIEW % "update",
                                                             entry_line(hit[0], sha, sites)))
    errs += ["import_sweep.allow: [cipher] %s matches no file holding a selector name or spelling %s; remove it"
             % (g, " or ".join(SPELT)) for g in entries if g not in used]
    return errs


# Each listed group: what its importers are called, the allow file's section for them, and the records
# naming them. A group not listed here (wscanf) has no allowed importer.
LISTED = {"regex": ("a regex function", "", "the image -100290 record"),
          "glob": ("glob()", " [glob]", "the -126765 records")}


def refusals(places, allow, globs=()):
    """Each claim of the glibc records that PLACES break, against the regex entries ALLOW and the [glob]
    section's GLOBS (Entry, or a plain glob, which pins nothing). In each place, a file reaching a group is
    accepted by a GLOB entry matching it that pins its SHA-256 (#6299); or, when no GLOB entry matches it and
    it imports none of the group's functions itself, when each library it reaches them through matches a
    "via" entry and a GLOB entry of its own (#6297), so a new direct caller is never accepted by a library's
    review. Every entry has to accept a file somewhere, and every pin has to be a file's it accepts."""
    errs, used, pinned = [], set(), set()
    entries = {"regex": [entry(e) for e in allow], "glob": [entry(e) for e in globs]}
    for (g, p), at in sorted(reach(places).items()):
        if g not in LISTED:
            errs.append("%s: %s imports or reaches a wide scanf function; the -115819 records say nothing does"
                        % (" ".join(at), p))
            continue
        def matching(path, via):
            return [e for e in entries[g] if e.via == via and fnmatch.fnmatchcase(path, e.glob)]
        named = matching(p, False)
        used.update((g, e) for e in named)
        refused, other = {}, {}
        for place, (own, libs) in at.items():
            sha = places[place].get("sha256", {}).get(p) or "MISSING"
            if named:
                hit = [e for e in named if sha in e.sha256]
                pinned.update((g, e, sha) for e in hit)
                if not hit:
                    other[place] = sha
                continue
            vias = [matching(lib, True) for lib in libs]
            if own or not all(vias) or not all(matching(lib, False) for lib in libs):
                refused[place] = sha
                continue
            used.update((g, e) for v in vias for e in v)
        what, section, record = LISTED[g]
        pins = lambda d: " ".join("sha256=" + x for x in sorted(set(d.values())))
        if refused:
            errs.append("%s: %s imports or reaches %s and is not in import_sweep.allow%s; review it, name it in "
                        "%s, then add the entry: %s %s" % (" ".join(refused), p, what, section, record, p,
                                                           pins(refused)))
        if other:
            errs.append("%s: %s reaches %s and holds other bytes than import_sweep.allow%s %s pins (a new version, "
                        "or another file it matches); review it again, then pin them: %s %s" % (
                            " ".join(other), p, what, section, " ".join(e.glob for e in named), named[0].glob,
                            pins(other)))
    errs += ["import_sweep.allow:%s %s %s; remove it" % (
        LISTED[g][1], shown(e), "accepts no file that reaches %s only through a library it names that has an entry "
        "naming it" % LISTED[g][0] if e.via else "matches no file that reaches %s" % LISTED[g][0])
        for g in LISTED for e in entries[g] if (g, e) not in used]
    errs += ["import_sweep.allow:%s %s pins sha256=%s, which no file it accepts holds; remove it"
             % (LISTED[g][1], e.glob, d) for g in LISTED for e in entries[g] if (g, e) in used
             for d in e.sha256 if (g, e, d) not in pinned]
    return errs


def summary(places):
    lines = []
    for place, v in places.items():
        lines.append("%s: %d ELF files read" % (place, v["scanned"]))
        for g in GROUPS:
            how = {k: {p: [s for s in syms if group_of(s) == g] for p, syms in v.get(key, {}).items()}
                   for k, key in (("imports", "imports"), ("looks up", "lookups"), ("carries", "carries"))}
            how = {k: {p: s for p, s in d.items() if s} for k, d in how.items()}
            imp = {p for d in how.values() for p in d}
            via = {p: [lib for lib in libs if lib in imp] for p, libs in v["via"].items() if p not in imp}
            via = {p: libs for p, libs in via.items() if libs}
            lines.append("%s %s: %d files import a function (or look one up, or carry a copy), %d more reach "
                         "one through a NEEDED library" % (place, g, len(imp), len(via)))
            lines += ["  %s %s: %s" % (k, p, " ".join(s)) for k, d in how.items() for p, s in sorted(d.items())]
            lines += ["  via %s: %s" % (p, " ".join(libs)) for p, libs in via.items()]
        lines += ["  glibc %s holds the marks of: %s" % (p, " ".join(m) or "none") for p, m in v.get("glibc", {}).items()]
        lines += ["  packed %s: %s" % kv for kv in v.get("packed", {}).items()]
        cipher = v.get("cipher", {})
        lines.append("%s cipher: %d files hold a by-name cipher selector or spell %s"
                     % (place, len(cipher), " or ".join(SPELT)))
        lines += ["  sites %s" % entry_line(p, v.get("sha256", {}).get(p), s) for p, s in cipher.items()]
    return lines


def annotations(lines, size=3500, cap=10):
    """LINES as ::notice commands of about SIZE characters each. GitHub shows CAP notices per step and
    drops the rest, so the last one shown says where the rest are."""
    chunks, cur = [], ""
    for line in lines:
        if cur and len(cur) + len(line) + 1 > size:
            chunks.append(cur)
            cur = ""
        cur += line[:size] + "\n"
    chunks += [cur] if cur else []
    if len(chunks) > cap:
        chunks = chunks[:cap - 1] + [chunks[cap - 1] + "(%d more notices: the full list is in the step log)\n"
                                     % (len(chunks) - cap)]
    return ["::notice title=import sweep %d/%d::%s" % (i + 1, len(chunks), c.rstrip("\n").replace("%", "%25")
            .replace("\r", "%0D").replace("\n", "%0A")) for i, c in enumerate(chunks)]


def main(argv):
    if argv[:1] == ["--summary"] and len(argv) in (2, 3):
        places = json.loads(pathlib.Path(argv[1]).read_text())
        lines = summary(places)
        print("\n".join(lines + annotations(lines)))
        regex, cipher, globs = read_allow(argv[2] if len(argv) == 3 else ALLOW)
        errs = problems(places) + refusals(places, regex, globs) + cipher_refusals(places, cipher)
        for e in errs[:10]:
            print("::error title=import sweep::" + e.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"))
    elif len(argv) == 2 and argv[0] == "--tree":
        places = run_tree(argv[1])
        json.dump(places, sys.stdout, indent=1, sort_keys=True)
        errs = []
    elif len(argv) == 2:
        places = run_build(*argv)
        json.dump(places, sys.stdout, indent=1, sort_keys=True)
        errs = []  # --summary holds the result to the control and the allowlist
    else:
        sys.exit(__doc__)
    for e in errs:
        print("import sweep: " + e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
