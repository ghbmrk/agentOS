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
  import_sweep.py --record FILE [ALLOW]
                                  ALLOW with each pin's record (package, version, symbols) as FILE gives
                                  it for the bytes already pinned: no digest is added or changed (#6448)

It also reads, for the openssl records (#5341), which files hold the name of a by-name OpenSSL cipher
selector or spell GCM-SIV or KRB5KDF, as selecting AES-GCM-SIV takes one of its names (see CIPHER_NAMES
and SPELT), and counts their references to each selector and their spellings.
And, for the openssl QUIC records (#6671), it reads which files import or look up OpenSSL's QUIC entry
points (QUIC_NAMES), which only the openssl CLI may, and its datagram or connect BIO constructors
(DGRAM_NAMES), which only the files [dgram] names may (OPENSSL_USES).
And, for the expat record (DEBIAN-CVE-2026-134703, #6545), which files load expat's wide build, libexpatw.so.1,
which alone runs the UTF-16 converters the record accepts as unreached (EXPATW).

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
file or symbolic link of the place answers to, and those names (each place's links resolve names as the
loader does; resolve()); "packed", each file whose code is not in its bytes as stored,
and why (packed()); "cipher", each file whose bytes hold a CIPHER_NAMES or SPELT name and its references
to each (cipher_sites); "sha256", the SHA-256 of each file reaching a group or held under "cipher";
"quic" and "dgram", each file importing a name of that OPENSSL_USES group, or importing glibc's dlsym
or dlvsym and holding one's name at the end of a string, and those names (#6671); "owner", for a build (not
--tree), the package and version that installed each file under "sha256", "-" for none (package_data; #6448);
"expatw", each file whose
NEEDED closure holds a name or a library (by file name or SONAME) of expat's wide build, or, unless it is that
build, whose bytes hold its name anywhere, terminated or not (a dlopen argument: Rust and Go literals carry no
NUL), and those names and libraries (#6545; a static copy of expat is not told apart from the UTF-8 build, nor
a name built at run time from pieces); "unread", each ELF file objdump failed on; and, for an initrd, "others", its executable members that are not ELF files. Only symbols bound to a GLIBC_ version count, so a library's own
re_* names do not.

--summary exits 1 when a claim the glibc records rest on stops holding: any file, in any place, imports
or reaches a wide scanf function, or imports or reaches a regex function and is not accepted by ALLOW's
regex entries (the image -100290 record), or imports or reaches glob() and is not accepted by its [glob]
section (the -126765 records). A file is accepted by an entry naming it (a glob) that pins its SHA-256
(#6299), or, when no such glob names it and it imports none of the group's functions itself, by "via"
entries naming every library it reaches them through, each of which has an entry naming it (#6297): a
reviewed library's dependents need no entry each, and a new direct caller or new bytes still fail. An
entry that accepts nothing, or a pin no accepted file holds, also fails, so each list stays its record's.
Each pin also records what was reviewed: the file's package and version and the symbols the sweep reads in it
(syms()); a pinned file whose record the build no longer gives fails (record_refusals; #6448), and a refused
re-pin prints the old and new package version and the symbols added and removed beside the entry to paste.
It also exits 1 when a file holding a selector name or a SPELT name matches no [cipher] entry of ALLOW or
more than one, or holds other sites or other bytes (SHA-256) than the counted entry it matches, or an
entry matches nothing; on any packed file; on any unresolved NEEDED name that no [unresolved] entry pinning
the file accepts (unresolved_refusals); when a file in "quic" or "dgram" matches no entry of the allow
section of that name, or an entry matches no such file, so the openssl QUIC records' claim that only the files
named there make a QUIC object or a datagram BIO is read from the tree (#6671); on any file in "expatw", so the expat record's "nothing loads the wide build" is read
from the tree (#6545); and on an ALLOW it cannot read (read_allow). The control is the
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
# (crypto/objects/objects.txt, 3.5.9), so only a selector given one of its names picks it: EVP_CIPHER_fetch,
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
# Any import, whatever library or version it names, for LOOKUP_FUNCS (a dlsym that another library defines
# still resolves names).
UND_ANY = re.compile(r"\*UND\*\s+\S+\s+(?:Base\s+)?(?:\([^)]*\)\s+)?(\S+)$")
DYNAMIC = re.compile(r"^\s+(NEEDED|SONAME)\s+(\S+)$")
# #6298: two ways to reach a group's code that no import shows.
# A run-time lookup: a file whose own imports or NEEDED closure (in its root) import glibc's dlsym or
# dlvsym can resolve any function whose name it holds, itself or through a library's wrapper around them
# (libltdl, libuv and the like; #6299, L3 on #6339). dlopen alone runs only the opened file's code, which the
# sweep reads as a file of its own. Such a file holding a group function's name at the end of a string (a
# NUL after it, as a C string literal is stored; the linker stores "glob" as the tail of "safe_glob" when a
# file holds both, so no NUL need precede it: Security on #6382) counts as importing that function, except
# a COMPAT_ONLY name when nothing in reach imports dlvsym. The openssl group needs no such rule: [cipher] already
# holds every file whose bytes hold a selector's name, a dlsym caller's string included (#5341).
# A library's own export that passes its caller's name on to dlsym counts as a lookup function too, so a
# [wrapper] entry can hold that library to its own names and a caller of the export is still read: OpenSSL
# 3.5's libcrypto exports DSO_bind_func and DSO_global_lookup, which pass the name they are given to dlsym
# (crypto/dso/dso_dlfcn.c), and DSO_METHOD_openssl, the table that holds both. Its other dlsym calls take
# fixed names (provider_core.c, eng_dyn.c, conf_mod.c, the comp/ and rand_unix.c loaders).
LOOKUP_FUNCS = ("dlsym", "dlvsym", "DSO_bind_func", "DSO_global_lookup", "DSO_METHOD_openssl")
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
# expat's wide (XML_UNICODE) build, the only one that runs the UTF-16-to-UTF-16 converters the
# DEBIAN-CVE-2026-134703 record accepts (#6545): a NEEDED name, a file name or SONAME, and a by-name string
# (a dlopen argument) that names it. libexpat1 installs the library itself; nothing may load it.
EXPATW = re.compile(r"^libexpatw\.so(\.[0-9]+)*$")
EXPATW_NAME = re.compile(rb"libexpatw\.so(?:\.[0-9]+)*")
# A guest root in the main tree: a process there sees it as /, so its absolute links resolve under it.
GUEST_ROOT = re.compile(r"^/usr/lib/agentos/images/[^/]+(?=/)")


def root_of(path):
    """The root a process running PATH sees: a guest's (GUEST_ROOT) for a path under one, else ""."""
    m = GUEST_ROOT.match(path)
    return m.group() if m else ""


def resolve(path, links, hops=40):
    """The path PATH names once every symbolic link in it (LINKS: {path: target}, a directory's included)
    is followed, as a process whose root is PATH's sees it (a guest's root for a path under one: GUEST_ROOT),
    so ".." stops there and an absolute target starts there; None after HOPS links (a loop), as the
    kernel's ELOOP. Security on #6382: a NEEDED name the loader maps through a link is resolved."""
    m = GUEST_ROOT.match(path)
    root = m.group().strip("/").split("/") if m else []
    parts, done = path.strip("/").split("/")[len(root):], list(root)
    while parts:
        c = parts.pop(0)
        if c in ("", "."):
            continue
        if c == "..":
            done = done[:-1] if len(done) > len(root) else done
            continue
        cur = "/" + "/".join(done + [c])
        if cur not in links:
            done.append(c)
            continue
        hops -= 1
        if hops < 0:
            return None
        if links[cur].startswith("/"):
            done = list(root)
        parts = links[cur].split("/") + parts
    return "/" + "/".join(done)
# #6671: the openssl QUIC records in assurance/vulncheck.json (QUIC_RECORDS) rest on no file but the openssl
# CLI (s_client -quic, which nothing on the box runs) reaching OpenSSL's QUIC stack. A QUIC connection,
# listener or domain needs an SSL_CTX made with one of the QUIC methods (ssl/quic/quic_method.c, 3.5.9;
# TLS_method and the other TLS and DTLS methods make no QUIC object), and SSL_new_listener is 3.5's
# server entry. A file importing one, under any version or none, counts; so does a file importing dlsym or
# dlvsym that holds one's name at the end of a NUL-terminated string (GNU ld may store a name as the tail
# of a longer one), unless it defines that name itself: libssl, the one file implementing them, holds them
# all in its own dynamic table (libcrypto the datagram BIO's, below). A static copy of OpenSSL is not
# libssl3t64 and is outside these records.
QUIC_NAMES = ("OSSL_QUIC_client_method", "OSSL_QUIC_client_thread_method", "OSSL_QUIC_server_method",
              "SSL_new_listener")
QUIC_RECORDS = "DEBIAN-CVE-2026-88822, -95691, -124709, -107494 and -84785"
# L3 7157966663: -88822's flaw is in the datagram BIO's peer detection (crypto/bio/bss_dgram.c,
# BIO_CTRL_DGRAM_DETECT_PEER_ADDR), which a file can ask of any datagram BIO with no QUIC object. In OpenSSL
# 3.5.4's crypto/ and ssl/ (every source their build.info files name, read for these constructors), a
# datagram BIO comes from its own constructors (the SCTP one falls back to dgram_ctrl; the pair has no
# peer detection and is counted as fail-closed), from a connect BIO set to SOCK_DGRAM, which makes one
# (bss_conn.c conn_create_dgram_bio) and hands it out (BIO_get0_dgram_bio; L3 7158175373, Security
# 7158185323), and from libssl's fd_method for a QUIC object. So the connect BIO's constructors, and libssl's
# BIO_new_ssl_connect and BIO_new_buffer_ssl_connect over it, count too, and their importers and lookups are
# held the same way, to [dgram]. libcrypto's own connect BIO user, the HTTP client, never sets SOCK_DGRAM.
DGRAM_NAMES = ("BIO_s_datagram", "BIO_new_dgram", "BIO_s_datagram_sctp", "BIO_new_dgram_sctp", "BIO_s_dgram_pair",
               "BIO_new_bio_dgram_pair", "BIO_s_connect", "BIO_new_connect", "BIO_new_ssl_connect",
               "BIO_new_buffer_ssl_connect")
# Each group: its names, what they are, and the records resting on no unlisted file using them.
OPENSSL_USES = {"quic": (QUIC_NAMES, "OpenSSL's QUIC entry points",
                         "the openssl QUIC records (%s)" % QUIC_RECORDS),
                "dgram": (DGRAM_NAMES, "OpenSSL's datagram or connect BIO constructors",
                          "the DEBIAN-CVE-2026-88822 records")}
OPENSSL_HELD = re.compile(b"(?:%s)(?=\0)" % b"|".join(n.encode() for names, _w, _r in OPENSSL_USES.values()
                                                      for n in names))


def group_of(sym):
    return next((g for g, rx in GROUPS.items() if rx.match(sym)), None)


def read_elf(path):
    """(affected glibc symbols imported, NEEDED names, SONAME or None, read, lookup, static) of the ELF file
    at PATH. READ is False when objdump fails on it for any reason but its having no dynamic section (a
    static or relocatable file, which imports nothing), so a file objdump cannot parse is never counted
    clean. LOOKUP is the set of run-time lookup functions (LOOKUP_FUNCS) it imports. STATIC is whether it
    names no interpreter (PT_INTERP) and no NEEDED library, so whatever libc code it runs is in its own
    bytes (static_elf.py)."""
    r = subprocess.run(["objdump", "-pT", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, errors="replace")
    read = r.returncode == 0 or "not a dynamic object" in r.stderr
    syms, needed, soname, dl, interp = set(), [], None, set(), False
    for line in r.stdout.splitlines():
        interp = interp or line.split()[:1] == ["INTERP"]
        m = UND.search(line)
        if m and group_of(m.group(2)):
            syms.add(m.group(2))
        a = UND_ANY.search(line)
        if a and a.group(1) in LOOKUP_FUNCS:
            dl.add(a.group(1))
        m = DYNAMIC.match(line)
        if m and m.group(1) == "NEEDED":
            needed.append(m.group(2))
        elif m:
            soname = m.group(2)
    return sorted(syms), needed, soname, read, dl, not (interp or needed)


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


def lookup_names(held, src):
    """The names of HELD a file can look up through SRC ({file: the LOOKUP_FUNCS it imports}): none
    without a source, and a COMPAT_ONLY name only where one imports dlvsym."""
    funcs = {f for fs in src.values() for f in fs}
    return sorted(held if "dlvsym" in funcs else set(held) - set(COMPAT_ONLY)) if funcs else []


def unwrapped(places, wrappers):
    """(PLACES with each lookup recounted without the sources a [wrapper] entry accepts, the refusals of
    those entries). A [wrapper] entry names a library, pinned as a [glob] entry is, whose dlsym and dlvsym
    calls take only names of its own, so a dependent's string is no lookup through it (the libraries
    libsystemd-shared and libpam load plugins by fixed names). A file's own dlsym import always counts. An
    entry whose library's bytes it does not pin accepts nothing, and one that accepts nothing fails."""
    errs, used, out = [], set(), {}
    for place, v in places.items():
        v = dict(v, lookups=dict(v.get("lookups", {})))
        for p, src in v.get("through", {}).items():
            keep = {}
            for lib, funcs in src.items():
                hit = [e for e in wrappers if lib != p and fnmatch.fnmatchcase(lib, e.glob)]
                sha = v.get("sha256", {}).get(lib) or "MISSING"
                ok = [e for e in hit if sha in e.sha256]
                used.update((e, sha) for e in ok)
                used.update((e, None) for e in hit)
                if hit and not ok:
                    rec = found(places, "wrapper", [(place, lib)])[sha]
                    errs.append("%s: %s holds other bytes than import_sweep.allow [wrapper] %s pins (%s); review its "
                                "dlsym calls again, then pin them: %s" % (place, lib, hit[0].glob, drift(
                                    hit[0].records, rec), entry_text(hit[0].glob, [rec])))
                if not ok:
                    keep[lib] = funcs
            names = lookup_names(v["lookups"][p], keep)
            if names:
                v["lookups"][p] = names
            else:
                del v["lookups"][p]
        out[place] = v
    errs += ["import_sweep.allow: [wrapper] %s matches no library a lookup goes through; remove it" % e.glob
             for e in wrappers if (e, None) not in used]
    errs += ["import_sweep.allow: [wrapper] %s pins sha256=%s, which no library it matches holds; remove it"
             % (e.glob, d) for e in wrappers if (e, None) in used for d in e.sha256 if (e, d) not in used]
    return out, sorted(set(errs), key=errs.index)


def openssl_uses(path):
    """({group: the names of that OPENSSL_USES group the ELF file at PATH imports or looks up, sorted} for each
    group it uses; read). A file whose bytes end no string with one of the names is not read further. It looks
    one up when it imports glibc's dlsym or dlvsym, holds the name (OPENSSL_HELD) and does not define it. READ
    is False when objdump fails on it for any reason but its having no dynamic section, so a file it cannot
    read is never counted clean."""
    with open(path, "rb") as f:
        held = {m.group().decode() for m in OPENSSL_HELD.finditer(f.read())}
    if not held:
        return {}, True
    r = subprocess.run(["objdump", "-T", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, errors="replace")
    imports, defines, dl = set(), set(), False
    for line in r.stdout.splitlines():
        t = line.split()
        if t and t[-1] in held:
            (imports if "*UND*" in t else defines).add(t[-1])
        m = UND.search(line)
        dl = dl or bool(m and m.group(2) in LOOKUP_FUNCS)
    used = imports | (held - defines if dl else set())
    groups = {g: sorted(used & set(names)) for g, (names, _w, _r) in OPENSSL_USES.items()}
    return {g: n for g, n in groups.items() if n}, r.returncode == 0 or "not a dynamic object" in r.stderr


def own(v, p):
    """The group functions file P of place V imports itself: by import, by a run-time lookup of a name it
    holds, or as a copy of glibc's code it carries (#6298, #6299)."""
    return set(v["imports"].get(p, [])) | set(v.get("lookups", {}).get(p, [])) | set(v.get("carries", {}).get(p, []))


def sweep(files, links=None):
    """FILES maps a shown path to a readable path, and LINKS each symbolic link of the place (a shown path)
    to its target, so a NEEDED name a link answers to resolves to the file the link names (resolve()).
    Returns the place's record (module docstring)."""
    imports, needed, by_name, unread, cipher, digest = {}, {}, {}, [], {}, {}
    dl, names, carries, glibc, opaque, sonames, wide_names = {}, {}, {}, {}, {}, {}, {}
    uses = {g: {} for g in OPENSSL_USES}
    for shown, real in files.items():
        syms, needed[shown], soname, read, dl[shown], _static = read_elf(real)
        sonames[shown] = soname
        with open(real, "rb") as f:
            data = f.read()
        wide_names[shown] = {m.group().decode() for m in EXPATW_NAME.finditer(data)}
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
        groups, openssl_read = openssl_uses(real)
        for g, used in groups.items():
            uses[g][shown] = used
        if not (read and disassembled and openssl_read):
            unread.append(shown)
        if syms:
            imports[shown] = syms
        # A NEEDED entry names a library's SONAME, which on disk is a symbolic link to the file read. The
        # loader looks for it only in the process's own root, so a name answers only within one (root_of).
        for n in {os.path.basename(shown), soname} - {None}:
            by_name.setdefault((root_of(shown), n), []).append(shown)
    # A NEEDED name can also be a link's (libw.so -> libw-real.so, a library with no SONAME; Security on
    # #6382): the loader opens the link and maps the file it names, so the name answers to that file.
    for link in sorted(links or {}):
        to, n = resolve(link, links), (root_of(link), os.path.basename(link))
        if to in files and to not in by_name.get(n, []):
            by_name.setdefault(n, []).append(to)

    def closure(shown, names=False):
        """The files of this place in SHOWN's NEEDED closure, itself excluded: in SHOWN's root only. With
        NAMES, the NEEDED names met on the way (resolved or not) instead."""
        root = root_of(shown)
        seen, todo, libs = set(), list(needed[shown]), set()
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            for lib in by_name.get((root, n), []):
                libs.add(lib)
                todo += needed.get(lib, [])
        return seen if names else libs - {shown}
    reached = {shown: closure(shown) for shown in files}
    # #6545: each file loading expat's wide build: a NEEDED name in its closure naming it, a library in its
    # closure that is it (by file name or SONAME, so a link of another name still counts), or, for a file
    # that is not itself the wide build, its name anywhere in its bytes (a dlopen argument; dlopen maps it by
    # name). No NUL is required after it: Rust and Go keep literals unterminated (L3 on #6733).
    def is_wide(p):
        return bool(EXPATW.match(os.path.basename(p)) or EXPATW.match(sonames.get(p) or ""))
    expatw = {shown: sorted({n for n in closure(shown, True) if EXPATW.match(n)}
                            | {lib for lib in reached[shown] if is_wide(lib)}
                            | (set() if is_wide(shown) else wide_names[shown])) for shown in files}
    # A NEEDED name no file or link of the place answers to (Security R4 on #6382): what that library would
    # import or look up is not read, so it fails unless an [unresolved] entry says why it never loads there.
    unresolved = {shown: sorted(set(n for n in needed[shown] if (root_of(shown), n) not in by_name))
                  for shown in files}
    lookups, through = {}, {}
    for shown in files:
        src = {lib: sorted(dl[lib]) for lib in sorted(reached[shown] | {shown}) if dl[lib]}
        held = lookup_names(names[shown], src)
        if held:
            lookups[shown], through[shown] = held, src
    importers = set(imports) | set(lookups) | set(carries)
    via = {shown: sorted(reached[shown] & importers) for shown in files if reached[shown] & importers}
    # Each reaching or [cipher] file's SHA-256, and each lookup source's, for the pinned allow entries
    # (#5861, #6299).
    pinned = importers | set(via) | set(cipher) | {lib for src in through.values() for lib in src}
    pinned |= {p for p, n in unresolved.items() if n}
    return {"scanned": len(files), "imports": dict(sorted(imports.items())), "via": dict(sorted(via.items())),
            "lookups": dict(sorted(lookups.items())), "through": dict(sorted(through.items())),
            "carries": dict(sorted(carries.items())),
            "glibc": dict(sorted(glibc.items())), "packed": dict(sorted(opaque.items())),
            "unresolved": {p: n for p, n in sorted(unresolved.items()) if n},
            "expatw": {p: w for p, w in sorted(expatw.items()) if w},
            "unread": sorted(unread), "cipher": dict(sorted(cipher.items())),
            "sha256": {p: d for p, d in sorted(digest.items()) if p in pinned}, **{g: dict(sorted(u.items())) for g, u in uses.items()}}


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


def tree_links(top, prefix="/", skip=()):
    """Every symbolic link under TOP, a directory's included, as {prefix + relative path: its target}."""
    links = {}
    for d, dirs, names in walk(top):
        rel = os.path.relpath(d, top)
        if rel == ".":
            dirs[:] = [x for x in dirs if x not in skip]
        for n in dirs + names:
            p = os.path.join(d, n)
            if os.path.islink(p):
                links[os.path.normpath(os.path.join(prefix, rel, n))] = os.readlink(p)
    return links


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


def initrd_place(path, scratch, owner=None):
    """The record of the initrd at PATH: each regular ELF member written under SCRATCH and read, with its
    symbolic links, and each other name of a hard-linked ELF member as a link to it (Security on #6382)."""
    import finish_image
    files, others, links, group, data = {}, 0, {}, {}, {}
    for i, (name, mode, body, link) in enumerate(finish_image.cpio_members(pathlib.Path(path).read_bytes())):
        shown = "/" + name.lstrip("/")
        if shown in (INITRD_STATUS, INITRD_OWNERS) and stat.S_ISREG(mode):
            data[shown] = body
        if link is not None:
            group.setdefault(link, []).append(shown)
        if stat.S_ISLNK(mode):
            links[shown] = body.decode("utf-8", "surrogateescape")
        elif stat.S_ISREG(mode) and body[:4] == b"\x7fELF":
            f = os.path.join(scratch, "%d" % i)
            pathlib.Path(f).write_bytes(body)
            files[shown] = f
        elif stat.S_ISREG(mode) and mode & 0o111:
            others += 1
    for names in group.values():
        to = next((n for n in names if n in files), None)
        links.update({n: to for n in names if to and n not in files})
    # "others": executable regular members that are not ELF files (problems()). A modules initrd's
    # modules, indexes and firmware are not executable.
    return dict(owned(sweep(files, links), files, owner and initrd_owner(data)), others=others)


def owned(place, files, owner):
    """PLACE with "owner": OWNER(shown, readable path) of each file it pins (sha256), when OWNER is given."""
    return dict(place, owner={p: list(owner(p, files[p])) for p in place["sha256"]}) if owner else place


def run_tree(root, usr=None, owner=None):
    files = tree_files(root, skip=("usr",) if usr else ())
    links = tree_links(root, skip=("usr",) if usr else ())
    if usr:
        files.update(tree_files(usr, "/usr"))
        links.update(tree_links(usr, "/usr"))
    return {"tree": owned(sweep(files, links), files, owner)}


# The build's package data (#6448), each a file of OUT: dpkg's status of the main tree; {path: package} of
# each path a main-tree package installed (mkosi.postinst, drop.py's owners(): dpkg's .list files, usrmerge
# paths under /usr); and the guests' status with "MD5 PACKAGE" for each file image/guest-userland.sh copied
# into a guest root (image/guest-shipped.sh).
# Each initrd's own (drop.py, its postinst): its dpkg status and {path: package} of its regular files.
INITRD_STATUS, INITRD_OWNERS = "/usr/share/agentos/initrd.dpkg-status", "/usr/share/agentos/initrd.dpkg-owners"
STATUS, OWNERS, GUEST_STATUS, GUEST_MD5 = ("agentos.dpkg-status", "agentos.dpkg-owners", "guest/agentos.dpkg-status",
                                           "guest/agentos.md5sums")


LIB_ALIAS = re.compile(r"^/usr/(?=lib(64)?/)")


def versions(text):
    """{package: version} of the installed packages in dpkg status TEXT."""
    out = {}
    for para in text.split("\n\n"):
        f = dict(l.split(": ", 1) for l in para.splitlines() if ": " in l and not l.startswith(" "))
        if f.get("Status", "").endswith(" installed") and "Package" in f and "Version" in f:
            out[f["Package"]] = f["Version"]
    return out


def owners_of(by_path, status, by_md5=None, guest=None):
    """OWNER(shown, readable path): (packages, versions), "," joined, of the packages that installed the file,
    by its path in BY_PATH ({path: {package}}) at STATUS's versions, or for a guest root's file (with BY_MD5),
    by its MD5 at GUEST's; ("-", "-") for a file none did, and ("?", "?") for a package its status lacks."""
    def owner(shown, real):
        if by_md5 is not None and GUEST_ROOT.match(shown):
            with open(real, "rb") as f:
                pkgs, st = by_md5.get(hashlib.md5(f.read()).hexdigest(), set()), guest
        else:
            # drop.py spells /bin and /sbin under /usr; a package may still list /lib or /lib64 unmerged.
            pkgs, st = by_path.get(shown) or by_path.get(LIB_ALIAS.sub("/", shown), set()), status
        if not pkgs:
            return ("-", "-")
        if any(p not in st for p in pkgs):
            return ("?", "?")
        return (",".join(sorted(pkgs)), ",".join(st[p] for p in sorted(pkgs)))
    return owner


def unread(shown, real):
    return ("?", "?")


def owner_map(text):
    """{path: {package}} of an owners file ({path: package}, drop.py's owners())."""
    return {p: {k.split(":")[0]} for p, k in json.loads(text).items()}


def package_data(out):
    """OWNER(shown, readable path) for the main tree of the build in OUT (owners_of), or one that gives
    ("?", "?") for every file when OUT's package data cannot be read, which no record holds (fail closed)."""
    o = pathlib.Path(out)
    try:
        main, guest = versions((o / STATUS).read_text()), versions((o / GUEST_STATUS).read_text())
        by_path = owner_map((o / OWNERS).read_text())
        by_md5 = {}
        for line in (o / GUEST_MD5).read_text().splitlines():
            md5, pkg = line.split()
            by_md5.setdefault(md5, set()).add(pkg.split(":")[0])
    except (OSError, ValueError, AttributeError):
        return unread
    return owners_of(by_path, main, by_md5, guest)


def initrd_owner(members):
    """OWNER for an initrd's files from its own package data, MEMBERS ({shown: bytes}) holding drop.py's
    INITRD_STATUS and INITRD_OWNERS (#6801): an initrd keeps packages the main tree drops. Without both, or
    unreadable, every file gives ("?", "?") (fail closed)."""
    try:
        return owners_of(owner_map(members[INITRD_OWNERS].decode()), versions(members[INITRD_STATUS].decode()))
    except (KeyError, ValueError, AttributeError, UnicodeDecodeError):
        return unread


def run_build(out, version):
    import offline_systemd
    owner = package_data(out)
    root, usr, _cmdline, cleanup = offline_systemd.built_tree(out, version)
    try:
        places = run_tree(root, usr, owner)
    finally:
        cleanup()
    initrds = pathlib.Path(out) / "initrd"
    for p in sorted(pathlib.Path(d, n) for d, _, names in walk(initrds) for n in names
                    if is_file(os.path.join(d, n))):
        with tempfile.TemporaryDirectory() as scratch:
            places["initrd:" + str(p.relative_to(initrds))] = initrd_place(p, scratch, owner)
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
    # #6545: the expat record (DEBIAN-CVE-2026-134703) holds only while nothing loads the wide build.
    errs += ["%s: %s loads expat's wide build (%s), which runs the UTF-16 converters DEBIAN-CVE-2026-134703 "
             "(#6542) accepts as unreached; drop that user or the library, or read its reach and amend the record"
             % (k, p, " ".join(w)) for k, v in places.items() for p, w in v.get("expatw", {}).items()]
    # #6299: a file whose code is not in its bytes as stored can hide any import, lookup or copy.
    errs += ["%s: %s is packed (%s): its code cannot be read for imports, lookups or carried copies"
             % (k, p, why) for k, v in places.items() for p, why in v.get("packed", {}).items()]
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


# A [regex], [glob], [wrapper] or [unresolved] entry: GLOB and, for each file reviewed under it, its SHA-256
# and the record of what was reviewed (#6448): its Debian package and version and the symbols the sweep reads
# in it for that section (syms()). The digests accept: a file GLOB names is accepted only when its bytes are
# one of them (#6299: as [cipher] entries are keyed, so a new version, or another file the glob matches, is
# read before it is accepted). The records hold: record_refusals() fails each one the image no longer gives,
# so the allow file's diff shows what moved. Or "via GLOB", which accepts a file reaching the group only
# through libraries it names (refusals), whose own GLOB entries pin them.
Entry = collections.namedtuple("Entry", "glob via sha256 records", defaults=(False, (), ()))
# One pin's record: SHA-256, package and version ("-" for a file no package installs; several packages are
# joined by ",", their versions in the same order) and the sorted symbols, () for none.
Record = collections.namedtuple("Record", "sha256 pkg ver syms")
PKG = re.compile(r"^pkg=(-|[a-z0-9][a-z0-9+.-]*(?:,[a-z0-9][a-z0-9+.-]*)*)$")
VER = re.compile(r"^ver=(-|[A-Za-z0-9.+~:-]+(?:,[A-Za-z0-9.+~:-]+)*)$")
SYMS = re.compile(r"^syms=(-|[A-Za-z_][\w.+-]*(?:,[A-Za-z_][\w.+-]*)*)$")
# The sections whose entries are Entry lines, by read_allow's name for each (None: the regex entries).
PINNED = {None: "regex", "glob": "glob", "wrapper": "wrapper", "unresolved": "unresolved"}


def shown(e):
    return ("via " if e.via else "") + e.glob


def entry(e):
    """E as an Entry; a plain string is a GLOB entry pinning no bytes, which accepts no file."""
    return e if isinstance(e, Entry) else Entry(e)


def record_text(pkg, ver, syms):
    return "pkg=%s ver=%s syms=%s" % (pkg, ver, ",".join(syms) or "-")


def entry_text(glob, records):
    """The allow line of GLOB pinning RECORDS (Record, or (sha256, pkg, ver, syms)), in digest order."""
    return " ".join([glob] + ["sha256=%s %s" % (r[0], record_text(*r[1:])) for r in sorted(records)])


def parse_entry(line):
    """The Entry a [regex], [glob], [wrapper] or [unresolved] line gives, or why it is none (ENTRY_FORMAT)."""
    t = line.split()
    if t[0] == "via":
        return Entry(t[1], True) if len(t) == 2 else "%s is not an entry" % line
    if t[0].startswith("sha256="):
        return "%s is not an entry" % line
    if len(t) == 1:
        return "%s pins no SHA-256" % line
    records = []
    for i in range(1, len(t), 4):
        group = t[i:i + 4]
        if not DIGEST.match(group[0]):
            return "%s is not an entry: %s is not sha256=HEX" % (line, group[0])
        ms = [rx.match(w) for rx, w in zip((PKG, VER, SYMS), group[1:])]
        if len(group) < 4 or not all(ms):
            return "%s: %s is not followed by pkg=NAME ver=VERSION syms=NAME,..." % (line, group[0])
        pkg, ver, syms = (m.group(1) for m in ms)
        names = () if syms == "-" else tuple(syms.split(","))
        if pkg.count(",") != ver.count(",") or (pkg == "-") != (ver == "-"):
            return "%s: %s gives %s and %s, not one version for each package" % (line, group[0], group[1], group[2])
        if list(names) != sorted(set(names)):
            return "%s: %s lists its syms out of order or twice" % (line, group[0])
        records.append(Record(group[0][len("sha256="):].lower(), pkg, ver, names))
    pins = [r.sha256 for r in records]
    if len(set(pins)) < len(pins):
        return "%s gives a SHA-256 twice" % line
    records.sort()
    return Entry(t[0], False, tuple(pins and sorted(pins)), tuple(records))


ENTRY_FORMAT = ("GLOB sha256=HEX pkg=NAME ver=VERSION syms=NAME,... ... (for each file reviewed: its SHA-256, "
                "its package and version, - for none, and the symbols read in it, - for none) or via GLOB")


# A [cipher] entry's tokens: the SHA-256 of the file reviewed (hex in either case, kept lowercased), and
# each site count.
DIGEST = re.compile(r"^sha256=([0-9a-fA-F]{64})$")
COUNT = re.compile(r"^([A-Za-z_][\w-]*)=([0-9]+)$")
FORMAT = "GLOB sha256=HEX NAME=COUNT ... (NAME from CIPHER_NAMES or SPELT) or GLOB *"
# What every [cipher] refusal asks for, as the allow file's header does: % "add" or "update".
REVIEW = ("review where its names come from, then %s the [cipher] entry and the openssl records' "
          "reach note in assurance/vulncheck.json")


def read_allow(path):
    """(the regex entries, the [cipher] entries, the [glob] entries, the [wrapper] entries, the [unresolved]
    entries, {"quic": its globs, "dgram": its globs}) of ALLOW. The regex entries come first, one per line,
    then each section once, opened by its line ([glob], [cipher], [wrapper], [unresolved], [quic] or
    [dgram]); a regex, [glob], [wrapper] or [unresolved] entry is an Entry (ENTRY_FORMAT; a [wrapper] or
    [unresolved] entry is never "via"), each given once, and a [quic] or [dgram] entry one glob, given
    once. A [cipher] entry is a glob, then either "*" (not
    counted) or the SHA-256 of the file reviewed and the sites it holds exactly (FORMAT), read as
    {"sha256": hex, "sites": {name: count}}: a new package version changes the bytes, so the source is
    read again even when the counts hold (#5861). Exits naming the line on any other entry, a glob given
    twice, or a name or the digest given twice in one entry, and on a section line it does not know or
    has read already."""
    regex, cipher, globs, wrappers, unres, uses, section, seen = [], {}, [], [], [], {g: [] for g in OPENSSL_USES}, None, set()
    for n, l in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        l = l.split("#", 1)[0].strip()

        def bad(why):
            sys.exit("import sweep: %s:%d: %s; a [cipher] entry is %s" % (path, n, why, FORMAT))
        if l.startswith("["):
            section = l[1:-1] if l.endswith("]") else l
            if section not in ("glob", "cipher", "wrapper", "unresolved", *OPENSSL_USES) or section in seen:
                sys.exit("import sweep: %s:%d: %s is %s; the sections are [glob], [cipher], [wrapper], "
                         "[unresolved], [quic] and [dgram], each once"
                         % (path, n, l, "given again" if section in seen else "no section"))
            seen.add(section)
        elif l and section in (None, "glob", "wrapper", "unresolved"):
            e, into = parse_entry(l), {None: regex, "glob": globs, "wrapper": wrappers, "unresolved": unres}[section]
            if section in ("wrapper", "unresolved") and isinstance(e, Entry) and e.via:
                e = "%s is not an entry" % l
            if not isinstance(e, Entry) or (e.glob, e.via) in {(x.glob, x.via) for x in into}:
                sys.exit("import sweep: %s:%d: %s; a%s entry is %s, each given once" % (
                    path, n, e if not isinstance(e, Entry) else "%s is given again" % l,
                    " [glob]" if section else " regex", ENTRY_FORMAT))
            into.append(e)
        elif l and section in OPENSSL_USES:
            if len(l.split()) != 1 or l in uses[section]:
                sys.exit("import sweep: %s:%d: %s; a [%s] entry is one GLOB, each given once" % (
                    path, n, "%s is given again" % l if l in uses[section] else "%s is not an entry" % l, section))
            uses[section].append(l)
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
    return regex, cipher, globs, wrappers, unres, uses


def unresolved_refusals(places, entries):
    """Each file of PLACES with a NEEDED name no file or link of its place answers to (Security R4 on #6382)
    that no [unresolved] entry (ENTRY_FORMAT, never "via") accepts: one naming it that pins its SHA-256,
    whose comment says why that library never loads there (another architecture's or libc's build, a library
    the image does not ship and the file's own code never needs at run time). The loader would refuse such a
    file, or another file of that name it finds outside the place would run unread. Each entry has to accept
    a file and each pin has to be one's, as [wrapper] entries do."""
    errs, used = [], set()
    for place, v in places.items():
        for p, names in v.get("unresolved", {}).items():
            hit = [e for e in entries if fnmatch.fnmatchcase(p, e.glob)]
            sha = v.get("sha256", {}).get(p) or "MISSING"
            ok = [e for e in hit if sha in e.sha256]
            used.update((e, None) for e in hit)
            used.update((e, sha) for e in ok)
            rec = found(places, "unresolved", [(place, p)])[sha] if not ok else None
            if not hit:
                errs.append("%s: %s needs %s, which no file or link there answers to, so what it would import "
                            "through it is not read; find why it never loads there, then add the entry, with that "
                            "reason, to import_sweep.allow [unresolved]: %s"
                            % (place, p, " ".join(names), entry_text(p, [rec])))
            elif not ok:
                errs.append("%s: %s needs %s and holds other bytes than import_sweep.allow [unresolved] %s pins (%s); "
                            "review it again, then pin them: %s"
                            % (place, p, " ".join(names), hit[0].glob, drift(hit[0].records, rec),
                               entry_text(hit[0].glob, [rec])))
    errs += ["import_sweep.allow: [unresolved] %s matches no file with an unresolved NEEDED name; remove it" % e.glob
             for e in entries if (e, None) not in used]
    errs += ["import_sweep.allow: [unresolved] %s pins sha256=%s, which no file it matches holds; remove it"
             % (e.glob, d) for e in entries if (e, None) in used for d in e.sha256 if (e, d) not in used]
    return errs


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


def openssl_refusals(places, entries):
    """Each file of PLACES using a name of an OPENSSL_USES group that matches no glob of that group's section
    in ENTRIES ({group: globs}), and each glob matching no such file (#6671)."""
    errs = []
    for g, (_names, what, records) in OPENSSL_USES.items():
        used = set()
        for place, v in places.items():
            for p, names in v.get(g, {}).items():
                hit = [e for e in entries.get(g, []) if fnmatch.fnmatchcase(p, e)]
                used.update(hit)
                if not hit:
                    errs.append("%s: %s imports or looks up %s (%s) and is not in import_sweep.allow [%s]; %s "
                                "rest on no other file doing so: review what it does with them, update those "
                                "records, then add the entry: %s" % (place, p, what, " ".join(names), g, records, p))
        # L3 7157966663 item 3: an entry is also the control that this read still works.
        errs += ["import_sweep.allow: [%s] %s matches no file importing or looking up %s; each entry is also "
                 "the control that this scan still reads them, so remove it only once that file has left the "
                 "image or stopped using them, and otherwise treat the scan as broken" % (g, e, what)
                 for e in entries.get(g, []) if e not in used]
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
        if refused:
            errs.append("%s: %s imports or reaches %s and is not in import_sweep.allow%s; review it, name it in "
                        "%s, then add the entry: %s" % (" ".join(refused), p, what, section, record, entry_text(
                            p, found(places, g, [(k, p) for k in refused]).values())))
        if other:
            new = found(places, g, [(k, p) for k in other]).values()
            errs.append("%s: %s reaches %s and holds other bytes than import_sweep.allow%s %s pins (a new version, "
                        "or another file it matches; %s); review it again, then pin them: %s" % (
                            " ".join(other), p, what, section, " ".join(e.glob for e in named), "; ".join(
                                drift([r for e in named for r in e.records], n) for n in new),
                            entry_text(named[0].glob, new)))
    errs += ["import_sweep.allow:%s %s %s; remove it" % (
        LISTED[g][1], shown(e), "accepts no file that reaches %s only through a library it names that has an entry "
        "naming it" % LISTED[g][0] if e.via else "matches no file that reaches %s" % LISTED[g][0])
        for g in LISTED for e in entries[g] if (g, e) not in used]
    errs += ["import_sweep.allow:%s %s pins sha256=%s, which no file it accepts holds; remove it"
             % (LISTED[g][1], e.glob, d) for g in LISTED for e in entries[g] if (g, e) in used
             for d in e.sha256 if (g, e, d) not in pinned]
    return errs


def syms(section, v, p):
    """The symbols the sweep reads in file P of place V for SECTION (PINNED), which its entries record (#6448):
    for regex and glob, the group's functions it imports, looks up or carries itself (own()); for a wrapper,
    the LOOKUP_FUNCS it imports; for unresolved, its NEEDED names nothing in its place answers to."""
    if section in GROUPS:
        return tuple(sorted(x for x in own(v, p) if group_of(x) == section))
    if section == "wrapper":
        return tuple(sorted({f for src in v.get("through", {}).values() for f in src.get(p, [])}))
    return tuple(sorted(v.get("unresolved", {}).get(p, [])))


def owner(v, p):
    """(package, version) of file P of place V, as run_build read them (package_data); ("?", "?") when they
    were not read, which no record can hold."""
    o = v.get("owner", {}).get(p)
    return tuple(o) if o else ("?", "?")


def found(places, section, at):
    """The Record each sha256 of the files AT ([(place, path)]) gives for SECTION: {sha: Record}, the
    symbols united over its files, and "?" where its files give no one package and version."""
    out = {}
    for k, p in at:
        sha = places[k].get("sha256", {}).get(p) or "MISSING"
        out.setdefault(sha, (set(), set()))
        out[sha][0].add(owner(places[k], p))
        out[sha][1].update(syms(section, places[k], p))
    return {sha: Record(sha, *(next(iter(o)) if len(o) == 1 else ("?", "?")), tuple(sorted(n)))
            for sha, (o, n) in out.items()}


def drift(old, new):
    """What moved from the records OLD (an entry's) to the Record NEW, for a refusal (#6448): the package and
    version on each side, and the symbols added and removed against the record of the same package or, failing
    that, every record's. Says so when the build's package data was not read; the refusal stands."""
    base = [r for r in old if r.pkg == new.pkg] or list(old)
    was = " or ".join(sorted({"%s %s" % (r.pkg, r.ver) for r in base})) or "nothing"
    before = {x for r in base for x in r.syms}
    moved = ["+" + x for x in sorted(set(new.syms) - before)] + ["-" + x for x in sorted(before - set(new.syms))]
    now = ("its package could not be read from the build (the refusal stands)" if new.pkg == "?"
           else "now %s %s" % (new.pkg, new.ver))
    return "recorded %s, %s; symbols %s" % (was, now, " ".join(moved) or "unchanged (%s)" % (
        ",".join(new.syms) or "none"))


def accepted(places, sections):
    """{(section, Entry, sha256): [(place, path)]}: each file a GLOB entry of SECTIONS ({PINNED name: entries})
    names and pins by its bytes, among the files that section reads (reach for regex and glob, lookup sources
    for wrapper, unresolved NEEDED names for unresolved)."""
    out, r = {}, reach(places)
    for s, entries in sections.items():
        for place, v in places.items():
            if s in GROUPS:
                cands = {p for (g, p), at in r.items() if g == s and place in at}
            elif s == "wrapper":
                cands = {lib for src in v.get("through", {}).values() for lib in src}
            else:
                cands = set(v.get("unresolved", {}))
            for p in sorted(cands):
                sha = v.get("sha256", {}).get(p)
                for e in entries:
                    if not e.via and sha in e.sha256 and fnmatch.fnmatchcase(p, e.glob):
                        out.setdefault((s, e, sha), []).append((place, p))
    return out


def record_refusals(places, sections):
    """Each pin whose bytes the image holds but whose record it no longer gives (#6448): another package or
    version, or other symbols, or a package not read. The digest still decides what is accepted; this keeps
    the record a reviewer reads beside it true, so an allow diff shows what moved."""
    errs = []
    for (s, e, sha), at in sorted(accepted(places, sections).items(), key=lambda kv: (kv[0][0], kv[0][1].glob,
                                                                                        kv[0][2])):
        rec = {r.sha256: r for r in e.records}.get(sha)
        new = found(places, s, at)[sha]
        if rec != new:
            errs.append("%s: %s holds the bytes import_sweep.allow%s %s pins (sha256=%s), but its record is stale: "
                        "%s; review what moved, then record it (import_sweep.py --record): %s" % (
                            " ".join(sorted({k for k, _ in at})), " ".join(sorted({p for _, p in at})),
                            "" if s == "regex" else " [%s]" % s, e.glob, sha, drift([rec] if rec else [], new),
                            entry_text(e.glob, [r for r in e.records if r.sha256 != sha] + [new])))
    return errs


def record(text, places, sections):
    """TEXT, an allow file's lines, with each pinned entry's records as PLACES give them for the bytes it already
    pins (#6448): no digest is added, changed or removed, so nothing it prints accepts a file the allow file
    did not. Exits when a record cannot be read (a package not read)."""
    new = {(s, e.glob, sha): rec for (s, e, sha), at in accepted(places, sections).items()
           for rec in [found(places, s, at)[sha]]}
    bad = sorted("%s %s sha256=%s" % (s, g, sha) for (s, g, sha), r in new.items() if r.pkg == "?")
    if bad:
        sys.exit("import sweep: no package and version read for %s" % "; ".join(bad))
    out, section = [], None
    for line in text.splitlines():
        body, hash_, comment = line.partition("#")
        if body.strip().startswith("["):
            section = body.strip()[1:-1]
        elif body.strip() and section in PINNED:
            e = parse_entry(body.strip())
            if isinstance(e, Entry) and not e.via:
                recs = [new.get((PINNED[section], e.glob, r.sha256), r) for r in e.records]
                lead = body[:len(body) - len(body.lstrip())]
                gap = body[len(body.rstrip()):] if hash_ else ""
                line = lead + entry_text(e.glob, recs) + gap + hash_ + comment
        out.append(line)
    return "\n".join(out) + "\n"


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
        lines += ["  looks up through %s: %s" % (p, " ".join("%s=%s" % (lib, "+".join(f)) for lib, f in src.items()))
                  for p, src in v.get("through", {}).items()]
        lines += ["  unresolved %s: %s" % (p, " ".join(n)) for p, n in v.get("unresolved", {}).items()]
        lines += ["  expatw %s: %s" % (p, " ".join(w)) for p, w in v.get("expatw", {}).items()]
        cipher = v.get("cipher", {})
        lines.append("%s cipher: %d files hold a by-name cipher selector or spell %s"
                     % (place, len(cipher), " or ".join(SPELT)))
        lines += ["  sites %s" % entry_line(p, v.get("sha256", {}).get(p), s) for p, s in cipher.items()]
        for g, (_names, what, _records) in OPENSSL_USES.items():
            u = v.get(g, {})
            lines.append("%s %s: %d files import or look up %s" % (place, g, len(u), what))
            lines += ["  %s %s: %s" % (g, p, " ".join(names)) for p, names in u.items()]
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
        regex, cipher, globs, wrappers, unres, uses = read_allow(argv[2] if len(argv) == 3 else ALLOW)
        places, wrapped = unwrapped(places, wrappers)
        errs = (problems(places) + unresolved_refusals(places, unres) + wrapped + refusals(places, regex, globs)
                + record_refusals(places, {"regex": regex, "glob": globs, "wrapper": wrappers, "unresolved": unres})
                + cipher_refusals(places, cipher) + openssl_refusals(places, uses))
        for e in errs[:10]:
            print("::error title=import sweep::" + e.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"))
    elif argv[:1] == ["--record"] and len(argv) in (2, 3):
        allow = argv[2] if len(argv) == 3 else ALLOW
        regex, _cipher, globs, wrappers, unres, _uses = read_allow(allow)
        places, _ = unwrapped(json.loads(pathlib.Path(argv[1]).read_text()), wrappers)
        sys.stdout.write(record(pathlib.Path(allow).read_text(), places,
                                {"regex": regex, "glob": globs, "wrapper": wrappers, "unresolved": unres}))
        errs = []
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
