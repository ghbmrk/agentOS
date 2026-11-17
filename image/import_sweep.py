#!/usr/bin/env python3
"""Which ELF files in a built image import glibc's POSIX regex or wide scanf functions (#5697, EVL-5).

The image's glibc records (assurance/vulncheck.json, DEBIAN-CVE-2026-100290 and -115819) accept the
advisories on the grounds that no long-lived or network-facing process calls the affected functions.
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

The JSON maps each place ("tree", and "initrd:<path>" for each initrd) to: "scanned", the ELF files
read; "imports", each file importing an affected glibc symbol and those symbols; and "via", each other
ELF file whose NEEDED closure (by SONAME or file name, within that place) holds an importing library, and those
libraries; "cipher", each file whose bytes hold a CIPHER_NAMES or SPELT name and its references to each
(cipher_sites); "sha256", each of those files' SHA-256; "unread", each ELF file objdump failed on; and, for an initrd, "others", its executable
members that are not ELF files. Only symbols bound to a GLIBC_ version count, so a library's own re_*
names do not.

--summary exits 1 when a claim the glibc records rest on stops holding: any file, in any place, imports
or reaches a wide scanf function, or imports or reaches a regex function and matches no glob in ALLOW
(each a file the image -100290 record names); a glob that matches nothing also fails, so the list
stays the record's. It also exits 1 when a file holding a selector name or a SPELT name matches no [cipher]
entry of ALLOW or more than one, or holds other sites or other bytes (SHA-256) than the counted entry it
matches, or an entry matches nothing; and on an ALLOW it cannot read (read_allow). The
control is the scan itself: it also exits 1 when objdump failed on a file,
the main tree or an initrd with executable members read no ELF file, the main tree has no importer
of regcomp (bash and grep always import it), or no call site of EVP_CIPHER_fetch (libcryptsetup and
libcrypto always hold one), so a clean result is not a scan that read nothing.
"""
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import stat
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
GROUPS = {
    "regex": re.compile(r"(regcomp|regexec|re_\w+|rpmatch|step|advance)$"),
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


def group_of(sym):
    return next((g for g, rx in GROUPS.items() if rx.match(sym)), None)


def read_elf(path):
    """(affected glibc symbols imported, NEEDED names, SONAME or None, read) of the ELF file at PATH. READ is
    False when objdump fails on it for any reason but its having no dynamic section (a static or
    relocatable file, which imports nothing), so a file objdump cannot parse is never counted clean."""
    r = subprocess.run(["objdump", "-pT", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, errors="replace")
    out = r.stdout
    read = r.returncode == 0 or "not a dynamic object" in r.stderr
    syms, needed, soname = set(), [], None
    for line in out.splitlines():
        m = UND.search(line)
        if m and group_of(m.group(2)):
            syms.add(m.group(2))
        m = DYNAMIC.match(line)
        if m and m.group(1) == "NEEDED":
            needed.append(m.group(2))
        elif m:
            soname = m.group(2)
    return sorted(syms), needed, soname, read


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


def sweep(files):
    """FILES maps a shown path to a readable path. Returns the place's record (module docstring)."""
    imports, needed, by_name, unread, cipher, digest = {}, {}, {}, [], {}, {}
    for shown, real in files.items():
        syms, needed[shown], soname, read = read_elf(real)
        sites, disassembled = cipher_sites(real)
        if sites is not None:
            cipher[shown] = sites
            with open(real, "rb") as f:
                digest[shown] = hashlib.sha256(f.read()).hexdigest()
        if not (read and disassembled):
            unread.append(shown)
        if syms:
            imports[shown] = syms
        # A NEEDED entry names a library's SONAME, which on disk is a symbolic link to the file read.
        for n in {os.path.basename(shown), soname} - {None}:
            by_name.setdefault(n, []).append(shown)
    importers = set(imports)
    via = {}
    for shown in needed:
        seen, todo, hits = set(), list(needed[shown]), set()
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            for lib in by_name.get(n, []):
                if lib in importers and lib != shown:
                    hits.add(lib)
                todo += needed.get(lib, [])
        if hits and shown not in importers:
            via[shown] = sorted(hits)
    return {"scanned": len(files), "imports": dict(sorted(imports.items())), "via": dict(sorted(via.items())),
            "unread": sorted(unread), "cipher": dict(sorted(cipher.items())),
            "sha256": dict(sorted(digest.items()))}


def tree_files(top, prefix="/", skip=()):
    """Every regular ELF file under TOP (symbolic links not followed), as {prefix + relative path: path}."""
    files = {}
    for d, dirs, names in os.walk(top):
        rel = os.path.relpath(d, top)
        if rel == ".":
            dirs[:] = [x for x in dirs if x not in skip]
        for n in names:
            p = os.path.join(d, n)
            if stat.S_ISREG(os.lstat(p).st_mode) and is_elf(p):
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
    for p in sorted(x for x in initrds.rglob("*") if x.is_file()):
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
    return errs


def reach(places):
    """{(group, path): [places]} of every file that imports or reaches a function of the group."""
    out = {}
    for place, v in places.items():
        for p, syms in v["imports"].items():
            for g in {group_of(x) for x in syms}:
                out.setdefault((g, p), []).append(place)
        for p, libs in v["via"].items():
            for g in {group_of(x) for lib in libs for x in v["imports"].get(lib, [])}:
                out.setdefault((g, p), []).append(place)
    return out


def load_allow(path):
    """The regex globs of ALLOW: one per line, after any '#' comment, up to a [cipher] line."""
    return read_allow(path)[0]


# A [cipher] entry's tokens: the SHA-256 of the file reviewed, and each site count.
DIGEST = re.compile(r"^sha256=([0-9a-f]{64})$")
COUNT = re.compile(r"^([A-Za-z_][\w-]*)=([0-9]+)$")
FORMAT = "GLOB sha256=HEX NAME=COUNT ... (NAME from CIPHER_NAMES or SPELT) or GLOB *"
# What every [cipher] refusal asks for, as the allow file's header does.
REVIEW = ("review where its names come from, then update the [cipher] entry and the openssl records' "
          "reach note in assurance/vulncheck.json")


def read_allow(path):
    """(the regex globs, the [cipher] entries) of ALLOW. A [cipher] entry is a glob, then either "*" (not
    counted) or the SHA-256 of the file reviewed and the sites it holds exactly (FORMAT), read as
    {"sha256": hex, "sites": {name: count}}: a new package version changes the bytes, so the source is
    read again even when the counts hold (#5861). Exits naming the line on any other entry, a glob given
    twice, or a name or the digest given twice in one entry."""
    regex, cipher, section = [], {}, None
    for n, l in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        l = l.split("#", 1)[0].strip()

        def bad(why):
            sys.exit("import sweep: %s:%d: %s; a [cipher] entry is %s" % (path, n, why, FORMAT))
        if l == "[cipher]":
            section = "cipher"
        elif l and section is None:
            regex.append(l)
        elif l:
            glob, *want = l.split()
            if glob in cipher:
                bad("%s has an entry already" % glob)
            if want == ["*"]:
                cipher[glob] = "*"
                continue
            if not want or "*" in want:
                bad("%s names %s" % (glob, "nothing" if not want else "'*' with other tokens"))
            digests = [w[len("sha256="):] for w in want if DIGEST.match(w)]
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
    return regex, cipher


def entry_line(p, sha, sites):
    return " ".join([p, "sha256=" + (sha or "?")] + ["%s=%d" % kv for kv in sorted(sites.items())])


def cipher_refusals(places, entries):
    """Each file of PLACES holding a selector name or a SPELT name that matches no [cipher] entry or more
    than one, or whose sites or SHA-256 differ from the counted entry it matches; and each entry matching
    no such file."""
    errs, used = [], set()
    for place, v in places.items():
        for p, sites in v.get("cipher", {}).items():
            hit = [g for g in entries if fnmatch.fnmatchcase(p, g)]
            used.update(hit)
            sha = v.get("sha256", {}).get(p)
            got = " ".join("%s=%d" % kv for kv in sorted(sites.items()))
            if not hit:
                errs.append("%s: %s holds a by-name cipher selector or spells %s (%s) and is not in "
                            "import_sweep.allow [cipher]; %s, adding: %s"
                            % (place, p, " or ".join(SPELT), got, REVIEW, entry_line(p, sha, sites)))
            elif len(hit) > 1:
                errs.append("%s: %s matches %d [cipher] entries (%s); keep one, so no entry hides another's "
                            "review" % (place, p, len(hit), " ".join(hit)))
            elif entries[hit[0]] != "*" and entries[hit[0]] != {"sha256": sha, "sites": sites}:
                want = entries[hit[0]]
                what = ["cipher references %s, not the %s reviewed" % (got, " ".join(
                    "%s=%d" % kv for kv in sorted(want["sites"].items())))] if want["sites"] != sites else []
                what += ["other bytes (a new version?) than the ones reviewed"] if want["sha256"] != sha else []
                errs.append("%s: %s holds %s; %s, as: %s" % (place, p, " and ".join(what), REVIEW,
                                                             entry_line(hit[0], sha, sites)))
    errs += ["import_sweep.allow: [cipher] %s matches no file holding a selector name or spelling %s; remove it"
             % (g, " or ".join(SPELT)) for g in entries if g not in used]
    return errs


def refusals(places, allow):
    """Each claim of the glibc records that PLACES break, against the regex globs ALLOW."""
    errs, used = [], set()
    for (g, p), where in sorted(reach(places).items()):
        if g == "wscanf":
            errs.append("%s: %s imports or reaches a wide scanf function; the -115819 records say nothing does"
                        % (" ".join(where), p))
            continue
        hit = [a for a in allow if fnmatch.fnmatchcase(p, a)]
        used.update(hit)
        if not hit:
            errs.append("%s: %s imports or reaches a regex function and is not in import_sweep.allow; review it, "
                        "name it in the image -100290 record, then add the entry: %s" % (" ".join(where), p, p))
    errs += ["import_sweep.allow: %s matches no file that reaches a regex function; remove it" % a
             for a in allow if a not in used]
    return errs


def summary(places):
    lines = []
    for place, v in places.items():
        lines.append("%s: %d ELF files read" % (place, v["scanned"]))
        for g in GROUPS:
            imp = {p: [s for s in syms if group_of(s) == g] for p, syms in v["imports"].items()}
            imp = {p: s for p, s in imp.items() if s}
            via = {p: [lib for lib in libs if lib in imp] for p, libs in v["via"].items()}
            via = {p: libs for p, libs in via.items() if libs}
            lines.append("%s %s: %d files import a function, %d more reach an importing library through NEEDED"
                         % (place, g, len(imp), len(via)))
            lines += ["  imports %s: %s" % (p, " ".join(s)) for p, s in imp.items()]
            lines += ["  via %s: %s" % (p, " ".join(libs)) for p, libs in via.items()]
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
        regex, cipher = read_allow(argv[2] if len(argv) == 3 else ALLOW)
        errs = problems(places) + refusals(places, regex) + cipher_refusals(places, cipher)
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
