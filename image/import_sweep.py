#!/usr/bin/env python3
"""Which ELF files in a built image import glibc's POSIX regex or wide scanf functions (#5697, EVL-5).

The image's glibc records (assurance/vulncheck.json, DEBIAN-CVE-2026-100290 and -115819) accept the
advisories on the grounds that no long-lived or network-facing process calls the affected functions.
This reads that from the tree CI builds, not from another distribution's builds: every ELF file's
dynamic imports (objdump -pT), in the main tree (the root partition and the verified /usr) and in each
initrd of the boot entry (OUT/initrd/, every cpio member).

  import_sweep.py OUT VERSION     the build in OUT (as root: offline_systemd.built_tree mounts it)
  import_sweep.py --tree DIR      a plain directory, read as a main tree
  import_sweep.py --summary FILE  the JSON the two forms print, as lines and as ::notice annotations

The JSON maps each place ("tree", and "initrd:<path>" for each initrd) to: "scanned", the ELF files
read; "imports", each file importing an affected glibc symbol and those symbols; and "via", each other
ELF file whose NEEDED closure (by file name, within that place) holds an importing library, and those
libraries. Only symbols bound to a GLIBC_ version count, so a library's own re_* names do not.

The control is the scan itself: it exits 1 when the main tree or every initrd read no ELF file, or the
main tree has no importer of regcomp (bash and grep always import it), so a clean result is not a scan that read nothing.
"""
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# DEBIAN-CVE-2026-100290 (regcomp/regexec and the GNU re_* interface over the same engine) and
# DEBIAN-CVE-2026-115819 (the wide scanf family, with the C99/C23 aliases glibc's headers bind them to).
GROUPS = {
    "regex": re.compile(r"(regcomp|regexec|re_\w+)$"),
    "wscanf": re.compile(r"(__isoc(99|23)_)?v?(sw|fw|w)scanf$"),
}
UND = re.compile(r"\*UND\*\s+\S+\s+(?:Base\s+)?\((GLIBC_[^)]*)\)\s+(\S+)$")
NEEDED = re.compile(r"^\s+NEEDED\s+(\S+)$")


def group_of(sym):
    return next((g for g, rx in GROUPS.items() if rx.match(sym)), None)


def read_elf(path):
    """(affected glibc symbols imported, NEEDED names) of the ELF file at PATH."""
    out = subprocess.run(["objdump", "-pT", str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         text=True, errors="replace").stdout
    syms, needed = set(), []
    for line in out.splitlines():
        m = UND.search(line)
        if m and group_of(m.group(2)):
            syms.add(m.group(2))
        m = NEEDED.match(line)
        if m:
            needed.append(m.group(1))
    return sorted(syms), needed


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def sweep(files):
    """FILES maps a shown path to a readable path. Returns the place's record (module docstring)."""
    imports, needed = {}, {}
    for shown, real in files.items():
        syms, needed[shown] = read_elf(real)
        if syms:
            imports[shown] = syms
    by_name = {}
    for shown in needed:
        by_name.setdefault(os.path.basename(shown), []).append(shown)
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
    return {"scanned": len(files), "imports": dict(sorted(imports.items())), "via": dict(sorted(via.items()))}


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
    files = {}
    for i, (name, mode, body, _link) in enumerate(finish_image.cpio_members(pathlib.Path(path).read_bytes())):
        if stat.S_ISREG(mode) and body[:4] == b"\x7fELF":
            f = os.path.join(scratch, "%d" % i)
            pathlib.Path(f).write_bytes(body)
            files["/" + name.lstrip("/")] = f
    return sweep(files)


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
    # An initrd of only kernel modules (compressed .ko files) holds no ELF file, so the initrds count
    # together: some initrd must hold one.
    initrds = [v["scanned"] for k, v in places.items() if k.startswith("initrd:")]
    errs = [] if places.get("tree", {}).get("scanned") else ["tree: no ELF file read"]
    if initrds and not any(initrds):
        errs.append("initrd: no ELF file read in any initrd")
    if "regcomp" not in {s for syms in places.get("tree", {}).get("imports", {}).values() for s in syms}:
        errs.append("tree: no file imports regcomp, so the scan read nothing it should have (control)")
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
            lines.append("%s %s: %d import, %d reach one through NEEDED" % (place, g, len(imp), len(via)))
            lines += ["  imports %s: %s" % (p, " ".join(s)) for p, s in imp.items()]
            lines += ["  via %s: %s" % (p, " ".join(libs)) for p, libs in via.items()]
    return lines


def annotations(lines, size=3500):
    chunks, cur = [], ""
    for line in lines:
        if cur and len(cur) + len(line) + 1 > size:
            chunks.append(cur)
            cur = ""
        cur += line[:size] + "\n"
    chunks += [cur] if cur else []
    return ["::notice title=import sweep %d/%d::%s" % (i + 1, len(chunks), c.rstrip("\n").replace("%", "%25")
            .replace("\r", "%0D").replace("\n", "%0A")) for i, c in enumerate(chunks)]


def main(argv):
    if len(argv) == 2 and argv[0] == "--summary":
        places = json.loads(pathlib.Path(argv[1]).read_text())
        lines = summary(places)
        print("\n".join(lines + annotations(lines)))
        errs = problems(places)
    elif len(argv) == 2 and argv[0] == "--tree":
        places = run_tree(argv[1])
        json.dump(places, sys.stdout, indent=1, sort_keys=True)
        errs = []
    elif len(argv) == 2:
        places = run_build(*argv)
        json.dump(places, sys.stdout, indent=1, sort_keys=True)
        errs = problems(places)
    else:
        sys.exit(__doc__)
    for e in errs:
        print("import sweep: " + e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
