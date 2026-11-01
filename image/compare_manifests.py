#!/usr/bin/env python3
"""Compare the package manifests of two builds of one commit (the image workflow's reproduce job).

Each directory must hold exactly one mkosi JSON manifest (*.manifest) that parses and lists at
least one package, each with a name and a version; otherwise this exits non-zero, so a missing,
empty or truncated manifest can never read as "same packages" (#1474). It prints each side's
package count, then whether the package lists match. A difference is reported, not fatal: the /usr
root hash comparison already fails on any content difference.
Usage: compare_manifests.py DIR_A DIR_B
       compare_manifests.py --initrd FILE_A FILE_B   (exit 0 only when the two initrds are the
                                             same bytes; otherwise print every cpio member that
                                             differs and how, so a runner-to-runner difference
                                             names its file, IMG-2)
       compare_manifests.py --usr LIST_A LIST_B   (exit 0 only when the two builds' /usr lists,
                                             finish_image.py's agentos_VERSION.usr.list, are
                                             alike; otherwise print each path that differs and
                                             in which field, #4059)"""
import hashlib
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import finish_image  # noqa: E402  the initrd reader the build's Bluetooth check uses

# A newc header's 13 fields after the magic, as cpio(5) names them; "check" is always 0 in newc.
NEWC_FIELDS = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize", "devmajor", "devminor",
               "rdevmajor", "rdevminor", "namesize", "check")


def packages(d):
    """The (name, version, architecture) of every package in D's one manifest. Raises ValueError."""
    found = sorted(pathlib.Path(d).glob("*.manifest"))
    if len(found) != 1:
        raise ValueError("%s: expected one *.manifest, found %d" % (d, len(found)))
    try:
        m = json.loads(found[0].read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("%s: unreadable manifest: %s" % (found[0], e))
    pkgs = m.get("packages") if isinstance(m, dict) else None
    if not isinstance(pkgs, list) or not pkgs:
        raise ValueError("%s: manifest lists no packages" % found[0])
    out = []
    for p in pkgs:
        if not isinstance(p, dict) or not p.get("name") or not p.get("version"):
            raise ValueError("%s: package entry without a name and version: %r" % (found[0], p))
        out.append((p["name"], p["version"], p.get("architecture", "")))
    return sorted(out)


def initrd_members(data):
    """Every member of an initrd, in order, as (name, header fields, sha256 of the body): newc cpio
    archives and compressed streams of them back to back, read as finish_image.cpio_names reads
    them. A name that repeats (an early and a main archive) gets a #N suffix. Raises ValueError."""
    out, seen = [], {}

    def walk(data):
        off = 0
        while True:
            while off < len(data) and data[off] == 0:
                off += 1
            if off >= len(data):
                return
            fn = next((fn for magic, fn in ((finish_image.ZSTD, finish_image.unzstd),
                                            (finish_image.XZ, finish_image.unxz),
                                            (finish_image.GZIP, finish_image.ungzip))
                       if data.startswith(magic, off)), None)
            if fn:
                inner, rest = fn(data[off:])
                walk(inner)
                data, off = rest, 0
                continue
            while True:
                if off + 110 > len(data) or data[off:off + 6] not in finish_image.CPIO_MAGICS:
                    raise ValueError("initrd: bad cpio header at offset %d" % off)
                try:
                    hdr = dict(zip(NEWC_FIELDS, (int(data[off + 6 + 8 * i:off + 14 + 8 * i], 16)
                                                 for i in range(13))))
                except ValueError:
                    raise ValueError("initrd: bad cpio header at offset %d" % off)
                end = off + 110 + hdr["namesize"]
                if hdr["namesize"] < 1 or end > len(data):
                    raise ValueError("initrd: truncated cpio name at offset %d" % off)
                name = data[off + 110:end - 1].decode("utf-8", "surrogateescape")
                off = (end + 3) & ~3
                if off + hdr["filesize"] > len(data):
                    raise ValueError("initrd: truncated cpio file %s" % name)
                body = data[off:off + hdr["filesize"]]
                off = (off + hdr["filesize"] + 3) & ~3
                if name == "TRAILER!!!":
                    break
                name = name[2:] if name.startswith("./") else name
                seen[name] = seen.get(name, 0) + 1
                key = name if seen[name] == 1 else "%s#%d" % (name, seen[name])
                del hdr["namesize"], hdr["check"]
                out.append((key, hdr, hashlib.sha256(body).hexdigest()))

    walk(data)
    return out


def initrd_diff(a, b, limit=200):
    """Lines naming each member that differs between initrd bytes A and B, and in what: a header
    field (its two values) or the content. Empty when A and B hold the same members alike."""
    ma, mb = initrd_members(a), initrd_members(b)
    da, db = {k: (h, c) for k, h, c in ma}, {k: (h, c) for k, h, c in mb}
    lines = ["only in a: %s" % k for k in da if k not in db]
    lines += ["only in b: %s" % k for k in db if k not in da]
    for k, (ha, ca) in da.items():
        if k not in db:
            continue
        hb, cb = db[k]
        what = ["%s %s/%s" % (f, ha[f], hb[f]) for f in ha if ha[f] != hb[f]]
        if ca != cb:
            what.append("content")
        if what:
            lines.append("%s: %s" % (k, ", ".join(what)))
    if not lines and [k for k, _, _ in ma] != [k for k, _, _ in mb]:
        lines.append("same members in a different order")
    if len(lines) > limit:
        lines = lines[:limit] + ["... and %d more" % (len(lines) - limit)]
    return lines


def compare_initrds(fa, fb):
    """0 when initrd files FA and FB are the same bytes. Otherwise prints what differs, member by
    member, and returns 1, so the reproduce job fails and names the file to fix (IMG-2)."""
    try:
        a, b = pathlib.Path(fa).read_bytes(), pathlib.Path(fb).read_bytes()
    except OSError as e:
        print("MISMATCH initrd: %s" % e)
        return 1
    if a == b:
        print("same initrd %s" % pathlib.Path(fa).name)
        return 0
    print("MISMATCH initrd a=%s b=%s" % (hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()))
    try:
        lines = initrd_diff(a, b)
    except (ValueError, subprocess.CalledProcessError) as e:
        print("  unreadable initrd: %s" % e)
        return 1
    for ln in lines or ["every member alike: the compressed bytes differ"]:
        print("  " + ln)
    return 1


def usr_entries(path):
    """{path: fields} of a /usr list file. Raises ValueError on a missing, empty or malformed one."""
    fields = finish_image.USR_LIST_FIELDS
    try:
        text = pathlib.Path(path).read_text()
        rows = [json.loads(ln) for ln in text.splitlines()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("%s: unreadable /usr list: %s" % (path, e))
    if not rows:
        raise ValueError("%s: empty /usr list" % path)
    out = {}
    for r in rows:
        if not isinstance(r, list) or len(r) != len(fields) or not isinstance(r[0], str) or r[0] in out:
            raise ValueError("%s: bad /usr list line %r" % (path, r))
        out[r[0]] = dict(zip(fields[1:], r[1:]))
    return out


def usr_diff(a, b, limit=200):
    """Lines naming each path whose entry differs between /usr lists A and B ({path: fields}), and
    in which fields (their two values). Empty when every entry is alike."""
    lines = ["only in a: %s" % k for k in sorted(a) if k not in b]
    lines += ["only in b: %s" % k for k in sorted(b) if k not in a]
    for k in sorted(a):
        if k in b and a[k] != b[k]:
            lines.append("%s: %s" % (k, ", ".join("%s %s/%s" % (f, a[k][f], b[k][f]) for f in a[k] if a[k][f] != b[k][f])))
    if len(lines) > limit:
        lines = lines[:limit] + ["... and %d more" % (len(lines) - limit)]
    return lines


def compare_usr(fa, fb):
    """0 when /usr list files FA and FB list the same entries alike. Otherwise prints each entry
    that differs and returns 1, so the reproduce job names the /usr file to fix (#4059)."""
    try:
        a, b = usr_entries(fa), usr_entries(fb)
    except ValueError as e:
        print("MISMATCH /usr list: %s" % e)
        return 1
    lines = usr_diff(a, b)
    if not lines:
        print("same /usr files (%d entries)" % len(a))
        return 0
    print("MISMATCH /usr files a=%d b=%d entries" % (len(a), len(b)))
    for ln in lines:
        print("  " + ln)
    return 1


def main(a, b):
    try:
        pa, pb = packages(a), packages(b)
    except ValueError as e:
        print("MISMATCH package manifest: %s" % e)
        return 1
    print("packages a=%d b=%d" % (len(pa), len(pb)))
    if pa == pb:
        print("same packages")
    else:
        sa, sb = set(pa), set(pb)
        print("package manifests differ: only in a %s; only in b %s" % (sorted(sa - sb), sorted(sb - sa)))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--initrd":
        sys.exit(compare_initrds(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 4 and sys.argv[1] == "--usr":
        sys.exit(compare_usr(sys.argv[2], sys.argv[3]))
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
