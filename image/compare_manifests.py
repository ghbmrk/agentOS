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
                                             in which field, time and link count differences last,
                                             #4059)
       compare_manifests.py --release DIR_A DIR_B   (the rest of the reproduce job's check, IMG-2:
                                             the /usr lists, then the /usr root hash, boot entry
                                             and every boot file of the two release records, a
                                             differing initrd member by member; exit 0 only when
                                             all match)
Every line it prints goes through say(), and every name or value read from a build through
shown(), so a build's output can never forge a log line (#4612, #4648)."""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import finish_image  # noqa: E402  the initrd reader the build's Bluetooth check uses

# A newc header's 13 fields after the magic, as cpio(5) names them; "check" is always 0 in newc.
NEWC_FIELDS = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize", "devmajor", "devminor",
               "rdevmajor", "rdevminor", "namesize", "check")


def shown(v):
    """V as one JSON token: a name or value read from a build prints quoted, with every control
    and non-ASCII character escaped, so it can never end a log line, start a forged one or an
    Actions workflow command (::...), or move the terminal (#4612)."""
    return json.dumps(v)


def say(line):
    """Print LINE: the only way this script writes to the log. Callers build each line from fixed
    text and shown() values, so it is printable ASCII; a line that is not (a value that missed
    shown()) still prints as one quoted line, never as two or as a workflow command (#4648)."""
    print(line if line.isascii() and line.isprintable() else shown(line))


def why(e):
    """E's reason, without the file name an OSError carries raw: the caller names the file."""
    return e.strerror if isinstance(e, OSError) and e.strerror else str(e)


def one(d, pattern):
    """The one file in directory D matching PATTERN. Raises ValueError on none or several."""
    found = sorted(pathlib.Path(d).glob(pattern))
    if len(found) != 1:
        raise ValueError("%s: expected one %s, found %d" % (shown(str(d)), pattern, len(found)))
    return found[0]


def read_json(path, what):
    """PATH parsed as JSON. Raises ValueError naming WHAT on a missing or malformed file."""
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("%s: unreadable %s: %s" % (shown(str(path)), what, why(e)))


def packages(d):
    """The (name, version, architecture) of every package in D's one manifest. Raises ValueError."""
    found = one(d, "*.manifest")
    m = read_json(found, "manifest")
    pkgs = m.get("packages") if isinstance(m, dict) else None
    if not isinstance(pkgs, list) or not pkgs:
        raise ValueError("%s: manifest lists no packages" % shown(str(found)))
    out = []
    for p in pkgs:
        if not isinstance(p, dict) or not p.get("name") or not p.get("version"):
            raise ValueError("%s: package entry without a name and version: %s" % (shown(str(found)), shown(p)))
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
                    raise ValueError("initrd: truncated cpio file %s" % shown(name))
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
    lines = ["only in a: %s" % shown(k) for k in da if k not in db]
    lines += ["only in b: %s" % shown(k) for k in db if k not in da]
    for k, (ha, ca) in da.items():
        if k not in db:
            continue
        hb, cb = db[k]
        what = ["%s %s/%s" % (f, ha[f], hb[f]) for f in ha if ha[f] != hb[f]]
        if ca != cb:
            what.append("content")
        if what:
            lines.append("%s: %s" % (shown(k), ", ".join(what)))
    if not lines and [k for k, _, _ in ma] != [k for k, _, _ in mb]:
        lines.append("same members in a different order")
    if len(lines) > limit:
        lines = lines[:limit] + ["... and %d more" % (len(lines) - limit)]
    return lines


def compare_initrds(fa, fb):
    """0 when initrd files FA and FB are the same bytes. Otherwise prints what differs, member by
    member, and returns 1, so the reproduce job fails and names the file to fix (IMG-2)."""
    try:
        a = pathlib.Path(fa).read_bytes()
        b = pathlib.Path(fb).read_bytes()
    except OSError as e:
        say("MISMATCH initrd: cannot read %s: %s" % (shown(str(e.filename)), why(e)))
        return 1
    if a == b:
        say("same initrd %s" % shown(pathlib.Path(fa).name))
        return 0
    say("MISMATCH initrd a=%s b=%s" % (hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()))
    try:
        lines = initrd_diff(a, b)
    except (ValueError, subprocess.CalledProcessError) as e:
        say("  unreadable initrd: %s" % e)
        return 1
    for ln in lines or ["every member alike: the compressed bytes differ"]:
        say("  " + ln)
    return 1


def usr_entries(path):
    """{path: fields} of a /usr list file. Raises ValueError on a missing, empty or malformed one."""
    fields = finish_image.USR_LIST_FIELDS
    try:
        text = pathlib.Path(path).read_text()
        rows = [json.loads(ln) for ln in text.splitlines()]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("%s: unreadable /usr list: %s" % (shown(str(path)), why(e)))
    if not rows:
        raise ValueError("%s: empty /usr list" % shown(str(path)))
    out = {}
    for r in rows:
        if not isinstance(r, list) or len(r) != len(fields) or not isinstance(r[0], str) or r[0] in out:
            raise ValueError("%s: bad /usr list line %s" % (shown(str(path)), shown(r)))
        out[r[0]] = dict(zip(fields[1:], r[1:]))
    return out


# The fields that only say when a path was written and how many names it has. A difference in any
# other field (what the path holds, its mode or its owner) is printed before these.
USR_META_FIELDS = ("mtime_ns", "nlink")


def usr_diff(a, b, limit=200):
    """Lines naming each path whose entry differs between /usr lists A and B ({path: fields}), and
    in which fields (their two values). Paths only one side has and differences in content, mode or
    owner come first, so many time-only differences past LIMIT never hide a changed file (#4471).
    Empty when every entry is alike."""
    lines = ["only in a: %s" % shown(k) for k in sorted(a) if k not in b]
    lines += ["only in b: %s" % shown(k) for k in sorted(b) if k not in a]
    meta = []
    for k in sorted(a):
        if k in b and a[k] != b[k]:
            fs = [f for f in a[k] if a[k][f] != b[k][f]]
            line = "%s: %s" % (shown(k), ", ".join("%s %s/%s" % (f, shown(a[k][f]), shown(b[k][f]))
                                                    for f in fs))
            (meta if all(f in USR_META_FIELDS for f in fs) else lines).append(line)
    lines += meta
    if len(lines) > limit:
        lines = lines[:limit] + ["... and %d more" % (len(lines) - limit)]
    return lines


def compare_usr(fa, fb):
    """0 when /usr list files FA and FB list the same entries alike. Otherwise prints each entry
    that differs and returns 1, so the reproduce job names the /usr file to fix (#4059)."""
    try:
        a, b = usr_entries(fa), usr_entries(fb)
    except ValueError as e:
        say("MISMATCH /usr list: %s" % e)
        return 1
    lines = usr_diff(a, b)
    if not lines:
        say("same /usr files (%d entries)" % len(a))
        return 0
    say("MISMATCH /usr files a=%d b=%d entries" % (len(a), len(b)))
    for ln in lines:
        say("  " + ln)
    return 1


def main(a, b):
    try:
        pa, pb = packages(a), packages(b)
    except ValueError as e:
        say("MISMATCH package manifest: %s" % e)
        return 1
    say("packages a=%d b=%d" % (len(pa), len(pb)))
    if pa == pb:
        say("same packages")
    else:
        sa, sb = set(pa), set(pb)
        say("package manifests differ: only in a %s; only in b %s"
            % (shown(sorted(sa - sb)), shown(sorted(sb - sa))))
    return 0


# A release record's boot file name: a relative path of plain segments, so the name cannot leave
# the build's initrd directory when it is joined to it.
BOOT_NAME = re.compile(r"[A-Za-z0-9_+-][A-Za-z0-9._+-]*(/[A-Za-z0-9_+-][A-Za-z0-9._+-]*)*\Z")


def digest(v):
    """V when it is a non-empty string (a hash a release record holds), else None: a missing or
    null value on both sides never reads as the same (#4648)."""
    return v if isinstance(v, str) and v else None


def release(d):
    """D's one release record (*.release.json). Raises ValueError unless it holds a boot map."""
    path = one(d, "*.release.json")
    r = read_json(path, "release record")
    if not isinstance(r, dict) or not isinstance(r.get("boot"), dict):
        raise ValueError("%s: release record without a boot map" % shown(str(path)))
    return r


def compare_release(da, db):
    """0 when build directories DA and DB (the release-a and release-b artifacts) hold the same
    release (IMG-2): the same /usr files, /usr root hash and boot entry, and every boot file named
    in either record with the same hash. Otherwise prints each difference, an initrd's member by
    member, and returns 1. Prints whether the outputs (SHA256SUMS) match, without failing on it."""
    ok = True
    try:
        ra, rb = release(da), release(db)
    except ValueError as e:
        say("MISMATCH release record: %s" % e)
        ra = rb = None
        ok = False
    if ra is not None:
        say("usrhash a=%s" % shown(ra.get("usrhash")))
        say("usrhash b=%s" % shown(rb.get("usrhash")))
    try:
        sa, sb = [(pathlib.Path(d) / "SHA256SUMS").read_text().splitlines() for d in (da, db)]
    except (OSError, UnicodeDecodeError) as e:
        say("SHA256SUMS unreadable: %s" % why(e))
    else:
        if sa == sb:
            say("every output identical")
        else:
            say("outputs differ (SHA256SUMS):")
            for ln in sorted(set(sa) - set(sb)):
                say("  only in a: %s" % shown(ln))
            for ln in sorted(set(sb) - set(sa)):
                say("  only in b: %s" % shown(ln))
    # Every /usr file's hash and metadata (#4059): a differing file is named here.
    try:
        usr_ok = compare_usr(one(da, "*.usr.list"), one(db, "*.usr.list")) == 0
    except ValueError as e:
        say("MISMATCH /usr list: %s" % e)
        usr_ok = False
    ok = usr_ok and ok
    if ra is None:
        return 1
    if not (digest(ra.get("usrhash")) and ra.get("usrhash") == rb.get("usrhash")):
        say("MISMATCH /usr root hash")
        ok = False
        if usr_ok:
            say("  every /usr file alike: the erofs layout or an extended attribute differs, not a"
                " file's content or metadata")
    ea, eb = (r.get("boot_entry") if isinstance(r.get("boot_entry"), dict) else {} for r in (ra, rb))
    if digest(ea.get("sha256")) and ea.get("sha256") == eb.get("sha256"):
        say("same boot entry")
    else:
        say("MISMATCH boot entry")
        ok = False
    ba, bb = ra["boot"], rb["boot"]
    for k in sorted(set(ba) | set(bb)):
        if not BOOT_NAME.match(k):
            say("MISMATCH boot file name %s: not a relative path of plain names" % shown(k))
            ok = False
        elif digest(ba.get(k)) and ba.get(k) == bb.get(k):
            say("same %s" % shown(k))
        else:
            say("MISMATCH %s" % shown(k))
            ok = False
            if k.endswith("initrd"):
                compare_initrds(pathlib.Path(da) / "initrd" / k, pathlib.Path(db) / "initrd" / k)
    if len(ba) < 2:
        say("MISMATCH release.json lists no kernel and initrd")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--release":
        sys.exit(compare_release(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 4 and sys.argv[1] == "--initrd":
        sys.exit(compare_initrds(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 4 and sys.argv[1] == "--usr":
        sys.exit(compare_usr(sys.argv[2], sys.argv[3]))
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
