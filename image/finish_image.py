#!/usr/bin/env python3
"""Finish a built AgentOS image: one counted boot entry, and the release manifest (UPD-1, UPD-1a).

mkosi writes one boot entry named after the kernel. This replaces it, inside the image's ESP,
with agentos_VERSION+3.conf: systemd-boot counts down the 3 tries on each unblessed boot and
falls back once they run out, and systemd-bless-boot drops the counter after agentos-health
passes (boot-complete.target). The entry's usrhash= names the /usr verity root hash, so the
entry and the /usr partitions are one release: the build verifies the split /usr partition and
its hash tree against that hash with veritysetup, and the manifest records both.
Uses mtools on the raw image, so no loop devices or mounts are needed. Before mkosi runs, it also
stages the build's device drivers into the image tree (DEVSLOT-image), and the manifest carries
their list. Beside the release it writes agentos_VERSION.usr.list, every /usr file's hash and
metadata read back from the verified partition with fsck.erofs (#4059), so two builds whose /usr
root hashes differ name the differing file.
Usage: finish_image.py OUTDIR VERSION [DRIVERS_JSON]; finish_image.py --stage-drivers DRIVERS STAGE CHECKER"""
import errno
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
# Linux swap (IMG-nodump): the broker's memory holds the Owner Card passphrase (card C13).
SWAP_GUID = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"
# The x86-64 root (30-root.conf, Type=root). agentosd caps each machine's disk with project quotas
# (RES-4, broker/quota), which need the ext4 quota and project features and the prjquota mount.
ROOT_GUID = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
# The /usr slots (10-usr-a.conf to 13-usr-b-verity.conf): slot A is named agentos_VERSION and
# agentos_VERSION_verity, slot B _empty.
USR_GUID, USR_VERITY_GUID = "8484680c-9521-48c6-9c11-b0720656f69e", "77ff5f63-e7b6-4633-acf4-1565b864c0e6"
EXT4_MAGIC, RO_COMPAT_QUOTA, RO_COMPAT_PROJECT = 0xEF53, 0x0100, 0x2000
TRIES = 3
# No menu: boot the default entry at once (a held key still shows it on a PC with a screen).
# No editor: anyone at the keyboard could otherwise drop usrhash= or add init=/bin/sh (Type #1
# entries are not covered by Secure Boot, HW-5a). Never offer to enroll keys.
LOADER_CONF = "timeout 0\neditor no\nsecure-boot-enroll off\n"
# What the ESP may hold, besides the kernel and initrd the entry names. Anything else (a
# loader/random-seed, a system token) would ship identical on every drive (HW-1).
ESP_ALLOWED = (r"EFI/BOOT/[^/]+", r"EFI/systemd/[^/]+", r"loader/loader\.conf", r"loader/entries\.srel",
               r"loader/entries/agentos_[^/]+\.conf")


def usrhash(entry):
    m = re.search(r"(?:^|\s)usrhash=([0-9a-f]{64})(?:\s|$)", entry, re.M)
    if not m:
        raise ValueError("boot entry has no usrhash=")
    return m.group(1)


def counted_entry(src, version, tries=TRIES):
    """From mkosi's entry text, return (file name, text) of the AgentOS entry for VERSION."""
    usrhash(src)
    body = [ln for ln in src.splitlines() if not re.match(r"(title|version|sort-key)\b", ln)]
    lines = ["title AgentOS", "sort-key agentos", "version %s" % version] + body
    return "agentos_%s+%d.conf" % (version, tries), "\n".join(lines) + "\n"


def boot_files(entry):
    """The ESP paths the entry boots: its linux and initrd lines, without the leading slash."""
    return [ln.split(None, 1)[1].strip().lstrip("/") for ln in entry.splitlines()
            if re.match(r"(linux|initrd)\s", ln)]


def initrd_files(entry):
    """The ESP paths of the entry's initrd lines, without the leading slash."""
    return [ln.split(None, 1)[1].strip().lstrip("/") for ln in entry.splitlines() if re.match(r"initrd\s", ln)]


def esp_violations(paths, entry):
    """ESP files outside the allowlist (HW-1). paths: every file on the ESP, relative."""
    allowed = set(boot_files(entry))
    return sorted(p for p in paths
                  if p not in allowed and not any(re.fullmatch(a, p) for a in ESP_ALLOWED))


def options_line(entry):
    """The entry's kernel command line: systemd-boot joins every options line, indented or not."""
    return " ".join(ln.split(None, 1)[1] for ln in entry.splitlines()
                    if re.match(r"\s*options\s", ln) and len(ln.split(None, 1)) > 1)


def entry_args(entry, name):
    """Every value of the entry's kernel argument NAME=, in order."""
    return re.findall(r"(?:^|\s)%s=(\S*)" % re.escape(name), options_line(entry))


# The command-line credentials the image ships (mkosi.conf): emergency and rescue mode run the
# fallback (I4). Any other credential could carry sysctl.extra or tmpfiles.extra (#1530).
SHIPPED_CREDENTIALS = ("systemd.unit-dropin.emergency.service", "systemd.unit-dropin.rescue.service")
MKOSI_CONF = pathlib.Path(__file__).resolve().parent / "mkosi" / "mkosi.conf"


def config_cmdline(conf=MKOSI_CONF):
    """The words of mkosi.conf's KernelCommandLine= and its indented continuation lines."""
    words, on = [], False
    for ln in pathlib.Path(conf).read_text().splitlines():
        if ln.startswith("KernelCommandLine="):
            on, ln = True, ln.split("=", 1)[1]
        elif not (on and ln[:1].isspace() and ln.strip()):
            on = False
            continue
        words += ln.split()
    return words


def cmdline_words(entry):
    """The entry's kernel command line split as the kernel's next_arg splits it: on whitespace
    outside double quotes. Quotes are dropped from each word, which errs safe: a word is checked
    as the bare text either the kernel or systemd could take from it."""
    return [w.replace('"', "") for w in re.findall(r'(?:[^\s"]|"[^"]*"?)+', options_line(entry))]


def cmdline_violations(entry, conf=MKOSI_CONF):
    """#1530: the command line is an allowlist. mkosi v24.3 writes exactly usrhash=<root hash> and
    mkosi.conf's KernelCommandLine words (finalize_cmdline), so every other word is refused: an
    unknown word reaches PID 1 as an argument or environment variable, and systemd.run=, init= or a
    sysctl.<key>= could turn forwarding on while sysctl.d is clean. Some words are refused even when
    mkosi.conf lists them: sysctl.<key>= and sysctl/<key>= (the kernel writes them at boot, Linux
    5.8+), systemd.run and init (PID 1 runs them), and any credential but the shipped ones, which
    could carry sysctl.extra or tmpfiles.extra. Names are compared as systemd compares them (- and _
    alike, an rd. prefix for the initrd) and case-blind, which errs safe."""
    allowed, out = set(config_cmdline(conf)), []
    for w in cmdline_words(entry):
        key, _, val = w.partition("=")
        k = key.lower().replace("-", "_")
        if k.startswith("rd."):
            k = k[3:]
        if k.startswith(("sysctl.", "sysctl/")):
            out.append("%s: the kernel sets sysctls from the command line" % key)
        elif k.startswith(("systemd.run", "init", "rdinit")):
            out.append("%s: PID 1 would run it" % key)
        elif k in ("systemd.set_credential", "systemd.set_credential_binary") and \
                val.split(":", 1)[0] not in SHIPPED_CREDENTIALS:
            out.append("%s=%s: only the shipped credentials %s may be set"
                       % (key, val.split(":", 1)[0], ", ".join(SHIPPED_CREDENTIALS)))
        elif w not in allowed and not re.fullmatch(r"usrhash=[0-9a-f]{64}", w):
            out.append("%s: not in mkosi.conf's KernelCommandLine; add it there" % w[:80])
    return out


def swap_violations(partitions, entry):
    """No swap on the built disk (IMG-nodump): no partition of the swap type, and the entry turns
    off swap units (its last systemd.swap= is 0). partitions: sfdisk -J's list."""
    out = ["swap partition %s" % p.get("node", "?") for p in partitions if p["type"].lower() == SWAP_GUID]
    vals = entry_args(entry, "systemd.swap")
    if not vals or vals[-1] not in ("0", "no", "false", "off"):
        out.append("boot entry does not set systemd.swap=0")
    return out


def quota_violations(img, table, entry):
    """Project quotas on the built root (RES-4): one ext4 root partition whose superblock has the
    quota and project features and a project quota inode, and an entry whose last rootflags=
    includes prjquota. table: sfdisk -J's partition table."""
    out = []
    roots = [p for p in table["partitions"] if p["type"].lower() == ROOT_GUID]
    if len(roots) != 1:
        out.append("expected one root partition, found %d" % len(roots))
    else:
        with open(img, "rb") as f:
            f.seek(roots[0]["start"] * table.get("sectorsize", 512) + 1024)
            sb = f.read(1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != EXT4_MAGIC:
            out.append("root is not ext4")
        else:
            ro = struct.unpack_from("<I", sb, 0x64)[0]
            if not ro & RO_COMPAT_QUOTA:
                out.append("root ext4 lacks the quota feature")
            if not ro & RO_COMPAT_PROJECT:
                out.append("root ext4 lacks the project feature")
            if not struct.unpack_from("<I", sb, 0x26C)[0]:
                out.append("root ext4 has no project quota inode")
    flags = entry_args(entry, "rootflags")
    if not flags or "prjquota" not in flags[-1].split(","):
        out.append("boot entry does not mount root with rootflags=prjquota")
    return out


def noexec_violations(entry):
    """UPD-10: the entry mounts root noexec. gpt-auto takes the last rootflags=, and of its exec,
    noexec and defaults (which means exec) the last decides, as libmount applies them in order."""
    flags = entry_args(entry, "rootflags")
    last = None
    for o in (flags[-1] if flags else "").split(","):
        if o in ("exec", "noexec", "defaults"):
            last = o
    return [] if last == "noexec" else ["boot entry does not mount root with rootflags=...,noexec"]


# HW-1 on the built disk, not only on the tree mkosi.finalize saw (IMG-1): every byte of the disk
# outside /usr slot A (the partition table, the ESP, root and the empty slot B) holds no private key
# and no Owner Card. Slot A is checked apart (slot_a_violations): its ranges equal the verified split
# files, and the data holds no key but the allowlisted ones (image/ASSUMPTIONS.md IMG-1-1). A hit
# names its kind and offset, never its bytes.
SECRET_PATTERNS = (
    # A PEM or PGP private key with its body: libcrypto and gpg carry the header alone. Its line
    # breaks may be real or JSON-escaped (a literal backslash-n, as provider credential files hold).
    # A line holds no backslash but an escaped slash (\/, which some encoders write), so an escaped
    # break ends it in one place and a match stays linear. The body may be indented by up to 16
    # spaces or tabs (a YAML block scalar, or a JSON value pretty-printed inside a nested object).
    ("private key", re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:\\r)?(?:\\n|\r?\n)"
                               rb"(?:(?:[ -\[\]-~]|\\/){0,128}(?:\\r)?(?:\\n|\r?\n)){0,8}[ \t]{0,16}[A-Za-z0-9+/]{40}")),
    ("age secret key", re.compile(rb"AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}")),
    # The first-boot card record and the card's vault slot (broker/firstboot, broker/recovery):
    # the box makes both on its own drive at first boot (HW-1, D-102).
    ("Owner Card", re.compile(rb"firstboot-card\.json|owner-card")),
)
# Read in chunks; each read runs on by the overlap, longer than any match, so none is cut.
SCAN_CHUNK, SCAN_OVERLAP = 1 << 22, 4096


def data_extents(f, start, end):
    """The (start, end) byte ranges of f between start and end that are not holes."""
    pos = start
    while pos < end:
        try:
            d = os.lseek(f.fileno(), pos, os.SEEK_DATA)
        except OSError as e:
            if e.errno == errno.ENXIO:
                return
            raise
        if d >= end:
            return
        h = min(os.lseek(f.fileno(), d, os.SEEK_HOLE), end)
        yield d, h
        pos = h


def scan_hits(f, start, end, patterns=SECRET_PATTERNS):
    """(kind, offset, matched bytes) for every secret pattern in the data extents of f between
    start and end, read in SCAN_CHUNK pieces that run on by SCAN_OVERLAP."""
    for d, h in data_extents(f, start, end):
        for p in range(d, h, SCAN_CHUNK):
            f.seek(p)
            buf = f.read(min(SCAN_CHUNK + SCAN_OVERLAP, h - p))
            for what, pat in patterns:
                # A match starting in the overlap is the next chunk's.
                for m in pat.finditer(buf):
                    if m.start() < SCAN_CHUNK:
                        yield what, p + m.start(), m.group()


def slot_a_parts(table):
    """The (data, verity) partitions of /usr slot A, or None unless there are exactly those two."""
    a = [p for p in table["partitions"] if p["type"].lower() == USR_GUID and p.get("name") != "_empty"]
    v = [p for p in table["partitions"] if p["type"].lower() == USR_VERITY_GUID and p.get("name") != "_empty"]
    return (a[0], v[0]) if len(a) == 1 and len(v) == 1 else None


def secret_violations(img, table):
    """Every private key or Owner Card on the disk IMG outside /usr slot A. table: sfdisk -J's."""
    ss = table.get("sectorsize", 512)
    parts = slot_a_parts(table)
    skip = sorted((p["start"] * ss, (p["start"] + p["size"]) * ss) for p in parts) if parts else []
    out = []
    if not parts:
        out.append("expected /usr slot A's two partitions; scanned all of them")
    with open(img, "rb") as f:
        size, pos = os.fstat(f.fileno()).st_size, 0
        for a, b in skip + [(size, size)]:
            out += ["%s at byte %d" % (what, off) for what, off, _ in scan_hits(f, pos, a)]
            pos = max(pos, b)
    return out


SLOT_A_ALLOW = pathlib.Path(__file__).resolve().parent / "slot_a_scan.allow"
# Slot A is the box's own packages, so agentosd's binary holds the card's names; only key material
# is looked for there.
SLOT_A_PATTERNS = tuple(p for p in SECRET_PATTERNS if p[0] != "Owner Card")


def slot_a_allowed(path=SLOT_A_ALLOW):
    """The keys known to ship in /usr: lines of 'KIND SHA256 [# why]', the SHA-256 of the matched
    bytes (the header and the start of the body, never the whole key)."""
    out = set()
    for ln in pathlib.Path(path).read_text().splitlines():
        ln = ln.split("#", 1)[0].split()
        if ln:
            out.add((" ".join(ln[:-1]), ln[-1]))
    return out


def slot_a_violations(img, table, data, tree, allowed=None):
    """HW-1 for /usr slot A on the built disk. The disk's slot A ranges must equal the split
    files veritysetup verified (so the usrhash covers every byte the box boots, and the verity
    partition's slack after the hash tree is zero), and the data holds no private key outside the
    allowlist (a key a builder's token copied into /usr/lib/agentos/ would otherwise pass every check:
    the reproduce job builds the same bytes on both runners). A hit names its kind, offset and the
    SHA-256 to allow, never its bytes."""
    allowed = slot_a_allowed() if allowed is None else allowed
    parts = slot_a_parts(table)
    if not parts:
        return ["expected /usr slot A's two partitions"]
    ss, out = table.get("sectorsize", 512), []
    for part, path, scan in ((parts[0], data, True), (parts[1], tree, False)):
        start, size = part["start"] * ss, part["size"] * ss
        n = os.path.getsize(path)
        if n > size:
            out.append("%s (%d bytes) does not fit its %d byte partition" % (os.path.basename(str(path)), n, size))
            continue
        name = os.path.basename(str(path))
        with open(img, "rb", buffering=0) as di, open(path, "rb") as fi:
            same = True
            for p in range(0, n, SCAN_CHUNK):
                fi.seek(p)
                want = fi.read(min(SCAN_CHUNK + SCAN_OVERLAP, n - p))
                di.seek(start + p)
                got = di.read(min(SCAN_CHUNK, n - p))
                if got != want[:len(got)] or len(got) != min(SCAN_CHUNK, n - p):
                    i = next((i for i in range(len(got)) if got[i] != want[i]), len(got))
                    out.append("disk differs from %s at byte %d" % (name, p + i))
                    same = False
                    break
                for what, pat in SLOT_A_PATTERNS if scan else ():
                    for m in pat.finditer(want):
                        digest = hashlib.sha256(m.group()).hexdigest()
                        if m.start() < SCAN_CHUNK and (what, digest) not in allowed:
                            out.append("%s in %s at byte %d, sha256 %s" % (what, name, p + m.start(), digest))
            # The partition past the split file (the slack after a hash tree) holds nothing.
            for d, h in data_extents(di, start + n, start + size) if same else ():
                for p in range(d, h, SCAN_CHUNK):
                    di.seek(p)
                    if di.read(min(SCAN_CHUNK, h - p)).strip(b"\0"):
                        out.append("disk holds data after %s in its partition, from byte %d" % (name, p - start))
                        break
    return out


CPIO_MAGICS = (b"070701", b"070702")
ZSTD, XZ, GZIP = b"\x28\xb5\x2f\xfd", b"\xfd7zXZ\x00", b"\x1f\x8b"


def unzstd(data):
    """All of DATA as zstd frames: the zstd tool fails on anything after the last frame."""
    return subprocess.run(["zstd", "-dcq"], input=data, stdout=subprocess.PIPE, check=True).stdout, b""


def one_stream(d, data, what):
    """Decompress the one stream at the start of DATA with decompressor D: (output, the bytes
    after the stream). The kernel's unpack_to_rootfs reads on after a compressed segment, so the
    rest is checked as well (#1513); lzma.decompress and gzip.decompress would drop it."""
    try:
        out = d.decompress(data)
    except Exception as e:
        raise ValueError("initrd: bad %s stream (%s)" % (what, e))
    if not d.eof:
        raise ValueError("initrd: truncated %s stream" % what)
    return out, d.unused_data


def unxz(data):
    import lzma
    return one_stream(lzma.LZMADecompressor(lzma.FORMAT_XZ), data, "xz")


def ungzip(data):
    import zlib
    return one_stream(zlib.decompressobj(31), data, "gzip")


def cpio_names(data, decompress=None):
    """Every path in an initrd: newc cpio archives and compressed (zstd, xz or gzip) streams of
    them, back to back with zero padding between them, read on as the kernel does. Anything else
    raises ValueError, so an initrd this cannot read fails the build rather than passing unchecked.
    DECOMPRESS maps a magic to a function returning (output, the bytes after the stream)."""
    decompress = decompress or {ZSTD: unzstd, XZ: unxz, GZIP: ungzip}
    names, off = [], 0
    while True:
        while off < len(data) and data[off] == 0:
            off += 1
        if off >= len(data):
            return names
        fn = next((fn for magic, fn in decompress.items() if data.startswith(magic, off)), None)
        if fn:
            out, rest = fn(data[off:])
            names += cpio_names(out, decompress)
            data, off = rest, 0
            continue
        if data[off:off + 6] not in CPIO_MAGICS:
            raise ValueError("initrd: unknown data at offset %d" % off)
        while True:
            if off + 110 > len(data) or data[off:off + 6] not in CPIO_MAGICS:
                raise ValueError("initrd: truncated cpio header at offset %d" % off)
            try:
                size, namesize = int(data[off + 54:off + 62], 16), int(data[off + 94:off + 102], 16)
            except ValueError:
                raise ValueError("initrd: bad cpio header at offset %d" % off)
            end = off + 110 + namesize
            if namesize < 1 or end > len(data):
                raise ValueError("initrd: truncated cpio name at offset %d" % off)
            name = data[off + 110:end - 1].decode("utf-8", "surrogateescape")
            off = (end + 3) & ~3
            if off + size > len(data):
                raise ValueError("initrd: truncated cpio file %s" % name)
            off = (off + size + 3) & ~3
            if name == "TRAILER!!!":
                break
            names.append(name[2:] if name.startswith("./") else name)


# Bluetooth must not come up in the initrd either (#1475): the image blocks btusb and btmtk with a
# modprobe drop-in in mkosi.extra, which mkosi's default initrd does not get, and a module udev
# loads there stays loaded after the switch to /usr. All Linux Bluetooth drivers and the stack sit
# under drivers/bluetooth and net/bluetooth; the names also catch bluetoothd and its units, and
# the firmware patterns the vendors' Bluetooth firmware (MediaTek, Intel, Realtek, Broadcom).
BT_PATTERNS = (r"(?i)bluetooth", r"(^|/)bt(usb|mtk)(\.ko|$)", r"(^|/)BT_RAM_CODE", r"(^|/)rtl_bt/",
               r"(^|/)intel/ibt-", r"(^|/)brcm/[^/]*\.hcd(\.\w+)?$")
# systemd ships bluetooth.target for the system and user managers (the default initrd carries the
# user one, CI build of #1509): a synchronisation point that starts nothing by itself.
BT_ALLOWED = ("usr/lib/systemd/system/bluetooth.target", "usr/lib/systemd/user/bluetooth.target")


def bluetooth_violations(names):
    """The initrd paths that could bring up Bluetooth: a module, firmware, daemon or unit."""
    return sorted(n for n in names if n not in BT_ALLOWED and any(re.search(p, n) for p in BT_PATTERNS))


def check_initrd(path, data):
    """Exit unless the initrd at PATH lists files and none of them is Bluetooth (#1475)."""
    names = cpio_names(data)
    print("initrd %s: %d files, %d kernel modules" % (path, len(names), sum(".ko" in n for n in names)))
    bad = bluetooth_violations(names) if names else ["no files"]
    if bad:
        sys.exit("initrd %s could bring up Bluetooth (#1475): %s" % (path, bad))


def manifest(version, roothash, entry_name, entry_text, files, boot=None, drivers=None):
    """The release (UPD-1a): /usr verity root hash plus the boot entry that mounts it, the
    sha256 of the kernel and initrd that entry boots, and drivers.json's list (DEVSLOT-image)."""
    if usrhash(entry_text) != roothash:
        raise ValueError("entry usrhash %s != /usr root hash %s" % (usrhash(entry_text), roothash))
    return {
        "version": version,
        "usrhash": roothash,
        "boot_entry": {"name": re.sub(r"\+\d+(-\d+)?\.conf$", ".conf", entry_name),
                       "sha256": hashlib.sha256(entry_text.encode()).hexdigest()},
        "boot": boot or {},
        "files": files,
        "drivers": drivers or [],
    }


def verify_usr(data, tree, roothash):
    """Check the /usr partition and its hash tree against the entry's usrhash, independently of mkosi."""
    r = subprocess.run(["veritysetup", "verify", str(data), str(tree), roothash])
    if r.returncode != 0:
        raise ValueError("/usr does not verify against usrhash=%s" % roothash)


# One line per entry of the /usr list, a JSON array of these fields (#4059). digest: a file's
# sha256, a link's target, a device's major:minor, else "". Extended attributes are not listed:
# fsck.erofs 1.7 does not extract them, so a difference only there reads as same files, other layout.
USR_LIST_FIELDS = ("path", "type", "mode", "uid", "gid", "mtime_ns", "nlink", "size", "digest")
USR_TYPES = ((stat.S_ISREG, "f"), (stat.S_ISDIR, "d"), (stat.S_ISLNK, "l"), (stat.S_ISCHR, "c"),
             (stat.S_ISBLK, "b"), (stat.S_ISFIFO, "p"), (stat.S_ISSOCK, "s"))


def usr_list(root):
    """The /usr list of the tree at ROOT: one JSON line per entry below it, sorted by path."""
    root = pathlib.Path(root)
    lines = []
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            path = pathlib.Path(dirpath) / n
            st = path.lstat()
            kind = next(c for test, c in USR_TYPES if test(st.st_mode))
            digest = (sha256(path) if kind == "f" else os.readlink(path) if kind == "l"
                      else "%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev)) if kind in "cb" else "")
            lines.append(json.dumps([path.relative_to(root).as_posix(), kind, "%04o" % stat.S_IMODE(st.st_mode),
                                     st.st_uid, st.st_gid, st.st_mtime_ns, st.st_nlink if kind != "d" else 0,
                                     st.st_size if kind == "f" else 0, digest]))
    return sorted(lines, key=lambda ln: json.loads(ln)[0])


def write_usr_list(data, dst):
    """Write DATA's (the /usr erofs partition's) /usr list to DST, from a copy fsck.erofs extracts
    with owners, modes, times and hard links kept beside DST, and removed again."""
    dst = pathlib.Path(dst)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix=".usr-list-", dir=dst.parent))
    try:
        subprocess.run(["fsck.erofs", "--extract=%s" % (tmp / "usr"), "--preserve", str(data)], check=True,
                       stdout=subprocess.DEVNULL)
        lines = usr_list(tmp / "usr")
    finally:
        shutil.rmtree(tmp)
    if not lines:
        raise ValueError("/usr list of %s is empty" % data)
    dst.write_text("\n".join(lines) + "\n")
    return len(lines)


def partition_table(img):
    return json.loads(subprocess.check_output(["sfdisk", "-J", img]))["partitiontable"]


def esp_offset(img):
    t = partition_table(img)
    p = next(p for p in t["partitions"] if p["type"].lower() == ESP)
    return p["start"] * t.get("sectorsize", 512)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(out, version, drivers_json=None):
    out = pathlib.Path(out)
    drivers = json.loads(pathlib.Path(drivers_json).read_text())["drivers"] if drivers_json else []
    img = out / ("agentos_%s.raw" % version)
    fs = "%s@@%d" % (img, esp_offset(str(img)))
    names = subprocess.check_output(["mdir", "-i", fs, "-b", "::/loader/entries"], text=True).split()
    names = [n.rsplit("/", 1)[-1] for n in names if n.endswith(".conf")]
    if len(names) != 1:
        sys.exit("expected one mkosi boot entry, found %s" % names)
    src = subprocess.check_output(["mtype", "-i", fs, "::/loader/entries/" + names[0]], text=True)
    name, text = counted_entry(src, version)
    subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/entries/" + name], input=text.encode(), check=True)
    subprocess.run(["mdel", "-i", fs, "::/loader/entries/" + names[0]], check=True)
    subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/loader.conf"], input=LOADER_CONF.encode(), check=True)
    (out / name).write_text(text)
    listing = subprocess.check_output(["mdir", "-i", fs, "-/", "-b", "::/"], text=True).splitlines()
    paths = [p[3:] for p in listing if p.startswith("::/") and not p.endswith("/")]
    print("ESP:\n  " + "\n  ".join(sorted(paths)))
    bad = esp_violations(paths, text)
    if bad:
        sys.exit("ESP holds files outside the allowlist (HW-1): %s" % bad)
    bad = cmdline_violations(text)
    if bad:
        sys.exit("boot entry has a kernel argument outside the allowlist (#1530): %s" % bad)
    bad = swap_violations(partition_table(str(img))["partitions"], text)
    if bad:
        sys.exit("image could swap or keep the broker's memory (IMG-nodump): %s" % bad)
    bad = quota_violations(str(img), partition_table(str(img)), text)
    if bad:
        sys.exit("agent machines would have no disk quota (RES-4): %s" % bad)
    bad = noexec_violations(text)
    if bad:
        sys.exit("code on the writable root could run (UPD-10): %s" % bad)
    bad = secret_violations(str(img), partition_table(str(img)))
    if bad:
        sys.exit("disk holds a private key or Owner Card outside /usr (HW-1): %s" % bad)
    boot = {}
    for p in boot_files(text):
        data_ = subprocess.check_output(["mtype", "-i", fs, "::/" + p])
        boot[p] = hashlib.sha256(data_).hexdigest()
        if p in initrd_files(text):
            check_initrd(p, data_)
    roothash = usrhash(text)
    data, tree = out / ("agentos_%s.usr.raw" % version), out / ("agentos_%s.usr-verity.raw" % version)
    verify_usr(data, tree, roothash)
    bad = slot_a_violations(str(img), partition_table(str(img)), data, tree)
    if bad:
        sys.exit("/usr slot A on the disk is not the verified /usr, or holds a private key (HW-1): %s; a key that ships in "
                 "/usr on purpose goes in image/slot_a_scan.allow with its sha256 once reviewed" % bad)
    print("/usr list: %d entries" % write_usr_list(data, out / ("agentos_%s.usr.list" % version)))
    # Only the two files just verified: mkosi also leaves arch-named split copies beside them.
    files = {p.name: sha256(p) for p in (data, tree)}
    m = manifest(version, roothash, name, text, files, boot, drivers)
    (out / ("agentos_%s.release.json" % version)).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    print(json.dumps(m, indent=2, sort_keys=True))


# DEVSLOT-image (DEV-1, KRN-2, D-189): what each <name>/ in the build's drivers directory holds,
# and its entry.json's keys. The units and drivers.json's entry rules are mkosi.finalize's, which
# checks the tree the build makes from them.
DRIVER_FILES = ("driver", "entry.json")
DRIVER_ENTRY_KEYS = ("repository", "commit", "declaration", "classes", "measure")
ET_EXEC, EM_X86_64, PT_DYNAMIC, PT_INTERP = 2, 62, 2, 3


def finalize_module():
    """mkosi.finalize as a module: the driver template and drivers.json's entry rules."""
    path = pathlib.Path(__file__).resolve().parent / "mkosi" / "mkosi.finalize"
    loader = importlib.machinery.SourceFileLoader("image_check", str(path))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("image_check", loader))
    loader.exec_module(mod)
    return mod


def static_refusal(data):
    """Why DATA is not a static x86-64 executable, or None (part b point 1, Security 6433764278
    point 2): a dynamically linked binary has the system's loader and libraries run its code at exec,
    outside anything this repository reviews. A fixed-address executable (ET_EXEC) with no PT_INTERP
    and no PT_DYNAMIC program header is what CGO_ENABLED=0 go build makes."""
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return "not a 64-bit little-endian ELF file"
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_machine != EM_X86_64:
        return "not an x86-64 executable"
    if e_type != ET_EXEC:
        return "not a fixed-address executable (ELF type %d); only a static binary ships" % e_type
    phoff, = struct.unpack_from("<Q", data, 32)
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize != 56 or not phnum or phoff + 56 * phnum > len(data):
        return "malformed program headers"
    for i in range(phnum):
        p_type, = struct.unpack_from("<I", data, phoff + 56 * i)
        if p_type in (PT_DYNAMIC, PT_INTERP):
            return "dynamically linked (%s); only a static binary ships" % ("PT_INTERP" if p_type == PT_INTERP else "PT_DYNAMIC")
    return None


def driver_entry(src, name, checker, check):
    """drivers.json's entry for driver directory SRC/NAME; ValueError for anything the build refuses."""
    d = pathlib.Path(src) / name
    if not check.DRIVER_NAME.match(name):
        raise ValueError("driver name %r is off the alphabet %s" % (name, check.DRIVER_NAME.pattern))
    if d.is_symlink() or not d.is_dir():
        raise ValueError("driver %s: not a directory" % name)
    if sorted(os.listdir(d)) != sorted(DRIVER_FILES):
        raise ValueError("driver %s: holds %s; must hold exactly %s" % (name, sorted(os.listdir(d)), ", ".join(DRIVER_FILES)))
    for f in DRIVER_FILES:
        if not stat.S_ISREG(os.lstat(d / f).st_mode):
            raise ValueError("driver %s: %s is not a regular file" % (name, f))
    try:
        e = json.loads((d / "entry.json").read_text())
    except ValueError as err:
        raise ValueError("driver %s: entry.json: %s" % (name, err))
    if not isinstance(e, dict) or sorted(e) != sorted(DRIVER_ENTRY_KEYS):
        raise ValueError("driver %s: entry.json has exactly the keys %s" % (name, ", ".join(DRIVER_ENTRY_KEYS)))
    data = (d / "driver").read_bytes()
    bad = static_refusal(data)
    if bad:
        raise ValueError("driver %s: %s" % (name, bad))
    r = subprocess.run(checker, input=json.dumps({"declaration": e["declaration"], "classes": e["classes"]}).encode(),
                       capture_output=True)
    if r.returncode != 0:
        raise ValueError("driver %s: %s" % (name, r.stderr.decode(errors="replace").strip()))
    entry = {"name": name, "repository": e["repository"], "commit": e["commit"],
             "sha256": hashlib.sha256(data).hexdigest(), "declaration": json.loads(r.stdout),
             "classes": e["classes"], "measure": e["measure"]}
    bad = check.driver_entry_refusal(entry)
    if bad:
        raise ValueError(bad)
    return entry, data


def stage_drivers(src, stage, checker):
    """Stage the drivers in directory SRC (none if SRC is empty) into the image tree STAGE: each binary
    under usr/lib/agentos/drivers/<name>/, its units and user from mkosi.finalize's template, and
    drivers.json. CHECKER is the drivercheck command (devslot.Check). Returns drivers.json's list;
    ValueError for anything the build refuses."""
    check = finalize_module()
    stage = pathlib.Path(stage)
    entries = []
    for name in sorted(os.listdir(src)) if src else []:
        entry, data = driver_entry(src, name, checker, check)
        entries.append(entry)
        b = stage / check.DRIVERS_DIR / name / "driver"
        b.parent.mkdir(parents=True, exist_ok=True)
        b.write_bytes(data)
        b.chmod(0o755)
        for rel, text in check.driver_units(name).items():
            (stage / rel).parent.mkdir(parents=True, exist_ok=True)
            (stage / rel).write_text(text)
    j = stage / check.DRIVERS_JSON
    j.parent.mkdir(parents=True, exist_ok=True)
    j.write_text(json.dumps({"drivers": entries}, indent=2, sort_keys=True) + "\n")
    return entries


if __name__ == "__main__":
    if sys.argv[1:2] == ["--stage-drivers"] and len(sys.argv) == 5:
        try:
            stage_drivers(sys.argv[2], sys.argv[3], [sys.argv[4]])
        except (ValueError, OSError) as e:
            sys.exit("drivers refused (DEVSLOT-image): %s" % e)
    else:
        main(*sys.argv[1:4])
