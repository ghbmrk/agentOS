#!/usr/bin/env python3
"""Finish a built AgentOS image: one counted boot entry, and the release manifest (UPD-1, UPD-1a).

mkosi writes one boot entry named after the kernel. This replaces it, inside the image's ESP,
with agentos_VERSION+3.conf: systemd-boot counts down the 3 tries on each unblessed boot and
falls back once they run out, and systemd-bless-boot drops the counter after agentos-health
passes (boot-complete.target). The entry's usrhash= names the /usr verity root hash, so the
entry and the /usr partitions are one release: the build verifies the split /usr partition and
its hash tree against that hash with veritysetup, and the manifest records both.
Uses mtools on the raw image, so no loop devices or mounts are needed.
Usage: finish_image.py OUTDIR VERSION"""
import errno
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys

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


# HW-1 on the built disk, not only on the tree mkosi.finalize saw (IMG-1): every byte of the disk
# outside /usr slot A (the partition table, the ESP, root and the empty slot B) holds no private key
# and no Owner Card. Slot A is package content, verified against the entry's usrhash, and the
# reproduce job builds the same usrhash on another runner, which a key or card made during the build
# would break (image/ASSUMPTIONS.md IMG-1-1). A hit names its kind and offset, never its bytes.
SECRET_PATTERNS = (
    # A PEM or PGP private key with its body: libcrypto and gpg carry the header alone.
    ("private key", re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----\r?\n"
                               rb"(?:[ -~]{0,128}\r?\n){0,8}[A-Za-z0-9+/]{40}")),
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


def secret_violations(img, table):
    """Every private key or Owner Card on the disk IMG outside /usr slot A. table: sfdisk -J's."""
    ss = table.get("sectorsize", 512)
    skip = sorted((p["start"] * ss, (p["start"] + p["size"]) * ss) for p in table["partitions"]
                  if p["type"].lower() in (USR_GUID, USR_VERITY_GUID) and p.get("name") != "_empty")
    out = []
    if len(skip) != 2:
        out.append("expected /usr slot A's two partitions, found %d; scanned all of them" % len(skip))
        skip = []
    with open(img, "rb") as f:
        size, pos = os.fstat(f.fileno()).st_size, 0
        for a, b in skip + [(size, size)]:
            for d, h in data_extents(f, pos, a):
                for p in range(d, h, SCAN_CHUNK):
                    f.seek(p)
                    buf = f.read(min(SCAN_CHUNK + SCAN_OVERLAP, h - p))
                    for what, pat in SECRET_PATTERNS:
                        # A match starting in the overlap is the next chunk's.
                        out += ["%s at byte %d" % (what, p + m.start())
                                for m in pat.finditer(buf) if m.start() < SCAN_CHUNK]
            pos = max(pos, b)
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


def manifest(version, roothash, entry_name, entry_text, files, boot=None):
    """The release (UPD-1a): /usr verity root hash plus the boot entry that mounts it, and the
    sha256 of the kernel and initrd that entry boots."""
    if usrhash(entry_text) != roothash:
        raise ValueError("entry usrhash %s != /usr root hash %s" % (usrhash(entry_text), roothash))
    return {
        "version": version,
        "usrhash": roothash,
        "boot_entry": {"name": re.sub(r"\+\d+(-\d+)?\.conf$", ".conf", entry_name),
                       "sha256": hashlib.sha256(entry_text.encode()).hexdigest()},
        "boot": boot or {},
        "files": files,
    }


def verify_usr(data, tree, roothash):
    """Check the /usr partition and its hash tree against the entry's usrhash, independently of mkosi."""
    r = subprocess.run(["veritysetup", "verify", str(data), str(tree), roothash])
    if r.returncode != 0:
        raise ValueError("/usr does not verify against usrhash=%s" % roothash)


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


def main(out, version):
    out = pathlib.Path(out)
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
    # Only the two files just verified: mkosi also leaves arch-named split copies beside them.
    files = {p.name: sha256(p) for p in (data, tree)}
    m = manifest(version, roothash, name, text, files, boot)
    (out / ("agentos_%s.release.json" % version)).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    print(json.dumps(m, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(*sys.argv[1:3])
