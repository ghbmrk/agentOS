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
import functools
import hashlib
import importlib.machinery
import importlib.util
import json
import mmap
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
# Words that start like init= but name an early kernel parameter, which the kernel takes and never
# hands to PID 1: init_on_free=1 zeroes memory as it is freed, the wipe agentos-mor rests on before it
# clears the memory-overwrite request at shutdown (HW-8, #4794). Each must still be in mkosi.conf.
KERNEL_INIT_PARAMS = ("init_on_free",)


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
        elif k.startswith(("systemd.run", "init", "rdinit")) and k not in KERNEL_INIT_PARAMS:
            out.append("%s: PID 1 would run it" % key)
        elif k in ("systemd.set_credential", "systemd.set_credential_binary") and \
                val.split(":", 1)[0] not in SHIPPED_CREDENTIALS:
            out.append("%s=%s: only the shipped credentials %s may be set"
                       % (key, val.split(":", 1)[0], ", ".join(SHIPPED_CREDENTIALS)))
        elif w not in allowed and not re.fullmatch(r"usrhash=[0-9a-f]{64}", w):
            out.append("%s: not in mkosi.conf's KernelCommandLine; add it there" % w[:80])
    return out


# IMG-keeper-reach-gen (#5289): systemd-gpt-auto-generator mounts, from the root's disk, the ESP at
# /boot and any /home, /srv, /var or /var/tmp partition, and adds swap units; systemd-repart makes any
# partition its definitions name. Those mounts are units no unit directory, fstab or system.conf holds,
# so the tree check never reads them. The definitions may name only these four types, and the built
# disk must hold exactly the partitions mkosi.repart defines, in order, so gpt-auto has the ESP and
# root and nothing else. /usr/lib/repart.d (first boot) may hold only mkosi.extra's files.
REPART_TYPES = {"esp": ESP, "usr": USR_GUID, "usr-verity": USR_VERITY_GUID, "root": ROOT_GUID}
REPART_DIR = MKOSI_CONF.parent / "mkosi.repart"
REPART_D = MKOSI_CONF.parent / "mkosi.extra" / "usr" / "lib" / "repart.d"


def repart_types(d):
    """(file name, Type=) for each *.conf in D, sorted by name as systemd-repart sorts them. A file
    with no [Partition] Type= or more than one gives None, which no allowed type matches."""
    out = []
    for f in sorted(pathlib.Path(d).glob("*.conf")):
        section, types = None, []
        for ln in f.read_text().splitlines():
            ln = ln.strip()
            if ln.startswith("[") and ln.endswith("]"):
                section = ln[1:-1]
            elif section == "Partition" and ln.partition("=")[0].strip() == "Type":
                types.append(ln.partition("=")[2].strip())
        out.append((f.name, types[0] if len(types) == 1 else None))
    return out


def partition_violations(partitions, defs=REPART_DIR, runtime=REPART_D):
    """The built disk's partitions (sfdisk -J's list) against the repart definitions: every
    definition names an allowed type, and the disk holds exactly mkosi.repart's partitions."""
    out = ["%s/%s: Type=%s; gpt-auto or systemd-repart would act on it (allowed: %s)"
           % (pathlib.Path(d).name, n, t, ", ".join(sorted(REPART_TYPES)))
           for d in (defs, runtime) for n, t in repart_types(d) if t not in REPART_TYPES]
    want = [REPART_TYPES.get(t) for _, t in repart_types(defs)]
    got = [p["type"].lower() for p in partitions]
    if got != want:
        out.append("disk partition types %s are not mkosi.repart's %s" % (got, want))
    return out


# The /usr steps on the way to systemd-repart's /usr definitions: each must be a plain directory, so
# no link points a definition directory elsewhere in /usr. lib/repart.d must exist; the rest may not.
USR_REPART_STEPS = ("lib", "lib/repart.d", "local", "local/lib", "local/lib/repart.d")
# systemd-confext merges the images in these /usr directories over /etc (discover-image.c, v257), so an
# image there could add a repart.d or a unit the checks here never read (#5418). /usr ships neither.
USR_CONFEXTS = ("lib/confexts", "local/lib/confexts")


def usr_repart_violations(rows, runtime=REPART_D):
    """The /usr list rows (path, type, ..., digest) that let systemd-repart read a definition other than
    mkosi.extra's repart.d files, byte for byte: a changed, added or missing file under lib/repart.d or
    local/lib/repart.d, or a step on the way to either that is not a plain directory; or that give
    systemd-confext an image to merge over /etc (USR_CONFEXTS)."""
    want = {"lib/repart.d/" + f.name: sha256(f) for f in pathlib.Path(runtime).glob("*.conf")}
    out, seen = [], set()
    kinds = {r[0]: r[1] for r in rows}
    for step in USR_REPART_STEPS:
        if kinds.get(step, "d" if step.startswith("local") else None) != "d":
            out.append("/usr/%s: not a plain directory (%s)" % (step, kinds.get(step, "missing")))
    for r in rows:
        path, kind, digest = r[0], r[1], r[-1]
        if any(path == c or path.startswith(c + "/") for c in USR_CONFEXTS):
            out.append("/usr/%s: systemd-confext would merge it over /etc" % path)
        if not path.startswith(("lib/repart.d/", "local/lib/repart.d/")):
            continue
        seen.add(path)
        if kind != "f" or want.get(path) != digest:
            out.append("/usr/%s: not mkosi.extra's repart.d file" % path)
    out += ["/usr/%s: missing" % p for p in sorted(set(want) - seen)]
    return out


# Directories on the writable root that systemd reads definitions or images from (#5289, #5418):
# systemd-repart's repart.d, systemd-sysext's extensions (merged over /usr) and systemd-confext's
# confexts (merged over /etc), each by the v257 search paths (discover-image.c). The image ships none
# of them (/run is an empty mount point for a tmpfs), so every step to each listed directory must be
# a plain directory, readable, and hold none of its names. Read with debugfs's raw directory listing
# (ls -p: /inode/mode/uid/gid/name/size/), which follows no link.
ROOT_READS = {"etc": ("repart.d", "extensions"), "run": ("repart.d", "extensions", "confexts"),
              "var/lib": ("extensions", "confexts")}
READERS = {"repart.d": "systemd-repart would make what it defines", "extensions": "systemd-sysext would merge it "
           "over /usr", "confexts": "systemd-confext would merge it over /etc"}
DEBUGFS_ROW = re.compile(r"/(\d+)/([0-7]{6})/(\d+)/(\d+)/(.*)/(\d*)/")
# What debugfs writes to stderr on every run; anything else there is a failure, as debugfs exits 0 when
# it cannot open the image or find a path (e2fsprogs 1.47).
DEBUGFS_BANNER = re.compile(r"debugfs \S+ \([^()\n]*\)\n")
# Superblock incompat features under which a name in a directory block is not the name debugfs prints
# (#5418): an encrypted directory's names are ciphertext, and a casefolded one matches "Repart.D" as
# repart.d. The root ext4 has neither (mkosi.conf's SYSTEMD_REPART_MKFS_OPTIONS_EXT4 sets neither).
EXT4_HIDING = {0x10000: "encrypt", 0x20000: "casefold"}


class ToolError(Exception):
    """debugfs failed: the build stops on the tool, not on the image."""


def debugfs_ls(img, offset, path):
    """{name: octal mode} of directory PATH in the ext4 file system at byte OFFSET of IMG. A listing
    with no "." entry (not a directory) gives None. Raises ToolError when debugfs exits non-zero, writes
    anything to stderr but its banner, or prints a line that is not a row or a name twice (a name holding
    a newline could forge a row; Security 6804479798 release a)."""
    p = subprocess.run(["debugfs", "-R", "ls -p %s" % path, "%s?offset=%d" % (img, offset)],
                       capture_output=True, text=True)
    err = DEBUGFS_BANNER.sub("", p.stderr, count=1).strip()
    if p.returncode or err:
        raise ToolError("debugfs ls -p %s exited %d: %s" % (path, p.returncode, err or "no message"))
    rows = {}
    for ln in p.stdout.splitlines():
        m = DEBUGFS_ROW.fullmatch(ln)
        if not m and ln.strip():
            raise ToolError("debugfs ls -p %s printed a line that is not a row: %r" % (path, ln))
        if m and m.group(5) in rows:
            raise ToolError("debugfs ls -p %s listed %r twice" % (path, m.group(5)))
        if m:
            rows[m.group(5)] = m.group(2)
    return rows if "." in rows else None


def ext4_hiding_violations(img, offset):
    """The root's superblock, read as quota_violations reads it: ext4, with no EXT4_HIDING feature."""
    with open(img, "rb") as f:
        f.seek(offset + 1024)
        sb = f.read(1024)
    if len(sb) < 1024 or struct.unpack_from("<H", sb, 0x38)[0] != EXT4_MAGIC:
        return ["root is not ext4"]
    incompat = struct.unpack_from("<I", sb, 0x60)[0]
    return ["root ext4 has the %s feature; debugfs would not read its names as systemd does" % n
            for bit, n in sorted(EXT4_HIDING.items()) if incompat & bit]


def root_repart_violations(img, table, ls=debugfs_ls):
    """The root partition's ROOT_READS directories that are not plain, readable directories on every
    step, or hold a name systemd would read; and a root ext4 debugfs cannot read as systemd does."""
    roots = [p for p in table["partitions"] if p["type"].lower() == ROOT_GUID]
    if len(roots) != 1:
        return ["expected one root partition, found %d" % len(roots)]
    offset = roots[0]["start"] * table.get("sectorsize", 512)
    out = ext4_hiding_violations(img, offset)
    if out:
        return out
    seen = {}

    def listing(path):
        if path not in seen:
            seen[path] = None
            up, _, name = path.rpartition("/")
            top = listing(up) if path else {}
            if top is None:
                return None
            mode = top.get(name, "missing") if path else "040"
            if not mode.startswith("04"):
                out.append("/%s: not a plain directory on root (%s)" % (path, mode))
                return None
            got = ls(img, offset, "/" + path)
            if not got:
                out.append("/%s: unreadable on root" % path)
                return None
            seen[path] = got
        return seen[path]

    try:
        for d, names in ROOT_READS.items():
            got = listing(d) or {}
            out += ["/%s/%s: on root; %s" % (d, n, READERS[n]) for n in names if n in got]
    except ToolError as e:
        return ["%s; a tool failure, not the image's" % e]
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
# A newc header's 13 fields after the magic, as cpio(5) names them; "check" is always 0 in newc.
NEWC_FIELDS = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize", "devmajor", "devminor",
               "rdevmajor", "rdevminor", "namesize", "check")
HEX8 = re.compile(rb"[0-9A-Fa-f]{8}")


def newc_header(data, off):
    """The fields of the newc header at OFF in DATA, by NEWC_FIELDS name. Raises ValueError unless
    each is exactly 8 hex digits: int(x, 16) alone takes a sign, spaces, 0x and _, and a negative
    size moves a reader back onto its own header, so it never ends (#4662). Unsigned fields make
    every member move the offset forward by at least its 110-byte header."""
    raw = [data[off + 6 + 8 * i:off + 14 + 8 * i] for i in range(len(NEWC_FIELDS))]
    if not all(HEX8.fullmatch(f) for f in raw):
        raise ValueError("initrd: bad cpio header at offset %d" % off)
    return dict(zip(NEWC_FIELDS, (int(f, 16) for f in raw)))
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


def cpio_members(data, decompress=None, archive=None):
    """Every member of an initrd, as (path, mode, content, link): newc cpio archives and compressed
    (zstd, xz or gzip) streams of them, back to back with zero padding between them, read on as the
    kernel does. LINK is the key the kernel's find_link groups hard links by (the archive, as its table
    is freed at each trailer, then ino, devmajor, devminor and file type) when nlink is 2 or more and
    it is not a directory or link (do_name links only those), else None. Anything else raises ValueError, so an initrd this cannot read fails the build rather than
    passing unchecked. DECOMPRESS maps a magic to a function returning (output, the bytes after the
    stream). ARCHIVE, a one-item list, counts the archives read so far: pass one list for every initrd
    of an entry, as the kernel unpacks them all into one rootfs and its link table restarts only at a
    trailer (Security delta 6804788432)."""
    decompress = decompress or {ZSTD: unzstd, XZ: unxz, GZIP: ungzip}
    archive = archive if archive is not None else [0]
    members, off = [], 0
    while True:
        while off < len(data) and data[off] == 0:
            off += 1
        if off >= len(data):
            return members
        fn = next((fn for magic, fn in decompress.items() if data.startswith(magic, off)), None)
        if fn:
            out, rest = fn(data[off:])
            members += cpio_members(out, decompress, archive)
            data, off = rest, 0
            continue
        if data[off:off + 6] not in CPIO_MAGICS:
            raise ValueError("initrd: unknown data at offset %d" % off)
        while True:
            if off + 110 > len(data) or data[off:off + 6] not in CPIO_MAGICS:
                raise ValueError("initrd: truncated cpio header at offset %d" % off)
            hdr = newc_header(data, off)
            size, namesize = hdr["filesize"], hdr["namesize"]
            end = off + 110 + namesize
            if namesize < 1 or end > len(data):
                raise ValueError("initrd: truncated cpio name at offset %d" % off)
            name = data[off + 110:end - 1].decode("utf-8", "surrogateescape")
            off = (end + 3) & ~3
            if off + size > len(data):
                raise ValueError("initrd: truncated cpio file %s" % name)
            body, off = data[off:off + size], (off + size + 3) & ~3
            if name == "TRAILER!!!":
                archive[0] += 1
                break
            link = ((archive[0], hdr["ino"], hdr["devmajor"], hdr["devminor"], stat.S_IFMT(hdr["mode"]))
                    if hdr["nlink"] >= 2 and stat.S_IFMT(hdr["mode"]) not in (stat.S_IFDIR, stat.S_IFLNK) else None)
            members.append((name[2:] if name.startswith("./") else name, hdr["mode"], body, link))


def cpio_names(data, decompress=None):
    """Every path in an initrd (cpio_members)."""
    return [m[0] for m in cpio_members(data, decompress)]


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


# The initrd's own files that would give its systemd a unit, mount, device or partition no check here
# or in mkosi.finalize reads (#5418; mkosi.finalize's tree check reads only the main tree). The initrd
# is built from packages alone (it has no mkosi.extra), so each of these is refused whatever its content:
# - a repart.d entry. In the initrd systemd-repart reads /sysusr's or /sysroot's definitions (repart.c,
#   v257), which the disk checks above hold, but the initrd's own would be the first that
#   systemd-repart.service's conditions see;
# - an fstab, crypttab, veritytab or integritytab line: the fstab, cryptsetup, veritysetup and
#   integritysetup generators make mounts and devices from them. A file of blank and # lines is empty;
# - a credential in a store (the main tree's rule and exceptions: mkosi.finalize CREDSTORE_ALLOWED);
# - a generator outside /usr/lib (in /etc/systemd or /usr/local/lib/systemd), and a unit or drop-in in
#   any unit directory outside /usr/lib (UNIT_PATHS: system.control, system, system.attached and
#   /usr/local's) but an enablement link or mask: a link to /usr/lib/systemd/system/<name>, not
#   systemd-sysext's or systemd-confext's, or /dev/null;
# - a sysext or confext image in systemd-sysext's or systemd-confext's initrd search paths
#   (discover-image.c, v257; .extra is systemd-stub's, which the image does not use).
# The check judges the tree the kernel unpacks, not the members one by one (Security 6804479798): every
# initrd of the entry in boot order into one tree, as the kernel unpacks them into one rootfs; a hard
# link's content is its group's, written into one inode as maybe_link() does; names are taken as the
# kernel resolves them ("", "." and ".." steps). A member written through a link (a link on its way, or a
# link at its own name, which O_CREAT follows) is refused, so every file lands at its own name; and every
# step to a checked directory, and the directory itself, is a directory (or absent). /run is a tmpfs in
# the initrd too, so its files are hidden. The units and generators packages ship in /usr/lib are
# packages' files, like every binary (I21).
INITRD_REPART = ("etc/repart.d", "usr/lib/repart.d", "usr/local/lib/repart.d")
INITRD_TABS = ("etc/fstab", "etc/crypttab", "etc/veritytab", "etc/integritytab")
INITRD_CREDSTORES = tuple("%s/%s" % (top, n) for top in ("etc", "usr/local/lib", "usr/lib")
                          for n in ("credstore", "credstore.encrypted"))
INITRD_CREDS_ALLOWED = ("usr/lib/credstore/firstboot.keymap", "usr/lib/credstore/firstboot.locale",
                        "usr/lib/credstore/firstboot.timezone", "usr/lib/credstore/passwd.hashed-password.root")
INITRD_GENERATOR_DIRS = ("etc/systemd/system-generators", "usr/local/lib/systemd/system-generators")
INITRD_IMAGE_DIRS = ("etc/extensions", "run/extensions", "var/lib/extensions", ".extra/sysext", "run/confexts",
                     "var/lib/confexts", "usr/local/lib/confexts", "usr/lib/confexts", ".extra/confext")
# An enablement link or mask; never one that turns on systemd-sysext or systemd-confext (L3 6804604094: in
# v257 both run in the initrd, and mkosi-initrd's preset, disable *, is all that leaves them off).
INITRD_UNIT_LINK = re.compile(r"/usr/lib/systemd/system/(?!systemd-(sysext|confext)[.@])[^/]+|/dev/null")


@functools.lru_cache(maxsize=None)
def initrd_checked():
    """(the unit directories outside /usr/lib, from mkosi.finalize's UNIT_PATHS, so the two checks share
    one list (L3 6804604094); every step to a checked directory or tab, and each checked directory
    itself, which must be directories or absent)."""
    units = tuple(d for d in finalize_module().UNIT_PATHS if not d.startswith("usr/lib/"))
    checked = INITRD_REPART + INITRD_CREDSTORES + units + INITRD_GENERATOR_DIRS + INITRD_IMAGE_DIRS
    steps = {"/".join(d.split("/")[:i]) for d in checked + INITRD_TABS for i in range(1, d.count("/") + 1)}
    return units, tuple(sorted(steps | set(checked)))


def initrd_tree(members):
    """(the tree MEMBERS unpack to, {path: [type, content]}, hard links sharing one list; the members
    refused as the model could differ from the kernel there). A member written through a link (a link on
    its way, or at its own name, which O_CREAT follows) is refused, as is one that replaces an entry of
    another type or a link, so each name is resolved lexically and lands where the kernel puts it. A
    regular file over a regular file is written into its inode (O_TRUNC), as do_name does; a hard link
    (cpio_members' LINK) joins its group's inode and is written from the start without truncating, as
    maybe_link() does."""
    tree, groups, out = {}, {}, []
    for name, mode, body, link in members:
        cur, why = [], None
        parts = [x for x in name.split("/") if x not in ("", ".")]
        if not parts or parts[-1] == "..":
            continue
        for x in parts[:-1]:
            if x == "..":
                cur = cur[:-1]
                continue
            cur.append(x)
            if tree.get("/".join(cur), [None])[0] == stat.S_IFLNK:
                why = why or "unpacked through the link %s" % "/".join(cur)
        path = "/".join(cur + [parts[-1]])
        kind, old = stat.S_IFMT(mode), tree.get(path)
        if not why and old and (kind == stat.S_IFLNK or old[0] != kind):
            why = "replaces a %s at %s" % ("link" if old[0] == stat.S_IFLNK else "%o entry" % old[0], path)
        if why:
            out.append("%s: %s" % (name, why))
            continue
        node = tree.get(groups[link]) if link in groups else None
        if node is not None and node[0] == kind:
            node[1] = body + node[1][len(body):]
            tree[path] = node
        elif old:
            old[1] = body if kind == stat.S_IFREG else old[1]
        else:
            tree[path] = [kind, body]
        if link and link not in groups:
            groups[link] = path
    return tree, out


def initrd_violations(members):
    """The unpacked initrd's files that add a unit, mount, device or partition (above)."""
    tree, out = initrd_tree(members)
    unit_dirs, steps = initrd_checked()
    for path, (kind, body) in sorted(tree.items()):
        def at(dirs):
            return any(path == d or path.startswith(d + "/") for d in dirs)
        if path in steps and kind != stat.S_IFDIR:
            out.append("%s: not a directory; a checked path could be reached through it" % path)
        elif at(INITRD_REPART):
            out.append("%s: a repart.d entry; systemd-repart would make what it defines" % path)
        elif path in INITRD_TABS and (kind != stat.S_IFREG or any(
                ln.strip() and not ln.strip().startswith(b"#") for ln in body.splitlines())):
            out.append("%s: has an entry; a generator would make a mount or device from it" % path)
        elif at(INITRD_CREDSTORES) and kind != stat.S_IFDIR and path not in INITRD_CREDS_ALLOWED:
            out.append("%s: a credential in a store" % path)
        elif at(unit_dirs) and kind != stat.S_IFDIR and not (
                kind == stat.S_IFLNK and INITRD_UNIT_LINK.fullmatch(body.decode("utf-8", "replace"))):
            out.append("%s: a unit or drop-in outside /usr/lib" % path)
        elif at(INITRD_GENERATOR_DIRS) and kind != stat.S_IFDIR:
            out.append("%s: a generator outside /usr/lib" % path)
        elif at(INITRD_IMAGE_DIRS) and kind != stat.S_IFDIR:
            out.append("%s: an image systemd-sysext or systemd-confext would merge" % path)
    return out


def check_initrd(path, data, archive=None):
    """Exit unless the initrd at PATH lists files and none of them is Bluetooth (#1475); its members,
    for check_initrd_tree (ARCHIVE: cpio_members', shared by the entry's initrds)."""
    members = cpio_members(data, archive=archive)
    names = [m[0] for m in members]
    print("initrd %s: %d files, %d kernel modules" % (path, len(names), sum(".ko" in n for n in names)))
    bad = bluetooth_violations(names) if names else ["no files"]
    if bad:
        sys.exit("initrd %s could bring up Bluetooth (#1475): %s" % (path, bad))
    return members


def check_initrd_tree(paths, members):
    """Exit if the tree the entry's initrds PATHS unpack to, MEMBERS in boot order, adds a unit, mount,
    device or partition (initrd_violations, #5418)."""
    bad = initrd_violations(members)
    if bad:
        sys.exit("initrds %s add a unit, mount, device or partition no check reads (#5418): %s"
                 % (" ".join(paths), bad))


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


EROFS_MAGIC = 0xE0F5E1E2
EROFS_PLAIN, EROFS_INLINE = 0, 2  # the uncompressed data layouts, the only ones a directory has here
EROFS_INCOMPAT_KNOWN = 0x7F  # erofs-utils 1.7's features; a later one (48-bit layout 0x80) moves root_nid


def erofs_inodes(data):
    """Map each path below the root of erofs image DATA to its inode's (mode, uid, gid), read from the
    on-disk inodes (#4470): fsck.erofs 1.7 extracts a setuid or setgid file without the bit, and
    dump.erofs prints only the low 9 mode bits. A layout this reader does not know raises ValueError."""
    with open(data, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as img:
        return erofs_walk(data, img)


def erofs_walk(data, img):
    magic, blkbits, root = struct.unpack_from("<I8xBxH", img, 1024)
    if magic != EROFS_MAGIC:
        raise ValueError("%s is not erofs" % data)
    if struct.unpack_from("<I", img, 1024 + 80)[0] & ~EROFS_INCOMPAT_KNOWN:
        raise ValueError("%s uses an erofs feature this reader does not know" % data)
    bs, meta = 1 << blkbits, struct.unpack_from("<I", img, 1024 + 40)[0] << blkbits

    def inode(nid):
        off = meta + 32 * nid
        fmt, xcount, mode = struct.unpack_from("<HHH", img, off)
        if fmt & 1:  # extended, 64 bytes
            size, u, uid, gid = struct.unpack_from("<QI4xII", img, off + 8)
            isize = 64
        else:  # compact, 32 bytes
            size, u, uid, gid = struct.unpack_from("<I4xI4xHH", img, off + 8)
            isize = 32
        tail = off + isize + (12 + 4 * (xcount - 1) if xcount else 0)
        return mode, uid, gid, (fmt >> 1) & 7, size, u, tail

    def entries(nid):
        mode, _, _, layout, size, u, tail = inode(nid)
        if layout not in (EROFS_PLAIN, EROFS_INLINE):
            raise ValueError("%s: directory inode %d has data layout %d" % (data, nid, layout))
        full = size if layout == EROFS_PLAIN else size - size % bs
        body = img[u * bs:u * bs + full] + img[tail:tail + size - full]
        if len(body) != size:
            raise ValueError("%s: directory inode %d runs past the image" % (data, nid))
        for b in range(0, size, bs):
            blk = body[b:b + bs]
            count = struct.unpack_from("<8xH", blk)[0] // 12
            ents = [struct.unpack_from("<QH", blk, 12 * i) for i in range(count)] + [(0, len(blk))]
            for (child, start), (_, end) in zip(ents, ents[1:]):
                name = blk[start:end].split(b"\0", 1)[0]
                if name not in (b".", b".."):
                    yield os.fsdecode(name), child

    out, todo, seen = {}, [("", root)], set()
    while todo:
        prefix, nid = todo.pop()
        if nid in seen:
            raise ValueError("%s: directory inode %d is reached twice" % (data, nid))
        seen.add(nid)
        for name, child in entries(nid):
            path = prefix + name
            if path in out or "/" in name or not name:
                raise ValueError("%s: bad or repeated directory entry %r" % (data, path))
            mode, uid, gid = inode(child)[:3]
            out[path] = (mode, uid, gid)
            if stat.S_ISDIR(mode):
                todo.append((path + "/", child))
    return out


def write_usr_list(data, dst):
    """Write DATA's (the /usr erofs partition's) /usr list to DST, from a copy fsck.erofs extracts
    with times and hard links kept beside DST, and removed again. Each entry's mode and owner are
    the partition's inode's, never the copy's (#4470), and the copy must hold the same paths and types."""
    dst = pathlib.Path(dst)
    tmp = pathlib.Path(tempfile.mkdtemp(prefix=".usr-list-", dir=dst.parent))
    try:
        subprocess.run(["fsck.erofs", "--extract=%s" % (tmp / "usr"), "--preserve", str(data)], check=True,
                       stdout=subprocess.DEVNULL)
        rows = [json.loads(ln) for ln in usr_list(tmp / "usr")]
    finally:
        shutil.rmtree(tmp)
    if not rows:
        raise ValueError("/usr list of %s is empty" % data)
    inodes = erofs_inodes(data)
    if sorted(inodes) != [r[0] for r in rows]:
        raise ValueError("%s: fsck.erofs extracted other paths than its inodes name" % data)
    for r in rows:
        mode, uid, gid = inodes[r[0]]
        if next((c for test, c in USR_TYPES if test(mode)), None) != r[1]:
            raise ValueError("%s: %s extracted as another type than its inode's" % (data, r[0]))
        r[2:5] = "%04o" % stat.S_IMODE(mode), uid, gid
    dst.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return len(rows)


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
    bad = partition_violations(partition_table(str(img))["partitions"])
    if bad:
        sys.exit("disk holds a partition gpt-auto or systemd-repart could mount (#5289): %s" % bad)
    bad = root_repart_violations(str(img), partition_table(str(img)))
    if bad:
        sys.exit("root carries a repart.d systemd-repart would read (#5289): %s" % bad)
    boot, members, archive = {}, [], [0]
    for p in boot_files(text):
        data_ = subprocess.check_output(["mtype", "-i", fs, "::/" + p])
        boot[p] = hashlib.sha256(data_).hexdigest()
        if p in initrd_files(text):
            members += check_initrd(p, data_, archive)
    check_initrd_tree(initrd_files(text), members)
    roothash = usrhash(text)
    data, tree = out / ("agentos_%s.usr.raw" % version), out / ("agentos_%s.usr-verity.raw" % version)
    verify_usr(data, tree, roothash)
    bad = slot_a_violations(str(img), partition_table(str(img)), data, tree)
    if bad:
        sys.exit("/usr slot A on the disk is not the verified /usr, or holds a private key (HW-1): %s; a key that ships in "
                 "/usr on purpose goes in image/slot_a_scan.allow with its sha256 once reviewed" % bad)
    print("/usr list: %d entries" % write_usr_list(data, out / ("agentos_%s.usr.list" % version)))
    rows = [json.loads(ln) for ln in (out / ("agentos_%s.usr.list" % version)).read_text().splitlines()]
    bad = usr_repart_violations(rows)
    if bad:
        sys.exit("/usr ships a repart.d definition the build did not (#5289): %s" % bad)
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
