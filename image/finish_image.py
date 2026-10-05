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
import configparser
import hashlib
import hmac
import json
import pathlib
import re
import subprocess
import sys
import uuid

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
TRIES = 3
# No menu: boot the default entry at once (a held key still shows it on a PC with a screen).
# No editor: anyone at the keyboard could otherwise drop usrhash= or add init=/bin/sh (Type #1
# entries are not covered by Secure Boot, HW-5a). Never offer to enroll keys.
LOADER_CONF = "timeout 0\neditor no\nsecure-boot-enroll off\n"
# What the ESP may hold, besides the kernel and initrd the entry names. Anything else (a
# loader/random-seed, a system token) would ship identical on every drive (HW-1).
ESP_ALLOWED = (r"EFI/BOOT/[^/]+", r"EFI/systemd/[^/]+", r"loader/loader\.conf", r"loader/entries\.srel",
               r"loader/entries/agentos_[^/]+\.conf")
# Never shim's fallback: fbx64.efi reads BOOT*.CSV and rewrites the host's BootOrder; never
# MokManager where shim launches it, so no MOK enrollment writes MokList (HW-8, security carry on
# #175). Refused under any directory or name case, even where allowed above.
ESP_FORBIDDEN = r"(?i)(^|/)(fb[^/]*\.efi|boot[^/]*\.csv|mm[^/]*\.efi)$"


# The initrd must carry the drive ID check (mkosi.initrd/) and nothing that assembles LVM or
# MD-RAID: the host's disks are not hidden yet at that point (HW-8).
INITRD_REQUIRED = ("usr/lib/agentos/drive-ids", "usr/lib/systemd/system/agentos-drive-ids.service",
                   "usr/lib/systemd/system/sysroot.mount.d/agentos-drive-ids.conf")
INITRD_FORBIDDEN = r"(^|/)(lvm|pvscan|vgchange|lvchange|mdadm|mdmon)$|lvm[^/]*\.rules$|md-raid[^/]*\.rules$|mdadm[^/]*\.rules$"
# /usr is chosen by usrhash= alone: an ID on the command line could pick another drive's partition.
BY_ID = r"(?:^|\s)(root|mount\.usr|usr|systemd\.verity_usr_data|systemd\.verity_usr_hash|mount\.usrfstype)="


HERE = pathlib.Path(__file__).resolve().parent
DRIVE_IDS = HERE / "mkosi/mkosi.initrd/mkosi.extra/usr/lib/agentos/drive-ids"


def seed_disk():
    """The disk GUID systemd-repart gives every drive from mkosi.conf's Seed= (HMAC-SHA256 keyed by
    the seed over "disk-uuid", first half as a v4 UUID). The initrd's drive-ids treats a drive
    with this GUID as fresh and gives it IDs of its own (I10)."""
    c = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    c.read(HERE / "mkosi/mkosi.conf")
    b = bytearray(hmac.new(uuid.UUID(c["Output"]["Seed"]).bytes, b"disk-uuid", hashlib.sha256).digest()[:16])
    b[6], b[8] = (b[6] & 0x0F) | 0x40, (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def check_seed_disk(img_guid):
    """The built drive's GUID, drive-ids' SEED_DISK and the seed's derivation must agree, or a fresh
    drive would never get IDs of its own."""
    want = seed_disk()
    m = re.search(r"^SEED_DISK=([0-9a-f-]{36})$", DRIVE_IDS.read_text(), re.M)
    script = m.group(1) if m else None
    if not (img_guid.lower() == want == script):
        raise ValueError("disk GUID %s, seed derivation %s, drive-ids SEED_DISK %s must be equal"
                         % (img_guid, want, script))


def usrhash(entry):
    m = re.search(r"(?:^|\s)usrhash=([0-9a-f]{64})(?:\s|$)", entry, re.M)
    if not m:
        raise ValueError("boot entry has no usrhash=")
    return m.group(1)


def counted_entry(src, version, tries=TRIES):
    """From mkosi's entry text, return (file name, text) of the AgentOS entry for VERSION."""
    usrhash(src)
    for ln in src.splitlines():
        if ln.startswith("options") and re.search(BY_ID, ln):
            raise ValueError("boot entry picks a partition by name or ID: %s" % ln)
    body = [ln for ln in src.splitlines() if not re.match(r"(title|version|sort-key)\b", ln)]
    lines = ["title AgentOS", "sort-key agentos", "version %s" % version] + body
    return "agentos_%s+%d.conf" % (version, tries), "\n".join(lines) + "\n"


def boot_files(entry):
    """The ESP paths the entry boots: its linux and initrd lines, without the leading slash."""
    return [ln.split(None, 1)[1].strip().lstrip("/") for ln in entry.splitlines()
            if re.match(r"(linux|initrd)\s", ln)]


def esp_violations(paths, entry):
    """ESP files outside the allowlist (HW-1). paths: every file on the ESP, relative."""
    allowed = set(boot_files(entry))
    return sorted(p for p in paths
                  if re.search(ESP_FORBIDDEN, p)
                  or p not in allowed and not any(re.fullmatch(a, p) for a in ESP_ALLOWED))


def initrd_names(data):
    """File names in an initrd: newc cpio archives, concatenated and zero-padded, the last one
    possibly compressed (zstd, xz or gzip)."""
    names, i = [], 0
    while i < len(data):
        if data[i] == 0:
            i += 1
            continue
        magic = data[i:i + 6]
        if magic in (b"070701", b"070702"):
            while True:
                f = [int(data[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
                size, namesize = f[6], f[11]
                name = data[i + 110:i + 110 + namesize - 1].decode("utf-8", "replace")
                i += 110 + namesize
                i += -i % 4
                if name == "TRAILER!!!":
                    break
                names.append(name)
                i += size
                i += -i % 4
            continue
        for sig, tool in ((b"\x28\xb5\x2f\xfd", "zstd"), (b"\xfd7zXZ", "xz"), (b"\x1f\x8b", "gzip")):
            if data[i:i + len(sig)] == sig:
                out = subprocess.run([tool, "-dc"], input=data[i:], capture_output=True, check=True).stdout
                return names + initrd_names(out)
        raise ValueError("unreadable initrd at byte %d" % i)
    return names


def initrd_violations(names):
    """What is wrong with an initrd's file list: a missing drive ID check, or LVM or MD tools."""
    names = [n.lstrip("./") for n in names]
    out = ["missing %s" % r for r in INITRD_REQUIRED if r not in names]
    out += ["assembles LVM or MD: %s" % n for n in names if re.search(INITRD_FORBIDDEN, n)]
    return out


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


def esp_offset(img):
    t = json.loads(subprocess.check_output(["sfdisk", "-J", img]))["partitiontable"]
    check_seed_disk(t["id"])
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
    boot = {}
    for p in boot_files(text):
        data_ = subprocess.check_output(["mtype", "-i", fs, "::/" + p])
        boot[p] = hashlib.sha256(data_).hexdigest()
        if re.match(r"initrd\s+/?%s$" % re.escape(p), next(l for l in text.splitlines() if p in l)):
            bad = initrd_violations(initrd_names(data_))
            if bad:
                sys.exit("initrd check: %s" % bad)
            print("initrd check: clean")
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
