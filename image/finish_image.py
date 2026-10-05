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
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
TRIES = 3


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


def manifest(version, roothash, entry_name, entry_text, files):
    """The release (UPD-1a): /usr verity root hash plus the boot entry that mounts it."""
    if usrhash(entry_text) != roothash:
        raise ValueError("entry usrhash %s != /usr root hash %s" % (usrhash(entry_text), roothash))
    return {
        "version": version,
        "usrhash": roothash,
        "boot_entry": {"name": re.sub(r"\+\d+(-\d+)?\.conf$", ".conf", entry_name),
                       "sha256": hashlib.sha256(entry_text.encode()).hexdigest()},
        "files": files,
    }


def esp_offset(img):
    t = json.loads(subprocess.check_output(["sfdisk", "-J", img]))["partitiontable"]
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
    # No menu: boot the default entry at once. A held key still shows the menu on a PC with a screen.
    subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/loader.conf"], input=b"timeout 0\n", check=True)
    (out / name).write_text(text)
    # Check the /usr partition and its hash tree against the entry's usrhash, independently of mkosi.
    roothash = usrhash(text)
    data, tree = out / ("agentos_%s.usr.raw" % version), out / ("agentos_%s.usr-verity.raw" % version)
    subprocess.run(["veritysetup", "verify", str(data), str(tree), roothash], check=True)
    # Only the two files just verified: mkosi also leaves arch-named split copies beside them.
    files = {p.name: sha256(p) for p in (data, tree)}
    m = manifest(version, roothash, name, text, files)
    (out / ("agentos_%s.release.json" % version)).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    print(json.dumps(m, indent=2, sort_keys=True))


if __name__ == "__main__":
    main(*sys.argv[1:3])
