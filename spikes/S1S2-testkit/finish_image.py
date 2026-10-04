"""Turn mkosi's single boot entry into the test kit's two counted entries, in the image's ESP.

rollback  version 2, +2 tries, sorts first; boots that never bless themselves.
good      version 1, +3 tries; systemd-boot falls back to it once rollback's tries run out.
Uses mtools on the raw image, so no loop devices or mounts are needed."""
import json
import re
import subprocess
import sys

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"


def esp_offset(img):
    t = json.loads(subprocess.check_output(["sfdisk", "-J", img]))["partitiontable"]
    p = next(p for p in t["partitions"] if p["type"].lower() == ESP)
    return p["start"] * t.get("sectorsize", 512)


def entries_for(src):
    """From mkosi's entry text, build {filename: text} for the two test kit entries."""
    body = [ln for ln in src.splitlines() if not re.match(r"(title|version|sort-key)\b", ln)]
    out = {}
    for name, ver, tries, title, extra in (
            ("rollback", 2, 2, "AgentOS test kit (rollback test)",
             " agentos.tk=rollback systemd.mask=systemd-bless-boot.service"),
            ("good", 1, 3, "AgentOS test kit", " agentos.tk=good")):
        lines = ["title %s" % title, "sort-key agentos-tk", "version %d" % ver]
        lines += [ln + extra if ln.startswith("options ") else ln for ln in body]
        out["agentos-tk-%s+%d.conf" % (name, tries)] = "\n".join(lines) + "\n"
    return out


def main(img):
    fs = "%s@@%d" % (img, esp_offset(img))
    names = subprocess.check_output(["mdir", "-i", fs, "-b", "::/loader/entries"], text=True).split()
    names = [n.rsplit("/", 1)[-1] for n in names if n.endswith(".conf")]
    if len(names) != 1:
        sys.exit("expected one mkosi boot entry, found %s" % names)
    src = subprocess.check_output(["mtype", "-i", fs, "::/loader/entries/" + names[0]], text=True)
    for fname, text in entries_for(src).items():
        subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/entries/" + fname], input=text.encode(), check=True)
    subprocess.run(["mdel", "-i", fs, "::/loader/entries/" + names[0]], check=True)
    # No menu: boot the first entry at once. A held key still shows the menu on a PC with a screen.
    subprocess.run(["mcopy", "-o", "-i", fs, "-", "::/loader/loader.conf"], input=b"timeout 0\n", check=True)
    print(subprocess.check_output(["mdir", "-i", fs, "::/loader/entries"], text=True))


if __name__ == "__main__":
    main(sys.argv[1])
