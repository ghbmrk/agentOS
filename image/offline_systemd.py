#!/usr/bin/env python3
"""The built image's own systemd, run offline over the image's tree, for checks that ask what systemd
makes of the units instead of modelling how it reads them (#4667; shared with the unit-rule lint, #4677).

run() starts the tree's /usr/lib/systemd/systemd in test mode (`--test --system --unit=UNIT`). That
loads every unit UNIT reaches, runs the generators (so units written from etc/fstab and the kernel
command line are there) and prints each loaded unit with every dependency and every setting as systemd
resolved them: aliases, templates, specifiers and all drop-ins already applied. units() reads that dump.

The namespace (RUN) keeps the runner out of what systemd reads. The tree is overlaid, so /tmp is
writable without a mount: systemd would read a mount there as an active tmp.mount and skip its
dependencies. /proc is private and its cmdline is the boot entry's. /sys holds only the cgroup tree
that test mode needs. /dev holds five character devices. PID 1 of the namespace is a shell, never
systemd. Test mode refuses root, so systemd runs as nobody. It needs real root to set this up: in a
user namespace systemd cannot fork its generator sandbox, and mkosi's script sandbox has no /sys,
which is why this runs on the CI runner against the built disk (built_tree()), not in mkosi.finalize.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import finish_image  # noqa: E402

RUN = r'''set -eu
R=$1 USR=$2 PLANT=$3 CMDLINE=$4 UNIT=$5
W=$(mktemp -d)
mount -t tmpfs -o mode=755 tmpfs "$W"
mkdir "$W/upper" "$W/work" "$W/root"
[ -z "$PLANT" ] || cp -a "$PLANT/." "$W/upper/"
mount -t overlay -o "lowerdir=$R,upperdir=$W/upper,workdir=$W/work" overlay "$W/root"
N=$W/root
mount --rbind "$USR" "$N/usr"
mount -t proc -o nosuid,nodev,noexec proc "$N/proc"
printf "%s\n" "$CMDLINE" >"$W/cmdline"
mount --bind "$W/cmdline" "$N/proc/cmdline"
mount -t tmpfs -o mode=755 tmpfs "$N/sys"
mkdir -p "$N/sys/fs/cgroup"
mount --rbind /sys/fs/cgroup "$N/sys/fs/cgroup"
mount -t tmpfs -o mode=755 tmpfs "$N/dev"
for n in null zero full random urandom; do : >"$N/dev/$n"; mount --bind "/dev/$n" "$N/dev/$n"; done
mount -t tmpfs -o mode=755 tmpfs "$N/run"
mkdir -p "$N/tmp" && chmod 1777 "$N/tmp"
chroot "$N" setpriv --reuid=65534 --regid=65534 --clear-groups \
  /usr/lib/systemd/systemd --test --system --unit="$UNIT" --no-pager
'''

UNIT_RE = re.compile(r"^\t-> Unit (\S+):$")
EDGE_RE = re.compile(r"^\t\t([A-Za-z]+): (\S+) \((?:origin|destination)-[a-z-]+(?: (?:origin|destination)-[a-z-]+)*\)$")
SETTING_RE = re.compile(r"^\t\t([^\t:][^:]*): (.*)$")
GENERATOR_RE = re.compile(r"^(/\S+-generators/\S+) failed with exit status \d+\.$")


def run(root, usr, cmdline, unit, plant=""):
    """(exit status, stdout, stderr) of ROOT's own systemd in test mode for UNIT, with USR as /usr, CMDLINE
    as the kernel command line and PLANT (a directory, or "") copied over ROOT, as RUN says. As root."""
    r = subprocess.run(["unshare", "-m", "-p", "-f", "--propagation", "private", "sh", "-c", RUN, "offline-systemd",
                        str(root), str(usr), str(plant), cmdline, unit],
                       capture_output=True, text=True, timeout=600)
    return r.returncode, r.stdout, r.stderr


def units(text):
    """{unit: {"edges": [(kind, target)], "settings": [(key, value)]}} from a test-mode dump's "-> By units:"
    part. A dependency is a line whose value is one unit name and an origin/destination mask; every other
    "Key: value" line of the unit (two tabs deep, so not its job's lines) is a setting, in the dump's order."""
    out, cur = {}, None
    for line in text.split("\n"):
        if line == "-> By jobs:":
            break
        m = UNIT_RE.match(line)
        if m:
            cur = out.setdefault(m.group(1), {"edges": [], "settings": []})
            continue
        if cur is None:
            continue
        m = EDGE_RE.match(line)
        if m:
            cur["edges"].append((m.group(1), m.group(2)))
            continue
        m = SETTING_RE.match(line)
        if m:
            cur["settings"].append((m.group(1), m.group(2)))
    return out


def failed_generator(line):
    """The name of the generator a stderr LINE of run() says failed, or None."""
    m = GENERATOR_RE.match(line.strip())
    return m.group(1).rsplit("/", 1)[1] if m else None


def built_tree(out, version):
    """Mount build OUT's root partition and its verified /usr (finish_image checked it against the entry's
    usrhash=) read-only. Returns (root, usr, the boot entry's command line, cleanup)."""
    out = pathlib.Path(out)
    img = out / ("agentos_%s.raw" % version)
    usr = out / ("agentos_%s.usr.raw" % version)
    entries = sorted(out.glob("agentos_%s*.conf" % version))
    if len(entries) != 1:
        sys.exit("offline systemd: expected one boot entry in %s, found %s" % (out, [e.name for e in entries]))
    cmdline = finish_image.options_line(entries[0].read_text())
    table = finish_image.partition_table(str(img))
    roots = [p for p in table["partitions"] if p["type"].lower() == finish_image.ROOT_GUID]
    if len(roots) != 1:
        sys.exit("offline systemd: expected one root partition in %s, found %d" % (img, len(roots)))
    sector = table.get("sectorsize", 512)
    d = pathlib.Path(tempfile.mkdtemp(prefix="offline-systemd-"))
    (d / "root").mkdir()
    (d / "usr").mkdir()
    subprocess.run(["mount", "-o", "ro,noload,loop,offset=%d,sizelimit=%d" % (roots[0]["start"] * sector,
                                                                             roots[0]["size"] * sector),
                    str(img), str(d / "root")], check=True)
    subprocess.run(["mount", "-t", "erofs", "-o", "ro,loop", str(usr), str(d / "usr")], check=True)

    def cleanup():
        for m in ("usr", "root"):
            subprocess.run(["umount", str(d / m)], check=False)
    return d / "root", d / "usr", cmdline, cleanup
