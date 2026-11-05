#!/usr/bin/env python3
"""The built image's own systemd, running offline over the image's tree, for checks that ask systemd
what it makes of the units instead of modelling how it reads them (#4667, and the unit-rule lint,
#4677).

Manager boots the tree's /usr/lib/systemd/systemd as PID 1 of a container (MANAGER) and asks it over
its private bus with the runner's systemctl (CTL). show() returns properties as systemd resolved them:
aliases, templates, specifiers and every drop-in are already applied, and generators have run, so units
written from etc/fstab and the kernel command line are there too. Callers ask only for properties whose
values cannot hold a newline (unit names, enums, paths), so no unit's text can pose as systemd's reply.
An earlier version parsed `systemd --test`'s dump, and an Environment= value could write a fake unit
header into that (#4779 Security round 1).

The container has its own mount, UTS, IPC, PID, network and cgroup namespaces, a read-only /proc/sys
and a nodev /dev, so PID 1 cannot set the runner's hostname or a global sysctl. It is still real root
on the runner, as are the generators it runs; the tree is the build's own. Container mode means some
generators see a different machine than the box: fstab-generator skips fstab entries that name a device
(callers refuse those in the tree themselves), and gpt-auto-generator finds no disk. A runner booted by
systemd gives the manager a delegated scope of its own. The console is a pty, read for the lines PID 1
logs (failed generators).
"""
import os
import pathlib
import re
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import tty

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import finish_image  # noqa: E402

# The tree's own systemd as PID 1 of a container: an overlay of the tree (writable, so nothing needs
# a mount over it), its own /usr, a private /proc with /proc/sys read-only, a /sys with only a cgroup2
# tree in its own cgroup namespace, five character devices and a pty as console, an empty /run, no network. It starts only
# -.slice, which every manager has and which starts nothing. Its argv is the boot entry's command line,
# which systemd in a container reads as the kernel's, then the pinned options (manager_argv).
MANAGER = r'''set -eu
R=$1 USR=$2 PLANT=$3 CONSOLE=$4
shift 4
W=$(mktemp -d)
mount -t tmpfs -o mode=755 tmpfs "$W"
mkdir "$W/upper" "$W/work" "$W/root"
[ -z "$PLANT" ] || cp -a "$PLANT/." "$W/upper/"
mount -t overlay -o "lowerdir=$R,upperdir=$W/upper,workdir=$W/work" overlay "$W/root"
N=$W/root
mkdir -p "$N/usr" "$N/proc" "$N/sys" "$N/dev" "$N/run" "$N/tmp"  # the built root partition leaves out /usr
mount --rbind "$USR" "$N/usr"
mount -t proc -o nosuid,nodev,noexec proc "$N/proc"
mount --bind "$N/proc/sys" "$N/proc/sys"; mount -o remount,bind,ro "$N/proc/sys"  # no global sysctl from here
mount -t tmpfs -o mode=755 tmpfs "$N/sys"
mkdir -p "$N/sys/fs/cgroup"
mount -t cgroup2 cgroup2 "$N/sys/fs/cgroup"
mount -t tmpfs -o mode=755,nosuid,nodev tmpfs "$N/dev"
for n in null zero full random urandom; do : >"$N/dev/$n"; mount --bind "/dev/$n" "$N/dev/$n"; done
: >"$N/dev/console"; mount --bind "$CONSOLE" "$N/dev/console"
mount -t tmpfs -o mode=755 tmpfs "$N/run"
chmod 1777 "$N/tmp"
exec env -i container=agentos-offline "$(command -v chroot)" "$N" /usr/lib/systemd/systemd "$@"
'''
# The runner's systemctl, in the manager's PID namespace (systemd refuses a bus peer it cannot see),
# reaching its private bus through /proc/PID/root.
CTL = r'''set -eu
S=$1; shift
mount -t tmpfs -o mode=755 tmpfs /run
mkdir -p /run/systemd/system
ln -s "$S" /run/systemd/private
exec systemctl "$@"
'''
# How PID 1 says a generator failed (systemd 257 exec-util.c do_execute, process-util.c
# wait_for_terminate_and_check): one console line, the generator's path, then an exit status, a signal or
# no reason. Any other console line that names a generator directory (a world-writable warning, a stat
# that failed) counts as a failure too, named by the line itself.
GENERATOR_FAILED = re.compile(r"(/\S*-generators/.+?) (failed with exit status \d+|terminated by signal \S+|"
                              r"failed due to unknown reason)(, ignoring)?\.")
# A generator still running at systemd's 90 s generator timeout is killed with no line (the executor
# dies of SIGALRM, unlogged), so a run that came within GENERATOR_SLACK_S of it counts as a failure.
GENERATOR_TIMEOUT_S, GENERATOR_SLACK_S = 90, 10
GENERATOR_TIMEOUT = "(generators ran into systemd's 90 s timeout)"


def generator_failures(text):
    """The failures the console TEXT shows, by generator file name, or by the whole line where it names
    a generator directory in another form."""
    out = set()
    for line in text.split("\n"):
        line = line.strip()
        if "-generators/" not in line:
            continue
        m = GENERATOR_FAILED.fullmatch(line)
        out.add(m.group(1).rsplit("/", 1)[1] if m else line[:300])
    return out


class Manager:
    """The tree at ROOT (with USR as /usr, PLANT, a directory or "", copied over it, and CMDLINE as the
    kernel command line) under its own running systemd. As root. view_root is the tree as it sees it."""

    def __init__(self, root, usr, cmdline, plant=""):
        # The manager's console is a pty whose other end is drained into self.log. systemd in a container
        # logs to the console only when it is a terminal (open_terminal refuses a regular file), and that
        # log is where it says a generator failed.
        self.log = tempfile.NamedTemporaryFile(prefix="offline-systemd-console-")
        self.err = tempfile.NamedTemporaryFile(prefix="offline-systemd-stderr-")
        self.master, self.slave = os.openpty()
        tty.setraw(self.slave)
        self.lock = threading.Lock()
        self.drain = threading.Thread(target=self._drain, daemon=True)
        self.drain.start()
        wrap = []
        if os.path.isdir("/run/systemd/system"):  # a runner booted by systemd: a delegated scope of our own
            wrap = ["systemd-run", "--scope", "--quiet", "-p", "Delegate=yes", "--"]
        self.proc = subprocess.Popen(wrap + manager_argv(root, usr, cmdline, plant, os.ttyname(self.slave)),
                                     stdout=subprocess.DEVNULL, stderr=self.err)
        self.pid = None
        try:
            self.wait()
        except BaseException:
            self.stop()
            raise
        self.view_root = "/proc/%d/root" % self.pid

    def _drain(self):
        while self._pump(0.2) is not None:
            pass

    def _pump(self, wait):
        """Copy what the pty holds to self.log, waiting up to WAIT seconds for some. None once it is closed.
        The wait is outside the lock, so a reader that takes it never waits behind a select (Python's lock
        is not fair: a thread that releases and retakes it can starve the other)."""
        try:
            ready = select.select([self.master], [], [], wait)[0]
        except (OSError, ValueError):
            return None
        if not ready:
            return 0
        with self.lock:
            try:
                if not select.select([self.master], [], [], 0)[0]:
                    return 0
                data = os.read(self.master, 65536)
            except (OSError, ValueError):
                return None
            if not data:
                return None
            self.log.write(data)
            self.log.flush()
            return len(data)

    def wait(self, timeout=120):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                break
            try:
                with open("/proc/%d/task/%d/children" % (self.proc.pid, self.proc.pid)) as f:
                    kids = f.read().split()
            except OSError:
                kids = []
            if kids:
                self.pid = int(kids[0])
                r = self.ctl(["show", "-p", "SystemState", "--value"], check=False)
                if r.returncode == 0 and r.stdout.strip() in ("running", "degraded"):
                    return
            time.sleep(0.2)
        raise SystemExit("offline systemd: the tree's systemd did not start: %s" % self.console())

    def console(self):
        out = ""
        for f in (self.err, self.log):
            try:
                out += pathlib.Path(f.name).read_text(errors="replace")[-3000:]
            except OSError:
                pass
        return out

    def failed_generators(self):
        """The generators that failed in this run (generator_failures() of the whole console, after the pty
        is drained), plus GENERATOR_TIMEOUT when the generators ran close to systemd's timeout."""
        while self._pump(0):
            pass
        with self.lock:  # the drain thread may hold a chunk it read but has not yet written (#4876)
            pass
        out = generator_failures(pathlib.Path(self.log.name).read_text(errors="replace"))
        t = self.manager(("GeneratorsStartTimestampMonotonic", "GeneratorsFinishTimestampMonotonic"))
        start, finish = int(t["GeneratorsStartTimestampMonotonic"]), int(t["GeneratorsFinishTimestampMonotonic"])
        if not finish or finish - start >= (GENERATOR_TIMEOUT_S - GENERATOR_SLACK_S) * 1000000:
            out.add(GENERATOR_TIMEOUT)
        return out

    def ctl(self, args, check=True):
        r = subprocess.run(["nsenter", "-t", str(self.pid), "-p", "--", "unshare", "-m", "--propagation", "private",
                            "sh", "-c", CTL, "offline-systemd-ctl", "/proc/%d/root/run/systemd/private" % self.pid]
                           + args, capture_output=True, text=True, timeout=300)
        if check and r.returncode != 0:
            raise SystemExit("offline systemd: systemctl %s: %s" % (" ".join(args[:3]), r.stderr[-2000:]))
        return r

    def manager(self, props):
        """{prop: value} of the manager itself."""
        return parse_block(self.ctl(["show", "-p", ",".join(props)]).stdout.rstrip("\n"), props, "the manager")

    def show(self, units, props):
        """{name: {prop: value}} for each of UNITS, one systemctl reply block each, in order. Id and Names are
        always asked for, and a block whose Names lack the unit asked for is refused. Ask only for properties
        whose values hold no newline."""
        props = ("Id", "Names") + tuple(p for p in props if p not in ("Id", "Names"))
        out = {}
        units = list(units)
        for i in range(0, len(units), 200):
            batch = units[i:i + 200]
            text = self.ctl(["show", "--all", "-p", ",".join(props), "--"] + batch).stdout
            blocks = text.rstrip("\n").split("\n\n") if text.strip() else []
            if len(blocks) != len(batch):
                raise SystemExit("offline systemd: systemctl gave %d blocks for %d units" % (len(blocks), len(batch)))
            for name, block in zip(batch, blocks):
                got = parse_block(block, props, name)
                if name not in shell_words(got["Names"], name):
                    raise SystemExit("offline systemd: %s: systemctl gave %s" % (name, got))
                out[name] = got
        return out

    def stop(self):
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.proc.kill()
        self.proc.wait()
        os.close(self.slave)
        with self.lock:
            os.close(self.master)
            self.master = -1
        self.drain.join(5)
        self.log.close()
        self.err.close()


# systemd's own options, after the boot entry's words: its getopt_long permutes argv and the last value
# of an option wins, so no entry word can change these (#4767 Security release 2, #4876). The console
# target and info level keep the generator-failure lines (LOG_ERR, LOG_WARNING) on the console;
# parse_argv runs after system.conf and the command line, so LogLevel= and systemd.log_level= lose too.
PINNED = ("--unit=-.slice", "--log-target=console", "--log-level=info")


def manager_argv(root, usr, cmdline, plant, console):
    """unshare's argv for MANAGER over the tree: the boot entry's CMDLINE words, then PINNED. A word that
    starts with "-" is refused: "--" would end systemd's option parsing before PINNED, and a short option
    that takes an argument ("-z") would swallow the first of them."""
    words = cmdline.split()
    bad = [w for w in words if w.startswith("-")]
    if bad:
        raise SystemExit("offline systemd: the boot entry's command line holds options %r" % bad)
    return (["unshare", "-m", "-u", "-i", "-p", "-f", "-n", "-C", "--propagation", "private",
             "sh", "-c", MANAGER, "offline-systemd", str(root), str(usr), str(plant), console]
            + words + list(PINNED))


def shell_words(value, name):
    """A list property's entries. systemctl quotes an entry with a backslash in it ("a\\x2db.device"), as a
    shell word, so the list is split as one."""
    try:
        return shlex.split(value)
    except ValueError as e:
        raise SystemExit("offline systemd: %s: %r is not a list (%s)" % (name, value, e))


def parse_block(block, props, name):
    """{prop: value} from one systemctl show block: each line one of PROPS, each once, all of them."""
    got = {}
    for line in block.split("\n"):
        k, sep, v = line.partition("=")
        if not sep or k not in props or k in got:
            raise SystemExit("offline systemd: %s: systemctl line %r" % (name, line))
        got[k] = v
    if set(got) != set(props):
        raise SystemExit("offline systemd: %s: systemctl gave %s" % (name, sorted(got)))
    return got


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
