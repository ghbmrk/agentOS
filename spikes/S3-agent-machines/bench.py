#!/usr/bin/env python3
"""S3 spike: agent-machine density and snapshot/fork/rollback timings at an 8 GiB floor.

Runs as root on Linux with cgroup v1 memory+freezer controllers, bubblewrap and
gVisor's runsc on PATH, and an unpacked rootfs (with node at /opt/node/bin/node).
Every machine is launched inside /sys/fs/cgroup/memory/s3 (limit = --floor GiB),
so all memory it causes (anon, shmem, page cache, kernel) is charged there.

  bench.py density --backend bwrap|gvisor --workload sh|node
  bench.py fill    --backend ... --workload ...      # launch until OOM / failure
  bench.py ops     --backend ...                     # checkpoint / rollback / fork(n)
Results are appended as JSON lines to results.jsonl next to this file.
"""
import argparse
import json
import os
import select
import pathlib
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import analysis  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
WORK = pathlib.Path(os.environ.get("S3_WORK", "/srv/s3"))
BASE = WORK / "base"
MEM = pathlib.Path("/sys/fs/cgroup/memory/s3")
FRZ = pathlib.Path("/sys/fs/cgroup/freezer/s3")
RUNSC_ROOT = WORK / "runsc-state"
GiB, MiB = 1 << 30, 1 << 20

NODE = "/opt/node/bin/node"
# "agent" stands in for a guest runtime with a working set: H MiB of heap that
# does not compress or dedupe, D MiB written to its root filesystem.
AGENT_JS = r"""
const fs=require('fs'),c=require('crypto');
const H=+process.env.HEAP_MB||0, D=+process.env.DISK_MB||0;
globalThis.keep=[];for(let i=0;i<H;i++)keep.push(c.randomBytes(1<<20));
if(D&&!fs.existsSync('/root/data.bin')){const f=fs.openSync('/root/data.bin','w');
for(let i=0;i<D;i++)fs.writeSync(f,c.randomBytes(1<<20));fs.closeSync(f);}
// Probe: touch one byte in every 4 KiB page of the heap and report the sum, so an
// answer proves the guest runs and its whole heap is resident and unchanged.
const sum=()=>{let s=0;for(const b of keep)for(let i=0;i<b.length;i+=4096)s=(s*31+b[i])%2147483647;return s;};
setInterval(()=>{if(fs.existsSync('/root/probe')){fs.unlinkSync('/root/probe');
fs.writeFileSync('/root/probe.tmp',String(sum()));fs.renameSync('/root/probe.tmp','/root/probe.out');}},5);
console.log('ready');
"""
WORKLOADS = {
    "sh": ["/bin/sh", "-c", "echo ready; exec sleep infinity"],
    "node": [NODE, "-e", "console.log('ready');setInterval(()=>{},1<<30)"],
    "agent": [NODE, "-e", AGENT_JS],
}


def w(path, value):
    pathlib.Path(path).write_text(str(value))


def r(path):
    return pathlib.Path(path).read_text()


def setup_cgroups(floor_gib):
    for cg in (MEM, FRZ):
        cg.mkdir(exist_ok=True)
    w(MEM / "memory.limit_in_bytes", int(floor_gib * GiB))


def usage():
    stat = dict(line.split() for line in r(MEM / "memory.stat").splitlines())
    return {
        "usage": int(r(MEM / "memory.usage_in_bytes")),
        "rss": int(stat["total_rss"]),
        "shmem": int(stat.get("total_shmem", 0)),
        "cache": int(stat["total_cache"]),
        "failcnt": int(r(MEM / "memory.failcnt")),
        "oom_kill": int(dict(l.split() for l in r(MEM / "memory.oom_control").splitlines()).get("oom_kill", 0)),
    }


def drop_caches():
    subprocess.run(["sync"])
    w("/proc/sys/vm/drop_caches", 3)


def into_cgroup(name):
    def fn():
        for root in (MEM, FRZ):
            d = root / name
            d.mkdir(exist_ok=True)
            w(d / "cgroup.procs", os.getpid())
        os.setsid()
    return fn


def wait_ready(proc, timeout=60):
    """Block until the workload prints 'ready'; return seconds or None."""
    t0 = time.monotonic()
    buf = b""
    while (left := timeout - (time.monotonic() - t0)) > 0:
        if not select.select([proc.stdout], [], [], left)[0]:
            break
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            return None
        buf += chunk
        if b"ready\n" in buf:
            return time.monotonic() - t0
    return None


class Bwrap:
    name = "bwrap"

    def __init__(self):
        self.procs = {}

    def dirs(self, mid):
        d = WORK / "m" / mid
        return d / "upper", d / "work"

    def unmount(self, mid):
        subprocess.run(["umount", "-l", str(WORK / "m" / mid / "root")], stderr=subprocess.DEVNULL)

    def start(self, mid, argv, env=None, upper_from=None):
        # bwrap 0.9 has no --overlay, so the overlay is mounted on the host and bound in.
        upper, work = self.dirs(mid)
        root = upper.parent / "root"
        self.unmount(mid)
        shutil.rmtree(upper.parent, ignore_errors=True)
        work.mkdir(parents=True)
        root.mkdir()
        if upper_from:
            subprocess.run(["cp", "-a", "--reflink=auto", str(upper_from), str(upper)], check=True)
        else:
            upper.mkdir()
        subprocess.run(["mount", "-t", "overlay", "overlay", "-o",
                        f"lowerdir={BASE},upperdir={upper},workdir={work}", str(root)], check=True)
        cmd = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--bind", str(root), "/",
               "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/root"]
        for k, v in (env or {}).items():
            cmd += ["--setenv", k, str(v)]
        self.procs[mid] = subprocess.Popen(cmd + ["--"] + argv, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, preexec_fn=into_cgroup(mid))
        return self.procs[mid]

    def stop(self, mid):
        p = self.procs.pop(mid, None)
        if p:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        # The guest dies with bwrap's PID namespace, asynchronously; wait until it is gone.
        procs, t0 = MEM / mid / "cgroup.procs", time.monotonic()
        while procs.exists() and r(procs).strip() and time.monotonic() - t0 < 10:
            time.sleep(0.01)
        self.unmount(mid)

    def probe(self, mid, timeout=120):
        """Ask the guest for its heap checksum; returns the answer or None."""
        r = WORK / "m" / mid / "root" / "root"
        (r / "probe.out").unlink(missing_ok=True)
        (r / "probe").touch()
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            if (r / "probe.out").exists():
                return (r / "probe.out").read_text()
            time.sleep(0.005)
        return None

    def verify(self, mid, disk_mb):
        f = self.dirs(mid)[0] / "root" / "data.bin"
        return _alive(self.procs.get(mid)) and f.exists() and f.stat().st_size == disk_mb * MiB

    def checkpoint(self, mid, snap):
        """Filesystem-only checkpoint: freeze, copy upper, thaw. Process memory is not saved."""
        upper, _ = self.dirs(mid)
        shutil.rmtree(snap, ignore_errors=True)
        w(FRZ / mid / "freezer.state", "FROZEN")
        subprocess.run(["cp", "-a", "--reflink=auto", str(upper), str(snap)], check=True)
        w(FRZ / mid / "freezer.state", "THAWED")

    def restore(self, mid, snap, argv, env):
        """Rollback/fork: new machine from the snapshot's filesystem; process restarts."""
        p = self.start(mid, argv, env, upper_from=snap)
        return p, wait_ready(p)


def _alive(p):
    return p is not None and p.poll() is None


class Gvisor:
    name = "gvisor"

    def __init__(self):
        self.procs = {}
        RUNSC_ROOT.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def cid(mid):
        # runsc resolves container IDs by prefix ("d1" matches "d10"), so terminate them.
        return mid + "_"

    def runsc(self, *args):
        return ["runsc", "--root", str(RUNSC_ROOT), "--platform=systrap", "--network=none",
                "--ignore-cgroups", *args]

    def bundle(self, mid, argv, env):
        d = WORK / "m" / mid
        shutil.rmtree(d, ignore_errors=True)
        (d / "upper").mkdir(parents=True)
        cfg = {
            "ociVersion": "1.0.0",
            "process": {"terminal": False, "user": {"uid": 0, "gid": 0}, "args": argv, "cwd": "/root",
                        "env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"] + [f"{k}={v}" for k, v in (env or {}).items()]},
            "root": {"path": str(BASE), "readonly": False},  # writes land in the overlay
            "hostname": mid,
            "mounts": [{"destination": "/proc", "type": "proc", "source": "proc"},
                       {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs"}],
            "linux": {"namespaces": [{"type": t} for t in ("pid", "network", "ipc", "uts", "mount")]},
        }
        (d / "config.json").write_text(json.dumps(cfg))
        return d

    def start(self, mid, argv, env=None):
        d = self.bundle(mid, argv, env)
        cmd = self.runsc(f"--overlay2=root:dir={d / 'upper'}", "run", "--bundle", str(d), self.cid(mid))
        self.procs[mid] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                           preexec_fn=into_cgroup(mid))
        return self.procs[mid]

    def stop(self, mid):
        try:
            subprocess.run(self.runsc("kill", self.cid(mid), "KILL"), stderr=subprocess.DEVNULL, timeout=30)
        except subprocess.TimeoutExpired:
            pass
        p = self.procs.pop(mid, None)
        if p:
            try:
                p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        subprocess.run(self.runsc("delete", "-force", self.cid(mid)), stderr=subprocess.DEVNULL)

    def probe(self, mid, timeout=120):
        sh = ("rm -f /root/probe.out; : > /root/probe; "
              "while [ ! -s /root/probe.out ]; do sleep 0.005; done; cat /root/probe.out")
        try:
            r = subprocess.run(self.runsc("exec", self.cid(mid), "/bin/sh", "-c", sh),
                               capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        return r.stdout.strip() or None

    def verify(self, mid, disk_mb):
        r = subprocess.run(self.runsc("exec", self.cid(mid), "/usr/bin/stat", "-c", "%s", "/root/data.bin"),
                           capture_output=True, text=True)
        return _alive(self.procs.get(mid)) and r.stdout.strip() == str(disk_mb * MiB)

    def checkpoint(self, mid, snap):
        """Full checkpoint (memory + filesystem); the machine keeps running."""
        shutil.rmtree(snap, ignore_errors=True)
        snap.mkdir(parents=True)
        subprocess.run(self.runsc("checkpoint", "--leave-running", f"--image-path={snap}", self.cid(mid)), check=True)

    def restore(self, mid, snap, argv, env):
        d = self.bundle(mid, argv, env)
        t0 = time.monotonic()
        p = subprocess.Popen(self.runsc(f"--overlay2=root:dir={d / 'upper'}", "restore", "--bundle", str(d),
                                        f"--image-path={snap}", self.cid(mid)),
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, preexec_fn=into_cgroup(mid))
        self.procs[mid] = p
        # Restore runs in the foreground; it is up once the container reports "running".
        while time.monotonic() - t0 < 60:
            s = subprocess.run(self.runsc("state", self.cid(mid)), capture_output=True, text=True)
            if s.returncode == 0 and json.loads(s.stdout).get("status") == "running":
                return p, time.monotonic() - t0
            if p.poll() is not None:
                return p, None
            time.sleep(0.01)
        return p, None


BACKENDS = {"bwrap": Bwrap, "gvisor": Gvisor}


def record(kind, **kw):
    kw.update(kind=kind, at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    with open(HERE / "results.jsonl", "a") as f:
        f.write(json.dumps(kw) + "\n")
    print(json.dumps(kw))


def stop_all(be):
    for mid in list(be.procs):
        be.stop(mid)


def density(be, workload, steps, settle):
    drop_caches()
    base = usage()["usage"]
    pts, starts, n = [], [], 0
    for target in steps:
        while n < target:
            p = be.start(f"d{n}", WORKLOADS[workload])
            t = wait_ready(p)
            if t is None:
                raise SystemExit(f"machine d{n} failed to start")
            starts.append(t)
            n += 1
        time.sleep(settle)
        u = usage()
        pts.append((n, u["usage"] - base))
        record("density-point", backend=be.name, workload=workload, n=n, **u, baseline=base)
    b0, slope = analysis.fit_line(pts)
    record("density", backend=be.name, workload=workload, per_instance_mib=round(slope / MiB, 2),
           intercept_mib=round(b0 / MiB, 1), start_s=analysis.summarize(starts), points=len(pts))
    stop_all(be)


def fill(be, workload, cap):
    drop_caches()
    n, starts, reason = 0, [], "cap"
    while n < cap:
        p = be.start(f"f{n}", WORKLOADS[workload])
        t = wait_ready(p, timeout=10)
        u = usage()
        if t is None or u["oom_kill"] or any(q.poll() is not None for q in be.procs.values()):
            reason = "oom" if u["oom_kill"] else "start-failed-or-died"
            break
        starts.append(t)
        n += 1
    u = usage()
    record("fill", backend=be.name, workload=workload, alive=n, stop_reason=reason,
           start_s=analysis.summarize(starts) if starts else None, **u)
    stop_all(be)


def du(path):
    return int(subprocess.run(["du", "-sb", str(path)], capture_output=True, text=True).stdout.split()[0])


def anon_mib(mid):
    st = dict(l.split() for l in r(MEM / mid / "memory.stat").splitlines())
    return (int(st["total_rss"]) + int(st.get("total_shmem", 0))) / MiB


def ops(be, heap_mb, disk_mb, forks, reps):
    """Rollback and fork are timed cold (page cache dropped first) until the guest
    answers a probe that touches every heap page, not just until it is "running"."""
    env = {"HEAP_MB": heap_mb, "DISK_MB": disk_mb}
    argv = WORKLOADS["agent"]
    snaps = WORK / "snaps"
    snaps.mkdir(exist_ok=True)
    cps, rbs, fks = [], [], []
    for rep in range(reps):
        drop_caches()
        p = be.start("src", argv, env)
        create = wait_ready(p, timeout=180)
        if create is None:
            raise SystemExit("source machine failed to start")
        src_sum = be.probe("src")
        src_mib = anon_mib("src")
        snap = snaps / f"s{rep}"
        t0 = time.monotonic()
        be.checkpoint("src", snap)
        cps.append(time.monotonic() - t0)
        size = du(snap)
        be.stop("src")
        drop_caches()
        t0 = time.monotonic()
        be.restore("rb", snap, argv, env)
        rb_sum = be.probe("rb")
        rbs.append(time.monotonic() - t0 if rb_sum else float("nan"))
        intact = be.verify("rb", disk_mb)
        be.stop("rb")
        drop_caches()
        t0 = time.monotonic()
        for i in range(forks):
            be.restore(f"k{i}", snap, argv, env)
        sums = [be.probe(f"k{i}") for i in range(forks)]
        fks.append(time.monotonic() - t0)
        fork_mib = [round(anon_mib(f"k{i}"), 1) for i in range(forks)]
        record("ops-rep", backend=be.name, heap_mb=heap_mb, disk_mb=disk_mb, rep=rep, create_s=create,
               checkpoint_s=cps[-1], snapshot_bytes=size, src_anon_mib=round(src_mib, 1),
               rollback_s=rbs[-1], rollback_files_intact=intact, rollback_heap_preserved=rb_sum == src_sum,
               forks=forks, forks_answered=sum(x is not None for x in sums),
               forks_heap_preserved=sum(x == src_sum for x in sums), fork_total_s=fks[-1],
               fork_anon_mib=fork_mib, timing="cold cache, until heap probe answers")
        stop_all(be)
        shutil.rmtree(snap, ignore_errors=True)
    record("ops", backend=be.name, heap_mb=heap_mb, disk_mb=disk_mb, forks=forks,
           checkpoint_s=analysis.summarize(cps), rollback_s=analysis.summarize(rbs),
           fork_total_s=analysis.summarize(fks), timing="cold cache, until heap probe answers")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["density", "fill", "ops"])
    ap.add_argument("--backend", choices=BACKENDS, required=True)
    ap.add_argument("--workload", choices=WORKLOADS, default="node")
    ap.add_argument("--floor", type=float, default=8.0, help="memory cgroup limit, GiB")
    ap.add_argument("--steps", default="1,2,4,8,16,32")
    ap.add_argument("--settle", type=float, default=3.0)
    ap.add_argument("--cap", type=int, default=400)
    ap.add_argument("--heap-mb", type=int, default=128)
    ap.add_argument("--disk-mb", type=int, default=64)
    ap.add_argument("--forks", type=int, default=4)
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    setup_cgroups(a.floor)
    be = BACKENDS[a.backend]()
    try:
        if a.cmd == "density":
            density(be, a.workload, [int(s) for s in a.steps.split(",")], a.settle)
        elif a.cmd == "fill":
            fill(be, a.workload, a.cap)
        else:
            ops(be, a.heap_mb, a.disk_mb, a.forks, a.reps)
    finally:
        stop_all(be)


if __name__ == "__main__":
    main()
