"""IMG-disk (#4317), IMG-disk-2 (#4366): the image build has a guaranteed runner disk budget and fails
fast when short, naming the runner's cloud.
systemd-repart died mid-copy with ENOSPC when the runner's disk, not the image's partition, filled
up. image.yml frees the runner's unused toolchains, then a guard checks every file system the job
writes to against DISK_NEED_GB and stops with both numbers; a last step fails a job whose sampled
growth, plus the largest rise in one sample interval (a peak between samples), reached the budget,
so the PR that grows the build is the one that goes red. These tests run the workflow's own step
scripts against a stand-in df that has several file systems."""
import json
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/image.yml"

# A stand-in df with several file systems: fs.json maps each mount point to [avail MB, used MB],
# and a path is on the mount that is its longest prefix (as df reports the mount of a path).
FAKE_DF = """#!/usr/bin/env python3
import json, os, sys
fs = json.load(open(os.path.join(os.path.dirname(sys.argv[0]), "fs.json")))
col = next(a.split("=", 1)[1] for a in sys.argv[1:] if a.startswith("--output="))
def mount(p):
    return max((m for m in fs if p == m or p.startswith(m.rstrip("/") + "/")), key=len)
print({"target": "Mounted on", "avail": "Avail", "used": "Used"}[col])
for p in (a for a in sys.argv[1:] if not a.startswith("-")):
    m = mount(p)
    print(m if col == "target" else "%dM" % fs[m][0 if col == "avail" else 1])
"""


def build_steps():
    """The build job's steps as (name or uses, step text), read as text: CI's Python has no YAML."""
    text = WORKFLOW.read_text()
    job = text[text.index("\n  build:\n"):text.index("\n  reproduce:\n")]
    out = []
    for block in re.split(r"\n(?=      - )", job[job.index("    steps:\n") + len("    steps:\n"):]):
        m = re.match(r"      - (?:name|uses): *(.+)", block)
        out.append((m.group(1).strip(), block))
    return job, out


def step(name):
    return next(b for n, b in build_steps()[1] if n == name)


def run_script(name):
    """A `run: |` block's script, dedented."""
    lines = step(name).split("\n")
    i = lines.index("        run: |")
    return "\n".join(l[10:] for l in lines[i + 1:]) + "\n"


class DiskBudgetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = pathlib.Path(self.tmp.name)
        (self.t / "bin").mkdir()
        df = self.t / "bin" / "df"
        df.write_text(FAKE_DF)
        df.chmod(0o755)
        (self.t / "temp").mkdir()
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.tmp.cleanup()

    def run_step(self, name, avail_mb=0, used_mb=0, need="30", fs=None, vendor=None):
        """Runs a step; FS maps mount points to (avail, used) MB, else one file system "/" has them."""
        (self.t / "bin" / "fs.json").write_text(json.dumps(fs or {"/": (avail_mb, used_mb)}))
        dmi = self.t / "dmi"
        dmi.mkdir(exist_ok=True)
        if vendor is not None:
            (dmi / "sys_vendor").write_text(vendor + "\n")
        env = dict(os.environ, PATH="%s:%s" % (self.t / "bin", os.environ["PATH"]),
                   RUNNER_TEMP=str(self.t / "temp"), DISK_NEED_GB=need, DMI_ID=str(dmi))
        p = subprocess.Popen(["bash", "-e", "-o", "pipefail", "-c", run_script(name)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)
        self.procs.append(p)
        out, _ = p.communicate(timeout=30)
        return p.returncode, out

    def test_guard_fails_fast_with_both_numbers_when_short(self):
        rc, out = self.run_step("Disk budget", avail_mb=20 * 1024, used_mb=50000)
        self.assertNotEqual(rc, 0)
        self.assertIn("::error title=disk budget::unknown-cloud (no DMI vendor) runner: image build needs 30 GB free on /, runner has 20 GB", out)
        self.assertFalse((self.t / "temp" / "disk.base").exists())

    def test_guard_passes_and_samples_when_the_budget_is_there(self):
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000)
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=disk budget::unknown-cloud (no DMI vendor) runner: image build needs 30 GB free on /, runner has 31 GB", out)
        self.assertEqual((self.t / "temp" / "disk.base").read_text().strip(), "50000")
        samples = self.t / "temp" / "disk.samples"
        for _ in range(50):
            if samples.exists() and samples.read_text().strip():
                break
            time.sleep(0.1)
        self.assertEqual(samples.read_text().split()[0], "50000")

    def held(self, *grew_mb, final_mb=50000):
        """The held check over samples growing by GREW_MB over a 50000 MB baseline, then FINAL_MB."""
        if not (self.t / "temp" / "disk-used").exists():
            self.run_step("Disk budget", avail_mb=40 * 1024, used_mb=50000)
        (self.t / "temp" / "disk.base").write_text("50000\n")
        (self.t / "temp" / "disk.samples").write_text(
            "".join(g + "\n" if isinstance(g, str) else "%d\n" % (50000 + g) for g in grew_mb))
        rc, out = self.run_step("Disk budget held", avail_mb=0, used_mb=final_mb)
        (self.t / "temp" / "disk.samples").unlink()
        return rc, out

    def ramp(self, top_gb, step_gb=1):
        return [g * 1024 for g in range(0, top_gb + 1, step_gb)]

    def test_held_fails_a_job_that_reached_its_budget(self):
        self.run_step("Disk budget", avail_mb=40 * 1024, used_mb=50000)
        # Growth in 1 GB steps: the bound is the highest sample plus one step.
        rc, out = self.held(*self.ramp(29))
        self.assertNotEqual(rc, 0)
        self.assertIn("::error title=disk budget::image build used 30 GB", out)
        rc, out = self.held(*self.ramp(28))
        self.assertEqual(rc, 0, out)
        self.assertIn("grew its disk use by at most 29 GB of its 30 GB budget (28 GB sampled, plus 1 GB", out)

    def test_held_counts_a_peak_that_falls_between_samples(self):
        # #4366: a short peak between two samples is not seen, so the largest rise in one interval
        # is added to the highest sample. A job that rose 4 GB in one interval and peaked at 26 GB
        # sampled could have peaked at 30 GB between samples: it fails, though no sample reached 30.
        rc, out = self.held(*(self.ramp(22) + [26 * 1024, 2 * 1024]))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("image build used 30 GB", out)
        rc, out = self.held(*(self.ramp(22) + [25 * 1024, 2 * 1024]))
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 28 GB of its 30 GB budget (25 GB sampled, plus 3 GB", out)
        # The first sample's rise over the baseline counts too, and so does the final reading.
        rc, out = self.held(29 * 1024 + 512)
        self.assertNotEqual(rc, 0, out)
        rc, out = self.held(0, final_mb=50000 + 30 * 1024)
        self.assertNotEqual(rc, 0, out)

    def test_held_skips_an_empty_sample_and_fails_closed_on_an_unreadable_reading(self):
        # An empty sample (one df that failed) is skipped, not read as 0.
        rc, out = self.held(1024, "", 1024)
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 2 GB of its 30 GB budget (1 GB sampled, plus 1 GB", out)
        # An empty final reading (df failed) fails the job instead of passing it as no growth.
        (self.t / "temp" / "disk.base").write_text("50000\n")
        (self.t / "temp" / "disk-used").write_text("#!/bin/sh\nexit 0\n")
        rc, out = self.run_step("Disk budget held")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("::error title=disk budget::cannot read the disk use", out)

    def test_held_passes_quietly_when_the_guard_never_ran(self):
        rc, out = self.run_step("Disk budget held", avail_mb=0, used_mb=0)
        self.assertEqual(rc, 0, out)
        self.assertIn("no baseline", out)

    def test_order_and_budget(self):
        job, steps = build_steps()
        names = [n for n, _ in steps]
        self.assertLess(names.index("Free runner disk"), names.index("Install build and boot tools"))
        self.assertEqual(names[names.index("Disk budget") + 1], "Build image")
        self.assertEqual(names[-1], "Disk budget held")
        self.assertIn("        if: always()\n", step("Disk budget held"))
        need = re.search(r'^      DISK_NEED_GB: "(\d+)"', job, re.M)
        self.assertGreater(int(need.group(1)), 0)
        # The guard checks the file system of each place the job writes, and samples every second.
        dfline = next(l for l in run_script("Disk budget").splitlines() if l.startswith("df "))
        for p in ('"$RUNNER_TEMP"', "/var/tmp", "/tmp", "/root"):
            self.assertIn(p, dfline)
        self.assertIn("; sleep 1; done", run_script("Disk budget"))
        # The build writes where the guard looks: its output in RUNNER_TEMP, HOME and GOCACHE.
        build = step("Build image")
        for p in ("HOME=/root", "GOCACHE=/tmp/", '"$RUNNER_TEMP/out"'):
            self.assertIn(p, build)

    def test_guard_reads_each_file_system_the_build_writes_to(self):
        # #4366: RUNNER_TEMP on its own small disk, /tmp on another, /var/tmp and /root on "/".
        temp = str(self.t / "temp")
        fs = {"/": (100 * 1024, 40000), temp: (10 * 1024, 1000), "/tmp": (35 * 1024, 2000)}
        rc, out = self.run_step("Disk budget", fs=fs)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("::error title=disk budget::unknown-cloud (no DMI vendor) runner: image build needs 30 GB free on %s, runner has 10 GB" % temp, out)
        self.assertEqual(out.count("::error"), 1, out)
        # One notice per file system: /var/tmp and /root share "/" and are read once.
        for m, gb in (("/", 100), (temp, 10), ("/tmp", 35)):
            self.assertEqual(out.count("::notice title=disk budget::unknown-cloud (no DMI vendor) runner: "
                                       "image build needs 30 GB free on %s, runner has %d GB\n" % (m, gb)), 1, out)
        self.assertEqual(out.count("::notice"), 3, out)

    def test_growth_sums_every_file_system(self):
        temp = str(self.t / "temp")
        fs = {"/": (100 * 1024, 40000), temp: (40 * 1024, 1000), "/tmp": (35 * 1024, 2000)}
        rc, out = self.run_step("Disk budget", fs=fs)
        self.assertEqual(rc, 0, out)
        self.assertEqual((self.t / "temp" / "disk.base").read_text().strip(), "43000")

    def test_guard_names_the_runner_cloud(self):
        # #4366: the ENOSPC sightings ran on AWS machines, the evidence runs on Azure ones. An
        # AWS-sized disk short of the budget fails with the provider named.
        rc, out = self.run_step("Disk budget", avail_mb=20 * 1024, used_mb=50000, vendor="Amazon EC2")
        self.assertNotEqual(rc, 0)
        self.assertIn("::error title=disk budget::AWS runner: image build needs 30 GB free on /, runner has 20 GB; "
                      "free more in \"Free runner disk\"", out)
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000, vendor="Microsoft Corporation")
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=disk budget::Azure runner: image build needs 30 GB free on /", out)
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000, vendor="QEMU")
        self.assertIn("unknown-cloud (QEMU) runner:", out)

if __name__ == "__main__":
    unittest.main()
