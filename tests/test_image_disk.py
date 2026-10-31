"""IMG-disk (#4317): the image build has a guaranteed runner disk budget and fails fast when short.
systemd-repart died mid-copy with ENOSPC when the runner's disk, not the image's partition, filled
up. image.yml frees the runner's unused toolchains, then a guard checks every file system the job
writes to against DISK_NEED_GB and stops with both numbers; a last step fails a job whose sampled
growth reached the budget, so the PR that grows the build is the one that goes red. These tests run
the workflow's own step scripts against a stand-in df."""
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

# A stand-in df: every path is on one file system whose avail and used (MB) come from files.
FAKE_DF = """#!/bin/sh
d=$(dirname "$0")
for a in "$@"; do case "$a" in --output=*) col=${a#--output=};; esac; done
case "$col" in
  target) echo "Mounted on"; echo /;;
  avail) echo Avail; echo "$(cat "$d/avail")M";;
  used) echo Used; echo "$(cat "$d/used")M";;
esac
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

    def run_step(self, name, avail_mb, used_mb, need="30"):
        (self.t / "bin" / "avail").write_text(str(avail_mb))
        (self.t / "bin" / "used").write_text(str(used_mb))
        env = dict(os.environ, PATH="%s:%s" % (self.t / "bin", os.environ["PATH"]),
                   RUNNER_TEMP=str(self.t / "temp"), DISK_NEED_GB=need)
        p = subprocess.Popen(["bash", "-e", "-o", "pipefail", "-c", run_script(name)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)
        self.procs.append(p)
        out, _ = p.communicate(timeout=30)
        return p.returncode, out

    def test_guard_fails_fast_with_both_numbers_when_short(self):
        rc, out = self.run_step("Disk budget", avail_mb=20 * 1024, used_mb=50000)
        self.assertNotEqual(rc, 0)
        self.assertIn("::error title=disk budget::image build needs 30 GB free on /, runner has 20 GB", out)
        self.assertFalse((self.t / "temp" / "disk.base").exists())

    def test_guard_passes_and_samples_when_the_budget_is_there(self):
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000)
        self.assertEqual(rc, 0, out)
        self.assertIn("disk budget: image build needs 30 GB free on /, runner has 31 GB", out)
        self.assertEqual((self.t / "temp" / "disk.base").read_text().strip(), "50000")
        samples = self.t / "temp" / "disk.samples"
        for _ in range(50):
            if samples.exists() and samples.read_text().strip():
                break
            time.sleep(0.1)
        self.assertEqual(samples.read_text().split()[0], "50000")

    def held(self, grew_mb):
        (self.t / "temp" / "disk.base").write_text("50000\n")
        (self.t / "temp" / "disk.samples").write_text("50000\n%d\n" % (50000 + grew_mb))
        rc, out = self.run_step("Disk budget held", avail_mb=0, used_mb=50000)
        (self.t / "temp" / "disk.samples").unlink()
        return rc, out

    def test_held_fails_a_job_that_reached_its_budget(self):
        self.run_step("Disk budget", avail_mb=40 * 1024, used_mb=50000)
        rc, out = self.held(30 * 1024)
        self.assertNotEqual(rc, 0)
        self.assertIn("::error title=disk budget::image build used 30 GB", out)
        rc, out = self.held(29 * 1024)
        self.assertEqual(rc, 0, out)
        self.assertIn("grew its disk use by at most 29 GB of its 30 GB budget", out)

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
        # The guard checks the file system of each place the job writes.
        for p in ('"$RUNNER_TEMP"', "/var/tmp", "/tmp", "/root"):
            self.assertIn(p, run_script("Disk budget").splitlines()[0])

if __name__ == "__main__":
    unittest.main()
