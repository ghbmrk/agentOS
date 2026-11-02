"""IMG-disk (#4317), IMG-disk-2 (#4366), IMG-disk-4 (#4434): the image build has a guaranteed runner disk budget and fails
fast when short, naming the runner's cloud.
systemd-repart died mid-copy with ENOSPC when the runner's disk, not the image's partition, filled
up. image.yml frees the runner's unused toolchains, then a guard checks every file system the job
writes to against DISK_NEED_GB and stops with both numbers; a last step fails a job whose sampled
growth, plus the largest rise in one sample interval (a peak between samples), reached the budget,
so the PR that grows the build is the one that goes red. These tests never run the workflow's text:
they run the test's own copies of the steps, each checked against its step byte for byte, against a
stand-in df that has several file systems ("Free runner disk", whose sudo deletes no test runs, only
as copies of its df read and notices: #4440, #4541). Its messages add up, say a bound is a bound,
and give a next step that works for the mount that is short."""
import difflib
import json
import os
import pathlib
import re
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

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

# A stand-in sudo that runs nothing and logs each call, first on PATH for every step a test runs:
# a backstop that run_step asserts was never called.
FAKE_SUDO = """#!/bin/sh
printf '%s\\n' "$*" >> "$(dirname "$0")/sudo.log"
"""

# #4440: the "Free runner disk" step deletes toolchains through sudo, so no test runs its text.
# The test owns these copies of the step's df read and notices, checks that each is a line of the
# step byte for byte, and runs only its copies. An edit to one of these lines in image.yml fails
# the test until the copy here is changed to match in the same PR.
FREE_DISK_GB = "gb() { echo $(( $(df -BM --output=avail / | tail -n 1 | tr -dc 0-9) / 1024 )); }"
FREE_DISK_NOTICES = (
    'echo "::notice title=disk budget::/ had $(gb) GB free before freeing the runner disk"',
    'echo "::notice title=disk budget::/ has $(gb) GB free after freeing the runner disk"',
)


# IMG-disk-6 (#4541): the "Disk budget" steps run in tests, so the test owns whole copies of their scripts
# and runs only those. Each copy must equal its step's script byte for byte; the step's text is only
# compared, never run, so no edit to image.yml (a full-path sudo, a repo script) reaches the shell here.
# An edit to either step fails the test until its copy here is changed to match in the same PR.
DISK_BUDGET = r"""vendor=$(cat "${DMI_ID:-/sys/class/dmi/id}/sys_vendor" 2>/dev/null || true)
case "$vendor" in
  "Amazon EC2"*) cloud=AWS;; "Microsoft Corporation"*) cloud=Azure;; *) cloud="unknown-cloud (${vendor:-no DMI vendor})";;
esac
df -BM --output=target "$RUNNER_TEMP" /var/tmp /tmp /root | tail -n +2 | sort -u > "$RUNNER_TEMP/disk.mounts"
fail=0
while read -r m; do
  have=$(( $(df -BM --output=avail "$m" | tail -n 1 | tr -dc 0-9) / 1024 ))
  echo "::notice title=disk budget::$cloud runner: image build needs $DISK_NEED_GB GB free on $m, runner has $have GB"
  # "Free runner disk" frees space on / only; a short mount of its own needs the build's writes moved.
  if [ "$m" = / ]; then fix='free more in "Free runner disk"'
  else fix="$m is its own file system, which \"Free runner disk\" does not free: move what every step of this job writes under $m to a directory on /, and put that directory in place of $m in this step's df line"; fi
  [ "$have" -ge "$DISK_NEED_GB" ] || { echo "::error title=disk budget::$cloud runner: image build needs $DISK_NEED_GB GB free on $m, runner has $have GB; $fix"; fail=1; }
done < "$RUNNER_TEMP/disk.mounts"
[ "$fail" = 0 ]
# Used MB summed over those file systems (awk reads "1234M" as 1234).
printf '%s\n' '#!/bin/sh' 'xargs -d "\n" df -BM --output=used < "$RUNNER_TEMP/disk.mounts" | awk "NR > 1 {s += \$1} END {print s}"' > "$RUNNER_TEMP/disk-used"
chmod +x "$RUNNER_TEMP/disk-used"
"$RUNNER_TEMP/disk-used" > "$RUNNER_TEMP/disk.base"
nohup sh -c 'while :; do "$RUNNER_TEMP/disk-used" >> "$RUNNER_TEMP/disk.samples"; sleep 1; done' >/dev/null 2>&1 &
"""
DISK_BUDGET_HELD = r"""[ -s "$RUNNER_TEMP/disk.base" ] || { echo "disk budget: no baseline, the guard did not pass"; exit 0; }
now=$("$RUNNER_TEMP/disk-used")
[[ "$now" =~ ^[0-9]+$ ]] || { echo "::error title=disk budget::cannot read the disk use (got '$now'), so the budget is unchecked: df read none of the file systems the \"Disk budget\" notices list, or $RUNNER_TEMP/disk-used is gone; rerun the job, and if it fails again check that those mounts and that script still exist when the job ends"; exit 1; }
echo "$now" >> "$RUNNER_TEMP/disk.samples"
# Growth of the highest sample over the baseline, and the largest rise between two samples (MB).
# An empty sample (one df that failed) is skipped; the final reading above always counts.
read -r peak rise < <(awk -v b="$(cat "$RUNNER_TEMP/disk.base")" \
  'BEGIN {p = b; q = b} /^[0-9]+$/ {if ($1 > p) p = $1; if ($1 - q > r) r = $1 - q; q = $1} END {print p - b, r + 0}' "$RUNNER_TEMP/disk.samples")
# In tenths of a GB, each rounded up.
p=$(( (peak * 10 + 1023) / 1024 )); r=$(( (rise * 10 + 1023) / 1024 )); t=$(( p + r ))
gb() { echo "$(( $1 / 10 )).$(( $1 % 10 ))"; }
echo "::notice title=disk budget::the job grew its disk use by at most $(gb $t) GB of its $DISK_NEED_GB GB budget ($(gb $p) GB sampled, plus $(gb $r) GB, the largest rise in one sample interval, for a peak between samples)"
[ "$t" -lt $(( DISK_NEED_GB * 10 )) ] || { echo "::error title=disk budget::image build may have used up to $(gb $t) GB, at or over its $DISK_NEED_GB GB budget; raise DISK_NEED_GB in .github/workflows/image.yml (the build job's env)"; exit 1; }
"""


def free_disk_copies(script):
    """The test's own copies of the step's df read and notices, once each is found as a whole line of
    SCRIPT; the step's text is only compared, never run."""
    lines = script.splitlines()
    for line in (FREE_DISK_GB,) + FREE_DISK_NOTICES:
        if line not in lines:
            raise AssertionError("Free runner disk: no line reads exactly: " + line)
    return "\n".join((FREE_DISK_GB,) + FREE_DISK_NOTICES) + "\n"


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


def copy_of(name, script):
    """The test's own copy of step NAME, once it is checked against SCRIPT, the step's text, which is only
    compared, never run. A step with no copy here raises KeyError, so it cannot run."""
    if name == "Free runner disk":
        return free_disk_copies(script)
    own = {"Disk budget": DISK_BUDGET, "Disk budget held": DISK_BUDGET_HELD}[name]
    if script != own:
        diff = "".join(difflib.unified_diff(own.splitlines(True), script.splitlines(True), "test copy", "image.yml"))
        raise AssertionError("%s: image.yml's step differs from the test's copy; change the copy in "
                             "tests/test_image_disk.py to match in the same PR:\n%s" % (name, diff))
    return own


class DiskBudgetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = pathlib.Path(self.tmp.name)
        (self.t / "bin").mkdir()
        df = self.t / "bin" / "df"
        df.write_text(FAKE_DF)
        df.chmod(0o755)
        sudo = self.t / "bin" / "sudo"
        sudo.write_text(FAKE_SUDO)
        sudo.chmod(0o755)
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
        """Runs the test's own copy of a step (copy_of), never the step's text; FS maps mount points to
        (avail, used) MB, else one file system "/" has them."""
        script = copy_of(name, run_script(name))
        (self.t / "bin" / "fs.json").write_text(json.dumps(fs or {"/": (avail_mb, used_mb)}))
        dmi = self.t / "dmi"
        dmi.mkdir(exist_ok=True)
        if vendor is not None:
            (dmi / "sys_vendor").write_text(vendor + "\n")
        env = dict(os.environ, PATH="%s:%s" % (self.t / "bin", os.environ["PATH"]),
                   RUNNER_TEMP=str(self.t / "temp"), DISK_NEED_GB=need, DMI_ID=str(dmi))
        p = subprocess.Popen(["bash", "-e", "-o", "pipefail", "-c", script], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             start_new_session=True)
        self.procs.append(p)
        out, _ = p.communicate(timeout=30)
        self.assertFalse((self.t / "bin" / "sudo.log").exists(), "%s called sudo:\n%s" % (name, out))
        return p.returncode, out

    def test_guard_fails_fast_with_both_numbers_when_short(self):
        rc, out = self.run_step("Disk budget", avail_mb=20 * 1024, used_mb=50000)
        self.assertNotEqual(rc, 0)
        self.assertIn("::error title=disk budget::unknown-cloud (no DMI vendor) runner: image build needs 30 GB free on /, runner has 20 GB", out)
        self.assertFalse((self.t / "temp" / "disk.base").exists())

    def test_guard_passes_with_exactly_the_budget_free(self):
        # #4434: free space equal to the budget passes; one MB less (29 GB in whole GB) fails.
        rc, out = self.run_step("Disk budget", avail_mb=30 * 1024, used_mb=50000)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("::error", out)
        rc, out = self.run_step("Disk budget", avail_mb=30 * 1024 - 1, used_mb=50000)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("runner has 29 GB; free more in \"Free runner disk\"", out)

    def test_free_runner_disk_notices_read_like_the_guard(self):
        # #4434: one space, and GB as the guard writes it. #4440: the test's copies run, not the step.
        rc, out = self.run_step("Free runner disk", avail_mb=86 * 1024 + 500, used_mb=1000)
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=disk budget::/ had 86 GB free before freeing the runner disk\n", out)
        self.assertIn("::notice title=disk budget::/ has 86 GB free after freeing the runner disk\n", out)

    def test_free_runner_disk_copies_match_the_step(self):
        # #4440: the step frees disk through sudo, and an edit to any copied line fails the test.
        script = run_script("Free runner disk")
        self.assertRegex(script, r"(?m)^sudo rm -rf /usr/local/lib/android ")
        for line in (FREE_DISK_GB,) + FREE_DISK_NOTICES:
            for edited in (line.replace("1024", "1000"), line.replace("GB", "GiB"), " " + line, line + " "):
                if edited != line:
                    with self.assertRaises(AssertionError, msg=edited):
                        free_disk_copies(script.replace(line, edited))
            with self.assertRaises(AssertionError, msg=line):
                free_disk_copies(script.replace(line + "\n", ""))

    def test_disk_budget_steps_run_only_as_the_tests_copies(self):
        # #4541: an edit to a "Disk budget" step that would reach a full-path sudo (here /bin/touch of a
        # marker), or the step moved into a script file, fails the test before anything runs.
        marker = self.t / "ran"
        moved = self.t / "moved.sh"
        mutant = self.t / "image.yml"
        text = WORKFLOW.read_text()
        for name in ("Disk budget", "Disk budget held"):
            block = step(name)
            head, body = block.split("        run: |\n")
            moved.write_text(run_script(name) + "/bin/touch %s\n" % marker)
            for edited in (head + "        run: |\n          /bin/touch %s\n" % marker + body,
                           block + "\n          /bin/touch %s" % marker,
                           head + "        run: |\n          sh %s" % moved):
                mutant.write_text(text.replace(block, edited))
                with self.subTest(name=name, edited=edited[-60:]), mock.patch.dict(globals(), WORKFLOW=mutant):
                    with self.assertRaisesRegex(AssertionError, "differs from the test's copy"):
                        self.run_step(name, avail_mb=40 * 1024, used_mb=50000)
                    self.assertFalse(marker.exists())
        # A step with no copy here cannot run at all, even one whose text is a plain `run: |` block.
        with self.assertRaises(KeyError):
            self.run_step("Install build and boot tools")

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
        self.assertIn("::error title=disk budget::image build may have used up to 30.0 GB, at or over its 30 GB "
                      "budget; raise DISK_NEED_GB in .github/workflows/image.yml (the build job's env)", out)
        rc, out = self.held(*self.ramp(28))
        self.assertEqual(rc, 0, out)
        self.assertIn("grew its disk use by at most 29.0 GB of its 30 GB budget (28.0 GB sampled, plus 1.0 GB", out)
        # #4434: the bound is the sum of the printed parts; one tenth under the budget passes.
        rc, out = self.held(*(self.ramp(28) + [29593]))
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 29.9 GB of its 30 GB budget (28.9 GB sampled, plus 1.0 GB", out)
        rc, out = self.held(*(self.ramp(28) + [29594]))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("may have used up to 30.0 GB", out)

    def test_held_line_adds_up(self):
        # #4434: a 12.7 GB sampled peak and a 1.7 GB rise printed as "at most 13 GB (12 GB, plus 1 GB)".
        # Each part is now rounded up to 0.1 GB and the bound is their sum.
        rc, out = self.held(*(self.ramp(11) + [11 * 1024 + 1700]))
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 14.4 GB of its 30 GB budget (12.7 GB sampled, plus 1.7 GB", out)
        # A 205 MB part is 0.2002 GB: rounded up, it prints as 0.3.
        rc, out = self.held(205)
        self.assertIn("at most 0.6 GB of its 30 GB budget (0.3 GB sampled, plus 0.3 GB", out)
        for grew in ([1], [1023, 1024, 1025], self.ramp(9) + [9 * 1024 + 517, 4000]):
            rc, out = self.held(*grew)
            t, p, r = (float(x) for x in re.search(r"at most ([\d.]+) GB .*\(([\d.]+) GB sampled, plus ([\d.]+) GB", out).groups())
            self.assertAlmostEqual(t, p + r, places=6, msg=out)
            self.assertGreaterEqual(p * 1024, max(grew))

    def test_held_counts_a_peak_that_falls_between_samples(self):
        # #4366: a short peak between two samples is not seen, so the largest rise in one interval
        # is added to the highest sample. A job that rose 4 GB in one interval and peaked at 26 GB
        # sampled could have peaked at 30 GB between samples: it fails, though no sample reached 30.
        rc, out = self.held(*(self.ramp(22) + [26 * 1024, 2 * 1024]))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("image build may have used up to 30.0 GB", out)
        rc, out = self.held(*(self.ramp(22) + [25 * 1024, 2 * 1024]))
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 28.0 GB of its 30 GB budget (25.0 GB sampled, plus 3.0 GB", out)
        # The first sample's rise over the baseline counts too, and so does the final reading.
        rc, out = self.held(29 * 1024 + 512)
        self.assertNotEqual(rc, 0, out)
        rc, out = self.held(0, final_mb=50000 + 30 * 1024)
        self.assertNotEqual(rc, 0, out)

    def test_held_skips_an_empty_sample_and_fails_closed_on_an_unreadable_reading(self):
        # An empty sample (one df that failed) is skipped, not read as 0.
        rc, out = self.held(1024, "", 1024)
        self.assertEqual(rc, 0, out)
        self.assertIn("at most 2.0 GB of its 30 GB budget (1.0 GB sampled, plus 1.0 GB", out)
        # An empty final reading (df failed) fails the job instead of passing it as no growth.
        (self.t / "temp" / "disk.base").write_text("50000\n")
        (self.t / "temp" / "disk-used").write_text("#!/bin/sh\nexit 0\n")
        rc, out = self.run_step("Disk budget held")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("::error title=disk budget::cannot read the disk use (got ''), so the budget is unchecked: "
                      "df read none of the file systems the \"Disk budget\" notices list, or %s/disk-used is gone; "
                      "rerun the job, and if it fails again check that those mounts and that script still exist "
                      "when the job ends" % (self.t / "temp"), out)

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
        # #4434: "Free runner disk" frees only /, so a short mount of its own gets a step that works.
        self.assertIn("::error title=disk budget::unknown-cloud (no DMI vendor) runner: image build needs 30 GB free on %s, "
                      "runner has 10 GB; %s is its own file system, which \"Free runner disk\" does not free: move what "
                      "every step of this job writes under %s to a directory on /, and put that directory in place of "
                      "%s in this step's df line\n" % (temp, temp, temp, temp), out)
        self.assertNotIn("free more in", out)
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
