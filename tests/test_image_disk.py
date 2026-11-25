"""IMG-disk (#4317), IMG-disk-2 (#4366), IMG-disk-4 (#4434), #6150, #6357: every image.yml job that builds a large
tree has a guaranteed runner disk budget and fails fast when short, naming the runner's cloud and the job.
systemd-repart died mid-copy with ENOSPC when the runner's disk, not the image's partition, filled
up. The one local action .github/actions/disk-budget frees the runner's unused toolchains, then a guard
checks every file system the job writes to against the job's DISK_NEED_GB and stops with both numbers;
its held phase fails a job whose sampled growth, plus the largest rise in one sample interval (a peak
between samples), reached the budget, so the PR that grows the job is the one that goes red. These tests
never run the action's text: they run the test's own copies of its steps, each checked against its step
byte for byte, against a stand-in df that has several file systems ("Free runner disk", whose sudo deletes
no test runs, only as copies of its df read and notices: #4440, #4541). Its messages add up, say a bound is
a bound, name the job, and give a next step that works for the mount that is short. EveryDiskJobTest finds
the jobs that build a large tree by what they run (build.sh, mkosi, finish.sh), so each must call the
action (#6357)."""
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
ACTION = ROOT / ".github/actions/disk-budget/action.yml"
USES = "./.github/actions/disk-budget"

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
# step byte for byte, and runs only its copies. An edit to one of these lines in the action fails
# the test until the copy here is changed to match in the same PR.
FREE_DISK_GB = "gb() { echo $(( $(df -BM --output=avail / | tail -n 1 | tr -dc 0-9) / 1024 )); }"
FREE_DISK_NOTICES = (
    'echo "::notice title=disk budget::/ had $(gb) GB free before freeing the runner disk"',
    'echo "::notice title=disk budget::/ has $(gb) GB free after freeing the runner disk"',
)


# IMG-disk-6 (#4541): the action's budget steps run in tests, so the test owns whole copies of their scripts
# and runs only those. Each copy must equal its step's script byte for byte; the step's text is only
# compared, never run, so no edit to the action (a full-path sudo, a repo script) reaches the shell here.
# An edit to a step fails the test until its copy here is changed to match in the same PR. The action is
# the one copy every disk job runs (#6357), so no test compares one job's steps with another's.
DISK_BUDGET = r"""wf=${GITHUB_WORKFLOW_REF#*/*/}; wf=${wf%%@*}  # owner/repo/.github/workflows/x.yml@ref: the calling workflow
[[ "$DISK_NEED_GB" =~ ^[1-9][0-9]*$ ]] || { echo "::error title=disk budget::the $GITHUB_JOB job has no budget (DISK_NEED_GB is '$DISK_NEED_GB'): set DISK_NEED_GB, in GB, in its env in ${wf:-its workflow}"; exit 1; }
vendor=$(cat "${DMI_ID:-/sys/class/dmi/id}/sys_vendor" 2>/dev/null || true)
case "$vendor" in
  "Amazon EC2"*) cloud=AWS;; "Microsoft Corporation"*) cloud=Azure;; *) cloud="unknown-cloud (${vendor:-no DMI vendor})";;
esac
df -BM --output=target "$RUNNER_TEMP" /var/tmp /tmp /root "$HOME" | tail -n +2 | sort -u > "$RUNNER_TEMP/disk.mounts"
fail=0
while read -r m; do
  have=$(( $(df -BM --output=avail "$m" | tail -n 1 | tr -dc 0-9) / 1024 ))
  echo "::notice title=disk budget::$cloud runner: the $GITHUB_JOB job needs $DISK_NEED_GB GB free on $m, runner has $have GB"
  # "Free runner disk" frees space on / only; a short mount of its own needs the job's writes moved.
  if [ "$m" = / ]; then fix='free more in "Free runner disk" (.github/actions/disk-budget/action.yml)'
  else fix="$m is its own file system, which \"Free runner disk\" does not free: move what every step of the $GITHUB_JOB job writes under $m to a directory on /, and put that directory in place of $m in the df line of \"Disk budget\" (.github/actions/disk-budget/action.yml)"; fi
  [ "$have" -ge "$DISK_NEED_GB" ] || { echo "::error title=disk budget::$cloud runner: the $GITHUB_JOB job needs $DISK_NEED_GB GB free on $m, runner has $have GB; $fix"; fail=1; }
done < "$RUNNER_TEMP/disk.mounts"
[ "$fail" = 0 ]
# Used MB summed over those file systems (awk reads "1234M" as 1234).
printf '%s\n' '#!/bin/sh' 'xargs -d "\n" df -BM --output=used < "$RUNNER_TEMP/disk.mounts" | awk "NR > 1 {s += \$1} END {print s}"' > "$RUNNER_TEMP/disk-used"
chmod +x "$RUNNER_TEMP/disk-used"
"$RUNNER_TEMP/disk-used" > "$RUNNER_TEMP/disk.base"
nohup sh -c 'while :; do "$RUNNER_TEMP/disk-used" >> "$RUNNER_TEMP/disk.samples"; sleep 1; done' >/dev/null 2>&1 &
"""
DISK_BUDGET_HELD = r"""[ -s "$RUNNER_TEMP/disk.base" ] || { echo "disk budget: no baseline, the guard did not pass"; exit 0; }
wf=${GITHUB_WORKFLOW_REF#*/*/}; wf=${wf%%@*}  # owner/repo/.github/workflows/x.yml@ref: the calling workflow
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
echo "::notice title=disk budget::the $GITHUB_JOB job grew its disk use by at most $(gb $t) GB of its $DISK_NEED_GB GB budget ($(gb $p) GB sampled, plus $(gb $r) GB, the largest rise in one sample interval, for a peak between samples)"
[ "$t" -lt $(( DISK_NEED_GB * 10 )) ] || { echo "::error title=disk budget::the $GITHUB_JOB job may have used up to $(gb $t) GB, at or over its $DISK_NEED_GB GB budget; raise DISK_NEED_GB in ${wf:-its workflow} (the $GITHUB_JOB job's env)"; exit 1; }
"""
UNKNOWN_PHASE = r"""echo "::error title=disk budget::.github/actions/disk-budget has no phase '$PHASE' (the $GITHUB_JOB job's call): use start or held"
exit 1
"""

# The action's steps in order, each with the one condition that picks it by phase. A held check runs
# after a failed step too (always()), and a phase that is neither start nor held fails the job.
ACTION_STEPS = (
    ("Free runner disk", "inputs.phase == 'start'"),
    ("Disk budget", "inputs.phase == 'start'"),
    ("Disk budget held", "always() && inputs.phase == 'held'"),
    ("Unknown phase", "always() && inputs.phase != 'start' && inputs.phase != 'held'"),
)


def free_disk_copies(script):
    """The test's own copies of the step's df read and notices, once each is found as a whole line of
    SCRIPT; the step's text is only compared, never run."""
    lines = script.splitlines()
    for line in (FREE_DISK_GB,) + FREE_DISK_NOTICES:
        if line not in lines:
            raise AssertionError("Free runner disk: no line reads exactly: " + line)
    return "\n".join((FREE_DISK_GB,) + FREE_DISK_NOTICES) + "\n"


def build_steps(job_id="build", text=None):
    """Job JOB_ID's steps as (name or uses, step text), read as text: CI's Python has no YAML. The job
    ends at the next line indented two spaces (the next job, or a comment above it). A block of comments
    before the first step has the name None; a job with no steps (a called workflow) has none."""
    text = WORKFLOW.read_text() if text is None else text
    start = text.index("\n  %s:\n" % job_id, text.index("\njobs:\n"))
    end = re.compile(r"\n  [^ ]").search(text, start + 1)
    job = text[start:end.start() if end else len(text)]
    out = []
    if "\n    steps:\n" not in job:
        return job, out
    for block in re.split(r"\n(?=      - )", job[job.index("\n    steps:\n") + len("\n    steps:\n"):]):
        m = re.match(r"      - (?:name|uses): *(.+)", block)
        out.append((m.group(1).strip() if m else None, block))
    return job, out


def step(name, job_id="build"):
    """The one step named NAME; a second step of that name fails, so no test reads the wrong one."""
    blocks = [b for n, b in build_steps(job_id)[1] if n == name]
    if len(blocks) != 1:
        raise AssertionError("%d steps are named %s" % (len(blocks), name))
    return blocks[0]


def action_steps():
    """The action's steps as (name, step text), read as text like the workflow's."""
    text = ACTION.read_text()
    body = text[text.index("\n  steps:\n") + len("\n  steps:\n"):]
    out = []
    for block in re.split(r"\n(?=    - )", body):
        m = re.match(r"    - name: *(.+)", block)
        out.append((m.group(1).strip(), block))
    return out


def action_step(name):
    """The action's one step named NAME; a second step of that name fails."""
    blocks = [b for n, b in action_steps() if n == name]
    if len(blocks) != 1:
        raise AssertionError("%d action steps are named %s" % (len(blocks), name))
    return blocks[0]


def run_script(name):
    """The action step's `run: |` block, dedented; it ends at the first line indented less than it."""
    lines = action_step(name).split("\n")
    i = lines.index("      run: |")
    out = []
    for l in lines[i + 1:]:
        if l and not l.startswith("        "):
            break
        out.append(l[8:])
    while out and not out[-1]:
        out.pop()
    return "\n".join(out) + "\n"


def indent(script):
    """SCRIPT as the action's `run: |` block holds it."""
    return "".join("        " + l if l.strip() else l for l in script.splitlines(True))


def copy_of(name, script):
    """The test's own copy of step NAME, once it is checked against SCRIPT, the step's text, which is only
    compared, never run. A step with no copy here raises KeyError, so it cannot run."""
    if name == "Free runner disk":
        return free_disk_copies(script)
    own = {"Disk budget": DISK_BUDGET, "Disk budget held": DISK_BUDGET_HELD, "Unknown phase": UNKNOWN_PHASE}[name]
    if script != own:
        diff = "".join(difflib.unified_diff(own.splitlines(True), script.splitlines(True), "test copy", "action.yml"))
        raise AssertionError("%s: the action's step differs from the test's copy; change the copy in "
                             "tests/test_image_disk.py to match in the same PR:\n%s" % (name, diff))
    return own


# #6357: a job of any workflow builds a large tree when a line it runs (comments and step names aside) runs
# a build script, finish.sh or mkosi: any script named *build.sh or *finish.sh (image/build.sh, image/local-build.sh, Buildroot's
# image/camnode/build.sh, drone/sitl/build.sh, a script run from inside its directory), or mkosi as a command or a path's last part (/opt/mkosi/bin/mkosi, the clone of
# mkosi, `-C image/mkosi`), not a file under mkosi's config (image/mkosi/mkosi.sources).
HEAVY = re.compile(r"[\w-]*(?:build|finish)\.sh\b|(?<![\w.-])mkosi(?![\w./-])")
# What builds: those scripts, or the mkosi binary run (not its clone or checkout in a tool install).
BUILDS = re.compile(r"[\w-]*(?:build|finish)\.sh\b|/bin/mkosi\b")


def code(text):
    """TEXT's lines but its comments and step names, which name build.sh and mkosi without running them."""
    return [l for l in text.splitlines() if not re.match(r"\s*(?:#|(?:- )?name:)", l)]


def jobs(text):
    return re.findall(r"(?m)^  ([a-z][\w-]*):\n", text.split("\njobs:\n", 1)[1])


def heavy_jobs(text):
    """The jobs of workflow TEXT that build a large tree, by what their lines run."""
    out = []
    for j in jobs(text):
        if any(HEAVY.search(l) for l in code(build_steps(j, text)[0])):
            out.append(j)
    return out


def disk_job_problems(text):
    """Why workflow TEXT's disk jobs do not each keep a budget (empty when they do): each job that builds a
    large tree has DISK_NEED_GB in its env and calls the action twice, start then held, the held call last
    and run after a failure; and every job that calls the action is one of them."""
    heavy = heavy_jobs(text)
    problems = []
    for j in jobs(text):
        job, steps = build_steps(j, text)
        calls = [(n, b) for n, b in steps if re.search(r"(?m)^        uses: *%s *$" % re.escape(USES), b)]
        if USES in job and j not in heavy:
            problems.append("%s calls %s but runs nothing that builds a large tree" % (j, USES))
        if j not in heavy:
            continue
        if not re.search(r'(?m)^    env:\n(?:      .*\n)*?      DISK_NEED_GB: "[1-9]\d*"', job + "\n"):
            problems.append("%s builds a large tree with no DISK_NEED_GB in its env" % j)
        got = []
        for n, b in calls:
            phase = re.search(r"(?m)^          phase: *(\S+) *$", b)
            got.append((n, phase.group(1) if phase else None))
        if got != [("Disk budget", "start"), ("Disk budget held", "held")] or job.count(USES) != 2:
            problems.append("%s must call %s exactly twice, as \"Disk budget\" (phase: start) then \"Disk budget held\" "
                            "(phase: held); it calls it as %s" % (j, USES, got))
            continue
        names = [n for n, _ in steps]
        if names[-1] != "Disk budget held":
            problems.append("%s: \"Disk budget held\" is not its last step" % j)
        if "\n        if: always()\n" not in calls[1][1] + "\n":
            problems.append("%s: \"Disk budget held\" does not run with if: always()" % j)
        if "\n        if:" in calls[0][1]:
            problems.append("%s: \"Disk budget\" (phase: start) runs only on a condition" % j)
        # Tool installs (which clone mkosi) may come before the guard; no step that builds may.
        early = [n for n, b in steps[:names.index("Disk budget")] if any(BUILDS.search(l) for l in code(b))]
        if early:
            problems.append("%s builds before its \"Disk budget\" step: %s" % (j, early))
    return problems


class DiskBudgetTest(unittest.TestCase):
    """The action's steps, run as the test's copies for a job named JOB, a name no workflow uses, so each
    message that names it reads the job from $GITHUB_JOB (#6357)."""
    JOB = "heavy-job"

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

    def run_step(self, name, avail_mb=0, used_mb=0, need="30", fs=None, vendor=None, phase=None, ref=None):
        """Runs the test's own copy of a step (copy_of), never the step's text; FS maps mount points to
        (avail, used) MB, else one file system "/" has them."""
        script = copy_of(name, run_script(name))
        # The copies run as `shell: bash` runs a step (bash -e -o pipefail), so the step must say so.
        if name != "Free runner disk" and "\n      shell: bash\n" not in action_step(name):
            raise AssertionError("%s: the test runs its copy as `shell: bash`; the step no longer says that" % name)
        (self.t / "bin" / "fs.json").write_text(json.dumps(fs or {"/": (avail_mb, used_mb)}))
        dmi = self.t / "dmi"
        dmi.mkdir(exist_ok=True)
        if vendor is not None:
            (dmi / "sys_vendor").write_text(vendor + "\n")
        env = dict(os.environ, PATH="%s:%s" % (self.t / "bin", os.environ["PATH"]),
                   RUNNER_TEMP=str(self.t / "temp"), DISK_NEED_GB=need, DMI_ID=str(dmi), GITHUB_JOB=self.JOB,
                   GITHUB_WORKFLOW_REF="o/r/.github/workflows/heavy.yml@refs/pull/1/merge")
        if phase is not None:
            env["PHASE"] = phase
        if ref is not None:
            env["GITHUB_WORKFLOW_REF"] = ref
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
        self.assertIn("::error title=disk budget::unknown-cloud (no DMI vendor) runner: the heavy-job job needs 30 GB free on /, runner has 20 GB", out)
        self.assertFalse((self.t / "temp" / "disk.base").exists())

    def test_guard_passes_with_exactly_the_budget_free(self):
        # #4434: free space equal to the budget passes; one MB less (29 GB in whole GB) fails.
        rc, out = self.run_step("Disk budget", avail_mb=30 * 1024, used_mb=50000)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("::error", out)
        rc, out = self.run_step("Disk budget", avail_mb=30 * 1024 - 1, used_mb=50000)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("runner has 29 GB; free more in \"Free runner disk\" (.github/actions/disk-budget/action.yml)\n", out)

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
        # #4541: an edit to one of the action's steps that would reach a full-path sudo (here /bin/touch of a
        # marker), or the step moved into a script file, fails the test before anything runs.
        marker = self.t / "ran"
        moved = self.t / "moved.sh"
        mutant = self.t / "action.yml"
        text = ACTION.read_text()
        for name in ("Disk budget", "Disk budget held", "Unknown phase"):
            block = action_step(name)
            head, body = block.split("      run: |\n")
            moved.write_text(run_script(name) + "/bin/touch %s\n" % marker)
            for edited in (head + "      run: |\n        /bin/touch %s\n" % marker + body,
                           block.replace(indent(run_script(name)), indent(run_script(name) + "/bin/touch %s\n" % marker)),
                           head + "      run: |\n        sh %s\n" % moved):
                mutant.write_text(text.replace(block, edited))
                with self.subTest(name=name, edited=edited[-60:]), mock.patch.dict(globals(), ACTION=mutant):
                    with self.assertRaisesRegex(AssertionError, "differs from the test's copy"):
                        self.run_step(name, avail_mb=40 * 1024, used_mb=50000)
                    self.assertFalse(marker.exists())
            # A second step of the same name, or another shell, fails too: the test would not match CI.
            for edited in (block.rstrip("\n") + "\n" + block,
                           block.replace("      shell: bash\n", "      shell: sh\n")):
                mutant.write_text(text.replace(block, edited))
                with self.subTest(name=name, edited=edited[:60]), mock.patch.dict(globals(), ACTION=mutant):
                    with self.assertRaises(AssertionError):
                        self.run_step(name, avail_mb=40 * 1024, used_mb=50000)
        # A step with no copy here cannot run at all, even one whose text is a plain `run: |` block.
        with self.assertRaises(KeyError):
            copy_of("Install build and boot tools", "echo hi\n")

    def test_guard_refuses_a_job_with_no_budget(self):
        # #6357: the action reads the calling job's DISK_NEED_GB; a job that sets none, or not a whole
        # number of GB above 0, stops at the guard and names itself, with no baseline for a held pass.
        for need in ("", "0", "012", "-1", "1.5", "12 ", "x"):
            rc, out = self.run_step("Disk budget", avail_mb=400 * 1024, used_mb=50000, need=need)
            self.assertNotEqual(rc, 0, (need, out))
            self.assertIn("::error title=disk budget::the heavy-job job has no budget (DISK_NEED_GB is '%s'): set "
                          "DISK_NEED_GB, in GB, in its env in .github/workflows/heavy.yml\n" % need, out)
            self.assertNotIn("::notice", out)
            self.assertFalse((self.t / "temp" / "disk.base").exists())
        rc, out = self.run_step("Disk budget", avail_mb=400 * 1024, used_mb=50000, need="1")
        self.assertEqual(rc, 0, out)
        # With no workflow ref (never on a runner) the message still says where the budget goes.
        rc, out = self.run_step("Disk budget", avail_mb=400 * 1024, used_mb=50000, need="", ref="")
        self.assertIn("in its env in its workflow\n", out)

    def test_unknown_phase_fails(self):
        rc, out = self.run_step("Unknown phase", phase="stat")
        self.assertEqual(rc, 1, out)
        self.assertEqual(out, "::error title=disk budget::.github/actions/disk-budget has no phase 'stat' "
                              "(the heavy-job job's call): use start or held\n")

    def test_action_steps_and_phases(self):
        # #6357: one action, its steps in this order, each picked by its phase; the held check and the
        # refusal of an unknown phase run after a failed step too. Every step runs as bash.
        steps = action_steps()
        self.assertEqual([n for n, _ in steps], [n for n, _ in ACTION_STEPS])
        for (name, cond), (_, block) in zip(ACTION_STEPS, steps):
            self.assertEqual(re.findall(r"(?m)^      if: *(.*)$", block), [cond], name)
            self.assertEqual(re.findall(r"(?m)^      shell: *(.*)$", block), ["bash"], name)
        self.assertIn("\n  using: composite\n", ACTION.read_text())
        # The phase reaches the refusal's shell as an env value, never spliced into its script.
        self.assertIn("      env:\n        PHASE: ${{ inputs.phase }}\n", action_step("Unknown phase"))
        self.assertNotIn("${{", run_script("Unknown phase"))
        self.assertRegex(run_script("Free runner disk"), r"(?m)^sudo rm -rf /usr/local/lib/android ")
        # The guard checks the file system of each place a disk job writes, and samples every second.
        dfline = next(l for l in run_script("Disk budget").splitlines() if l.startswith("df "))
        for w in ('"$RUNNER_TEMP"', "/var/tmp", "/tmp", "/root", '"$HOME"'):
            self.assertIn(w, dfline)
        self.assertIn("; sleep 1; done", run_script("Disk budget"))

    def test_guard_passes_and_samples_when_the_budget_is_there(self):
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000)
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=disk budget::unknown-cloud (no DMI vendor) runner: the heavy-job job needs 30 GB free on /, runner has 31 GB", out)
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
        self.assertIn("::error title=disk budget::the heavy-job job may have used up to 30.0 GB, at or over its 30 GB "
                      "budget; raise DISK_NEED_GB in .github/workflows/heavy.yml (the %s job's env)" % self.JOB, out)
        rc, out = self.held(*self.ramp(28))
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=disk budget::the heavy-job job grew its disk use by at most 29.0 GB of its 30 GB budget (28.0 GB sampled, plus 1.0 GB", out)
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
        self.assertIn("the heavy-job job may have used up to 30.0 GB", out)
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

    def test_guard_reads_each_file_system_the_build_writes_to(self):
        # #4366: RUNNER_TEMP on its own small disk, /tmp on another, /var/tmp and /root on "/".
        temp = str(self.t / "temp")
        fs = {"/": (100 * 1024, 40000), temp: (10 * 1024, 1000), "/tmp": (35 * 1024, 2000)}
        rc, out = self.run_step("Disk budget", fs=fs)
        self.assertNotEqual(rc, 0, out)
        # #4434: "Free runner disk" frees only /, so a short mount of its own gets a step that works.
        self.assertIn("::error title=disk budget::unknown-cloud (no DMI vendor) runner: the heavy-job job needs 30 GB free on %s, "
                      "runner has 10 GB; %s is its own file system, which \"Free runner disk\" does not free: move what "
                      "every step of the heavy-job job writes under %s to a directory on /, and put that directory in "
                      "place of %s in the df line of \"Disk budget\" (.github/actions/disk-budget/action.yml)\n"
                      % (temp, temp, temp, temp), out)
        self.assertNotIn("free more in", out)
        self.assertEqual(out.count("::error"), 1, out)
        # One notice per file system: /var/tmp and /root share "/" and are read once.
        for m, gb in (("/", 100), (temp, 10), ("/tmp", 35)):
            self.assertEqual(out.count("::notice title=disk budget::unknown-cloud (no DMI vendor) runner: "
                                       "the heavy-job job needs 30 GB free on %s, runner has %d GB\n" % (m, gb)), 1, out)
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
        self.assertIn("::error title=disk budget::AWS runner: the heavy-job job needs 30 GB free on /, runner has 20 GB; "
                      "free more in \"Free runner disk\" (.github/actions/disk-budget/action.yml)\n", out)
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000, vendor="Microsoft Corporation")
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice title=disk budget::Azure runner: the heavy-job job needs 30 GB free on /", out)
        rc, out = self.run_step("Disk budget", avail_mb=31 * 1024, used_mb=50000, vendor="QEMU")
        self.assertIn("unknown-cloud (QEMU) runner:", out)


class DiskJobOrderTest(unittest.TestCase):
    """Each disk job's call of the action: tools installed, then the guard right before the job's first
    large write; every write after it lands where the guard looks; the held check last."""

    def calls(self, job_id, install):
        job, steps = build_steps(job_id)
        names = [n for n, _ in steps]
        self.assertEqual(names[names.index(install) + 1], "Disk budget")
        self.assertEqual(names[-1], "Disk budget held")
        self.assertGreater(int(re.search(r'^      DISK_NEED_GB: "(\d+)"', job, re.M).group(1)), 0)
        return names, names.index("Disk budget")

    def test_build(self):
        names, i = self.calls("build", "Install build and boot tools")
        # The stage's download and unpack (#4690, D-276) write to RUNNER_TEMP after the guard, as the build does.
        self.assertEqual(names[i + 1:i + 4], ["actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093  # v4.3.0",
                                              "Unpack the stage", "Build image"])
        self.assertIn('"$RUNNER_TEMP/out"', step("Unpack the stage"))
        # The build writes where the guard looks: its output in RUNNER_TEMP, HOME and GOCACHE.
        build = step("Build image")
        for p in ("HOME=/root", "OUT: ${{ runner.temp }}/out", '--output-dir "$OUT"'):
            self.assertIn(p, build)

    def test_stage(self):
        # #6150: the stage job runs build.sh's staging (guest roots, llama-server, the model) on its own
        # runner. Every step after the guard up to the upload writes to the file systems it reads: the loop
        # device's and fixtures' test binaries in RUNNER_TEMP, build.sh's tree in RUNNER_TEMP/out with
        # HOME=/root and GOCACHE in /tmp, and the tar in RUNNER_TEMP.
        names, i = self.calls("stage", "Install staging tools")
        self.assertEqual(names[i + 1:i + 5], ["Disk adapter on a loop device (UPD-b3 (c1))",
                                              "Unit-rule fixtures under systemd (image/unit_rules.py)",
                                              "Stage the image tree (image/build.sh)", "Pack the stage"])
        stage = step("Stage the image tree (image/build.sh)", "stage")
        for p in ("HOME=/root", "GOCACHE=/tmp/gocache", 'image/build.sh "$RUNNER_TEMP/out"'):
            self.assertIn(p, stage)
        self.assertIn('"$RUNNER_TEMP/stage.tar"', step("Pack the stage", "stage"))


class EveryDiskJobTest(unittest.TestCase):
    """#6357: the jobs of every workflow that build a large tree are found by what they run (HEAVY), not by a
    step they carry, so a new heavy job in any workflow with no budget fails here."""

    def test_every_job_that_builds_a_large_tree_keeps_a_budget(self):
        found, problems = [], []
        for wf in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            text = wf.read_text()
            if "\njobs:\n" not in text:
                problems.append("%s: no jobs: line, so its jobs are unread" % wf.name)
                continue
            found += ["%s %s" % (wf.name, j) for j in heavy_jobs(text)]
            problems += ["%s: %s" % (wf.name, p) for p in disk_job_problems(text)]
        self.assertEqual(problems, [])
        # The set as of #6357, so a detector that stops finding a job fails too.
        self.assertEqual(sorted(found), ["camnode-image.yml build", "drone-sitl.yml sitl", "enforcer-image.yml build",
                                         "image.yml build", "image.yml stage", "testkit.yml image"])

    def test_every_workflow_with_a_disk_job_runs_on_a_change_to_the_action(self):
        for wf in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
            text = wf.read_text()
            if "\njobs:\n" in text and heavy_jobs(text):
                on = text.split("\njobs:\n", 1)[0]
                lists = on.count("\n    paths:\n")
                with self.subTest(workflow=wf.name):
                    self.assertGreater(lists, 0)
                    self.assertEqual(on.count('\n      - ".github/actions/disk-budget/**"\n'), lists)

    def with_job(self, steps, env='    env:\n      DISK_NEED_GB: "12"\n'):
        """image.yml with one more job, NEW, of STEPS (step lines at six spaces) and ENV."""
        text = WORKFLOW.read_text()
        job = "  new:\n    runs-on: ubuntu-24.04\n%s    steps:\n%s" % (env, steps)
        return text.replace("\n  reproduce:\n", "\n" + job + "  reproduce:\n", 1)

    CHECKOUT = "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n"
    START = "      - name: Disk budget\n        uses: ./.github/actions/disk-budget\n        with:\n          phase: start\n"
    HELD = ("      - name: Disk budget held\n        if: always()\n        uses: ./.github/actions/disk-budget\n"
            "        with:\n          phase: held\n")

    def test_a_new_heavy_job_without_the_action_fails(self):
        # Whatever it runs that builds a tree, a job with no budget is found; the "Free runner disk"
        # step is gone from the workflow, so it cannot be how jobs are found.
        self.assertNotIn("Free runner disk", WORKFLOW.read_text())
        for run in ('sudo image/build.sh "$RUNNER_TEMP/out"', "cd image && sudo ./build.sh out",
                    'image/local-build.sh "$RUNNER_TEMP/out"', 'sudo image/finish.sh "$RUNNER_TEMP/out" 1',
                    "sudo /opt/mkosi/bin/mkosi -C image/mkosi build", "sudo mkosi -C image/mkosi build",
                    "sudo env MKOSI=/opt/mkosi/bin/mkosi spikes/x/build.sh out"):
            text = self.with_job(self.CHECKOUT + "      - name: Heavy\n        run: %s\n" % run)
            with self.subTest(run=run):
                self.assertIn("new", heavy_jobs(text))
                self.assertIn("new must call ./.github/actions/disk-budget exactly twice", "\n".join(disk_job_problems(text)))
        # The same job with the action's two calls and a budget passes.
        text = self.with_job(self.CHECKOUT + self.START + "      - name: Heavy\n        run: sudo image/finish.sh o 1\n" + self.HELD)
        self.assertEqual(disk_job_problems(text), [])

    def test_a_job_that_only_names_the_build_is_not_a_disk_job(self):
        # Comments, mkosi's config files and a step's name do not make a job heavy.
        for steps in ("      # runs image/build.sh elsewhere, then mkosi\n      - name: x\n        run: true\n",
                      "      - name: Sources\n        run: cat image/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources\n",
                      "      - name: Read\n        run: |\n          # finish.sh\n          true\n"):
            with self.subTest(steps=steps):
                self.assertNotIn("new", heavy_jobs(self.with_job(self.CHECKOUT + steps)))

    def test_each_broken_call_fails(self):
        heavy = "      - name: Heavy\n        run: sudo image/finish.sh o 1\n"
        bad = {
            "no DISK_NEED_GB": self.with_job(self.CHECKOUT + self.START + heavy + self.HELD, env=""),
            "a zero budget": self.with_job(self.CHECKOUT + self.START + heavy + self.HELD,
                                           env='    env:\n      DISK_NEED_GB: "0"\n'),
            "no held call": self.with_job(self.CHECKOUT + self.START + heavy),
            "no start call": self.with_job(self.CHECKOUT + heavy + self.HELD),
            "a held phase typo": self.with_job(self.CHECKOUT + self.START + heavy + self.HELD.replace("phase: held", "phase: hold")),
            "the calls swapped": self.with_job(self.CHECKOUT + self.HELD + heavy + self.START),
            "a third call": self.with_job(self.CHECKOUT + self.START + self.START + heavy + self.HELD),
            "held not last": self.with_job(self.CHECKOUT + self.START + self.HELD + heavy),
            "held not always()": self.with_job(self.CHECKOUT + self.START + heavy + self.HELD.replace("        if: always()\n", "")),
            "a conditional start": self.with_job(self.CHECKOUT + self.START.replace("        uses:", "        if: matrix.run == 'a'\n        uses:") + heavy + self.HELD),
            "a build before the guard": self.with_job(self.CHECKOUT + heavy + self.START + heavy + self.HELD),
            "the action by another path": self.with_job(self.CHECKOUT + self.START.replace("disk-budget\n", "disk-budget/\n") + heavy + self.HELD),
        }
        for why, text in bad.items():
            with self.subTest(why=why):
                self.assertNotEqual(disk_job_problems(text), [], why)
        # A job that calls the action but builds nothing is a problem too: the detector would be missing it.
        text = self.with_job(self.CHECKOUT + self.START + "      - name: x\n        run: true\n" + self.HELD)
        self.assertIn("new calls ./.github/actions/disk-budget but runs nothing that builds a large tree", disk_job_problems(text))


if __name__ == "__main__":
    unittest.main()
