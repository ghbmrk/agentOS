"""Merge-queue readiness: every check main requires also runs on merge_group.

No requirement IDs: CI tooling, not SPEC.md behaviour. The merge queue builds each queued
PR on a gh-readonly-queue/ commit and waits for main's required checks there; a required
check that never runs on merge_group stalls the queue. The g1-freeze queue job judges the
queued change with the base commit's list and fails closed, which the functional tests
below run against a scratch repository with a stand-in `gh`.
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
# Main's required status checks (the main-checks ruleset); keep in step with it.
REQUIRED = ("checks", "broker", "machines", "hostcheck", "g1-freeze")
QUEUE_STEP = "G1 freeze for the queued PR (base copy of tools/g1_scope.py)"


def triggers(text):
    """Top-level event names under `on:`."""
    m = re.search(r"^on:\n((?:[ #].*\n|\n)*)", text, re.M)
    return set(re.findall(r"^  ([a-z_]+):", m.group(1), re.M)) if m else set()


def job_checks(text):
    """Check names a workflow's jobs report: the job's `name:`, else its id."""
    m = re.search(r"^jobs:\n", text, re.M)
    names = set()
    for job in re.split(r"^  (?=[A-Za-z0-9_-]+:\s*$)", text[m.end():], flags=re.M)[1:]:
        jid = job.split(":", 1)[0]
        nm = re.search(r"^    name:\s*(\S.*?)\s*$", job, re.M)
        names.add(nm.group(1) if nm else jid)
    return names


def run_block(text, step_name):
    """The `run: |` script of the step named step_name, dedented."""
    lines = text.splitlines()
    i = next(n for n, line in enumerate(lines) if line.strip() == f"- name: {step_name}")
    j = next(n for n in range(i, len(lines)) if lines[n].strip() == "run: |")
    indent = len(lines[j + 1]) - len(lines[j + 1].lstrip())
    body = []
    for line in lines[j + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    return "\n".join(body) + "\n"


class RequiredChecksTest(unittest.TestCase):
    def test_every_required_check_runs_on_merge_group(self):
        found = {}
        for f in sorted(WORKFLOWS.glob("*.yml")):
            text = f.read_text()
            if "merge_group" in triggers(text):
                for name in job_checks(text):
                    found.setdefault(name, f.name)
        for check in REQUIRED:
            self.assertIn(check, found, f"no merge_group workflow reports `{check}`")

    def test_helpers_read_the_workflows(self):
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertTrue({"push", "pull_request", "merge_group"} <= triggers(ci))
        self.assertTrue({"scope", "checks", "broker", "machines", "hostcheck"} <= job_checks(ci))
        self.assertEqual(job_checks((WORKFLOWS / "g1-freeze-queue.yml").read_text()), {"g1-freeze"})

    def test_pr_only_ci_steps_stay_off_the_queue(self):
        # The queue commit has no PR test merge (HEAD^1/HEAD^2) and no PR diff; those steps ran
        # on the PR's own run, which the queue requires before a PR may join it.
        ci = (WORKFLOWS / "ci.yml").read_text()
        for m in re.finditer(r"^      - name: (.*)\n((?:        .*\n|\n)*)", ci, re.M):
            body = m.group(2)
            if "HEAD^" in body:
                self.assertRegex(body, r"if: github.event_name == 'pull_request'", m.group(1))

    def test_scope_reads_the_queue_base(self):
        text = (WORKFLOWS / "scope.yml").read_text()
        self.assertIn("QUEUE_BASE: ${{ github.event.merge_group.base_sha }}", text)
        self.assertIn("merge_group) base=$QUEUE_BASE head=$GITHUB_SHA ;;", text)
        # The decision is still the base copy of ci_scope.py.
        self.assertIn('git show "$base:tools/ci_scope.py"', text)

    def test_queue_freeze_runs_only_the_base_copy(self):
        text = (WORKFLOWS / "g1-freeze-queue.yml").read_text()
        self.assertEqual(triggers(text), {"merge_group"})
        uses = re.findall(r"uses:\s*(\S+)", text)
        self.assertEqual(len(uses), 1)
        self.assertTrue(uses[0].startswith("actions/checkout@"))
        self.assertIn("ref: ${{ github.event.merge_group.base_sha }}", text)
        self.assertIn("persist-credentials: false", text)
        script = run_block(text, QUEUE_STEP)
        self.assertEqual(script.count("exit 0"), 1)
        self.assertNotRegex(script, r"git (checkout|switch|worktree|restore)")
        for call in re.findall(r"python3[^\n]*", script):
            self.assertTrue(call.startswith("python3 -I tools/g1_scope.py "), call)


def git(cwd, *args, **kw):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, **kw).stdout.strip()


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class QueueFreezeScriptTest(unittest.TestCase):
    """Run the workflow's script on a scratch origin with a gh-readonly-queue ref."""

    LIST = "freeze on\nsince 2026-10-14T00:00:00Z\nallow tools/\nallow inside/\nexempt-pr 9\n"
    BEFORE = "2026-10-13T00:00:00Z"
    AFTER = "2026-10-15T00:00:00Z"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.script = run_block((WORKFLOWS / "g1-freeze-queue.yml").read_text(), QUEUE_STEP)
        origin, work = self.tmp / "origin.git", self.tmp / "work"
        git(self.tmp, "init", "-q", "--bare", "-b", "main", str(origin))
        git(self.tmp, "init", "-q", "-b", "main", str(work))
        for k, v in (("user.name", "t"), ("user.email", "t@example.invalid"), ("commit.gpgsign", "false")):
            git(work, "config", k, v)
        git(work, "remote", "add", "origin", str(origin))
        (work / "tools").mkdir()
        for name in ("g1_scope.py", "ci_scope.py"):
            shutil.copy(ROOT / "tools" / name, work / "tools" / name)
        (work / "tools" / "g1_scope.txt").write_text(self.LIST)
        self.commit(work, "base")
        self.origin, self.work = origin, work
        self.base = git(work, "rev-parse", "HEAD")
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text('#!/bin/sh\ncase "$*" in *pulls/*) cat "$FAKE_PR";; *) exit 3;; esac\n')
        gh.chmod(0o755)
        self.bin = bin_dir

    def commit(self, work, msg):
        git(work, "add", "-A")
        git(work, "commit", "-q", "-m", msg)
        return git(work, "rev-parse", "HEAD")

    def branch(self, start, files):
        git(self.work, "checkout", "-q", "--detach", start)
        for path, body in files.items():
            p = self.work / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return self.commit(self.work, "change")

    def queue(self, pr, pr_head, group_head, created, base=None, ref=None):
        base = base or self.base
        ref = ref or f"refs/heads/gh-readonly-queue/main/pr-{pr}-{base}"
        git(self.work, "push", "-q", "-f", "origin", f"{self.base}:refs/heads/main",
            f"{pr_head}:refs/pull/{pr}/head", f"{group_head}:{ref}" if ref.startswith("refs/heads/gh") else f"{group_head}:refs/heads/other")
        run = self.tmp / f"run-{pr}-{group_head[:7]}"
        git(self.tmp, "clone", "-q", str(self.origin), str(run))
        git(run, "checkout", "-q", "--detach", base)
        fake = self.tmp / "pr.txt"
        fake.write_text(f"{pr_head} {created}\n")
        temp = self.tmp / "runner"
        temp.mkdir(exist_ok=True)
        env = dict(os.environ, BASE_SHA=base, GROUP_REF=ref, GROUP_SHA=group_head, REPO="o/r",
                   GH_TOKEN="x", RUNNER_TEMP=str(temp), FAKE_PR=str(fake),
                   PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")
        return subprocess.run(["bash", "-e", "-c", self.script], cwd=run, env=env,
                              capture_output=True, text=True)

    def single(self, pr, files, created):
        head = self.branch(self.base, files)
        return self.queue(pr, head, head, created)

    def test_listed_paths_pass(self):
        r = self.single(5, {"inside/a.txt": "x"}, self.AFTER)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("every path is on the G1 list", r.stdout)

    def test_unlisted_paths_fail_without_an_exemption(self):
        r = self.single(5, {"outside/a.go": "x"}, self.AFTER)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("outside/a.go", r.stderr)

    def test_the_queued_prs_own_exemptions_apply(self):
        self.assertEqual(self.single(5, {"outside/a.go": "x"}, self.BEFORE).returncode, 0)
        r = self.single(9, {"outside/b.go": "x"}, self.AFTER)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("exempt-pr line", r.stdout)

    def test_an_exemption_does_not_cover_another_prs_paths(self):
        # The queue entry for exempt PR #9 sits on PR #5's unlisted change.
        first = self.branch(self.base, {"outside/a.go": "x"})
        pr9 = self.branch(self.base, {"outside/b.go": "x"})
        git(self.work, "checkout", "-q", "--detach", first)
        (self.work / "outside" / "b.go").write_text("x")
        group = self.commit(self.work, "queue entry for #9")
        r = self.queue(9, pr9, group, self.AFTER)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("outside/a.go", r.stderr)
        self.assertIn("does not change", r.stderr)

    def test_a_ref_without_a_pr_number_fails_closed(self):
        head = self.branch(self.base, {"inside/a.txt": "x"})
        r = self.queue(5, head, head, self.AFTER, ref="refs/heads/other")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("failing closed", r.stderr)

    def test_a_failed_pr_lookup_fails_closed(self):
        head = self.branch(self.base, {"outside/a.go": "x"})
        (self.bin / "gh").write_text("#!/bin/sh\nexit 1\n")
        r = self.queue(5, head, head, self.AFTER)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_base_without_the_tool_passes(self):
        git(self.work, "checkout", "-q", "--detach", self.base)
        shutil.rmtree(self.work / "tools")
        (self.work / "x.txt").write_text("x")
        old = self.commit(self.work, "no tool")
        head = self.branch(old, {"outside/a.go": "x"})
        r = self.queue(5, head, head, self.AFTER, base=old)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not active on this base", r.stdout)


if __name__ == "__main__":
    unittest.main()
