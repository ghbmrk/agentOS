"""Workflow hygiene (security review 2, finding 9).

No requirement IDs: CI tooling, not SPEC.md behaviour. Every action is pinned by full commit
SHA, and every checkout in a workflow that runs pull-request code drops the job's token from
the working tree (persist-credentials: false), so PR code never reads it from .git/config.
"""
import pathlib
import re
import unittest

WORKFLOWS = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"


def steps(text):
    """Yield (action, step text) for each `uses:` step."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)-\s+uses:\s*([^\s#]+)", line)
        if not m:
            continue
        indent = len(m.group(1))
        body = [line]
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                break
            body.append(nxt)
        yield m.group(2), "\n".join(body)


class WorkflowTest(unittest.TestCase):
    def files(self):
        files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
        self.assertTrue(files)
        return files

    def test_actions_are_pinned_by_full_sha(self):
        for f in self.files():
            for action, _ in steps(f.read_text()):
                if action.startswith("./"):
                    continue
                self.assertRegex(action, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", f"{f.name}: {action}")

    def test_checkouts_running_pr_code_keep_no_token(self):
        for f in self.files():
            text = f.read_text()
            if not re.search(r"^\s*pull_request(_target)?\s*:", text, re.M):
                continue
            for action, step in steps(text):
                if action.startswith("actions/checkout@"):
                    self.assertRegex(step, r"persist-credentials:\s*false", f"{f.name}: {step}")

    def test_no_workflow_pushes_to_main(self):
        # main requires status checks, so a workflow push to it would be rejected; trace.yml
        # and metrics.yml push a bot branch, open its PR and dispatch ci.yml there instead.
        for f in self.files():
            self.assertNotRegex(f.read_text(), r"git push\b[^\n]*\bmain\b", f.name)
        self.assertIn("workflow_dispatch:", (WORKFLOWS / "ci.yml").read_text())
        for name in ("trace.yml", "metrics.yml"):
            text = (WORKFLOWS / name).read_text()
            self.assertIn("gh pr create --base main", text, name)
            self.assertIn('gh workflow run ci.yml --ref "$BRANCH"', text, name)
            self.assertIn('gh pr merge "$BRANCH" --auto --squash', text, name)

    def test_fuzz_runs_go_through_fuzzrun_and_never_by_duration(self):
        # P1-4-flake-ci (REQ: LOOP-7): a duration -fuzztime can end in the fuzz coordinator's
        # deadline race ("context deadline exceeded", no input), so no workflow passes one,
        # and every `go test ... -fuzz` runs through tools/fuzzrun.py, which counts and caps.
        for f in self.files():
            text = f.read_text()
            for m in re.finditer(r"-fuzztime[ =]+(\S+)", text):
                self.assertRegex(m.group(1), r"^\d+x$", f"{f.name}: -fuzztime {m.group(1)}")
            for m in re.finditer(r"go test\b[^\n]*(?:\\\n[^\n]*)*", text):
                self.assertNotRegex(m.group(0), r"-fuzz\b", f"{f.name}: go test -fuzz outside fuzzrun")
        for name in ("ci.yml", "soak.yml"):
            self.assertIn("tools/fuzzrun.py", (WORKFLOWS / name).read_text(), name)

    def assert_runs_only_the_base_copy(self, name, command):
        text = (WORKFLOWS / name).read_text()
        job = name.removesuffix(".yml")
        on = re.search(r"^on:\n((?:[ \t]+.*\n)+)", text, re.M).group(1)
        self.assertRegex(on, r"(?m)^\s+pull_request_target:\s*$", on)
        self.assertNotRegex(on, r"(?m)^\s+(pull_request|push|workflow_dispatch|workflow_run)\s*:", on)
        self.assertRegex(on, r"types:\s*\[opened, synchronize, reopened, edited\]")
        self.assertRegex(text, rf"(?m)^  {job}:\n    name: {job}$")
        self.assertNotRegex(text, r":\s*write\b")
        uses = list(steps(text))
        self.assertEqual([a.split("@")[0] for a, _ in uses], ["actions/checkout"], uses)
        step = uses[0][1]
        self.assertRegex(step, r"ref:\s*\$\{\{ github\.event\.pull_request\.base\.sha \}\}")
        self.assertRegex(step, r"persist-credentials:\s*false")
        self.assertIn(command, text)
        for verb in (r"git (checkout|switch|worktree|merge|reset|restore)\b", r"pip install",
                     r"\$\{\{ github\.(head_ref|event\.pull_request\.title)"):
            for line in text.splitlines():
                if line.lstrip().startswith(("run:", "git ", "python3 ", "if ")):
                    self.assertNotRegex(line, verb, line)
        # One gate: no fallback to the PR's copy inside the PR-controlled ci.yml.
        self.assertNotIn("--pr-branch", (WORKFLOWS / "ci.yml").read_text())

    def test_lane_gate_runs_only_the_base_copy(self):
        # CTRL-lane-gate (#1300, security review B1/B2): the gate is its own workflow on
        # pull_request_target, so GitHub runs the base commit's workflow file; it checks out
        # only the base and runs the base's tools/risk_tier.py on the diff to the PR head,
        # which it fetches as objects and never checks out. No step can run PR code first.
        self.assert_runs_only_the_base_copy(
            "lane-gate.yml",
            'python3 -I tools/risk_tier.py --git "$BASE_SHA" "$HEAD_SHA" '
            '--pr-branch "$PR_BRANCH" --pr-title "$PR_TITLE"')

    def test_g1_freeze_runs_only_the_base_copy(self):
        # G1-freeze (#1687): the same shape as the lane gate, so a PR cannot widen the G1
        # list, flip its switch or exempt itself; the base's list decides.
        self.assert_runs_only_the_base_copy(
            "g1-freeze.yml",
            'python3 -I tools/g1_scope.py --git "$BASE_SHA" "$HEAD_SHA" --pr "$PR_NUMBER" '
            '--pr-created "$PR_CREATED"')
        text = (WORKFLOWS / "g1-freeze.yml").read_text()
        # The opening time comes from the event, which the PR author cannot set.
        self.assertIn("PR_CREATED: ${{ github.event.pull_request.created_at }}", text)
        # The only fail-open is a base that predates the tool.
        self.assertIn('if [ ! -f tools/g1_scope.py ]; then echo "g1 freeze: not active on this base"; exit 0; fi', text)
        self.assertEqual(text.count("exit 0"), 1)

    def test_steps_finds_steps(self):
        sample = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          x: 1\n      - run: echo\n"
        self.assertEqual(list(steps(sample)), [("actions/checkout@v4", "      - uses: actions/checkout@v4\n        with:\n          x: 1")])


if __name__ == "__main__":
    unittest.main()
