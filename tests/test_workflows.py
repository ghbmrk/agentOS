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


# CTRL-lane-gate r3 (#1347, Security R3 on #1303): lane-gate.yml must run only the base's
# code and fail closed. Keys are whitelisted, so `if:`, `continue-on-error:`, `shell:`,
# `container:` and the like fail; the env block and the run body must equal these lines, so
# no edit can point HEAD_SHA at the base, swallow an exit code or run fetched code.
LANE_GATE_KEYS = {
    "name", "on", "pull_request_target", "types", "permissions", "contents", "jobs",
    "lane-gate", "runs-on", "timeout-minutes", "steps", "uses", "with", "ref", "fetch-depth",
    "persist-credentials", "env", "BASE_SHA", "HEAD_SHA", "PR_NUMBER", "PR_BRANCH", "PR_TITLE",
    "run",
}
LANE_GATE_ENV = [
    "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
    "HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "PR_NUMBER: ${{ github.event.pull_request.number }}",
    "PR_BRANCH: ${{ github.head_ref }}",
    "PR_TITLE: ${{ github.event.pull_request.title }}",
]
LANE_GATE_RUN = [
    'git fetch --no-tags origin "+refs/pull/$PR_NUMBER/head:refs/remotes/pr/head"',
    'git cat-file -e "$HEAD_SHA^{commit}"',
    'python3 -I tools/risk_tier.py --git "$BASE_SHA" "$HEAD_SHA" --pr-branch "$PR_BRANCH" --pr-title "$PR_TITLE"',
]


def lane_gate_problems(text):
    """Return why lane-gate.yml could fail open or run PR code; empty when it cannot."""
    problems = []
    if "||" in text:
        problems.append("`||` can swallow the gate's exit code")
    if re.search(r"\bsecrets\b", text):
        problems.append("secrets are referenced")
    lines = text.splitlines()
    structure, run, env, runs = [], [], [], 0
    i = 0
    while i < len(lines):
        line = lines[i]
        indent = len(line) - len(line.lstrip())
        if re.match(r"^\s*(-\s+)?run\s*:", line):
            runs += 1
            if not re.match(r"^\s*(-\s+)?run: \|$", line):
                problems.append("run is not a `|` block: " + line.strip())
            i += 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
                if lines[i].strip():
                    run.append(lines[i].strip())
                i += 1
            continue
        if re.match(r"^\s*env\s*:\s*$", line):
            i += 1
            while i < len(lines) and len(lines[i]) - len(lines[i].lstrip()) > indent:
                env.append(lines[i].strip())
                i += 1
            structure.append(line)
            continue
        structure.append(line)
        i += 1
    if runs != 1:
        problems.append("expected one run step, found %d" % runs)
    if any("${{" in r for r in run):
        problems.append("an expression is expanded inside the run body")
    for r in run:
        if "$HEAD_SHA" in r and not r.startswith(("git fetch ", "git cat-file ", "python3 -I tools/risk_tier.py ")):
            problems.append("HEAD_SHA reaches a command other than git fetch, git cat-file or risk_tier.py: " + r)
    if run != LANE_GATE_RUN:
        problems.append("run body differs from the three gate commands: %r" % run)
    if env != LANE_GATE_ENV:
        problems.append("env differs from the five gate inputs: %r" % env)
    seen = set()
    for line in structure:
        code = re.sub(r"\s#.*$", "", line) if not line.lstrip().startswith("#") else ""
        if not code.strip():
            continue
        bare = re.sub(r"\$\{\{[^}]*\}\}", "", code)
        if "{" in bare or "&" in bare or re.search(r"(^|\s)[*!]", bare):
            problems.append("flow mapping, anchor, alias or tag: " + line.strip())
        if "[" in bare and not re.match(r"^\s*types:\s*\[opened, synchronize, reopened, edited\]$", bare):
            problems.append("flow sequence: " + line.strip())
        m = re.match(r"""^\s*(?:-\s+)?["']?([^"':\s][^"':]*?)["']?\s*:(\s|$)""", bare)
        if not m:
            problems.append("not a key line: " + line.strip())
        elif m.group(1) not in LANE_GATE_KEYS:
            problems.append("unexpected key %r" % m.group(1))
        elif m.group(1) in seen and m.group(1) not in ("name", "permissions", "contents"):
            problems.append("repeated key %r" % m.group(1))
        else:
            seen.add(m.group(1))
    return problems


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

    def test_lane_gate_runs_only_the_base_copy(self):
        # CTRL-lane-gate (#1300, security review B1/B2): the gate is its own workflow on
        # pull_request_target, so GitHub runs the base commit's workflow file; it checks out
        # only the base and runs the base's tools/risk_tier.py on the diff to the PR head,
        # which it fetches as objects and never checks out. No step can run PR code first.
        text = (WORKFLOWS / "lane-gate.yml").read_text()
        on = re.search(r"^on:\n((?:[ \t]+.*\n)+)", text, re.M).group(1)
        self.assertRegex(on, r"(?m)^\s+pull_request_target:\s*$", on)
        self.assertNotRegex(on, r"(?m)^\s+(pull_request|push|workflow_dispatch|workflow_run)\s*:", on)
        self.assertRegex(on, r"types:\s*\[opened, synchronize, reopened, edited\]")
        self.assertRegex(text, r"(?m)^  lane-gate:\n    name: lane-gate$")
        self.assertNotRegex(text, r":\s*write\b")
        uses = list(steps(text))
        self.assertEqual([a.split("@")[0] for a, _ in uses], ["actions/checkout"], uses)
        step = uses[0][1]
        self.assertRegex(step, r"ref:\s*\$\{\{ github\.event\.pull_request\.base\.sha \}\}")
        self.assertRegex(step, r"persist-credentials:\s*false")
        self.assertIn('python3 -I tools/risk_tier.py --git "$BASE_SHA" "$HEAD_SHA" '
                      '--pr-branch "$PR_BRANCH" --pr-title "$PR_TITLE"', text)
        for verb in (r"git (checkout|switch|worktree|merge|reset|restore)\b", r"pip install",
                     r"\$\{\{ github\.(head_ref|event\.pull_request\.title)"):
            for line in text.splitlines():
                if line.lstrip().startswith(("run:", "git ", "python3 ")):
                    self.assertNotRegex(line, verb, line)
        # One gate: no fallback to the PR's copy inside the PR-controlled ci.yml.
        self.assertNotIn("--pr-branch", (WORKFLOWS / "ci.yml").read_text())

    def test_lane_gate_has_no_fail_open_or_fetched_code_path(self):
        # CTRL-lane-gate r3 (#1347): the shipped workflow passes the strict check.
        self.assertEqual(lane_gate_problems((WORKFLOWS / "lane-gate.yml").read_text()), [])

    def test_lane_gate_check_catches_each_reported_edit(self):
        # CTRL-lane-gate r3 (#1347): every edit Security R3 showed passing the old test fails now.
        text = (WORKFLOWS / "lane-gate.yml").read_text()
        gate = LANE_GATE_RUN[2]
        step = "      - name: Lane gate (base copy of tools/risk_tier.py)\n"
        job = "    runs-on: ubuntu-latest\n"
        edits = {
            "job continue-on-error": (job, job + "    continue-on-error: true\n"),
            "step continue-on-error": (step, step + "        continue-on-error: true\n"),
            "job if": (job, job + "    if: false\n"),
            "step if": (step, step + "        if: ${{ false }}\n"),
            "quoted if": (step, step + "        \"if\": false\n"),
            "flow mapping if": (job, job + "    defaults: {run: {shell: sh}}\n"),
            "or true": (gate, gate + " || true"),
            "secret env": ("          PR_TITLE:", "          TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          PR_TITLE:"),
            "head as base": ("BASE_SHA: ${{ github.event.pull_request.base.sha }}",
                             "BASE_SHA: ${{ github.event.pull_request.head.sha }}"),
            "checkout with -c": (gate, 'git -c x=y checkout "$HEAD_SHA"\n          ' + gate),
            "archive": (gate, 'git archive "$HEAD_SHA" | tar x\n          ' + gate),
            "show to file": (gate, 'git show "$HEAD_SHA":tools/risk_tier.py > f\n          ' + gate),
            "title on echo": (gate, 'echo "${{ github.event.pull_request.title }}"\n          ' + gate),
            "shell override": (step, step + "        shell: python {0}\n"),
            "container": (job, job + "    container: python:3\n"),
            "second run step": (gate, gate + "\n      - run: |\n          true"),
            "inline run": ("        run: |\n", "        run: >\n"),
            "repeated ref": ("          persist-credentials: false\n",
                             "          persist-credentials: false\n          ref: ${{ github.event.pull_request.head.sha }}\n"),
        }
        for name, (old, new) in edits.items():
            with self.subTest(name):
                self.assertIn(old, text)
                self.assertTrue(lane_gate_problems(text.replace(old, new, 1)), name)

    def test_steps_finds_steps(self):
        sample = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          x: 1\n      - run: echo\n"
        self.assertEqual(list(steps(sample)), [("actions/checkout@v4", "      - uses: actions/checkout@v4\n        with:\n          x: 1")])


if __name__ == "__main__":
    unittest.main()
