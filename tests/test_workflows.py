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


# CTRL-lane-gate r3 (#1347, Security R3 and L3 on #1583): lane-gate.yml must run only the
# base's code and fail closed. Every line that is not blank or a whole-line comment must equal
# this pin, in order, so no edit can add `if:` or `continue-on-error:`, swap the action, point
# the checkout or HEAD_SHA at the PR head, widen permissions, change the runner, swallow an
# exit code or run fetched code without changing this test in the same PR.
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
LANE_GATE_LINES = [
    "name: lane-gate",
    "on:",
    "  pull_request_target:",
    "    types: [opened, synchronize, reopened, edited]",
    "permissions:",
    "  contents: read",
    "jobs:",
    "  lane-gate:",
    "    name: lane-gate",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 5",
    "    permissions:",
    "      contents: read",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
    "        with:",
    "          ref: ${{ github.event.pull_request.base.sha }}",
    "          fetch-depth: 0 # the merge base with the PR head",
    "          persist-credentials: false",
    "      - name: Lane gate (base copy of tools/risk_tier.py)",
    "        env:",
] + ["          " + e for e in LANE_GATE_ENV] + [
    "        run: |",
] + ["          " + r for r in LANE_GATE_RUN]


def lane_gate_problems(text):
    """Return why lane-gate.yml differs from the pinned gate; empty when it matches."""
    problems = []
    # Only printable ASCII and \n: YAML also breaks lines at \r, which could hide a line
    # inside what this check reads as a comment.
    if re.search(r"[^\x20-\x7e\n]", text):
        problems.append("a character other than printable ASCII or a newline")
    code = [l for l in text.split("\n") if l.strip() and not l.lstrip().startswith("#")]
    for i in range(max(len(code), len(LANE_GATE_LINES))):
        got = code[i] if i < len(code) else "<missing>"
        want = LANE_GATE_LINES[i] if i < len(LANE_GATE_LINES) else "<none>"
        if got != want:
            problems.append("line %d is %r, pinned %r" % (i + 1, got, want))
            break
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
        # main requires status checks, so a workflow push to it would be rejected; trace.yml,
        # metrics.yml and records.yml push a bot branch, open its PR and dispatch ci.yml there instead.
        for f in self.files():
            self.assertNotRegex(f.read_text(), r"git push\b[^\n]*\bmain\b", f.name)
        self.assertIn("workflow_dispatch:", (WORKFLOWS / "ci.yml").read_text())
        for name in ("trace.yml", "metrics.yml", "records.yml"):
            text = (WORKFLOWS / name).read_text()
            self.assertIn("gh pr create --base main", text, name)
            self.assertIn('gh workflow run ci.yml --ref "$BRANCH"', text, name)
            self.assertIn('gh pr merge "$BRANCH" --auto --squash', text, name)

    def test_records_batch_runs_at_most_daily(self):
        # RECORDS-INLINE (#1816, D-120): the bot batch is the only writer of records, so it runs on a
        # daily schedule or by hand, never on every push to main.
        text = (WORKFLOWS / "records.yml").read_text()
        on = re.search(r"^on:\n((?:[ \t]+.*\n)+)", text, re.M).group(1)
        self.assertRegex(on, r"(?m)^\s+schedule:\s*$")
        self.assertRegex(on, r"cron:\s*'\d+ \d+ \* \* \*'")
        self.assertRegex(on, r"(?m)^\s+workflow_dispatch:")
        self.assertNotRegex(on, r"(?m)^\s+push:")

    def test_bot_token_jobs_run_in_the_bot_environment(self):
        # BOT_PR_TOKEN is a `bot` environment secret restricted to main (#1691, #1769), so every
        # job that can write contents must name that environment, and nothing else names it.
        for f in self.files():
            jobs = re.split(r"(?m)^  (?=[a-z][\w-]*:\n)", f.read_text().split("\njobs:\n", 1)[-1])
            for job in jobs:
                writes, env = "contents: write" in job, bool(re.search(r"(?m)^    environment: bot$", job))
                if f.name in ("trace.yml", "metrics.yml", "metrics-refresh.yml", "records.yml"):
                    self.assertEqual(writes, env, f"{f.name}: {job.split(':', 1)[0]}")
                else:
                    self.assertFalse(env or "BOT_PR_TOKEN" in job, f.name)

    def test_inline_python_is_isolated(self):
        # A job holding a write token runs no repository module: `python3 -I -` ignores the
        # repo root and cwd on sys.path, so a file on main cannot shadow the stdlib (#1691).
        for f in self.files():
            self.assertNotRegex(f.read_text(), r"python3? -(?:\s|$)", f.name)

    def test_board_crosses_jobs_as_an_artifact(self):
        # CX-BOARD-ARGV (#1787): a job output or env var holding the rendered board passes 128 KiB
        # (MAX_ARG_STRLEN) once BOARD.md grows, and bash in the commit job never starts. The board
        # goes from render to commit as an artifact; the only job output is a small flag.
        text = (WORKFLOWS / "board.yml").read_text()
        render, commit = text.split("\n  commit:\n", 1)
        self.assertNotIn("base64", text)
        self.assertNotIn("BOARD_B64", text)
        self.assertEqual(re.findall(r"(?m)^    outputs:\n((?:      .*\n)+)", render),
                         ["      rendered: ${{ steps.gen.outputs.rendered }}\n"])
        self.assertIn('echo "rendered=true" >> "$GITHUB_OUTPUT"', render)
        self.assertIn("if: needs.render.outputs.rendered == 'true'", commit)
        uploads = [s for a, s in steps(render) if a.startswith("actions/upload-artifact@")]
        downloads = [s for a, s in steps(commit) if a.startswith("actions/download-artifact@")]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(len(downloads), 1)
        self.assertRegex(uploads[0], r"name: board\b")
        self.assertRegex(downloads[0], r"name: board\b")
        # The artifact lands outside the checkout, and only BOARD.md is copied into it.
        self.assertRegex(downloads[0], r"path: \$\{\{ runner\.temp \}\}/board\b")
        self.assertIn('cp "$RUNNER_TEMP/board/BOARD.md" BOARD.md', commit)

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

    def test_lane_gate_has_no_fail_open_or_fetched_code_path(self):
        # CTRL-lane-gate r3 (#1347): the shipped workflow passes the strict check.
        self.assertEqual(lane_gate_problems((WORKFLOWS / "lane-gate.yml").read_text()), [])

    def test_lane_gate_check_catches_each_reported_edit(self):
        # CTRL-lane-gate r3 (#1347): every edit Security R3 and L3 showed passing an older check fails.
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
            "ref to head": ("ref: ${{ github.event.pull_request.base.sha }}",
                            "ref: ${{ github.event.pull_request.head.sha }}"),
            "swapped uses": ("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", "evil/x@main"),
            "persist credentials": ("persist-credentials: false", "persist-credentials: true"),
            "contents write": ("  contents: read\njobs:", "  contents: write\njobs:"),
            "write-all": ("permissions:\n  contents: read\njobs:", "permissions: write-all\njobs:"),
            "self-hosted": ("runs-on: ubuntu-latest", "runs-on: self-hosted"),
            "carriage return in comment": ("# CTRL-lane-gate (docs/LANES.md)",
                                           "# CTRL-lane-gate\r    if: false\r# (docs/LANES.md)"),
        }
        for name, (old, new) in edits.items():
            with self.subTest(name):
                self.assertIn(old, text)
                self.assertTrue(lane_gate_problems(text.replace(old, new, 1)), name)

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
