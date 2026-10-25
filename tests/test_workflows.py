"""Workflow hygiene (security review 2, finding 9).

No requirement IDs: CI tooling, not SPEC.md behaviour. Every action is pinned by full commit
SHA, and every checkout in a workflow that runs pull-request code drops the job's token from
the working tree (persist-credentials: false), so PR code never reads it from .git/config.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
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


# PREMERGE-wire (#1860): premerge.yml is pinned the same way. It needs `statuses: write`, so
# the exact pin, not the read-only base-copy check, is what keeps it base-only and fail-closed:
# triggers, permissions, the base checkout, the fetch-only head and the one status it posts.
PREMERGE_LINES = [
    'name: premerge',
    'on:',
    '  pull_request_target:',
    '    types: [opened, synchronize, reopened, edited]',
    '  issue_comment:',
    '    types: [created, edited, deleted]',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: premerge-${{ github.event.pull_request.number || github.event.issue.number }}',
    '  cancel-in-progress: false',
    'jobs:',
    '  premerge-gate:',
    '    name: premerge-gate',
    "    if: github.event_name == 'pull_request_target' || github.event.issue.pull_request",
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 5',
    '    environment: premerge # deployment branches: main only; holds PREMERGE_APP_KEY',
    '    outputs:',
    "      arm-node: ${{ steps.gate.outputs.arm-node }}",
    "      arm-head: ${{ steps.gate.outputs.arm-head }}",
    '    permissions:',
    '      contents: read',
    '      issues: read',
    '      pull-requests: read',
    '      statuses: write # the `premerge` status on the PR head, nothing else',
    '    steps:',
    '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2',
    '        with:',
    '          fetch-depth: 0 # the merge base with the PR head',
    '          persist-credentials: false',
    '      - name: premerge App token',
    '        id: app',
    "        if: vars.PREMERGE_APP_CLIENT_ID != ''",
    '        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1  # v3.2.0',
    '        with:',
    '          client-id: ${{ vars.PREMERGE_APP_CLIENT_ID }}',
    '          private-key: ${{ secrets.PREMERGE_APP_KEY }}',
    '          permission-statuses: write',
    '      - name: Premerge (base copy of tools/premerge.py)',
    '        id: gate',
    '        env:',
    '          PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}',
    '          REPO: ${{ github.repository }}',
    '          GH_TOKEN: ${{ github.token }}',
    '          STATUS_TOKEN: ${{ steps.app.outputs.token || github.token }}',
    '        run: |',
    '          gh api "repos/$REPO/pulls/$PR_NUMBER" > "$RUNNER_TEMP/pr.json"',
    '          HEAD_SHA=$(jq -r .head.sha "$RUNNER_TEMP/pr.json")',
    '          echo "$HEAD_SHA" | grep -Eqx \'[0-9a-f]{40}\'',
    '          posted=no',
    '          post() {',
    '            GH_TOKEN="$STATUS_TOKEN" gh api -X POST "repos/$REPO/statuses/$HEAD_SHA" -f state="$1" -f context=premerge \\',
    '              -f description="$2" -f target_url="$GITHUB_SERVER_URL/$REPO/actions/runs/$GITHUB_RUN_ID" > /dev/null',
    '            posted=yes',
    '          }',
    '          trap \'[ "$posted" = yes ] || post failure error\' EXIT',
    '          HEAD_REF=$(jq -r .head.ref "$RUNNER_TEMP/pr.json")',
    '          HEAD_REPO=$(jq -r \'.head.repo.full_name // ""\' "$RUNNER_TEMP/pr.json")',
    '          BASE_REF=$(jq -r .base.ref "$RUNNER_TEMP/pr.json")',
    '          state=failure',
    '          out=$(',
    '            [ "$BASE_REF" = main ] || { echo "base-not-main"; exit 1; }',
    '            git fetch --no-tags origin "+refs/pull/$PR_NUMBER/head:refs/remotes/pr/head" \\',
    '              "+refs/heads/$BASE_REF:refs/remotes/pr/base" || exit 1',
    '            git cat-file -e "$HEAD_SHA^{commit}" || exit 1',
    '            if [ "$HEAD_REPO" = "$REPO" ] && [ "${HEAD_REF#bot/}" != "$HEAD_REF" ]; then',
    '              exec python3 -I tools/premerge.py --bot "$HEAD_REF" --base refs/remotes/pr/base "$HEAD_SHA"',
    '            fi',
    '            gh api --paginate "repos/$REPO/issues/$PR_NUMBER/comments" \\',
    '              --jq \'.[] | {author_association, created_at, updated_at, body}\' > "$RUNNER_TEMP/comments.jsonl" || exit 1',
    '            jq -s . "$RUNNER_TEMP/comments.jsonl" > "$RUNNER_TEMP/comments.json" || exit 1',
    '            exec python3 -I tools/premerge.py --check "$RUNNER_TEMP/comments.json" "$PR_NUMBER" --base refs/remotes/pr/base "$HEAD_SHA"',
    '          ) && state=success',
    '          out=$(printf \'%s\' "${out:-error}" | tail -n 1 | tr -cd \'\\40-\\176\' | cut -c 1-120)',
    '          echo "premerge $HEAD_SHA: $state ($out)"',
    '          post "$state" "$out"',
    '          if [ "$state" = success ] && [ "$out" = same ]; then',
    '            node=$(jq -r \'select(.state == "open" and .draft == false and .auto_merge == null) | .node_id\' "$RUNNER_TEMP/pr.json")',
    '            if echo "$node" | grep -Eqx \'[A-Za-z0-9_=-]+\'; then',
    '              printf \'arm-node=%s\\narm-head=%s\\n\' "$node" "$HEAD_SHA" >> "$GITHUB_OUTPUT"',
    '            fi',
    '          fi',
    '  arm:',
    '    name: arm',
    '    needs: premerge-gate',
    "    if: needs.premerge-gate.outputs.arm-node != ''",
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 5',
    '    environment: bot # deployment branches: main only; holds BOT_PR_TOKEN',
    '    permissions: {}',
    '    steps:',
    '      - name: Arm auto-merge at the accepted head',
    '        env:',
    '          GH_TOKEN: ${{ secrets.BOT_PR_TOKEN }}',
    '          PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number }}',
    '          REPO: ${{ github.repository }}',
    '          PR_NODE: ${{ needs.premerge-gate.outputs.arm-node }}',
    '          HEAD_SHA: ${{ needs.premerge-gate.outputs.arm-head }}',
    '        run: |',
    '          [ -n "$GH_TOKEN" ] || { echo "::warning::BOT_PR_TOKEN unset: arm #$PR_NUMBER by hand (OPERATING section 7)"; exit 0; }',
    '          echo "$HEAD_SHA" | grep -Eqx \'[0-9a-f]{40}\'',
    '          if ! gh api graphql -f id="$PR_NODE" -f sha="$HEAD_SHA" -f query=\'mutation($id: ID!, $sha: GitObjectID!) { enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: MERGE, expectedHeadOid: $sha}) { clientMutationId } }\' > /dev/null; then',
    '            gh api -X PUT "repos/$REPO/pulls/$PR_NUMBER/merge" -f merge_method=merge -f sha="$HEAD_SHA" > /dev/null',
    '          fi',
    '          echo "armed #$PR_NUMBER at $HEAD_SHA"',
]


# BOARD-INTAKE-wf (#2668): intake.yml holds `issues: write` on an event any collaborator
# triggers by editing an issue, so it is pinned line by line too: the trigger set, the
# collaborator and work-item condition, the permissions, a credential-free checkout of main and
# a run line whose only event value is the issue number, passed through env (INTAKE-3).
INTAKE_LINES = [
    "name: intake",
    "on:",
    "  issues:",
    "    types: [opened, edited, labeled, unlabeled]",
    "permissions:",
    "  contents: read",
    "concurrency:",
    "  group: intake-${{ github.event.issue.number }}",
    "  cancel-in-progress: false",
    "jobs:",
    "  intake:",
    "    if: >-",
    "      contains(fromJSON('[\"OWNER\", \"MEMBER\", \"COLLABORATOR\"]'), github.event.issue.author_association)",
    "      && (contains(github.event.issue.labels.*.name, 'work-item') || github.event.label.name == 'work-item')",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 5",
    "    permissions:",
    "      contents: read",
    "      issues: write # the intake comment on this issue",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
    "        with:",
    "          persist-credentials: false",
    "      - name: Comment on the issue while it cannot render (tools/board.py intake)",
    "        env:",
    "          GITHUB_TOKEN: ${{ github.token }}",
    "          ISSUE: ${{ github.event.issue.number }}",
    '        run: python3 -I tools/board.py intake --repo "$GITHUB_REPOSITORY" --issue "$ISSUE"',
]

def lane_gate_problems(text, pinned=LANE_GATE_LINES):
    """Return why lane-gate.yml (or another `pinned` gate) differs from its pin; empty when it matches."""
    problems = []
    # Only printable ASCII and \n: YAML also breaks lines at \r, which could hide a line
    # inside what this check reads as a comment.
    if re.search(r"[^\x20-\x7e\n]", text):
        problems.append("a character other than printable ASCII or a newline")
    code = [l for l in text.split("\n") if l.strip() and not l.lstrip().startswith("#")]
    for i in range(max(len(code), len(pinned))):
        got = code[i] if i < len(code) else "<missing>"
        want = pinned[i] if i < len(pinned) else "<none>"
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
        # main requires status checks, so a workflow push to it would be rejected; trace.yml
        # and metrics.yml push a bot branch and open its PR instead; ci.yml is dispatched
        # there only when BOT_PR_TOKEN is unset, since a BOT_PR_TOKEN push already starts its run.
        for f in self.files():
            self.assertNotRegex(f.read_text(), r"git push\b[^\n]*\bmain\b", f.name)
        self.assertIn("workflow_dispatch:", (WORKFLOWS / "ci.yml").read_text())
        for name in ("trace.yml", "metrics.yml"):
            text = (WORKFLOWS / name).read_text()
            self.assertIn("gh pr create --base main", text, name)
            self.assertIn('if [ "$BOT_TOKEN_SET" != true ]; then gh workflow run ci.yml --ref "$BRANCH"; fi', text, name)
            self.assertIn("BOT_TOKEN_SET: ${{ secrets.BOT_PR_TOKEN != '' }}", text, name)
            self.assertIn('gh pr merge "$BRANCH" --auto --squash', text, name)

    def test_no_records_bot(self):
        # Cut 4 (#2172): the verdict comment on the PR is the record, so no workflow writes reviews/.
        self.assertFalse((WORKFLOWS / "records.yml").exists())

    def test_trace_batch_runs_at_most_daily(self):
        # One TRACE.md PR a day instead of one per merge (GitHub process audit, 2026-10-17):
        # ci.yml's `trace.py --check` still guards every PR's markers.
        text = (WORKFLOWS / "trace.yml").read_text()
        on = re.search(r"^on:\n((?:[ \t]+.*\n)+)", text, re.M).group(1)
        self.assertRegex(on, r"cron:\s*'\d+ \d+ \* \* \*'")
        self.assertRegex(on, r"(?m)^\s+workflow_dispatch:")
        self.assertNotRegex(on, r"(?m)^\s+push:")

    def test_no_per_push_metrics_refresh(self):
        # The strict up-to-date rule it served was dropped on 2026-10-15; the daily PR merges as is.
        self.assertFalse((WORKFLOWS / "metrics-refresh.yml").exists())

    def test_bot_token_jobs_run_in_the_bot_environment(self):
        # BOT_PR_TOKEN is a `bot` environment secret restricted to main (#1691, #1769), so every
        # job that can write contents must name that environment, and nothing else names it.
        for f in self.files():
            jobs = re.split(r"(?m)^  (?=[a-z][\w-]*:\n)", f.read_text().split("\njobs:\n", 1)[-1])
            for job in jobs:
                writes, env = "contents: write" in job, bool(re.search(r"(?m)^    environment: bot$", job))
                if f.name in ("board.yml", "trace.yml", "metrics.yml"):
                    self.assertEqual(writes, env, f"{f.name}: {job.split(':', 1)[0]}")
                elif f.name == "premerge.yml" and job.startswith("arm:\n"):
                    # ARM-on-accept (#3103): arms with BOT_PR_TOKEN, so its merge starts push workflows on main.
                    self.assertRegex(job, r"(?m)^    environment: bot #.*\n    permissions: \{\}$", f.name)
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

    def test_board_renders_on_a_schedule_not_per_issue_event(self):
        # BOARD-debounce (#3099): a render per issue event merged one main commit per label burst,
        # and main's strict up-to-date rule put every open PR behind each one. Renders run on a
        # schedule, on dispatch, and on a push that touches BOARD.md, never on an issue event.
        triggers = (WORKFLOWS / "board.yml").read_text().split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(re.findall(r"(?m)^  ([a-z_]+):", triggers), ["schedule", "push", "workflow_dispatch"])
        self.assertRegex(triggers, r"(?m)^    - cron: '\d+ \*/\d+ \* \* \*'$")

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

    def test_intake_is_pinned(self):
        # BOARD-INTAKE-wf (#2668, INTAKE-3): the shipped workflow equals its pin, and no other
        # workflow runs the intake command.
        self.assertEqual(lane_gate_problems((WORKFLOWS / "intake.yml").read_text(), INTAKE_LINES), [])
        for f in self.files():
            if f.name != "intake.yml":
                self.assertNotIn("board.py intake", f.read_text(), f.name)

    def test_intake_check_catches_each_reported_edit(self):
        # BOARD-INTAKE-wf (#2668, INTAKE-3): each widening or issue-text path fails the pin.
        text = (WORKFLOWS / "intake.yml").read_text()
        run = INTAKE_LINES[-1][len("        run: "):]
        step = "      - name: Comment on the issue while it cannot render (tools/board.py intake)\n"
        edits = {
            "comment trigger": ("on:\n  issues:", "on:\n  issue_comment:\n  issues:"),
            "closed type": ("labeled, unlabeled]", "labeled, unlabeled, closed]"),
            "target trigger": ("on:\n", "on:\n  pull_request_target:\n"),
            "outsider": ("\"COLLABORATOR\"]", "\"COLLABORATOR\", \"NONE\"]"),
            "any label": ("contains(github.event.issue.labels.*.name, 'work-item')", "true"),
            "pull-requests write": ("      issues: write", "      issues: write\n      pull-requests: write"),
            "contents write": ("      contents: read\n      issues", "      contents: write\n      issues"),
            "write-all": ("permissions:\n  contents: read\n#", "permissions: write-all\n#"),
            "title in env": ("          ISSUE: ${{ github.event.issue.number }}",
                             "          ISSUE: ${{ github.event.issue.title }}"),
            "body in run": (run, run + ' --note "${{ github.event.issue.body }}"'),
            "persist credentials": ("persist-credentials: false", "persist-credentials: true"),
            "secret env": ("          GITHUB_TOKEN: ${{ github.token }}", "          GITHUB_TOKEN: ${{ secrets.BOT_PR_TOKEN }}"),
            "step continue-on-error": (step, step + "        continue-on-error: true\n"),
            "shell override": (step, step + "        shell: python {0}\n"),
            "not isolated": ("python3 -I tools", "python3 tools"),
            "no concurrency": ("  cancel-in-progress: false", "  cancel-in-progress: true"),
            "self-hosted": ("runs-on: ubuntu-latest", "runs-on: self-hosted"),
            "carriage return in comment": ("# One run at a time", "# One\r    if: false\r# run at a time"),
        }
        for name, (old, new) in edits.items():
            with self.subTest(name):
                self.assertIn(old, text)
                self.assertTrue(lane_gate_problems(text.replace(old, new, 1), INTAKE_LINES), name)

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

    def test_premerge_status_is_pinned(self):
        # PREMERGE-wire (#1860): triggers (PR pushes and PR comments), the `premerge` context, the
        # base-only checkout and the fail-closed status post are pinned line by line.
        text = (WORKFLOWS / "premerge.yml").read_text()
        self.assertEqual(lane_gate_problems(text, PREMERGE_LINES), [])
        for edit in (("statuses: write", "statuses: write\n      contents: write"),
                     ("    types: [created, edited, deleted]", "    types: [created]"),
                     ("context=premerge", "context=premerge-x"),
                     ("          trap ", "          # trap "),
                     ("          post \"$state\" \"$out\"", "          post success \"$out\""),
                     (") && state=success", ") || true; state=success"),
                     ("git cat-file -e \"$HEAD_SHA^{commit}\" || exit 1", "git cat-file -e \"$HEAD_SHA^{commit}\""),
                     ("          persist-credentials: false", "          persist-credentials: false\n          ref: refs/pull/1/head"),
                     # PREMERGE-source (#1943): the key's environment, the App token on the post,
                     # the token's one permission and the main-only base.
                     ("    environment: premerge", "    # environment: premerge"),
                     ("STATUS_TOKEN: ${{ steps.app.outputs.token || github.token }}", "STATUS_TOKEN: ${{ github.token }}"),
                     ('GH_TOKEN="$STATUS_TOKEN" gh api -X POST', "gh api -X POST"),
                     ("          permission-statuses: write", "          permission-statuses: write\n          permission-contents: write"),
                     ('[ "$BASE_REF" = main ] || ', ""),
                     # ARM-on-accept (#3103): only a `same` from --check arms (not `bot`), only an open,
                     # non-draft, unarmed PR, pinned to the gate's head, with the main-only bot token.
                     ('[ "$out" = same ]', '[ "$out" != error ]'),
                     ('.draft == false and .auto_merge == null', '.auto_merge == null'),
                     ("expectedHeadOid: $sha", "expectedHeadOid: null"),
                     ('-f merge_method=merge -f sha="$HEAD_SHA"', "-f merge_method=merge"),
                     ("    environment: bot", "    # environment: bot"),
                     ("    permissions: {}", "    permissions:\n      contents: write"),
                     ("GH_TOKEN: ${{ secrets.BOT_PR_TOKEN }}", "GH_TOKEN: ${{ secrets.BOT_PR_TOKEN || github.token }}"),
                     ):
            with self.subTest(edit[0]):
                self.assertIn(edit[0], text)
                self.assertTrue(lane_gate_problems(text.replace(*edit, 1), PREMERGE_LINES), edit)
        # Only this workflow may post commit statuses, so no other job can fake `premerge`.
        for f in self.files():
            if f.name != "premerge.yml":
                self.assertNotRegex(f.read_text(), r"statuses:\s*write|/statuses/", f.name)

    def test_premerge_ruleset_context_is_documented(self):
        # PREMERGE-wire (#1860): the context the ruleset must require is the one the workflow posts.
        ops = (WORKFLOWS.parent.parent / "docs" / "OPERATING.md").read_text()
        self.assertIn("requires the `premerge` status", ops)

    def test_steps_finds_steps(self):
        sample = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          x: 1\n      - run: echo\n"
        self.assertEqual(list(steps(sample)), [("actions/checkout@v4", "      - uses: actions/checkout@v4\n        with:\n          x: 1")])


# PREMERGE-stale (#1946): run premerge.yml's own script under the runner's shell with `gh`, `git`,
# `python3` and `jq` stubbed, so the job result and the posted status are checked, not just pinned.
STUB_GH = r"""#!/bin/sh
case "$*" in
  "api -X POST "*) [ "$FAIL_AT" = post ] && [ ! -e "$STUBS/post-failed" ] && { : > "$STUBS/post-failed"; exit 1; }
                   echo "$*" >> "$STUBS/posts"; echo "$GH_TOKEN" >> "$STUBS/post-tokens"; exit 0 ;;
  "api --paginate "*) [ "$FAIL_AT" = comments ] && exit 1; echo '{"author_association":"OWNER","created_at":"t","body":"b"}' ;;
  "api repos/"*) [ "$FAIL_AT" = pulls ] && exit 1
                 echo '{"head":{"sha":"'"$SHA"'","ref":"'"$REF"'","repo":{"full_name":"o/r"}},"base":{"ref":"'"$BASE"'"},'"$PR_STATE"'}' ;;
  *) exit 2 ;;
esac
"""
STUB_JQ = r"""#!/bin/sh
[ "$FAIL_AT" = jq ] && [ "$2" = .head.ref ] && exit 1
exec "$REAL_JQ" "$@"
"""
STUB_PY = r"""#!/bin/sh
echo "$VERDICT"; [ "$VERDICT" = same ] || [ "$VERDICT" = bot ]
"""


def premerge_script():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    return run_block(lines, lines.index("        run: |") + 1)


def run_block(lines, start):
    end = next((i for i in range(start, len(lines)) if lines[i].strip() and not lines[i].startswith("          ")), len(lines))
    return "\n".join(l[10:] for l in lines[start:end]) + "\n"


def arm_script():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    return run_block(lines, lines.index("        run: |", lines.index("  arm:")) + 1)


class PremergeRunTest(unittest.TestCase):
    SHA = "a" * 40

    OPEN = '"state":"open","draft":false,"auto_merge":null,"node_id":"PR_kw1"'

    def run_gate(self, verdict="no-verdict", fail_at="", ref="feature", base="main", tokens=None, outputs=None, pr_state=OPEN):
        real_jq = shutil.which("jq")
        self.assertTrue(real_jq, "jq is on the runner image; the test needs it")
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            for name, body in (("gh", STUB_GH), ("jq", STUB_JQ), ("python3", STUB_PY), ("git", "#!/bin/sh\nexit 0\n")):
                (stubs / name).write_text(body)
                (stubs / name).chmod(0o755)
            (stubs / "run.sh").write_text(premerge_script())
            env = {"PATH": "%s:/usr/bin:/bin" % stubs, "STUBS": d, "REAL_JQ": real_jq, "SHA": self.SHA,
                   "REF": ref, "BASE": base, "VERDICT": verdict, "FAIL_AT": fail_at, "RUNNER_TEMP": d, "PR_NUMBER": "7",
                   "REPO": "o/r", "GH_TOKEN": "synthetic", "STATUS_TOKEN": "synthetic-app", "GITHUB_SERVER_URL": "https://example.invalid",
                   "GITHUB_RUN_ID": "1", "GITHUB_OUTPUT": str(stubs / "out"), "PR_STATE": pr_state}
            # The runner's default `run` shell.
            proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(stubs / "run.sh")],
                                  env=env, cwd=d, capture_output=True, text=True, timeout=30)
            posts = (stubs / "posts").read_text().splitlines() if (stubs / "posts").exists() else []
            if tokens is not None:
                tokens.extend((stubs / "post-tokens").read_text().split())
            if outputs is not None and (stubs / "out").exists():
                outputs.extend((stubs / "out").read_text().split())
        return proc.returncode, [re.search(r"state=(\w+)", p).group(1) for p in posts]

    def test_failure_verdict_posts_failure_but_job_passes(self):
        # The `premerge` status is the gate, not the job: a failing verdict rides only on the
        # status, so comment-time runs (attached to main's head) don't read as main breaking.
        self.assertEqual(self.run_gate("no-verdict"), (0, ["failure"]))
        self.assertEqual(self.run_gate("fix-list"), (0, ["failure"]))

    def test_same_posts_success(self):
        self.assertEqual(self.run_gate("same"), (0, ["success"]))
        self.assertEqual(self.run_gate("bot", ref="bot/trace"), (0, ["success"]))

    def test_error_after_head_known_posts_failure(self):
        # The #1946 path: a rerun that dies outside the guarded block must not leave the head's
        # earlier `success` standing. The job stays red so the error is visible.
        code, states = self.run_gate("same", fail_at="jq")
        self.assertEqual((code != 0, states), (True, ["failure"]))
        self.assertEqual(self.run_gate("same", fail_at="comments"), (0, ["failure"]))
        code, states = self.run_gate("same", fail_at="post")
        self.assertEqual((code != 0, states), (True, ["failure"]))

    def test_status_is_posted_with_the_app_token(self):
        # PREMERGE-source-a (#1943): the post uses STATUS_TOKEN (the App's, which the ruleset
        # pins), on success and on the trap's failure alike; reads keep the job's own token.
        for verdict, fail_at in (("same", ""), ("no-verdict", ""), ("same", "jq")):
            tokens = []
            self.run_gate(verdict, fail_at=fail_at, tokens=tokens)
            self.assertEqual(tokens, ["synthetic-app"], (verdict, fail_at))

    def test_base_other_than_main_fails(self):
        # PREMERGE-source-b (#1943): a comment run uses main's workflow for a PR into any branch;
        # a head accepted against another base must not carry `success` into a PR to main.
        self.assertEqual(self.run_gate("same", base="stacked"), (0, ["failure"]))
        self.assertEqual(self.run_gate("bot", ref="bot/trace", base="stacked"), (0, ["failure"]))

    def test_only_a_full_accept_on_an_open_unarmed_pr_arms(self):
        # ARM-on-accept (#3103): the gate hands the arm job the PR and the head it read, only on `same`.
        out = []
        self.assertEqual(self.run_gate("same", outputs=out), (0, ["success"]))
        self.assertEqual(out, ["arm-node=PR_kw1", "arm-head=" + self.SHA])
        for verdict, kw in (("no-verdict", {}), ("needs-security", {}), ("edited-verdict", {}), ("bot", {"ref": "bot/trace"}),
                            ("same", {"base": "stacked"}), ("same", {"fail_at": "comments"}),
                            ("same", {"pr_state": self.OPEN.replace('"draft":false', '"draft":true')}),
                            ("same", {"pr_state": self.OPEN.replace('"state":"open"', '"state":"closed"')}),
                            ("same", {"pr_state": self.OPEN.replace('"auto_merge":null', '"auto_merge":{"merge_method":"merge"}')}),
                            ("same", {"pr_state": self.OPEN.replace('PR_kw1', 'PR\\nx=1')})):
            out = []
            self.run_gate(verdict, outputs=out, **kw)
            self.assertEqual(out, [], (verdict, kw))

    def test_error_before_head_known_fails_the_job(self):
        # Residual named in #1946: with the pulls API down there is no head to post to.
        code, states = self.run_gate("same", fail_at="pulls")
        self.assertEqual((code != 0, states), (True, []))


STUB_ARM_GH = r"""#!/bin/sh
echo "$*" >> "$STUBS/calls"
case "$1 $2" in
  "api graphql") [ "$ARM" = ok ] ;;
  "api -X") [ "$MERGE" = ok ] ;;
  *) exit 2 ;;
esac
"""


class ArmRunTest(unittest.TestCase):
    SHA = "b" * 40

    def run_arm(self, arm="ok", merge="ok", token="synthetic-bot", sha=SHA):
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            (stubs / "gh").write_text(STUB_ARM_GH)
            (stubs / "gh").chmod(0o755)
            (stubs / "run.sh").write_text(arm_script())
            env = {"PATH": "%s:/usr/bin:/bin" % stubs, "STUBS": d, "ARM": arm, "MERGE": merge, "GH_TOKEN": token,
                   "PR_NUMBER": "7", "REPO": "o/r", "PR_NODE": "PR_kw1", "HEAD_SHA": sha}
            proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", str(stubs / "run.sh")],
                                  env=env, cwd=d, capture_output=True, text=True, timeout=30)
            calls = (stubs / "calls").read_text().splitlines() if (stubs / "calls").exists() else []
        return proc.returncode, calls

    def test_arms_pinned_to_the_head(self):
        code, calls = self.run_arm()
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("-f id=PR_kw1 -f sha=" + self.SHA, calls[0])
        self.assertIn("expectedHeadOid: $sha", calls[0])

    def test_already_mergeable_merges_pinned(self):
        # GitHub refuses to arm a PR whose checks are all green already; the merge carries the same head pin.
        code, calls = self.run_arm(arm="refused")
        self.assertEqual(code, 0)
        self.assertEqual(calls[1], "api -X PUT repos/o/r/pulls/7/merge -f merge_method=merge -f sha=" + self.SHA)

    def test_head_moved_fails_visibly(self):
        # A push since the gate read the head makes GitHub refuse both calls; the job goes red.
        code, calls = self.run_arm(arm="refused", merge="refused")
        self.assertNotEqual(code, 0)
        self.assertEqual(len(calls), 2)

    def test_no_token_or_bad_head_never_calls(self):
        self.assertEqual(self.run_arm(token=""), (0, []))
        code, calls = self.run_arm(sha="b" * 39)
        self.assertEqual((code != 0, calls), (True, []))


if __name__ == "__main__":
    unittest.main()
