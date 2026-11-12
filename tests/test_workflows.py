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
import sys
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


def job_steps(text, job):
    """Return [(name, step text)] for each step of a top-level job, in order."""
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  \S|\Z)", text, re.M | re.S)
    assert m, job
    out = []
    for block in re.split(r"^(?=      - )", m.group(1), flags=re.M)[1:]:
        name = re.match(r"      - (?:uses: \S+\n\s+)?name: (.*)", block)
        out.append((name.group(1).strip() if name else "", block.rstrip()))
    return out


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
    "concurrency:",
    "  group: ${{ github.workflow }}-${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
    "  cancel-in-progress: ${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 }}",
    "permissions:",
    "  contents: read",
    "jobs:",
    "  lane-gate:",
    "    name: lane-gate",
    "    runs-on: ubuntu-24.04",
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
    '    types: [opened, synchronize, reopened, edited, closed]',
    '  issue_comment:',
    '    types: [created, edited, deleted]',
    '  workflow_run:',
    '    workflows: [ci, assurance, vulncheck, word-budget, lane-gate, trusted-base, formal, keycheck, image, testkit-image, mutgate, infer-real, vision-real, enforcer-image, camnode-image, drone-sitl]',
    '    types: [completed]',
    '  workflow_dispatch:',
    '    inputs:',
    '      pr:',
    "        description: the PR to rerun the gate for (premerge's fork-pr job)",
    '        required: true',
    '        type: number',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: premerge-${{ github.event.pull_request.number || github.event.issue.number || github.event.workflow_run.pull_requests[0].number || inputs.pr || github.run_id }}',
    '  cancel-in-progress: false',
    'jobs:',
    '  premerge-gate:',
    '    name: premerge-gate',
    "    if: (github.event_name == 'pull_request_target' && github.event.action != 'closed') || github.event.issue.pull_request || github.event.workflow_run.pull_requests[0] || github.event_name == 'workflow_dispatch'",
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    environment: premerge # deployment branches: main only; holds PREMERGE_APP_KEY',
    '    outputs:',
    '      merge-head: ${{ steps.gate.outputs.merge-head }}',
    '      merge-repo: ${{ steps.gate.outputs.merge-repo }}',
    '      merge-ref: ${{ steps.gate.outputs.merge-ref }}',
    '      rerun: ${{ steps.gate.outputs.rerun }}',
    '    permissions:',
    '      contents: read',
    '      issues: read',
    '      pull-requests: read',
    '      actions: read # a bot PR\'s writer run and its artifact',
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
    '        shell: bash # -eo pipefail: GitHub\'s default `bash -e` lets a failed read piped into jq pass',
    '        id: gate',
    '        env:',
    '          PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number || github.event.workflow_run.pull_requests[0].number || inputs.pr }}',
    '          REPO: ${{ github.repository }}',
    '          GH_TOKEN: ${{ github.token }}',
    '          STATUS_TOKEN: ${{ steps.app.outputs.token || github.token }}',
    '        run: |',
    '          [[ "$PR_NUMBER" =~ ^[1-9][0-9]{0,9}$ ]] || { echo "not a PR number: $PR_NUMBER"; exit 1; }',
    '          gh api "repos/$REPO/pulls/$PR_NUMBER" > "$RUNNER_TEMP/pr.json"',
    '          HEAD_SHA=$(jq -r .head.sha "$RUNNER_TEMP/pr.json")',
    '          echo "$HEAD_SHA" | grep -Eqx \'[0-9a-f]{40}\'',
    '          posted=no skipped=no fork=no',
    '          ours() {',
    '            n=$(gh api --paginate "repos/$REPO/pulls?state=open&base=main&per_page=100" \\',
    '              --jq ".[] | select(.head.sha == \\"$HEAD_SHA\\" and .head.repo.full_name == \\"$REPO\\" and .number != $PR_NUMBER) | .number") || return 1',
    '            grep -Eqx \'[1-9][0-9]{0,9}\' <<< "$n"',
    '          }',
    '          post() {',
    '            if [ "$fork" = yes ] && ours; then',
    '              echo "::notice::#$PR_NUMBER is a fork PR on the head of an open PR from $REPO; that PR\'s gate posts premerge"',
    '              posted=yes skipped=yes; return',
    '            fi',
    '            GH_TOKEN="$STATUS_TOKEN" gh api -X POST "repos/$REPO/statuses/$HEAD_SHA" -f state="$1" -f context=premerge \\',
    '              -f description="$2" -f target_url="$GITHUB_SERVER_URL/$REPO/actions/runs/$GITHUB_RUN_ID" > /dev/null',
    '            posted=yes',
    '            if [ "$fork" = yes ] && ours; then',
    '              echo "::notice::#$PR_NUMBER posted on the head of open PR(s)" $n "from $REPO; handoff reruns their gate"',
    '              printf \'rerun=%s\\n\' "$(tr \'\\n\' \' \' <<< "$n")" >> "$GITHUB_OUTPUT"; skipped=yes',
    '            fi',
    '          }',
    '          trap \'[ "$posted" = yes ] || post failure error\' EXIT',
    '          HEAD_REF=$(jq -r .head.ref "$RUNNER_TEMP/pr.json")',
    '          HEAD_REPO=$(jq -r \'.head.repo.full_name // ""\' "$RUNNER_TEMP/pr.json")',
    '          [ "$HEAD_REPO" = "$REPO" ] || fork=yes',
    '          BASE_REF=$(jq -r .base.ref "$RUNNER_TEMP/pr.json")',
    '          state=failure',
    '          out=$(',
    '            [ "$BASE_REF" = main ] || { echo "base-not-main"; exit 1; }',
    '            git fetch --no-tags origin "+refs/pull/$PR_NUMBER/head:refs/remotes/pr/head" \\',
    '              "+refs/heads/$BASE_REF:refs/remotes/pr/base" || exit 1',
    '            git cat-file -e "$HEAD_SHA^{commit}" || exit 1',
    '            if [ "$HEAD_REPO" = "$REPO" ] && [ "${HEAD_REF#bot/}" != "$HEAD_REF" ]; then',
    '              run_id=$(git log -1 --format=\'%(trailers:key=Bot-Run,valueonly)\' "$HEAD_SHA") || exit 1',
    '              [[ "$run_id" =~ ^[0-9]+$ ]] || { echo "bot-unproven no-run"; exit 1; }',
    '              gh api "repos/$REPO/actions/runs/$run_id" > "$RUNNER_TEMP/run.json" || exit 1',
    '              art=$(gh api --paginate "repos/$REPO/actions/runs/$run_id/artifacts?per_page=100" \\',
    '                | jq -r --arg name "${HEAD_REF#bot/}" \'.artifacts[] | select(.name == $name and (.expired | not)) | .id\' \\',
    '                | sort -n | tail -n 1) || exit 1',
    '              [[ "$art" =~ ^[0-9]+$ ]] || { echo "bot-unproven no-output"; exit 1; }',
    '              gh api "repos/$REPO/actions/artifacts/$art/zip" > "$RUNNER_TEMP/output.zip" || exit 1',
    '              exec python3 -I tools/premerge.py --bot "$HEAD_REF" --run "$RUNNER_TEMP/run.json" \\',
    '                --output "$RUNNER_TEMP/output.zip" --base refs/remotes/pr/base "$HEAD_SHA"',
    '            fi',
    '            gh api --paginate "repos/$REPO/issues/$PR_NUMBER/comments" \\',
    '              --jq \'.[] | {author_association, created_at, updated_at, body}\' > "$RUNNER_TEMP/comments.jsonl" || exit 1',
    '            jq -s . "$RUNNER_TEMP/comments.jsonl" > "$RUNNER_TEMP/comments.json" || exit 1',
    '            onto=$(git merge-base refs/remotes/pr/base "$HEAD_SHA") || exit 1',
    '            bash tools/premerge_runs.sh "$REPO" "$RUNNER_TEMP/pr.json" "$onto" > "$RUNNER_TEMP/runs.json" || exit 1',
    '            exec python3 -I tools/premerge.py --check "$RUNNER_TEMP/comments.json" "$PR_NUMBER" --runs "$RUNNER_TEMP/runs.json" \\',
    '              --base refs/remotes/pr/base "$HEAD_SHA"',
    '          ) && state=success',
    '          verdict=$out',
    '          out=$(printf \'%s\' "${out:-error}" | tail -n 1 | python3 -I -c \'import sys;s="".join(c for c in sys.stdin.buffer.read().decode(errors="replace") if " " <= c <= "~" or c == "\\u00b7");t=s[:120];i=t.rfind("/") if t.count(" ") < 2 else t.rfind(" ");sys.stdout.buffer.write((t if len(s) <= 120 or s[120] in " /" or i < 0 else t[:i+1].rstrip()).encode())\')',
    '          echo "premerge $HEAD_SHA: $state ($out)"',
    '          post "$state" "$out"',
    '          if [ "$state" = success ] && [ "$verdict" = same ] && [ "$skipped" = no ] && \\',
    '            jq -e \'.state == "open" and .draft == false and .auto_merge == null\' "$RUNNER_TEMP/pr.json" > /dev/null; then',
    '            printf \'merge-head=%s\\nmerge-repo=%s\\nmerge-ref=%s\\n\' "$HEAD_SHA" "$HEAD_REPO" "$HEAD_REF" >> "$GITHUB_OUTPUT"',
    '          fi',
    '  merge:',
    '    name: merge',
    '    needs: premerge-gate',
    "    if: needs.premerge-gate.outputs.merge-head != ''",
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    environment: bot # deployment branches: main only; holds BOT_PR_TOKEN',
    '    permissions: {}',
    '    steps:',
    '      - name: Merge the accepted head once every check on it is green',
    '        shell: bash # -eo pipefail: GitHub\'s default `bash -e` lets a failed read piped into jq pass',
    '        env:',
    '          GH_TOKEN: ${{ secrets.BOT_PR_TOKEN }}',
    '          PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number || github.event.workflow_run.pull_requests[0].number || inputs.pr }}',
    '          REPO: ${{ github.repository }}',
    '          HEAD_SHA: ${{ needs.premerge-gate.outputs.merge-head }}',
    '          HEAD_REPO: ${{ needs.premerge-gate.outputs.merge-repo }}',
    '          HEAD_REF: ${{ needs.premerge-gate.outputs.merge-ref }}',
    '        run: |',
    '          [[ "$PR_NUMBER" =~ ^[1-9][0-9]{0,9}$ ]] || { echo "not a PR number: $PR_NUMBER"; exit 1; }',
    '          [ -n "$GH_TOKEN" ] || { echo "::warning::BOT_PR_TOKEN unset: arm #$PR_NUMBER by hand (OPERATING section 7)"; exit 0; }',
    '          echo "$HEAD_SHA" | grep -Eqx \'[0-9a-f]{40}\'',
    '          [ -n "$HEAD_REPO" ] && [ -n "$HEAD_REF" ] || { echo "::warning::#$PR_NUMBER head repository unknown: arm by hand"; exit 0; }',
    '          suite=$(gh api "repos/$REPO/actions/runs/$GITHUB_RUN_ID" --jq .check_suite_id) && echo "$suite" | grep -Eqx \'[0-9]+\' \\',
    '            || { echo "::warning::#$PR_NUMBER own check suite unreadable; the next run retries"; exit 0; }',
    "          bwfs='[]' bruns='[]'",
    '          if base=$(gh api "repos/$REPO/compare/main...$HEAD_SHA" --jq .merge_base_commit.sha) && echo "$base" | grep -Eqx \'[0-9a-f]{40}\'; then',
    '            bw=$(gh api --paginate "repos/$REPO/actions/runs?head_sha=$base&per_page=100" --jq \'.workflow_runs[]\' \\',
    '              | jq -cs \'map(select(.head_branch == "main" and (.event | IN("push", "schedule")))) | group_by(.workflow_id)',
    '                        | map(max_by(.id) | select(.run_attempt == 1 and .conclusion == "failure"))\') || bw=\'[]\'',
    '            bwfs=$(printf \'%s\' "$bw" | jq -c \'map(.name)\') || bwfs=\'[]\'',
    '            bruns=$(printf \'%s\' "$bw" | jq -r \'.[].id\' | while read -r id; do',
    '                      echo "$id" | grep -Eqx \'[0-9]+\' && gh api --paginate "repos/$REPO/actions/runs/$id/attempts/1/jobs?per_page=100" --jq \'.jobs[]\' || exit 1',
    '                    done | jq -cs \'map(select(.conclusion == "failure") | .name) | unique\') || bruns=\'[]\'',
    '          fi',
    '          echo "excused as failed on the merge base: $bwfs $bruns"',
    '          hr=$(gh api --paginate "repos/$REPO/actions/runs?head_sha=$HEAD_SHA&per_page=100" --jq \'.workflow_runs[]\' \\',
    '            | jq -cs --arg repo "$HEAD_REPO" --arg ref "$HEAD_REF" \\',
    '                \'map({ours: (.head_repository.full_name == $repo and .head_branch == $ref), check_suite_id, path, workflow_id, id, status, conclusion, name})\') \\',
    '            || { echo "::warning::#$PR_NUMBER workflow runs unreadable; the next run retries"; exit 0; }',
    '          foreign=$(printf \'%s\' "$hr" | jq -c \'map(select(.ours | not) | .check_suite_id)\')',
    '          wfs=$(printf \'%s\' "$hr" \\',
    '            | jq -r --argjson base "$bwfs" \'map(select(.ours and (.path | startswith(".github/workflows/premerge.yml") | not))) | group_by(.workflow_id)[] | max_by(.id)',
    '                      | select(.status != "completed" or (.conclusion | IN("success", "skipped", "neutral") | not))',
    '                      | select(.conclusion != "failure" or (.name | IN($base[]) | not)) | .name\') \\',
    '            || { echo "::warning::#$PR_NUMBER workflow runs unreadable; the next run retries"; exit 0; }',
    '          runs=$(gh api --paginate "repos/$REPO/commits/$HEAD_SHA/check-runs?per_page=100" --jq \'.check_runs[]\' \\',
    '            | jq -r --argjson suite "$suite" --argjson foreign "$foreign" --argjson base "$bruns" \'select(.check_suite.id != $suite)',
    '                  | select(.check_suite.id | IN($foreign[]) | not)',
    '                  | select(.status != "completed" or (.conclusion | IN("success", "skipped", "neutral") | not))',
    '                  | select(.conclusion != "failure" or (.name | IN($base[]) | not)) | .name\') \\',
    '            || { echo "::warning::#$PR_NUMBER check runs unreadable; the next run retries"; exit 0; }',
    '          stats=$(gh api "repos/$REPO/commits/$HEAD_SHA/status?per_page=100" --jq \'.statuses[] | select(.state != "success") | .context\') \\',
    '            || { echo "::warning::#$PR_NUMBER statuses unreadable; the next run retries"; exit 0; }',
    '          if [ -n "$wfs$runs$stats" ]; then echo "::notice::#$PR_NUMBER not merged yet, waiting on:" $wfs $runs $stats; exit 0; fi',
    '          if ! gh api -X PUT "repos/$REPO/pulls/$PR_NUMBER/merge" -f merge_method=merge -f sha="$HEAD_SHA" > /dev/null; then',
    '            echo "::warning::#$PR_NUMBER merge refused at $HEAD_SHA; the next run retries, or arm by hand"; exit 0',
    '          fi',
    '          echo "merged #$PR_NUMBER at $HEAD_SHA"',
    '  fork-pr:',
    '    name: fork-pr',
    "    if: github.event_name == 'workflow_run' && !github.event.workflow_run.pull_requests[0] && startsWith(github.event.workflow_run.event, 'pull_request')",
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    permissions:',
    '      pull-requests: read',
    "      actions: write # dispatch premerge.yml on main for the run's PR, nothing else",
    '    steps:',
    "      - name: Rerun the gate for the run's one open PR into main",
    '        shell: bash # -eo pipefail: a failed read must stop the step, never read as no PR',
    '        env:',
    '          GH_TOKEN: ${{ github.token }}',
    '          REPO: ${{ github.repository }}',
    '          HEAD_OWNER: ${{ github.event.workflow_run.head_repository.owner.login }}',
    '          HEAD_REPO: ${{ github.event.workflow_run.head_repository.full_name }}',
    '          HEAD_BRANCH: ${{ github.event.workflow_run.head_branch }}',
    '        run: |',
    '          [[ "$HEAD_OWNER" =~ ^[A-Za-z0-9-]+$ ]] && [ "$HEAD_REPO" != "${HEAD_REPO#"$HEAD_OWNER"/}" ] && [ -n "$HEAD_BRANCH" ] \\',
    '            || { echo "::warning::the run names no head repository and branch; no gate rerun"; exit 0; }',
    '          gh api -X GET "repos/$REPO/pulls" -f state=open -f base=main -f head="$HEAD_OWNER:$HEAD_BRANCH" -f per_page=100 \\',
    '            > "$RUNNER_TEMP/prs.json"',
    '          prs=$(jq -c --arg repo "$HEAD_REPO" --arg ref "$HEAD_BRANCH" \\',
    '            \'[.[] | select(.head.repo.full_name == $repo and .head.ref == $ref and .base.ref == "main") | .number]\' "$RUNNER_TEMP/prs.json")',
    '          if [ "$(jq length <<< "$prs")" != 1 ]; then',
    '            echo "::warning::$HEAD_REPO:$HEAD_BRANCH has open PRs into main $prs, not one; no gate rerun"; exit 0',
    '          fi',
    '          pr=$(jq \'.[0]\' <<< "$prs")',
    '          [[ "$pr" =~ ^[1-9][0-9]{0,9}$ ]]',
    '          gh api -X POST "repos/$REPO/actions/workflows/premerge.yml/dispatches" -f ref=main -f "inputs[pr]=$pr" > /dev/null',
    '          echo "reran the gate for #$pr"',
    # PREMERGE-status-bind-fu (#5515): `handoff`, the second job holding `actions: write`.
    '  handoff:',
    '    name: handoff',
    '    needs: premerge-gate',
    "    if: ${{ !cancelled() && (needs.premerge-gate.outputs.rerun != '' || (github.event_name == 'pull_request_target' && (github.event.action == 'closed' || github.event.action == 'synchronize' || github.event.changes.base.ref.from))) }}",
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    permissions:',
    '      pull-requests: read',
    '      actions: write # dispatch premerge.yml on main for the other open PRs on a shared head, nothing else',
    '    steps:',
    '      - name: Rerun the gate for the other open PRs on a head this PR left or shares',
    '        shell: bash # -eo pipefail: a failed read must stop the step, never read as no PR',
    '        env:',
    '          GH_TOKEN: ${{ github.token }}',
    '          REPO: ${{ github.repository }}',
    '          PR_NUMBER: ${{ github.event.pull_request.number || github.event.issue.number || github.event.workflow_run.pull_requests[0].number || inputs.pr }}',
    '          RERUN: ${{ needs.premerge-gate.outputs.rerun }}',
    '          EVENT: ${{ github.event_name }}',
    '          ACTION: ${{ github.event.action }}',
    '          BEFORE: ${{ github.event.before }}',
    '          HEAD_SHA: ${{ github.event.pull_request.head.sha }}',
    '          RETARGETED: ${{ github.event.changes.base.ref.from }}',
    '        run: |',
    '          [[ "$PR_NUMBER" =~ ^[1-9][0-9]{0,9}$ ]] || { echo "not a PR number: $PR_NUMBER"; exit 1; }',
    '          left=none',
    '          if [ "$EVENT" = pull_request_target ]; then',
    '            case "$ACTION" in',
    '              synchronize) left=$BEFORE ;;',
    '              closed) left=$HEAD_SHA ;;',
    '              edited) [ -z "$RETARGETED" ] || left=$HEAD_SHA ;;',
    '            esac',
    '          fi',
    '          prs=$(tr \' \' \'\\n\' <<< "$RERUN")',
    '          if [ "$left" != none ]; then',
    '            [[ "$left" =~ ^[0-9a-f]{40}$ ]] || { echo "not a sha: $left"; exit 1; }',
    '            listed=$(gh api --paginate "repos/$REPO/pulls?state=open&base=main&per_page=100" \\',
    '              --jq ".[] | select(.head.sha == \\"$left\\" and .number != $PR_NUMBER) | .number")',
    "            prs+=$'\\n'$listed",
    '          fi',
    '          if grep -Evx \'([1-9][0-9]{0,9})?\' <<< "$prs"; then echo "not a PR number on the lines above"; exit 1; fi',
    '          for pr in $(sort -nu <<< "$prs"); do',
    '            gh api -X POST "repos/$REPO/actions/workflows/premerge.yml/dispatches" -f ref=main -f "inputs[pr]=$pr" > /dev/null',
    '            echo "reran the gate for #$pr"',
    '          done',
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
    "    runs-on: ubuntu-24.04",
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


# ACCEPT-reopen (#2919): acceptance.yml holds `issues: write` on every issue close, so it is
# pinned line by line like intake.yml: one trigger, main's code, a credential-free checkout and a
# run line whose only event value is the issue number, passed through env.
ACCEPTANCE_LINES = [
    'name: acceptance',
    'on:',
    '  issues:',
    '    types: [closed]',
    'permissions:',
    '  contents: read',
    'jobs:',
    '  reopen:',
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    permissions:',
    '      contents: read',
    '      issues: write # reopen a cited issue and comment on it',
    '    steps:',
    '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2',
    '        with:',
    '          persist-credentials: false',
    '      - name: Reopen the issue if a vulncheck record cites it (tools/vulncheck.py reopen)',
    '        env:',
    '          GITHUB_TOKEN: ${{ github.token }}',
    '          ISSUE: ${{ github.event.issue.number }}',
    '        run: python3 -I tools/vulncheck.py reopen "$ISSUE"',
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


# CI-hostcheck-runner-2604 (#4785, #4792): a floating label (ubuntu-latest) moves every job to a
# new runner image when GitHub chooses, so required checks change under unchanged code. Every job
# runs on RUNNER, written out; moving to another image is a reviewed edit of this line.
RUNNER = "ubuntu-24.04"
PLAIN_KEY = re.compile(r"([A-Za-z0-9_-]+):")
# YAML breaks lines at \r, NEL, LS and PS too; a tab or other control character has no place here.
NOT_TEXT = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f\u2028\u2029\ufeff]")
# Only the ASCII space separates or indents: Python's strip() and \s also take U+00A0, U+3000
# and the like, which YAML reads as part of a scalar (Security and L3 on #4820).
SP = " "


BLOCK_SCALAR = re.compile(r"(?:^|: |- )[|>][1-9]?[+-]?[1-9]?(?: +#.*)?$")


def _quote_end(s, i):
    """Return the index after the quoted scalar opening at s[i], or None if it runs past the line."""
    q, i = s[i], i + 1
    while i < len(s):
        if q == '"' and s[i] == "\\":
            i += 2
        elif s[i] == q and q == "'" and s[i + 1:i + 2] == "'":
            i += 2
        elif s[i] == q:
            return i + 1
        else:
            i += 1
    return None


def open_flow(s):
    """Return why one line leaves a quoted scalar or flow collection open past its end, or None.

    A scalar or collection that spans lines can make what reads here as a key be text inside
    it (Security on #4820), so the reader refuses every one: each must close on its own line.
    """
    depth, i, start = 0, 0, True  # start: a quote or bracket here opens a node
    while i < len(s):
        c = s[i]
        if c == SP:
            i += 1
        elif c == "#" and (i == 0 or s[i - 1] == SP):
            break
        elif start and c in "'\"":
            i = _quote_end(s, i)
            if i is None:
                return "a quoted scalar runs past its line"
            start = False
        elif (start or depth) and c in "[{":
            depth, i, start = depth + 1, i + 1, True
        elif depth and c in "]}":
            depth, i, start = depth - 1, i + 1, False
        elif depth and c == ",":
            i, start = i + 1, True
        elif start and c == "-" and s[i + 1:i + 2] in ("", SP):
            i += 1
        elif c == ":" and (s[i + 1:i + 2] in ("", SP) or depth and s[i + 1:i + 2] in (",", "]", "}")):
            i, start = i + 1, True
        else:
            i, start = i + 1, False
    return "a flow collection runs past its line" if depth else None


def workflow_runners(text):
    """Return ({job: runs-on}, problems) for a workflow, reading the YAML fail-closed.

    No YAML library is in CI's Python, and one that reads YAML 1.1 differs from GitHub's reader,
    so a library would add a parser GitHub does not share. This reads only the subset the
    workflows use: a top-level `jobs:` block mapping whose jobs are block mappings of plain keys
    at two and four spaces. Any other form at those two levels (flow mapping, quoted or escaped
    key, `?` key, anchor, alias, tag or merge key on a job or job key, odd indent), a runs-on
    value continued on the next line, and any runs-on value but RUNNER are problems, so a key
    GitHub reads as runs-on cannot hide from this reader.
    """
    problems = []
    for n, l in enumerate(text.split("\n"), 1):
        if NOT_TEXT.search(l):
            problems.append("line %d: a control character, tab or YAML line break other than \\n" % n)
    lines, block = [], None
    for l in text.split("\n"):
        if not l.strip(SP) or l.lstrip(SP).startswith("#"):
            continue
        indent = len(l) - len(l.lstrip(SP))
        if block is not None and indent > block:
            continue  # a block scalar's text (run: |), never structure
        block = None
        why = open_flow(l.lstrip(SP))
        if why:
            problems.append("line %r: %s" % (l, why))
        if BLOCK_SCALAR.search(l.lstrip(SP)):
            block = indent
        lines.append(l)
    top = {}
    for i, l in enumerate(lines):
        m = None if l[0] == SP else PLAIN_KEY.match(l)
        if m:
            top.setdefault(m.group(1), []).append(i)
        elif l[0] != SP:
            problems.append("top-level line %r is not a plain key" % l)
    problems += ["top-level key %r appears %d times" % (k, len(v)) for k, v in top.items() if len(v) > 1]
    starts = top.get("jobs", [])
    if len(starts) != 1 or lines[starts[0]].rstrip(SP) != "jobs:":
        return {}, problems + ["needs one block `jobs:`"]
    jobs, job, key = {}, None, None
    for l in lines[starts[0] + 1:]:
        indent = len(l) - len(l.lstrip(SP))
        body = re.split(r" +#", l.strip(SP), maxsplit=1)[0]
        if indent == 0:
            # No workflow has a top-level key after jobs:, so any column-0 line here is refused
            # rather than read as the end of jobs: (it could be text inside a scalar).
            problems.append("line %r: column 0 after jobs:" % l)
            continue
        if indent == 2:
            m = re.fullmatch(r"([A-Za-z0-9_-]+):", body)
            if not m:
                problems.append("job line %r is not a plain key opening a block mapping" % l)
                job = None
                continue
            job, key = m.group(1), None
            if job in jobs:
                problems.append("job %r appears twice" % job)
            jobs[job] = []
        elif indent == 4 and job:
            m = re.fullmatch(r"([A-Za-z0-9_-]+):(?: +(.*))?", body)
            if not m:
                problems.append("%s: line %r is not a plain key" % (job, l))
                key = None
                continue
            key = m.group(1)
            if key == "runs-on":
                jobs[job].append(m.group(2) or "")
            elif key == "uses":
                problems.append("%s: calls a reusable workflow, whose runs-on this cannot see" % job)
        elif indent > 4 and job and key:
            if key == "runs-on":
                problems.append("%s: runs-on continues on line %r" % (job, l))
        else:
            problems.append("line %r: indent %d outside a job's plain keys" % (l, indent))
    if not jobs:
        problems.append("no jobs")
    for job, runs in jobs.items():
        if runs != [RUNNER]:
            problems.append("%s: runs-on %r, must be exactly [%r]" % (job, runs, RUNNER))
    return jobs, problems


IMAGE_STEP = (
    "        id: image\n"
    '        run: (. /etc/os-release && echo "os=$ID-$VERSION_ID") >> "$GITHUB_OUTPUT"\n')
IMAGE_KEY = "${{ steps.image.outputs.os }}"


def cache_key_problems(text):
    """Return each actions/cache key or restore key that does not name the runner image (#4785).

    A cache keyed only on runner.os ("Linux") restored ot-rcp built on ubuntu-26.04 onto 24.04,
    where it could not run (GLIBC_2.42 not found). Each job with a cache computes the image in
    IMAGE_STEP before its first cache step, and every key line carries it.
    """
    problems = []
    jobs = re.split(r"^(?=  [A-Za-z0-9_-]+:\n)", text, flags=re.M)
    for job in jobs:
        blocks = re.split(r"^(?=      - )", job, flags=re.M)
        caches = [b for b in blocks if re.search(r"^\s+(- )?uses:\s*actions/cache\b", b, re.M)]
        if not caches:
            continue
        name = job.split(":", 1)[0].strip()
        if IMAGE_STEP not in job[:job.index(caches[0])]:
            problems.append("%s: no runner-image step before its first cache" % name)
        for s in caches:
            body = s.split("\n")
            keys = [l for l in body if re.match(r"\s+(key|restore-keys):", l)]
            if not keys:
                problems.append("%s: cache step with no key" % name)
            for i, l in enumerate(body):
                if re.match(r"\s+key:", l) and IMAGE_KEY not in l:
                    problems.append("%s: key %r does not name the runner image" % (name, l.strip()))
                m = re.match(r"(\s+)restore-keys:\s*(.*)$", l)
                if m:
                    entries = [m.group(2)] if m.group(2) not in ("|", "") else []
                    for nxt in body[i + 1:]:
                        if len(nxt) - len(nxt.lstrip()) <= len(m.group(1)):
                            break
                        entries.append(nxt.strip())
                    for e in entries:
                        if IMAGE_KEY not in e:
                            problems.append("%s: restore key %r does not name the runner image" % (name, e))
    return problems


# CI-cancel-superseded (#5345, #5348): a push to a PR leaves the old head's runs holding the
# Actions queue unless the workflow has a concurrency group per PR that cancels them. Every
# PR-triggered workflow but premerge carries this exact block (#5361), and a new one fails until it
# does and is listed below: a PR's first-attempt runs share its group and the newest cancels
# the older ones. A rerun (attempt 2 or later; trusted-base-rerun.yml lists heads before it reruns)
# and every push, merge-queue, schedule or dispatch run is a group of its own, so it can neither
# cancel the current head's running run nor replace its pending one, and main's runs are never
# cancelled.
SUPERSEDE_LINES = [
    "concurrency:",
    "  group: ${{ github.workflow }}-${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 && "
    "format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
    "  cancel-in-progress: ${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 }}",
]
SUPERSEDE = ["trusted-base.yml", "lane-gate.yml", "word-budget.yml", "formal.yml", "keycheck.yml",
             "ci.yml", "assurance.yml", "vulncheck.yml", "image.yml", "infer-real.yml", "vision-real.yml",
             "testkit.yml", "enforcer-image.yml", "camnode-image.yml", "drone-sitl.yml", "mutgate.yml"]
# premerge.yml queues its runs on purpose (its record handling) and never cancels one.
KEEPS_EVERY_RUN = {"premerge.yml"}


# #5377: the triggers as GitHub reads them. YAML 1.1 reads a plain `on` key as true, so a workflow
# may quote it, and a text match on `on:` missed `"on":`. Each top-level line must be one workflow
# key, plain or quoted, once; the triggers one plain or quoted event a line at one indent, or one
# flow list of names. Any other form (an anchor, alias, merge key, tag, `?` key, second document,
# tab, indented first key, unknown or repeated key) fails rather than being read, so no spelling hides a trigger.
TOP_KEY = re.compile(r"""(["']?)(name|run-name|on|permissions|env|defaults|concurrency|jobs)\1[ \t]*:(?=[ \t]|$)""")
EVENT = re.compile(r"""(["']?)([a-z_]+)\1[ \t]*:(?=[ \t]|$)""")
EVENT_LIST = re.compile(r"[a-z_]+|\[[ \t]*[a-z_]+(?:[ \t]*,[ \t]*[a-z_]+)*[ \t]*\]")


def workflow_triggers(text):
    """Return the events a workflow's `on` key names and why the check cannot read the workflow."""
    events, problems, seen, key, indent = [], [], set(), None, None
    # YAML 1.1 also breaks lines at CR, NEL, LS and PS, where this reader (and the `jobs:` search
    # below) splits at LF only (Security on #5408).
    problems += ["a line break other than LF: %r" % c for c in "\r\x85\u2028\u2029" if c in text]
    for line in text.split("\n"):
        bare = re.sub(r"(?:^|[ \t])#.*", "", line).rstrip(" \t")
        if not bare:
            continue
        if not bare.startswith(" "):
            m = TOP_KEY.match(bare)
            key = m and m.group(2)
            if not m or key in seen:
                problems.append("a top-level line that is not one workflow key: %r" % line)
                continue
            seen.add(key)
            rest = bare[m.end():].strip(" \t")
            if key == "on" and rest:
                if EVENT_LIST.fullmatch(rest):
                    events += re.findall(r"[a-z_]+", rest)
                else:
                    problems.append("triggers the check cannot read: %r" % rest)
                key = "on, flow"
            continue
        if key is None:
            problems.append("an indented line before the first top-level key: %r" % line)
        if key == "on, flow":
            problems.append("a line under a flow list of triggers: %r" % line)
        if key != "on":
            continue
        width = len(bare) - len(bare.lstrip(" "))
        indent = width if indent is None else indent
        m = EVENT.match(bare, width)
        if width == indent and m:
            events.append(m.group(2))
        elif width <= indent:
            problems.append("a trigger the check cannot read: %r" % line)
    return events, problems


def supersede_problems(name, text):
    """Return why a workflow can leave a superseded PR head's runs queued; empty when it cannot."""
    events, problems = workflow_triggers(text)
    if problems:
        return problems + [SUBSET]
    if not any(e.startswith("pull_request") for e in events):
        return []
    # The jobs line by the line, as GitHub reads it (`jobs: ` with a trailing space too); a PR
    # workflow without one fails rather than hide its jobs from the ban below (#5348).
    at = re.search(r"^jobs: *$", text, re.M)
    if not at:
        return ["no `jobs:` line"]
    top, jobs = text[:at.start()].split("\n"), text[at.end():]
    # #5348: a job-level group escapes the pinned block (it could cancel the required check on a
    # rerun, or share a group across PRs), so the workflow-level block is the only one allowed.
    if re.search(r"\bconcurrency\s*:", jobs):
        return ["a job sets its own concurrency group"]
    if name in KEEPS_EVERY_RUN:
        return []
    # #5361: no looser block passes; a rerun guard is part of every PR workflow's group.
    return concurrency_problems(top) or ([] if name in SUPERSEDE else ["a PR workflow missing from SUPERSEDE"])


# Lens R1 on #5408: a form the readers here do not read fails with the subset they do read, not a bare mismatch.
SUBSET = ("the check reads only this YAML subset: LF line breaks; each top-level key once at column 0, plain or "
          "quoted; triggers one event a line at one indent, or one flow list on the `on` line; a concurrency block "
          "of plain `key: value` lines at two spaces; no tab, anchor, alias, tag, `?` key or other flow style")
PINNED_CONCURRENCY = dict(l.strip(SP).split(": ", 1) for l in SUPERSEDE_LINES[1:])
CONCURRENCY_ENTRY = re.compile(r"  ([a-z-]+): ([^ &*!|>{\[\]}'\"%@`#,?-].*)")


def concurrency_problems(top):
    """Return why the top-level lines `top` hold no concurrency block equal to the pin, read whole.

    #5409 (from #5408's review): the block is read as a mapping to its last line, so a second
    `cancel-in-progress` or an extra key fails as surely as a changed value.
    """
    at = [i for i, l in enumerate(top) if re.match(r"""(["']?)concurrency\1[ \t]*:""", l)]
    if not at:
        return ["no per-PR concurrency block as pinned"]
    if top[at[0]] != "concurrency:":
        return ["a concurrency key the check cannot read: %r" % top[at[0]], SUBSET]
    block = {}
    for line in top[at[0] + 1:]:
        if not line.strip(" \t") or line.lstrip(SP).startswith("#"):
            continue
        if line[0] not in " \t":
            break
        m = CONCURRENCY_ENTRY.fullmatch(line)
        if not m:
            return ["a concurrency line the check cannot read: %r" % line, SUBSET]
        if m.group(1) in block:
            return ["concurrency sets %s twice" % m.group(1)]
        block[m.group(1)] = m.group(2)
    if block != PINNED_CONCURRENCY:
        return ["no per-PR concurrency block as pinned: %s" % ", ".join(
            "%s is %r, pinned %r" % (k, block.get(k, "<missing>"), PINNED_CONCURRENCY.get(k, "<none>"))
            for k in sorted(set(block) | set(PINNED_CONCURRENCY)) if block.get(k) != PINNED_CONCURRENCY.get(k))]
    return []


# CI-mutgate-head-guard (#5409): a rerun keeps its event, so it can test a head the PR has left.
# mutgate's first job is this one, pinned whole: it reads the PR's head from the API and, when the
# run's is older, ends with a notice. `claimed` runs only on its `current`, and no later job runs
# past a skipped claim but the `mutgate` job, which then fails, so a stale run never passes.
HEAD_GUARD_LINES = [
    "  head:",
    "    runs-on: ubuntu-24.04",
    "    timeout-minutes: 5",
    "    permissions:",
    "      pull-requests: read",
    "    outputs:",
    "      current: ${{ steps.head.outputs.current }}",
    "    steps:",
    "      - name: This run's head is the PR's current head",
    "        id: head",
    "        env:",
    "          GH_TOKEN: ${{ github.token }}",
    "          REPO: ${{ github.repository }}",
    "          PR_NUMBER: ${{ github.event.pull_request.number }}",
    "          RUN_HEAD: ${{ github.event.pull_request.head.sha }}",
    "        run: |",
    '          now=$(gh api "repos/$REPO/pulls/$PR_NUMBER" --jq .head.sha) || '
    '{ echo "::error::cannot read the PR\'s head"; exit 1; }',
    "          [[ \"$now\" =~ ^[0-9a-f]{40}$ ]] || { echo \"::error::the PR's head is not a sha: $now\"; exit 1; }",
    '          if [ "$now" = "$RUN_HEAD" ]; then echo "current=true" >> "$GITHUB_OUTPUT"; exit 0; fi',
    '          echo "::notice::this run\'s head $RUN_HEAD is not the PR\'s current head $now: no gate runs; '
    'the current head\'s own run decides"',
    '          echo "current=false" >> "$GITHUB_OUTPUT"',
]
CLAIM_WAITS = ["  claimed:", "    needs: head", "    if: ${{ needs.head.outputs.current == 'true' }}"]
# L3 on #5433: "Re-run failed jobs" copies `head`'s current=true from attempt 1, so each job that
# runs PR tests or decides reads the head itself as its first step and fails on an older one.
HEAD_CHECK_JOBS = ("plan", "mutants", "mutgate")
HEAD_CHECK_LINES = [
    "    permissions:",
    "      contents: read",
    "      pull-requests: read",
    "    steps:",
    "      - name: This run's head is still the PR's current head",
] + HEAD_GUARD_LINES[HEAD_GUARD_LINES.index("        env:"):-3] + [
    '          [ "$now" = "$RUN_HEAD" ] || { echo "::error::this run\'s head $RUN_HEAD is not the PR\'s current head '
    '$now: a rerun of an old head gates nothing; the current head\'s own run decides"; exit 1; }',
]


def head_guard_problems(text):
    """Return why mutgate.yml can run its gate on a head the PR has left; empty when it cannot."""
    if "\njobs:\n" not in text:
        return ["no `jobs:` line"]
    code = [l for l in text.split("\njobs:\n", 1)[1].split("\n") if l.strip(SP) and not l.lstrip(SP).startswith("#")]
    jobs = [i for i, l in enumerate(code) if re.match(r"  \S", l)] + [len(code)]
    first = code[:jobs[1]] if len(jobs) > 1 else code
    if first != HEAD_GUARD_LINES:
        return ["the first job is not the pinned head check"]
    claim = [i for i in jobs[:-1] if code[i] == "  claimed:"]
    if not claim or code[claim[0]:claim[0] + 3] != CLAIM_WAITS:
        return ["`claimed` does not wait on the head check"]
    # Only the deciding job may run past a skipped claim, and it fails unless the claim succeeded.
    for a, b in zip(jobs, jobs[1:]):
        body = "\n".join(code[a:b])
        name = code[a].strip(SP + ":")
        if name in HEAD_CHECK_JOBS:
            at = [i for i in range(a, b) if code[i] == "    permissions:"]
            if [l for l in code[a:b] if l.startswith("    permissions")] != ["    permissions:"] or \
                    code[at[0]:at[0] + len(HEAD_CHECK_LINES)] != HEAD_CHECK_LINES or "    steps:" in code[a:at[0]]:
                return ["%s does not read the PR's head first" % name]
        if code[a] != "  mutgate:" and re.search(r"\b(always|cancelled|failure|success)\(", body):
            return ["%s runs past a skipped claim" % name]
        if code[a] == "  mutgate:" and '[ "$CLAIMED" = success ] || exit 1' not in body:
            return ["the mutgate job does not fail when the claim did not run"]
    return []


class WorkflowTest(unittest.TestCase):
    def test_a_pr_push_cancels_the_older_heads_runs(self):
        # CI-cancel-superseded (#5345): every PR-triggered workflow but premerge cancels a
        # superseded head's runs with the pinned block (#5348, #5361), and no job sets its own group.
        names = [f.name for f in self.files()]
        self.assertTrue(set(SUPERSEDE) | KEEPS_EVERY_RUN <= set(names))
        self.assertEqual(len(SUPERSEDE), len(set(SUPERSEDE)))
        for f in self.files():
            with self.subTest(f.name):
                self.assertEqual(supersede_problems(f.name, f.read_text()), [])
        self.assertIn("  cancel-in-progress: false", (WORKFLOWS / "premerge.yml").read_text())

    def test_supersede_check_catches_each_edit(self):
        # CI-cancel-superseded (#5345): a rerun that cancels, a cancelled main push, one group
        # for every PR, a dropped block and a new PR workflow without one all fail.
        group, cancel = SUPERSEDE_LINES[1], SUPERSEDE_LINES[2]
        edits = {
            "rerun cancels": (cancel, "  cancel-in-progress: ${{ startsWith(github.event_name, 'pull_request') }}"),
            "always cancels": (cancel, "  cancel-in-progress: true"),
            "push group by sha": (group, group.replace("format('run-{0}', github.run_id)", "github.sha")),
            # #5348: a rerun back in the PR's group could replace the current head's pending run.
            "rerun in the PR group": (group, group.replace("github.run_attempt == 1 && ", "")),
            "one group": (group, "  group: ${{ github.workflow }}"),
            "no block": ("\n".join(SUPERSEDE_LINES) + "\n", ""),
            # #5348: a job-level block that cancels, even one that keeps the rerun guard.
            "job block": ("\njobs:\n", "\njobs:\n  x:\n    concurrency:\n      group: x\n"
                                       "      cancel-in-progress: true\n"),
            "job block, flow form": ("\njobs:\n", "\njobs:\n  x: {concurrency: x, runs-on: y}\n"),
            "job block, string": ("\njobs:\n", "\njobs:\n  x:\n    concurrency: x\n"),
            "job block after `jobs: `": ("\njobs:\n", "\njobs: \n  x:\n    concurrency: x\n"),
        }
        for name in SUPERSEDE:
            text = (WORKFLOWS / name).read_text()
            for edit, (old, new) in edits.items():
                with self.subTest(name, edit=edit):
                    self.assertIn(old, text)
                    self.assertTrue(supersede_problems(name, text.replace(old, new, 1)), edit)
        plain = "name: x\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n"
        self.assertTrue(supersede_problems("x.yml", plain))
        self.assertTrue(supersede_problems("x.yml", plain.replace("jobs:", "concurrency:\n  group: x\n"
                                                                   "  cancel-in-progress: false\njobs:")))
        self.assertEqual(supersede_problems("x.yml", plain.replace("pull_request", "push")), [])
        # #5361: a new PR workflow with a cancelling block but no rerun guard (the seven's old
        # blocks) fails, and one with the pinned block fails until it is listed in SUPERSEDE.
        for block in ["concurrency:\n  group: x-${{ github.event.pull_request.number || github.sha }}\n"
                      "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n",
                      "concurrency:\n  group: x-${{ github.ref }}\n  cancel-in-progress: true\n"]:
            with self.subTest(block=block):
                self.assertTrue(supersede_problems("x.yml", plain.replace("jobs:", block + "jobs:")))
        pinned = plain.replace("jobs:", "\n".join(SUPERSEDE_LINES) + "\njobs:")
        self.assertEqual(supersede_problems("x.yml", pinned), ["a PR workflow missing from SUPERSEDE"])
        self.assertEqual(supersede_problems("mutgate.yml", pinned), [])
        # A PR workflow: `jobs: ` with a trailing space still exposes its jobs, and
        # a jobs line the check cannot find fails (#5348).
        testkit = (WORKFLOWS / "testkit.yml").read_text()
        self.assertEqual(supersede_problems("testkit.yml", testkit), [])
        for old, new in [("\njobs:\n", "\njobs: \n  x:\n    concurrency: {group: shared, cancel-in-progress: true}\n"),
                         ("\njobs:\n", "\njobs:  \n  x:\n    concurrency: x\n"),
                         ("\njobs:\n", "\njobs: # x\n")]:
            with self.subTest(new=new):
                self.assertIn(old, testkit)
                self.assertTrue(supersede_problems("testkit.yml", testkit.replace(old, new, 1)))
        # premerge keeps every run, but a job of its own may not cancel one either (#5348).
        premerge = (WORKFLOWS / "premerge.yml").read_text()
        self.assertEqual(supersede_problems("premerge.yml", premerge), [])
        self.assertTrue(supersede_problems("premerge.yml", premerge.replace(
            "\njobs:\n", "\njobs:\n  x:\n    concurrency:\n      group: x\n      cancel-in-progress: true\n", 1)))

    def test_triggers_read_as_github_reads_them(self):
        # CI-rerun-guard-rest-fu (#5377): YAML 1.1 reads a plain `on` as true, so a workflow may
        # quote the key; a PR trigger under `on:`, `"on":` or `'on':` needs the pinned block, and a
        # push-only one does not.
        block = "\n".join(SUPERSEDE_LINES) + "\n"
        for key in ["on", '"on"', "'on'"]:
            for triggers in ["\n  pull_request:\n", "\n  # a comment at column 0 follows\n#\n  pull_request_target:\n",
                             " [push, pull_request]\n", " pull_request\n", " pull_request # x\n",
                             "\n  push:\n    branches: [main]\n  \"pull_request_review\": {types: [submitted]}\n"]:
                plain = "name: x\n" + key + ":" + triggers + "permissions:\n  contents: read\njobs:\n"
                with self.subTest(key=key, triggers=triggers):
                    self.assertTrue(supersede_problems("mutgate.yml", plain))
                    self.assertEqual(supersede_problems("mutgate.yml", plain.replace("jobs:", block + "jobs:")), [])
            with self.subTest(key=key, triggers="push"):
                push = "name: x\n" + key + ":\n  push:\n    paths: [pull_request]\njobs:\n"
                self.assertEqual(workflow_triggers(push), (["push"], []))
                self.assertEqual(supersede_problems("x.yml", push), [])
        # A form the check cannot read fails rather than hide a trigger, wherever it sits.
        plain = "name: x\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n"
        self.assertEqual(workflow_triggers(plain), (["pull_request"], []))
        unread = {
            "true key": ("on:", "true:"), "capital key": ("on:", "On:"), "explicit key": ("on:", "? on\n:"),
            "escaped key": ("on:", '"o\\x6en":'), "quotes that differ": ("on:", "\"on':"),
            "anchor": ("on:", "on: &t"), "alias": ("on:\n  pull_request:", "on: *t"),
            "merge key": ("  pull_request:", "  push:\n  <<: *t"), "tagged key": ("on:", "!!str on:"),
            "flow mapping": ("on:\n  pull_request:", "on: {pull_request: }"),
            "flow list on two lines": ("on:\n  pull_request:", "on: [push,\n  pull_request]"),
            "flow list then a block": ("on:", "on: [push]"), "sequence": ("  pull_request:", "  - pull_request"),
            "event under the event indent": ("  pull_request:", "   push:\n  pull_request:"),
            "tab": ("  pull_request:", "  \tpull_request:"), "key at column 0 with a tab": ("on:", "\ton:"),
            "second document": ("name: x", "---\nname: x"), "unknown key": ("permissions:", "permission:"),
            "key twice": ("permissions:", "on:\n  push:\npermissions:"), "carriage return": ("on:", "on:\r"),
            "continuation at column 0": ("name: x", 'name: "x\npull_request"'),
            "non-ASCII event": ("  pull_request:", "  pull_r\u0435quest:"),
            "no space after a key's colon": ("permissions:", "permissions:x"),
            "no space after an event's colon": ("  pull_request:", "  pull_request:x"),
            "a line of ideographic space": ("permissions:", "\u3000\npermissions:"),
            "two names without a list": ("on:\n  pull_request:", "on: push pull_request"),
            "alias in a flow list": ("on:\n  pull_request:", "on: [push, *t]"),
            "indented before the first key": ("name: x", " name: x"),
        }
        for brk in "\r\x85\u2028\u2029":
            unread.update({"%r in a comment" % brk: ("name: x", "name: x # a" + brk + "on: [pull_request]"),
                           "%r in a plain scalar" % brk: ("name: x", "name: x" + brk + "y"),
                           "%r in an env value" % brk: ("permissions:", "env:\n  A: a" + brk + "b\npermissions:")})
            with self.subTest(brk=brk):
                text = "name: x" + brk + "on: [pull_request]\njobs:\n"
                self.assertTrue(workflow_triggers(text)[1])
                self.assertTrue(supersede_problems("x.yml", text))
        # L3 on #5408: a document indented by one space throughout is still one GitHub reads.
        indented = "".join(" " + line for line in plain.splitlines(True))
        self.assertTrue(workflow_triggers(indented)[1])
        self.assertTrue(supersede_problems("mutgate.yml", indented))
        for name, (old, new) in unread.items():
            with self.subTest(name):
                self.assertIn(old, plain)
                text = plain.replace(old, new, 1)
                self.assertTrue(workflow_triggers(text)[1], name)
                self.assertTrue(supersede_problems("mutgate.yml", text.replace("jobs:", block + "jobs:")), name)
                self.assertTrue(supersede_problems("x.yml", text.replace("pull_request", "push")), name)

    def test_a_stale_mutgate_run_stops_at_its_first_job(self):
        # CI-mutgate-head-guard (#5409): mutgate's first job is the pinned head check, `claimed`
        # waits on it, and no job but the failing `mutgate` one runs past a skipped claim.
        text = (WORKFLOWS / "mutgate.yml").read_text()
        self.assertEqual(head_guard_problems(text), [])
        guard = "\n".join(HEAD_GUARD_LINES) + "\n"
        edits = {
            "no guard": (guard, ""),
            "a job before the guard": ("\njobs:\n", "\njobs:\n  early:\n    runs-on: ubuntu-24.04\n"),
            "guard widened": ("      pull-requests: read\n", "      pull-requests: write\n"),
            "guard always passes": ('if [ "$now" = "$RUN_HEAD" ]', 'if true || [ "$now" = "$RUN_HEAD" ]'),
            "guard reads the event": ('gh api "repos/$REPO/pulls/$PR_NUMBER" --jq .head.sha', 'echo "$RUN_HEAD"'),
            "claim ignores it": ("    if: ${{ needs.head.outputs.current == 'true' }}\n", ""),
            "claim waits on nothing": ("    needs: head\n", ""),
            "plan runs past a skip": ("    if: ${{ needs.claimed.outputs.packages != '[]' }}\n",
                                      "    if: ${{ always() && needs.claimed.outputs.packages != '[]' }}\n"),
            "gate passes a skip": ('[ "$CLAIMED" = success ] || exit 1', '[ "$CLAIMED" != failure ] || exit 1'),
            "no jobs line": ("\njobs:\n", "\njobs: \n"),
            # L3 on #5433: each job that runs PR tests or decides checks the head itself, first.
            "a job's check passes an old head": ('          [ "$now" = "$RUN_HEAD" ] || { echo "::error::this run',
                                                 '          true || { echo "::error::this run'),
            "a second permissions key": ("    if: ${{ !cancelled() }}\n", "    if: ${{ !cancelled() }}\n    permissions: {}\n"),
        }
        check = "\n".join(HEAD_CHECK_LINES[4:]) + "\n"
        for job in HEAD_CHECK_JOBS:
            body = text.split("\n  %s:\n" % job, 1)[1]
            edits["no check in " + job] = ("\n  %s:\n" % job + body[:body.index(check) + len(check)],
                                           "\n  %s:\n" % job + body[:body.index(check)].replace(
                                               "    permissions:\n      contents: read\n      pull-requests: read\n", ""))
            edits["check after the checkout in " + job] = (
                "\n  %s:\n" % job + body[:body.index(check) + len(check)] + "      - uses: actions/checkout@",
                "\n  %s:\n" % job + body[:body.index(check)] + "      - uses: actions/checkout@x\n" + check
                + "      - uses: actions/checkout@") if job != "mutgate" else (
                "\n  %s:\n" % job + body[:body.index(check) + len(check)] + "      - name: The claim ran",
                "\n  %s:\n" % job + body[:body.index(check)] + "      - run: true\n" + check + "      - name: The claim ran")
        for edit, (old, new) in edits.items():
            with self.subTest(edit):
                self.assertIn(old, text)
                self.assertTrue(head_guard_problems(text.replace(old, new, 1)), edit)
        # The guard's script: the current head runs the gate, an older one ends green with a notice,
        # and an unreadable head fails the job (so `claimed` and every gate job skip and mutgate fails).
        script = "\n".join(l[10:] for l in HEAD_GUARD_LINES[HEAD_GUARD_LINES.index("        run: |") + 1:])
        sha, other = "a" * 40, "b" * 40
        for out, rc, want_rc, want in [(sha, 0, 0, "current=true"), (other, 0, 0, "current=false"),
                                       ("", 1, 1, ""), ("not a sha", 0, 1, ""), (sha + "\n" + sha, 0, 1, "")]:
            with self.subTest(out=out, rc=rc), tempfile.TemporaryDirectory() as d:
                gh = pathlib.Path(d, "gh")
                gh.write_text("#!/bin/sh\nprintf '%s\\n' \"$STUB_OUT\"\nexit \"$STUB_RC\"\n")
                gh.chmod(0o755)
                env = {"PATH": d + ":/usr/bin:/bin", "STUB_OUT": out, "STUB_RC": str(rc), "RUN_HEAD": sha,
                       "REPO": "o/r", "PR_NUMBER": "1", "GITHUB_OUTPUT": str(pathlib.Path(d, "out"))}
                r = subprocess.run(["bash", "-e", "-c", script], env=env, capture_output=True, text=True)
                self.assertEqual(r.returncode, want_rc, r.stdout + r.stderr)
                got = pathlib.Path(d, "out").read_text().strip() if pathlib.Path(d, "out").exists() else ""
                self.assertEqual(got, want)
                self.assertEqual("::notice::this run's head" in r.stdout, want == "current=false")
                # Each later job's own check: only the current head goes on; anything else fails the job.
                check = "\n".join(l[10:] for l in HEAD_CHECK_LINES[HEAD_CHECK_LINES.index("        run: |") + 1:])
                r = subprocess.run(["bash", "-e", "-c", check], env=env, capture_output=True, text=True)
                self.assertEqual(r.returncode, 0 if want == "current=true" else 1, r.stdout + r.stderr)
                self.assertEqual("a rerun of an old head gates nothing" in r.stdout, want == "current=false")

    def test_concurrency_block_is_read_whole(self):
        # #5409 (from #5408's review): the pinned block's three lines with more after them fail,
        # whatever the extra line is; the same mapping in another order or with a comment passes.
        plain = "name: x\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n"
        block = "\n".join(SUPERSEDE_LINES) + "\n"
        group, cancel = SUPERSEDE_LINES[1], SUPERSEDE_LINES[2]
        self.assertEqual(supersede_problems("mutgate.yml", plain.replace("jobs:", block + "jobs:")), [])
        for edit, new in {
            "second cancel-in-progress": block + "  cancel-in-progress: true\n",
            "second group": block + "  group: shared\n",
            "extra key": block + "  x: y\n",
            "extra key after a comment": block + "  # c\n  x: y\n",
            "missing key": block.replace(cancel + "\n", ""),
        }.items():
            with self.subTest(edit):
                self.assertTrue(supersede_problems("mutgate.yml", plain.replace("jobs:", new + "jobs:")), edit)
        for edit, new in {"reordered": "concurrency:\n" + cancel + "\n" + group + "\n",
                          "comment and blank line inside": "concurrency:\n  # c\n\n" + group + "\n" + cancel + "\n"}.items():
            with self.subTest(edit):
                self.assertEqual(supersede_problems("mutgate.yml", plain.replace("jobs:", new + "jobs:")), [], edit)

    def test_unread_yaml_names_the_supported_subset(self):
        # Lens R1 on #5408: flow style, an anchor or a tab-indented block fails with the subset the
        # check reads, not a bare mismatch; a readable block that differs says what differs.
        plain = "name: x\non:\n  pull_request:\npermissions:\n  contents: read\njobs:\n"
        block = "\n".join(SUPERSEDE_LINES) + "\n"
        group, cancel = SUPERSEDE_LINES[1], SUPERSEDE_LINES[2]
        flow = "concurrency: {%s, %s}\n" % (group.strip(SP), cancel.strip(SP))
        for edit, new in {
            "flow mapping": flow,
            "anchor": block.replace("concurrency:", "concurrency: &c"),
            "quoted key": block.replace("concurrency:", '"concurrency":'),
            "tab-indented block": block.replace("  group", "\tgroup"),
            "tab after the indent": block.replace("  group", "  \tgroup"),
            "deeper line": block + "    x: y\n",
            "quoted value": block.replace(cancel, "  cancel-in-progress: 'x'"),
            "alias value": block.replace(cancel, "  cancel-in-progress: *c"),
            "flow triggers": ("on:\n  pull_request:", "on: {pull_request: }"),
        }.items():
            text = plain.replace("jobs:", block + "jobs:").replace(*new) if isinstance(new, tuple) \
                else plain.replace("jobs:", new + "jobs:")
            with self.subTest(edit):
                self.assertIn(SUBSET, supersede_problems("mutgate.yml", text), edit)
        changed = supersede_problems("mutgate.yml", plain.replace("jobs:", block.replace(cancel, "  cancel-in-progress: true") + "jobs:"))
        self.assertEqual(len(changed), 1)
        self.assertNotIn(SUBSET, changed)
        self.assertIn("cancel-in-progress is 'true', pinned", changed[0])

    def test_cache_keys_name_the_runner_image(self):
        seen = 0
        for wf in self.files():
            text = wf.read_text(encoding="utf-8")
            seen += len(re.findall(r"uses:\s*actions/cache", text))
            with self.subTest(wf.name):
                self.assertEqual(cache_key_problems(text), [])
        self.assertGreater(seen, 0)

    def test_cache_key_check_catches_mutants(self):
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        edits = {
            "os key": ("key: ot-bin-${{ steps.image.outputs.os }}-", "key: ot-bin-${{ runner.os }}-"),
            "restore key": ("            go-build-broker-${{ steps.image.outputs.os }}-",
                            "            go-build-broker-${{ runner.os }}-"),
            "inline restore key": ("restore-keys: go-build-broker-${{ steps.image.outputs.os }}-",
                                   "restore-keys: go-build-broker-"),
            "no image step": (IMAGE_STEP + "      - name: Go build cache (CI-PATHS)\n        # The root",
                              "      - name: Go build cache (CI-PATHS)\n        # The root"),
            "image step after the cache": (IMAGE_STEP + "      - name: Go build cache (CI-PATHS)\n        # The root",
                                           "        run: true\n      - name: Go build cache (CI-PATHS)\n        # The root"),
        }
        for name, (old, new) in edits.items():
            with self.subTest(name):
                self.assertIn(old, text)
                self.assertTrue(cache_key_problems(text.replace(old, new, 1)), name)

    def test_runners_pinned(self):
        for wf in self.files():
            with self.subTest(wf.name):
                jobs, problems = workflow_runners(wf.read_text(encoding="utf-8"))
                self.assertTrue(jobs)
                self.assertEqual(problems, [])

    def test_runner_pin_check_catches_mutants(self):
        # #4792: each form Security and L3 showed passing the text check on #4787, and more.
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        job = "    runs-on: ubuntu-24.04\n"
        head = "\n  checks:\n" + job
        self.assertIn(head, text)
        edits = {
            "ubuntu-latest": (job, "    runs-on: ubuntu-latest\n"),
            "another release": (job, "    runs-on: ubuntu-26.04\n"),
            "arm": (job, "    runs-on: ubuntu-24.04-arm\n"),
            "non-ASCII digit": (job, "    runs-on: ubuntu-2\u0664.04\n"),
            "quoted value": (job, "    runs-on: 'ubuntu-24.04'\n"),
            "matrix": (job, "    runs-on: ${{ matrix.os }}\n"),
            "list": (job, "    runs-on: [self-hosted, linux]\n"),
            "group": (job, "    runs-on:\n      group: big\n"),
            "alias": (job, "    runs-on: *runner\n"),
            "anchor": (job, "    runs-on: &r ubuntu-24.04\n"),
            "tag": (job, "    runs-on: !!str self-hosted\n"),
            "continued plain scalar": (job, "    runs-on: ubuntu-24.04\n      self-hosted\n"),
            "quoted key": (job, '    "runs-on": self-hosted\n'),
            "escaped key": (job, '    "runs\\x2Don": self-hosted\n'),
            "complex key": (job, "    ? runs-on\n    : self-hosted\n"),
            "merge key": (job, "    <<: *defaults\n"),
            "no runs-on": (job, ""),
            "second runs-on": (job, job + job),
            "flow mapping job": (head, "\n  checks: {runs-on: self-hosted}\n  checks2:\n" + job),
            "quoted job key": (head, "\n  'checks':\n" + job),
            "keys at six": (head, "\n  checks:\n      runs-on: self-hosted\n"),
            "keys at three": (head, "\n  checks:\n   runs-on: self-hosted\n"),
            "reusable workflow": (head, "\n  checks:\n    uses: other/repo/.github/workflows/x.yml@v1\n"),
            "tab": (job, "    runs-on:\tubuntu-24.04\n"),
            "no-break space after the value": (job, "    runs-on: ubuntu-24.04\u00a0\n"),
            "ideographic space after the value": (job, "    runs-on: ubuntu-24.04\u3000\n"),
            "ideographic space before a job key": (job, job + "\u3000   runs-on: self-hosted\n"),
            "no-break space separator": (job, "    runs-on:\u00a0ubuntu-24.04\n"),
            "no-break space before a comment": (job, "    runs-on: ubuntu-24.04\u00a0# pinned\n"),
            "duplicate job id": (head, head + "  checks:\n" + job),
            "top-level key after jobs": (head, head + "zz: y\n"),
            "flow collection across lines": (job, job + "    env: {A: 1,\n      B: 2}\n"),
            "second jobs": ("\njobs:\n", "\njobs: {}\njobs:\n"),
            "document marker": ("\njobs:\n", "\n---\njobs:\n"),
        }
        for name, (old, new) in edits.items():
            with self.subTest(name):
                self.assertTrue(workflow_runners(text.replace(old, new, 1))[1], name)
        # A line break YAML honours hides a second runs-on in what reads here as a comment; the job
        # keeps its pinned runs-on, so only the break character can fail it.
        for name, brk in (("carriage return", "\r"), ("next line", "\x85"), ("line separator", "\u2028"),
                          ("paragraph separator", "\u2029")):
            with self.subTest(name):
                jobs, problems = workflow_runners(text.replace(job, job + "    # pinned" + brk + "    runs-on: self-hosted\n", 1))
                self.assertEqual(jobs["checks"], [RUNNER])
                self.assertTrue(problems)
                self.assertTrue(all("YAML line break" in p for p in problems), problems)
        # Security on #4820: a quoted scalar spanning lines hid a column-0 line and a second
        # runs-on; the job keeps a pinned runs-on the reader sees, so only the open scalar fails.
        for name, q in (("single-quoted", "'"), ("double-quoted", '"')):
            with self.subTest(name):
                hidden = "    name: " + q + "abc\n" + job + "zz: y" + q + "\n    runs-on: self-hosted\n"
                _, problems = workflow_runners(text.replace(job, hidden, 1))
                self.assertTrue(any("quoted scalar runs past its line" in p for p in problems), problems)
        for line in ("    if: ${{ github.event_name == 'push' }}", "    name: \"a \\\" b\" # c", "    name: 'it''s'",
                     "    env: {A: '1', B: [x, \"y\"]}", "    if: x == 'a' || y"):
            with self.subTest(line):
                self.assertIsNone(open_flow(line.lstrip()), line)
        jobs, problems = workflow_runners(text.replace(job, "    runs-on: ubuntu-24.04  # pinned\n", 1))
        self.assertEqual((problems, jobs["checks"]), ([], [RUNNER]))

    def files(self):
        files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
        self.assertTrue(files)
        return files

    def test_go_builds_ignore_go_work(self):
        # #4007 Security: Go loads a go.work from the build's directory or any parent, and it
        # overrides broker/go.mod, go.sum and vendor/, so every Go run in CI and every image
        # build sets GOWORK=off; sudo drops the environment, so each sudo env sets it again.
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            text = wf.read_text()
            # trusted-base runs Go only through tools/trusted_base.py, which sets GOWORK=off itself.
            if "actions/setup-go@" not in text or wf.name == "trusted-base.yml":
                continue
            with self.subTest(workflow=wf.name):
                top = text.split("\njobs:", 1)[0].split("\nenv:\n", 1)
                self.assertEqual(len(top), 2, "no workflow-level env")
                env = re.findall(r"^  (\w+): *([^#\n]*?) *(?:#.*)?$", top[1].split("\n\n")[0], re.M)
                self.assertIn(("GOWORK", '"off"'), env)
                for line in text.splitlines():
                    if re.search(r"\bsudo\b.*\benv\b.*GOTOOLCHAIN=", line):
                        self.assertIn(" GOWORK=off ", line)
        root = WORKFLOWS.parent.parent
        for script in ("image/build.sh", "image/infer.sh", "image/camdecode.sh", "image/camnode/build.sh"):
            with self.subTest(script=script):
                text = (root / script).read_text()
                head, _, rest = text.partition("\nexport GOWORK=off\n")
                self.assertTrue(rest, "no export GOWORK=off")
                self.assertNotIn("go build", head)

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
                elif f.name == "premerge.yml" and job.startswith("merge:\n"):
                    # ARM-on-accept (#3103): merges with BOT_PR_TOKEN, so the merge starts push workflows on main.
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

    def test_trace_and_metrics_cross_jobs_as_an_artifact(self):
        # #1832: TRACE.md outgrew the 128 KiB env limit as base64 (trace run 41303991176: "Argument list too long"),
        # and MAIN-PROT-3 (#757) needs the artifact as the proof premerge --bot compares the PR with. Each writer
        # uploads its file from the read-only job, the commit job copies only that file in, and commits with Bot-Run.
        for name, f in (("trace", "TRACE.md"), ("metrics", "METRICS.md"), ("board", "BOARD.md")):
            text = (WORKFLOWS / f"{name}.yml").read_text()
            gen, commit = text.split("\n  commit:\n", 1)
            self.assertNotIn("base64", text, name)
            uploads = [s for a, s in steps(gen) if a.startswith("actions/upload-artifact@")]
            downloads = [s for a, s in steps(commit) if a.startswith("actions/download-artifact@")]
            self.assertEqual((len(uploads), len(downloads)), (1, 1), name)
            self.assertRegex(uploads[0], rf"name: {name}\n\s+path: {f}\n", name)
            self.assertRegex(downloads[0], rf"name: {name}\n\s+path: \$\{{\{{ runner\.temp \}}\}}/{name}$", name)
            self.assertIn(f'cp "$RUNNER_TEMP/{name}/{f}" {f}', commit, name)
            self.assertRegex(commit, r'git commit -qm "[^"]+" -m "Bot-Run: \$GITHUB_RUN_ID" -- ' + f, name)

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
        job = "    runs-on: ubuntu-24.04\n"
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
            "self-hosted": ("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
            "carriage return in comment": ("# CTRL-lane-gate (docs/LANES.md)",
                                           "# CTRL-lane-gate\r    if: false\r# (docs/LANES.md)"),
        }
        for name, (old, new) in edits.items():
            with self.subTest(name):
                self.assertIn(old, text)
                self.assertTrue(lane_gate_problems(text.replace(old, new, 1)), name)

    def test_acceptance_is_pinned(self):
        # ACCEPT-reopen (#2919): the shipped workflow equals its pin, and no other workflow
        # runs the reopen command.
        self.assertEqual(lane_gate_problems((WORKFLOWS / "acceptance.yml").read_text(), ACCEPTANCE_LINES), [])
        for f in self.files():
            if f.name != "acceptance.yml":
                self.assertNotIn("vulncheck.py reopen", f.read_text(), f.name)

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
            "self-hosted": ("runs-on: ubuntu-24.04", "runs-on: self-hosted"),
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
                     # MAIN-PROT-3 (#757): a bot PR passes only with its writer run and that run's artifact.
                     (' --run "$RUNNER_TEMP/run.json" \\\n                --output "$RUNNER_TEMP/output.zip"', ""),
                     ("      actions: read # a bot PR's writer run and its artifact\n", ""),
                     ('/zip" > "$RUNNER_TEMP/output.zip" || exit 1', '/zip" > "$RUNNER_TEMP/output.zip"'),
                     # ARM-on-accept (#3103): only a `same` from --check merges (not `bot`), only an open,
                     # non-draft, unarmed PR, only with every check green, pinned to the gate's head,
                     # with the main-only bot token.
                     ('[ "$verdict" = same ]', '[ "$out" != error ]'),
                     ('.draft == false and .auto_merge == null', '.auto_merge == null'),
                     ('IN("success", "skipped", "neutral")', 'IN("success", "skipped", "neutral", "failure")'),
                     ('select(.status != "completed" or ', 'select('),
                     ('.statuses[] | select(.state != "success")', '.statuses[] | select(.state == "failure")'),
                     ('if [ -n "$wfs$runs$stats" ]; then', 'if [ -n "$runs$stats" ]; then'),
                     ('startswith(".github/workflows/premerge.yml") | not', 'startswith(".github/workflows/") | not'),
                     ("max_by(.id)", "min_by(.id)"),
                     ("select(.check_suite.id != $suite)", "select(.name != \"merge\")"),
                     # PREMERGE-runs-local (#5386): a failed runs fetch never reaches --check.
                     ('"$onto" > "$RUNNER_TEMP/runs.json" || exit 1', '"$onto" > "$RUNNER_TEMP/runs.json"'),
                     # PREMERGE-merge-bind (#5384): only this PR's runs count, and only the other runs' suites are left out.
                     ("(.head_repository.full_name == $repo and .head_branch == $ref)", "(.head_branch == $ref)"),
                     ("map(select(.ours and (.path", "map(select((.path"),
                     ("map(select(.ours | not) | .check_suite_id)", "map(.check_suite_id)"),
                     ('[ -n "$HEAD_REPO" ] && [ -n "$HEAD_REF" ] || ', ""),
                     ('"$HEAD_SHA" "$HEAD_REPO" "$HEAD_REF"', '"$HEAD_SHA" "$REPO" "$HEAD_REF"'),
                     ('-f merge_method=merge -f sha="$HEAD_SHA"', "-f merge_method=merge"),
                     ("    environment: bot", "    # environment: bot"),
                     ("    permissions: {}", "    permissions:\n      contents: write"),
                     # PREMERGE-status-bind (#5442): only a fork PR, only beside an open repository PR into main on its
                     # head, holds its post back, and then hands the merge job nothing.
                     ('[ "$HEAD_REPO" = "$REPO" ] || fork=yes', '[ "$HEAD_REF" = "$REPO" ] || fork=yes'),
                     ('if [ "$fork" = yes ] && ours; then', 'if ours; then'),
                     ('.head.repo.full_name == \\"$REPO\\" and ', ''),
                     ('select(.head.sha == \\"$HEAD_SHA\\" and ', 'select('),
                     ("state=open&base=main&per_page=100", "state=open&per_page=100"),
                     (') | .number") || return 1', ') | .number")'),
                     ('[ "$verdict" = same ] && [ "$skipped" = no ] && ', '[ "$verdict" = same ] && '),
                     # PREMERGE-fork-rerun (#5383): the dispatched run joins the PR's group, reads only a number, and
                     # only the job that dispatches holds `actions: write`, for runs that name no PR.
                     ("|| inputs.pr || github.run_id }}", "|| github.run_id }}"),
                     ("        type: number", "        type: string"),
                     ("!github.event.workflow_run.pull_requests[0] && ", ""),
                     ("startsWith(github.event.workflow_run.event, 'pull_request')", "true"),
                     ("      actions: write # dispatch", "      contents: write\n      actions: write # dispatch"),
                     (".head.ref == $ref and .base.ref == \"main\"", ".base.ref == \"main\""),
                     ('!= 1 ]; then', '-lt 1 ]; then'),
                     ('-f ref=main -f "inputs[pr]=$pr"', '-f ref="$HEAD_BRANCH" -f "inputs[pr]=$pr"'),
                     ("GH_TOKEN: ${{ secrets.BOT_PR_TOKEN }}", "GH_TOKEN: ${{ secrets.BOT_PR_TOKEN || github.token }}"),
                     # PREMERGE-status-bind-fu (#5515): a close reaches `handoff` but never the gate; a fork's post reads the
                     # list again and hands its finds to `handoff` and nothing to the merge job; only `handoff` may dispatch
                     # besides fork-pr, on main, for the PRs on the head this PR left.
                     ("    types: [opened, synchronize, reopened, edited, closed]", "    types: [opened, synchronize, reopened, edited]"),
                     ("(github.event_name == 'pull_request_target' && github.event.action != 'closed')", "github.event_name == 'pull_request_target'"),
                     ("      rerun: ${{ steps.gate.outputs.rerun }}\n", ""),
                     ('"$GITHUB_OUTPUT"; skipped=yes', '"$GITHUB_OUTPUT"'),
                     ("${{ !cancelled() && (", "${{ ("),
                     ("      actions: write # dispatch premerge.yml on main for the other",
                      "      contents: write\n      actions: write # dispatch premerge.yml on main for the other"),
                     ("synchronize) left=$BEFORE ;;", "synchronize) left=$HEAD_SHA ;;"),
                     ('[ -z "$RETARGETED" ] || left=$HEAD_SHA', "left=$HEAD_SHA"),
                     ('select(.head.sha == \\"$left\\" and .number != $PR_NUMBER)', 'select(.number != $PR_NUMBER)'),
                     ("grep -Evx '([1-9][0-9]{0,9})?'", "grep -Evx '.*'"),
                     ('-f ref=main -f "inputs[pr]=$pr" > /dev/null\n            echo "reran the gate for #$pr"\n          done',
                      '-f ref="$HEAD_SHA" -f "inputs[pr]=$pr" > /dev/null\n            echo "reran the gate for #$pr"\n          done'),
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

    def test_mutants_job_sets_up_the_canary_sandbox_as_broker_race_does(self):
        # REV-CHK-mut-userns (#4010): gremlins' coverage run on loops runs the canary-round
        # test, whose sandbox needs subordinate ids and unprivileged user namespaces (tools/
        # ASSUMPTIONS.md D13). The mutants job sets them up with broker-race's own step, first.
        want = "Subordinate ids for the canary sandbox"
        race = dict(job_steps((WORKFLOWS / "ci.yml").read_text(), "broker-race"))
        guard = "        if: steps.scope.outputs.records != 'true'\n"
        self.assertIn(guard, race[want])
        # #4961: `plan` runs a test-only diff's changed tests for their coverage, so it needs it too.
        for job, first in (("mutants", "Gremlins on the package"), ("plan", "Shards for each package (#4961)")):
            mut = job_steps((WORKFLOWS / "mutgate.yml").read_text(), job)
            names = [n for n, _ in mut]
            self.assertIn(want, names)
            self.assertLess(names.index(want), names.index(first))
            # broker-race's copy also skips on a records-only change (CI-par-4); the rest is the same.
            self.assertEqual(dict(mut)[want], race[want].replace(guard, "", 1))

    def test_steps_finds_steps(self):
        sample = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          x: 1\n      - run: echo\n"
        self.assertEqual(list(steps(sample)), [("actions/checkout@v4", "      - uses: actions/checkout@v4\n        with:\n          x: 1")])


# PREMERGE-stale (#1946): run premerge.yml's own script under the runner's shell with `gh`, `git`,
# `python3` and `jq` stubbed, so the job result and the posted status are checked, not just pinned.
STUB_GH = r"""#!/bin/sh
case "$*" in
  "api -X POST "*) [ "$FAIL_AT" = post ] && [ ! -e "$STUBS/post-failed" ] && { : > "$STUBS/post-failed"; exit 1; }
                   echo "$*" >> "$STUBS/posts"; echo "$GH_TOKEN" >> "$STUBS/post-tokens"; exit 0 ;;
  "api --paginate repos/o/r/actions/runs/41/artifacts?per_page=100") [ "$FAIL_AT" = artifacts ] && exit 1
     echo '{"artifacts":[{"id":5,"name":"trace","expired":false},{"id":6,"name":"board","expired":false},{"id":4,"name":"trace","expired":true}]}' ;;
  "api repos/o/r/actions/runs/41") [ "$FAIL_AT" = run ] && exit 1; echo '{"id":41}' ;;
  "api repos/o/r/actions/artifacts/"*"/zip") [ "$FAIL_AT" = zip ] && exit 1; echo "$*" >> "$STUBS/zips" ;;
  "api --paginate repos/o/r/actions/runs?"*) [ "$FAIL_AT" = runs ] && exit 1; echo "$*" >> "$STUBS/runs" ;;
  "api --paginate repos/o/r/pulls?state=open&base=main&per_page=100 --jq "*) echo "$*" >> "$STUBS/lists"
     [ "$FAIL_AT" = list ] && exit 1; [ -e "$STUBS/posts" ] && [ "$FAIL_AT" = relist ] && exit 1
     prs=$OPEN_PRS; [ -e "$STUBS/posts" ] && [ -n "$OPEN_PRS_AFTER" ] && prs=$OPEN_PRS_AFTER
     printf '%s' "$prs" | "$REAL_JQ" -r "$5" ;;
  "api --paginate "*) [ "$FAIL_AT" = comments ] && exit 1; echo '{"author_association":"OWNER","created_at":"t","body":"b"}' ;;
  "api repos/"*) [ "$FAIL_AT" = pulls ] && exit 1
                 echo '{"head":{"sha":"'"$SHA"'","ref":"'"$REF"'","repo":{"full_name":"'"$HEAD_FULL"'"}},"base":{"ref":"'"$BASE"'"},'"$PR_STATE"'}' ;;
  *) exit 2 ;;
esac
"""
STUB_JQ = r"""#!/bin/sh
[ "$FAIL_AT" = jq ] && [ "$2" = .head.ref ] && exit 1
exec "$REAL_JQ" "$@"
"""
# #5545: the status filter step runs the real interpreter, so these tests post the text premerge.yml's filter makes.
STUB_PY = r"""#!/bin/sh
[ "$1" = -I ] && [ "$2" = -c ] && exec "$REAL_PY" "$@"
echo "$*" >> "$STUBS/py"
printf '%s\n' "$VERDICT"; [ "$VERDICT" = same ] || [ "$VERDICT" = bot ] || [ -n "$VERDICT_OK" ]
"""
# MAIN-PROT-3 (#757): `git log` answers the head commit's Bot-Run trailer; every other git call succeeds silently.
STUB_GIT = r"""#!/bin/sh
[ "$1" = log ] && printf '%s' "$TRAILER"
[ "$1" = merge-base ] && echo bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
exit 0
"""


def premerge_script():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    return run_block(lines, lines.index("        run: |") + 1)


def step_argv(lines, run):
    # GitHub runs a step with no `shell:` as `bash -e {0}`, and `shell: bash` as
    # `bash --noprofile --norc -eo pipefail {0}`; the tests run a step the way the runner would.
    start = max(i for i in range(run) if lines[i].startswith("      - "))
    shell = [l.split("#")[0].split(":", 1)[1].strip() for l in lines[start:run] if l.strip().startswith("shell:")]
    return {(): ["bash", "-e"], ("bash",): ["bash", "--noprofile", "--norc", "-eo", "pipefail"]}[tuple(shell)]


def gate_argv():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    return step_argv(lines, lines.index("        run: |"))


def merge_argv():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    return step_argv(lines, lines.index("        run: |", lines.index("  merge:")))


def run_block(lines, start):
    end = next((i for i in range(start, len(lines)) if lines[i].strip() and not lines[i].startswith("          ")), len(lines))
    return "\n".join(l[10:] for l in lines[start:end]) + "\n"


def merge_script():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    return run_block(lines, lines.index("        run: |", lines.index("  merge:")) + 1)


def fork_pr_script():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    run = lines.index("        run: |", lines.index("  fork-pr:"))
    return step_argv(lines, run), run_block(lines, run + 1)


# PREMERGE-fork-rerun (#5383): `gh` for the fork-pr job records each call's arguments one per line, answers the
# open-PR list with $PRS and accepts the dispatch.
STUB_FORK_GH = r"""#!/bin/sh
{ printf '%s\n' "$@"; echo --; } >> "$STUBS/calls"
case "$1 $2 $3" in
  "api -X GET") [ "$FAIL_AT" = pulls ] && exit 1; printf '%s' "$PRS" ;;
  "api -X POST") [ "$FAIL_AT" = dispatch ] && exit 1; : ;;
  *) exit 2 ;;
esac
"""


def handoff_script():
    lines = (WORKFLOWS / "premerge.yml").read_text().split("\n")
    run = lines.index("        run: |", lines.index("  handoff:"))
    return step_argv(lines, run), run_block(lines, run + 1)


# PREMERGE-status-bind-fu (#5515): `gh` for the handoff job records each call's arguments one per line, answers the
# open-PR list from $PRS through the call's own --jq filter and accepts the dispatch.
STUB_HANDOFF_GH = r"""#!/bin/sh
{ printf '%s\n' "$@"; echo --; } >> "$STUBS/calls"
case "$1 $2" in
  "api --paginate") [ "$FAIL_AT" = list ] && exit 1; printf '%s' "$PRS" | "$REAL_JQ" -r "$5" ;;
  "api -X") [ "$FAIL_AT" = dispatch ] && exit 1; : ;;
  *) exit 2 ;;
esac
"""


class PremergeRunTest(unittest.TestCase):
    SHA = "a" * 40

    OPEN = '"state":"open","draft":false,"auto_merge":null'

    def run_gate(self, verdict="no-verdict", fail_at="", ref="feature", base="main", tokens=None, outputs=None, pr_state=OPEN,
                 descriptions=None, trailer="41\n", calls=None, pr="7", head="o/r", open_prs=(), lists=None,
                 open_after=None, env_extra=None, raw=None):
        real_jq = shutil.which("jq")
        self.assertTrue(real_jq, "jq is on the runner image; the test needs it")
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            for name, body in (("gh", STUB_GH), ("jq", STUB_JQ), ("python3", STUB_PY), ("git", STUB_GIT)):
                (stubs / name).write_text(body)
                (stubs / name).chmod(0o755)
            (stubs / "run.sh").write_text(premerge_script())
            # The step runs from the base checkout, so its runs fetch is that checkout's tools/premerge_runs.sh (#5386).
            (stubs / "tools").mkdir()
            shutil.copy(WORKFLOWS.parent.parent / "tools/premerge_runs.sh", stubs / "tools")
            env = {"PATH": "%s:/usr/bin:/bin" % stubs, "STUBS": d, "REAL_JQ": real_jq, "REAL_PY": sys.executable, "SHA": self.SHA,
                   "REF": ref, "BASE": base, "VERDICT": verdict, "FAIL_AT": fail_at, "RUNNER_TEMP": d, "PR_NUMBER": pr,
                   "REPO": "o/r", "GH_TOKEN": "synthetic", "STATUS_TOKEN": "synthetic-app", "GITHUB_SERVER_URL": "https://example.invalid",
                   "GITHUB_RUN_ID": "1", "GITHUB_OUTPUT": str(stubs / "out"), "PR_STATE": pr_state, "TRAILER": trailer,
                   "HEAD_FULL": head, "OPEN_PRS": json.dumps(list(open_prs)),
                   "OPEN_PRS_AFTER": "" if open_after is None else json.dumps(list(open_after))}
            env.update(env_extra or {})
            # The runner's default `run` shell.
            proc = subprocess.run(gate_argv() + [str(stubs / "run.sh")],
                                  env=env, cwd=d, capture_output=True, text=True, timeout=30)
            posts = (stubs / "posts").read_text().splitlines() if (stubs / "posts").exists() else []
            if tokens is not None:
                tokens.extend((stubs / "post-tokens").read_text().split())
            if raw is not None and (stubs / "posts").exists():
                raw.append((stubs / "posts").read_bytes())
            if descriptions is not None:
                descriptions.extend(re.search(r"description=(\S+)", p).group(1) for p in posts)
            if outputs is not None and (stubs / "out").exists():
                outputs.extend((stubs / "out").read_text().split())
            if lists is not None:
                lists.extend((stubs / "lists").read_text().splitlines() if (stubs / "lists").exists() else [])
            if calls is not None:
                for f in ("zips", "py", "runs"):
                    calls.extend((stubs / f).read_text().splitlines() if (stubs / f).exists() else [])
        return proc.returncode, [re.search(r"state=(\w+)", p).group(1) for p in posts]

    def test_failure_verdict_posts_failure_but_job_passes(self):
        # The `premerge` status is the gate, not the job: a failing verdict rides only on the
        # status, so comment-time runs (attached to main's head) don't read as main breaking.
        self.assertEqual(self.run_gate("no-verdict"), (0, ["failure"]))
        self.assertEqual(self.run_gate("fix-list"), (0, ["failure"]))

    def test_same_posts_success(self):
        self.assertEqual(self.run_gate("same"), (0, ["success"]))
        # PREMERGE-runs-local (#5386): the base checkout's tools/premerge_runs.sh reads the head's and the merge base's runs
        # and --check reads its document.
        calls, a, b = [], self.SHA, "b" * 40
        self.assertEqual(self.run_gate("same", calls=calls), (0, ["success"]))
        q = "api --paginate repos/o/r/actions/runs?%s&per_page=100 --jq .workflow_runs[]"
        self.assertEqual(calls[1:], [q % f"head_sha={a}", q % f"head_sha={b}&event=push", q % f"head_sha={b}&event=schedule"])
        self.assertRegex(calls[0], r"^-I tools/premerge\.py --check \S+/comments\.json 7 --runs \S+/runs\.json --base refs/remotes/pr/base " + a + "$")

    @staticmethod
    def open_pr(number, sha, repo):
        return {"number": number, "head": {"sha": sha, "repo": {"full_name": repo}}}

    def test_fork_pr_leaves_a_shared_head_to_the_repository_pr(self):
        # PREMERGE-status-bind (#5442): a fork PR on the head of an open PR into main from this repository posts
        # nothing and hands the merge job nothing, whatever its verdict or error, so its `failure` cannot land
        # after that PR's `success`. The list is read just before each post, with this sha and PR number.
        ours = [self.open_pr(8, self.SHA, "o/r"), self.open_pr(7, self.SHA, "f/r")]
        for verdict, kw in (("same", {}), ("no-verdict", {}), ("same", {"fail_at": "comments"}), ("same", {"base": "stacked"})):
            with self.subTest(verdict=verdict, **kw):
                out, lists = [], []
                self.assertEqual(self.run_gate(verdict, head="f/r", open_prs=ours, outputs=out, lists=lists, **kw), (0, []))
                self.assertEqual(out, [])
                self.assertEqual(len(lists), 1)
                self.assertIn('select(.head.sha == "%s" and .head.repo.full_name == "o/r" and .number != 7)' % self.SHA, lists[0])
        # A fork PR alone on its head, or beside other forks, or beside a repository PR on another head, posts as before.
        b = "b" * 40
        for others in ([], [self.open_pr(7, self.SHA, "f/r")], [self.open_pr(9, self.SHA, "g/r")], [self.open_pr(8, b, "o/r")],
                       [{"number": 8, "head": {"sha": self.SHA, "repo": None}}]):
            with self.subTest(others=others):
                out = []
                self.assertEqual(self.run_gate("same", head="f/r", open_prs=others, outputs=out), (0, ["success"]))
                self.assertEqual(out, ["merge-head=" + self.SHA, "merge-repo=f/r", "merge-ref=feature"])
                self.assertEqual(self.run_gate("no-verdict", head="f/r", open_prs=others), (0, ["failure"]))
        # A fork whose head repository was deleted is a fork too.
        self.assertEqual(self.run_gate("no-verdict", head="", open_prs=ours[:1]), (0, []))

    def test_status_bind_fails_closed(self):
        # PREMERGE-status-bind (#5442): a repository PR always posts, without reading the list, even when another
        # repository PR shares its head; a failed list read, or an error before the head's repository is known,
        # posts `failure` as before.
        ours = [self.open_pr(8, self.SHA, "o/r")]
        for verdict, state in (("same", "success"), ("fix-list", "failure")):
            lists = []
            self.assertEqual(self.run_gate(verdict, open_prs=ours, lists=lists), (0, [state]))
            self.assertEqual(lists, [])
        self.assertEqual(self.run_gate("no-verdict", head="f/r", open_prs=ours, fail_at="list"), (0, ["failure"]))
        self.assertEqual(self.run_gate("same", head="f/r", open_prs=ours, fail_at="list"), (0, ["success"]))
        code, states = self.run_gate("same", head="f/r", open_prs=ours, fail_at="jq")
        self.assertEqual((code != 0, states), (True, ["failure"]))

    def test_fork_post_reruns_a_repository_pr_the_first_read_missed(self):
        # PREMERGE-status-bind-fu (#5515): a repository PR that opens on the head while a fork PR's post is on its way
        # (or that a lagging list left out) would keep the fork's verdict. The fork run reads the list again after
        # its post, hands that PR to `handoff` to rerun its gate after this post, and hands the merge job nothing.
        late = [self.open_pr(8, self.SHA, "o/r"), self.open_pr(7, self.SHA, "f/r")]
        for verdict, state in (("same", "success"), ("no-verdict", "failure")):
            with self.subTest(verdict=verdict):
                out, lists = [], []
                self.assertEqual(self.run_gate(verdict, head="f/r", open_after=late, outputs=out, lists=lists), (0, [state]))
                self.assertEqual(out, ["rerun=8"])
                self.assertEqual(len(lists), 2)
                self.assertEqual(lists[0], lists[1])
        out = []
        self.assertEqual(self.run_gate("same", head="f/r", open_after=late + [self.open_pr(9, self.SHA, "o/r")], outputs=out),
                         (0, ["success"]))
        self.assertEqual(out, ["rerun=8", "9"])
        # The error path's post reads again too.
        out = []
        self.assertEqual(self.run_gate("same", head="f/r", fail_at="comments", open_after=late, outputs=out), (0, ["failure"]))
        self.assertEqual(out, ["rerun=8"])
        # Nothing new on the head, a fork or another head's PR, or a failed second read: the post stands as before.
        b = "b" * 40
        for after, fail_at in (([], ""), ([self.open_pr(9, self.SHA, "g/r")], ""), ([self.open_pr(8, b, "o/r")], ""), (late, "relist")):
            with self.subTest(after=after, fail_at=fail_at):
                out = []
                self.assertEqual(self.run_gate("same", head="f/r", open_after=after, fail_at=fail_at, outputs=out), (0, ["success"]))
                self.assertEqual(out, ["merge-head=" + self.SHA, "merge-repo=f/r", "merge-ref=feature"])
        # A repository PR never reads the list, before or after its post.
        lists, out = [], []
        self.assertEqual(self.run_gate("same", open_after=late, lists=lists, outputs=out), (0, ["success"]))
        self.assertEqual((lists, out[0]), ([], "merge-head=" + self.SHA))

    def test_gate_reads_only_a_pr_number(self):
        # PREMERGE-fork-rerun (#5383): a dispatch carries its PR as an input, so the number is checked before any read.
        for pr in ("", "0", "07", "7a", "7 ", "-7", "12345678901"):
            with self.subTest(pr=pr):
                self.assertEqual(self.run_gate("same", pr=pr), (1, []))
        self.assertEqual(self.run_gate("same", pr="1234567890"), (0, ["success"]))

    def run_fork_pr(self, prs, owner="f", repo="f/r", branch="feat", fail_at=""):
        """Run premerge.yml's fork-pr step; return its exit code, the GET's arguments and the dispatched PR, if any."""
        real_jq = shutil.which("jq")
        self.assertTrue(real_jq, "jq is on the runner image; the test needs it")
        argv, script = fork_pr_script()
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            (stubs / "gh").write_text(STUB_FORK_GH)
            (stubs / "gh").chmod(0o755)
            (stubs / "jq").symlink_to(real_jq)
            (stubs / "run.sh").write_text(script)
            env = {"PATH": "%s:/usr/bin:/bin" % stubs, "STUBS": d, "RUNNER_TEMP": d, "GH_TOKEN": "synthetic", "REPO": "o/r",
                   "HEAD_OWNER": owner, "HEAD_REPO": repo, "HEAD_BRANCH": branch, "PRS": json.dumps(prs), "FAIL_AT": fail_at}
            proc = subprocess.run(argv + [str(stubs / "run.sh")], env=env, cwd=d, capture_output=True, text=True, timeout=30)
            calls = (stubs / "calls").read_text().split("--\n")[:-1] if (stubs / "calls").exists() else []
        calls = [c.splitlines() for c in calls]
        get = [c for c in calls if c[:3] == ["api", "-X", "GET"]]
        posts = [c for c in calls if c[:3] == ["api", "-X", "POST"]]
        self.assertLessEqual(len(posts), 1)
        for c in posts:
            self.assertEqual(c[:6], ["api", "-X", "POST", "repos/o/r/actions/workflows/premerge.yml/dispatches", "-f", "ref=main"])
        dispatched = [c[7].removeprefix("inputs[pr]=") for c in posts if c[6] == "-f" and c[7].startswith("inputs[pr]=")]
        return proc.returncode, get, dispatched

    @staticmethod
    def pr_(number=12, repo="f/r", ref="feat", base="main"):
        return {"number": number, "head": {"repo": {"full_name": repo}, "ref": ref}, "base": {"ref": base}}

    def test_fork_pr_reruns_the_gate_for_its_one_open_pr(self):
        # PREMERGE-fork-rerun (#5383): a fork PR's workflow_run names no PR, so the job finds the one open PR into
        # main whose head is the run's owner:branch and dispatches this workflow on main for it.
        code, get, dispatched = self.run_fork_pr([self.pr_()])
        self.assertEqual((code, dispatched), (0, ["12"]))
        self.assertEqual(get, [["api", "-X", "GET", "repos/o/r/pulls", "-f", "state=open", "-f", "base=main",
                                "-f", "head=f:feat", "-f", "per_page=100"]])
        # A branch name is one argument, never shell: the fork chooses it.
        odd = 'x";$(touch p)`id`&#'
        code, get, dispatched = self.run_fork_pr([self.pr_(ref=odd)], branch=odd)
        self.assertEqual((code, dispatched), (0, ["12"]))
        self.assertIn("head=f:" + odd, get[0])

    def test_fork_pr_reruns_nothing_without_exactly_one_matching_pr(self):
        # PREMERGE-fork-rerun (#5383): GitHub's head filter only narrows; the PR must name the run's repository and
        # branch exactly and target main, and anything but one such PR dispatches nothing (the job stays green).
        for prs in ([], [self.pr_(), self.pr_(13)], [self.pr_(repo="g/r")], [self.pr_(ref="feat2")], [self.pr_(ref="Feat")],
                    [self.pr_(base="dev")]):
            with self.subTest(prs=prs):
                code, get, dispatched = self.run_fork_pr(prs)
                self.assertEqual((code, len(get), dispatched), (0, 1, []))
        # One match among others is still one.
        self.assertEqual(self.run_fork_pr([self.pr_(repo="g/r", number=3), self.pr_(), self.pr_(base="dev", number=4)])[2], ["12"])

    def test_fork_pr_reads_nothing_without_a_head(self):
        # PREMERGE-fork-rerun (#5383): a deleted fork leaves no head repository; an owner that is not a login, or a
        # repository outside that owner, is not read at all.
        for kw in (dict(owner=""), dict(owner="f/g"), dict(owner="f:g"), dict(owner="f:g", repo="f:g/r"), dict(owner="", repo="/r"),
                   dict(owner="f g", repo="f g/r"), dict(repo=""), dict(repo="g/r"),
                   dict(repo="f"), dict(branch="")):
            with self.subTest(**kw):
                self.assertEqual(self.run_fork_pr([self.pr_()], **kw), (0, [], []))

    def test_fork_pr_fails_on_a_failed_read_or_dispatch(self):
        # PREMERGE-fork-rerun (#5383): a failed read must never read as no PR, a number that is not one is never
        # dispatched, and a refused dispatch turns the job red.
        self.assertEqual(self.run_fork_pr([self.pr_()], fail_at="pulls")[0::2], (1, []))
        self.assertNotEqual(self.run_fork_pr([self.pr_()], fail_at="dispatch")[0], 0)
        for number in ("12", "1 2", 0, -1, 1.5, None, [12]):
            with self.subTest(number=number):
                self.assertEqual(self.run_fork_pr([self.pr_(number=number)])[0::2], (1, []))
        self.assertEqual(self.run_gate("bot", ref="bot/trace"), (0, ["success"]))

    def run_handoff(self, prs=(), action="closed", event="pull_request_target", before="b" * 40, head="a" * 40, retargeted="",
                    rerun="", pr="7", fail_at=""):
        """Run premerge.yml's handoff step; return its exit code, its list reads and the PRs it dispatched the gate for."""
        real_jq = shutil.which("jq")
        self.assertTrue(real_jq, "jq is on the runner image; the test needs it")
        argv, script = handoff_script()
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            (stubs / "gh").write_text(STUB_HANDOFF_GH)
            (stubs / "gh").chmod(0o755)
            (stubs / "jq").symlink_to(real_jq)
            (stubs / "run.sh").write_text(script)
            env = {"PATH": "%s:/usr/bin:/bin" % stubs, "STUBS": d, "REAL_JQ": real_jq, "GH_TOKEN": "synthetic", "REPO": "o/r",
                   "PR_NUMBER": pr, "RERUN": rerun, "EVENT": event, "ACTION": action, "BEFORE": before, "HEAD_SHA": head,
                   "RETARGETED": retargeted, "PRS": json.dumps(list(prs)), "FAIL_AT": fail_at}
            proc = subprocess.run(argv + [str(stubs / "run.sh")], env=env, cwd=d, capture_output=True, text=True, timeout=30)
            calls = (stubs / "calls").read_text().split("--\n")[:-1] if (stubs / "calls").exists() else []
        calls = [c.splitlines() for c in calls]
        lists = [c for c in calls if c[:2] == ["api", "--paginate"]]
        posts = [c for c in calls if c[:3] == ["api", "-X", "POST"]]
        for c in posts:
            self.assertEqual(c[:6], ["api", "-X", "POST", "repos/o/r/actions/workflows/premerge.yml/dispatches", "-f", "ref=main"])
        return proc.returncode, lists, [c[7].removeprefix("inputs[pr]=") for c in posts]

    def test_handoff_reruns_the_gate_for_the_prs_left_on_a_head(self):
        # PREMERGE-status-bind-fu (#5515): a PR that closes, pushes past a head or moves off main leaves its last
        # `premerge` on that head, where a fork PR would read it as its own until its next event. `handoff` dispatches
        # the gate for every other open PR into main on the head it left, so each posts its own verdict.
        a, b = "a" * 40, "b" * 40
        left = [PremergeRunTest.open_pr(9, a, "f/r"), PremergeRunTest.open_pr(10, a, "g/r"), PremergeRunTest.open_pr(7, a, "o/r"),
                PremergeRunTest.open_pr(11, b, "f/r")]
        for kw, sha, want in ((dict(action="closed"), a, ["9", "10"]), (dict(action="synchronize"), b, ["11"]),
                              (dict(action="edited", retargeted="main"), a, ["9", "10"])):
            with self.subTest(**kw):
                code, lists, dispatched = self.run_handoff(left, **kw)
                self.assertEqual((code, dispatched), (0, want))
                self.assertEqual(lists, [["api", "--paginate", "repos/o/r/pulls?state=open&base=main&per_page=100", "--jq",
                                          '.[] | select(.head.sha == "%s" and .number != 7) | .number' % sha]])
        # A PR that stays on its head leaves nothing: no read and no dispatch.
        for kw in (dict(action="opened"), dict(action="reopened"), dict(action="edited"), dict(event="issue_comment", action="edited"),
                   dict(event="workflow_dispatch", action=""), dict(event="workflow_run", action="completed")):
            with self.subTest(**kw):
                self.assertEqual(self.run_handoff(left, **kw), (0, [], []))
        # The gate's `rerun` PRs are dispatched on any event, once each beside the PRs left behind.
        self.assertEqual(self.run_handoff(left, event="workflow_dispatch", action="", rerun="8 12 ")[0::2], (0, ["8", "12"]))
        self.assertEqual(self.run_handoff(left, rerun="10 8")[0::2], (0, ["8", "9", "10"]))

    def test_handoff_fails_on_a_failed_read_or_dispatch(self):
        # PREMERGE-status-bind-fu (#5515): a failed list read never reads as no PR left, a sha or number that is not one
        # dispatches nothing, and a refused dispatch turns the job red.
        left = [PremergeRunTest.open_pr(9, "a" * 40, "f/r")]
        self.assertEqual(self.run_handoff(left, fail_at="list", rerun="8")[0::2], (1, []))
        self.assertNotEqual(self.run_handoff(left, fail_at="dispatch")[0], 0)
        for kw in (dict(head="A" * 40), dict(head="a" * 39), dict(head=""), dict(action="synchronize", before="b" * 41),
                   dict(action="synchronize", before=""), dict(action="edited", retargeted="dev", head=""),
                   dict(rerun="8 0"), dict(rerun="8 08"), dict(rerun="8 8a"), dict(rerun="8 -1"), dict(rerun="8 $(id)"), dict(rerun="*"),
                   dict(pr=""), dict(pr="07"), dict(pr="7 ")):
            with self.subTest(**kw):
                code, _, dispatched = self.run_handoff(left, **kw)
                self.assertEqual((code, dispatched), (1, []))
        for number in ("1 2", "8\n9x", 0, None, 1.5):
            with self.subTest(number=number):
                self.assertEqual(self.run_handoff([{"number": number, "head": {"sha": "a" * 40}}])[0::2], (1, []))

    def test_error_after_head_known_posts_failure(self):
        # The #1946 path: a rerun that dies outside the guarded block must not leave the head's
        # earlier `success` standing. The job stays red so the error is visible.
        code, states = self.run_gate("same", fail_at="jq")
        self.assertEqual((code != 0, states), (True, ["failure"]))
        self.assertEqual(self.run_gate("same", fail_at="comments"), (0, ["failure"]))
        self.assertEqual(self.run_gate("same", fail_at="runs"), (0, ["failure"]))  # PREMERGE-runs-local (#5386)
        code, states = self.run_gate("same", fail_at="post")
        self.assertEqual((code != 0, states), (True, ["failure"]))

    def test_status_middle_dot_reaches_gh_intact(self):
        # PREMERGE-status-bytes (#5553): the status step's U+00B7 is two bytes, C2 B7, in the argument `gh api` receives,
        # under a UTF-8 locale and under LC_ALL=C (the filter decodes by itself, not by the shell's locale).
        verdict = "unparsed-record 7: Record: PR #7 \u00b7 package x \u00b7 head f"
        for env in ({"LC_ALL": "C.UTF-8"}, {"LC_ALL": "C"}, {"LC_ALL": "POSIX", "LANG": "C"}):
            raw = []
            self.assertEqual(self.run_gate(verdict, env_extra=env, raw=raw)[1], ["failure"], env)
            self.assertIn(b"description=unparsed-record 7: Record: PR #7 \xc2\xb7 package x \xc2\xb7 head f ", raw[0], env)

    def test_only_a_whole_same_output_arms_the_merge(self):
        # PREMERGE-status-cut-pins (#5561): the cut status of `same`, two spaces and a long token is `same`, and the filter
        # strips control characters; neither reaches the merge job, which reads the whole output. VERDICT_OK stands in
        # for a success exit, since premerge.py prints no such line today. A multi-line output ending in `same` shows
        # `same` too, since the status keeps the last line, and must not arm (PREMERGE-merge-whole-output-fu, #5563).
        for verdict, shown in (("same  " + "x" * 115, "same"), ("same\x07", "same"), ("x\nsame", "same"), ("same", "same")):
            with self.subTest(verdict=verdict):
                out, desc = [], []
                self.assertEqual(self.run_gate(verdict, env_extra={"VERDICT_OK": "1"}, outputs=out, descriptions=desc),
                                 (0, ["success"]))
                self.assertEqual(desc, [shown])
                self.assertEqual(out, ["merge-head=" + self.SHA, "merge-repo=o/r", "merge-ref=feature"] if verdict == "same" else [])

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

    def test_bot_pr_fetches_its_writer_run_and_artifact(self):
        # MAIN-PROT-3 (#757): the head's Bot-Run trailer names the run; the gate fetches that run and its newest
        # unexpired artifact named for the branch, and hands both to --bot. No trailer, no artifact or a failed
        # read posts failure without calling --bot.
        calls = []
        self.assertEqual(self.run_gate("bot", ref="bot/trace", calls=calls), (0, ["success"]))
        self.assertEqual(calls[0], "api repos/o/r/actions/artifacts/5/zip")
        self.assertRegex(calls[1], r"^-I tools/premerge\.py --bot bot/trace --run \S+/run\.json --output \S+/output\.zip "
                                   r"--base refs/remotes/pr/base a{40}$")
        calls = []
        self.assertEqual(self.run_gate("bot", ref="bot/board", calls=calls), (0, ["success"]))
        self.assertEqual(calls[0], "api repos/o/r/actions/artifacts/6/zip")
        for kw in ({"trailer": ""}, {"trailer": "41\n42"}, {"trailer": "41 x"}, {"trailer": "$(id)"},
                   {"ref": "bot/metrics"}, {"fail_at": "run"}, {"fail_at": "artifacts"}, {"fail_at": "zip"}):
            calls = []
            self.assertEqual(self.run_gate("bot", **{"ref": "bot/trace", **kw}, calls=calls), (0, ["failure"]), kw)
            self.assertFalse([c for c in calls if "premerge.py" in c], kw)

    def test_only_a_full_accept_on_an_open_unarmed_pr_merges(self):
        # ARM-on-accept (#3103): the gate hands the merge job the head it read, only on `same`.
        out = []
        self.assertEqual(self.run_gate("same", outputs=out), (0, ["success"]))
        self.assertEqual(out, ["merge-head=" + self.SHA, "merge-repo=o/r", "merge-ref=feature"])
        for verdict, kw in (("no-verdict", {}), ("needs-security", {}), ("edited-verdict", {}), ("bot", {"ref": "bot/trace"}),
                            ("same", {"base": "stacked"}), ("same", {"fail_at": "comments"}),
                            ("same", {"pr_state": self.OPEN.replace('"draft":false', '"draft":true')}),
                            ("same", {"pr_state": self.OPEN.replace('"state":"open"', '"state":"closed"')}),
                            ("same", {"pr_state": self.OPEN.replace('"auto_merge":null', '"auto_merge":{"merge_method":"merge"}')})):
            out = []
            self.run_gate(verdict, outputs=out, **kw)
            self.assertEqual(out, [], (verdict, kw))

    def test_error_before_head_known_fails_the_job(self):
        # Residual named in #1946: with the pulls API down there is no head to post to.
        code, states = self.run_gate("same", fail_at="pulls")
        self.assertEqual((code != 0, states), (True, []))


STUB_MERGE_GH = r"""#!/bin/sh
echo "$*" >> "$STUBS/calls"
case "$*" in
  "api repos/o/r/actions/runs/41 --jq .check_suite_id") [ "$READ" = suite ] && exit 1; echo 99 ;;
  "api repos/o/r/compare/main..."*" --jq .merge_base_commit.sha") [ "$READ" = base ] && exit 1; echo "$BASE" ;;
  "api --paginate repos/o/r/actions/runs?head_sha=$BASE&per_page=100 --jq .workflow_runs[]") [ "$READ" = bwfs ] && exit 1
     printf '%s' "$BWFS" | "$REAL_JQ" -c "$5" ;;
  "api --paginate repos/o/r/commits/$BASE/check-runs?per_page=100 --jq .check_runs[]") [ "$READ" = bruns ] && exit 1
     printf '%s' "$BRUNS" | "$REAL_JQ" -c "$5" ;;
  "api --paginate repos/o/r/actions/runs/"*"/attempts/1/jobs?per_page=100 --jq .jobs[]") [ "$READ" = bjobs ] && exit 1
     id=${3#repos/o/r/actions/runs/}; printf '%s' "$BJOBS" | "$REAL_JQ" -c --arg id "${id%%/*}" '.[$id] // [] | .[]' ;;
  "api --paginate repos/o/r/actions/runs?head_sha="*"&per_page=100 --jq .workflow_runs[]") [ "$READ" = wfs ] && exit 1
     printf '%s' "$WFS" | "$REAL_JQ" -c "$5" ;;
  "api --paginate repos/o/r/commits/"*"/check-runs?per_page=100 --jq .check_runs[]") [ "$READ" = fail ] && exit 1
     printf '%s' "$RUNS" | "$REAL_JQ" -c "$5" ;;
  "api repos/o/r/commits/"*"/status?per_page=100 --jq "*) [ "$READ" = stat ] && exit 1; printf "%s" "$STATUSES" | "$REAL_JQ" -r "$4" ;;
  "api -X PUT "*) [ "$MERGE" = ok ] ;;
  *) exit 2 ;;
esac
"""


def run_(name, status="completed", conclusion="success", suite=1, id=1):
    return {"name": name, "id": id, "status": status, "conclusion": conclusion, "check_suite": {"id": suite}}


def wf_(name, id=1, status="completed", conclusion="success", path=None, event="push", branch="main", attempt=1, suite=1,
        repo="o/r"):
    # The head runs default to branch main of o/r, which run_merge names as the PR's head (PREMERGE-merge-bind, #5384).
    return {"name": name, "id": id, "workflow_id": hash(name) % 1000, "status": status, "conclusion": conclusion,
            "path": path or ".github/workflows/%s.yml" % name, "event": event, "head_branch": branch,
            "run_attempt": attempt, "check_suite_id": suite, "head_repository": repo and {"full_name": repo}}


class MergeRunTest(unittest.TestCase):
    SHA = "b" * 40
    # This run's own jobs (suite 99) are left out whatever their state; an older premerge run's are green.
    GREEN = [run_("checks"), run_("count"), run_("formal", conclusion="skipped"), run_("premerge-gate", suite=7),
             run_("premerge-gate", status="completed", suite=99), run_("merge", status="in_progress", conclusion=None, suite=99)]
    WF_GREEN = [wf_("ci"), wf_("vulncheck"), wf_("formal", conclusion="skipped"),
                wf_("premerge", status="in_progress", conclusion=None)]

    def run_merge(self, runs=GREEN, wfs=WF_GREEN, statuses=(("premerge", "success"),), merge="ok", read="ok",
                  token="synthetic-bot", sha=SHA, base_runs=(), base_wfs=(), base_jobs=None, base="c" * 40,
                  head_repo="o/r", head_ref="main"):
        real_jq = shutil.which("jq")
        self.assertTrue(real_jq, "jq is on the runner image; the test needs it")
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            (stubs / "gh").write_text(STUB_MERGE_GH)
            (stubs / "gh").chmod(0o755)
            (stubs / "run.sh").write_text(merge_script())
            env = {"PATH": "%s:/usr/bin:/bin" % stubs, "STUBS": d, "REAL_JQ": real_jq, "MERGE": merge, "READ": read,
                   "GH_TOKEN": token, "PR_NUMBER": "7", "REPO": "o/r", "HEAD_SHA": sha, "GITHUB_RUN_ID": "41",
                   "HEAD_REPO": head_repo, "HEAD_REF": head_ref,
                   "RUNS": json.dumps({"check_runs": list(runs)}), "WFS": json.dumps({"workflow_runs": list(wfs)}),
                   "BASE": base, "BRUNS": json.dumps({"check_runs": list(base_runs)}), "BJOBS": json.dumps(base_jobs or {}),
                   "BWFS": json.dumps({"workflow_runs": list(base_wfs)}),
                   "STATUSES": json.dumps({"statuses": [{"context": c, "state": st} for c, st in statuses]})}
            proc = subprocess.run(merge_argv() + [str(stubs / "run.sh")],
                                  env=env, cwd=d, capture_output=True, text=True, timeout=30)
            calls = (stubs / "calls").read_text().splitlines() if (stubs / "calls").exists() else []
        return proc.returncode, [c for c in calls if c.startswith("api -X PUT")], proc.stdout

    def test_unfinished_workflow_runs_never_merge(self):
        # #3123 delta review: a job behind `needs: scope` has no check run yet, so an all-green check list
        # is not finished CI; every workflow run on the head but premerge's own must have passed.
        for bad in (wf_("vulncheck", status="queued", conclusion=None), wf_("assurance", status="in_progress", conclusion=None),
                    wf_("ci", conclusion="failure"), wf_("keycheck", status="pending", conclusion=None),
                    wf_("image", status="completed", conclusion="action_required")):
            code, puts, out = self.run_merge(wfs=self.WF_GREEN + [bad])
            self.assertEqual((code, puts), (0, []), bad)
            self.assertIn(bad["name"], out)
        # the newest run of a workflow counts: a green rerun clears an older red run, a red rerun holds
        self.assertEqual(len(self.run_merge(wfs=self.WF_GREEN + [wf_("ci", id=0, conclusion="failure")])[1]), 1)
        self.assertEqual(self.run_merge(wfs=self.WF_GREEN + [wf_("ci", id=2, conclusion="failure")])[:2], (0, []))
        # premerge is left out by path, not name: a workflow named premerge elsewhere still counts
        self.assertEqual(self.run_merge(wfs=self.WF_GREEN + [wf_("premerge", id=3, status="queued", conclusion=None,
                                                                  path=".github/workflows/other.yml")])[:2], (0, []))

    def test_only_this_runs_own_jobs_are_left_out(self):
        # #3123 delta review 3: another workflow's red job named `merge` or `premerge-gate` holds the merge.
        for bad in (run_("merge", conclusion="failure"), run_("premerge-gate", status="in_progress", conclusion=None, suite=7)):
            self.assertEqual(self.run_merge(runs=self.GREEN + [bad])[:2], (0, []), bad)

    def test_all_green_merges_pinned_to_the_head(self):
        self.assertEqual(self.run_merge()[:2],
                         (0, ["api -X PUT repos/o/r/pulls/7/merge -f merge_method=merge -f sha=" + self.SHA]))

    def test_any_check_not_green_never_merges(self):
        # #3123 review: main requires only some checks, so a running or red unrequired one must hold the merge too.
        for bad in (run_("count", status="in_progress", conclusion=None), run_("count", conclusion="failure"),
                    run_("vulncheck", conclusion="cancelled"), run_("lane-gate", status="queued", conclusion=None)):
            code, puts, out = self.run_merge(runs=self.GREEN + [bad])
            self.assertEqual((code, puts), (0, []), bad)
            self.assertIn(bad["name"], out)
        for st in ("pending", "failure", "error"):
            self.assertEqual(self.run_merge(statuses=(("premerge", "success"), ("ext", st)))[:2], (0, []), st)

    def test_a_failure_the_merge_base_had_is_excused(self):
        # PREMERGE-inherited (#3532): #3503's head branched from a main commit whose vulncheck was red, so its
        # own vulncheck stayed red after main's fix; the same failure on the merge base is not the PR's.
        red_wf, red_run = wf_("vulncheck", id=5, conclusion="failure"), run_("vulncheck", conclusion="failure")
        base_wf, failed_job = wf_("vulncheck", id=2, conclusion="failure", suite=8), {"name": "vulncheck", "conclusion": "failure"}
        jobs = {"2": [{"name": "scope / scope", "conclusion": "success"}, failed_job]}
        merged = (0, ["api -X PUT repos/o/r/pulls/7/merge -f merge_method=merge -f sha=" + self.SHA])
        self.assertEqual(self.run_merge(runs=self.GREEN + [red_run], wfs=self.WF_GREEN + [red_wf],
                                        base_wfs=[base_wf], base_jobs=jobs)[:2], merged)
        self.assertEqual(self.run_merge(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs=jobs)[:2], merged)
        sched = wf_("vulncheck", id=2, conclusion="failure", suite=8, event="schedule")
        self.assertEqual(self.run_merge(wfs=self.WF_GREEN + [red_wf], base_wfs=[sched])[:2], merged)
        held = [
            # the base's job passed, or the base never ran it (a pull_request_target workflow), or a later run passed
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs={"2": [{"name": "vulncheck", "conclusion": "success"}]}),
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf]),
            dict(runs=self.GREEN + [red_run], base_jobs=jobs),
            dict(wfs=self.WF_GREEN + [red_wf], base_wfs=[base_wf, wf_("vulncheck", id=3, suite=9)]),
            # a different job failed on the base, or the base's job is still going or was cancelled
            dict(runs=self.GREEN + [run_("broker-race", conclusion="failure")], base_wfs=[base_wf], base_jobs=jobs),
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs={"2": [{"name": "vulncheck", "conclusion": None}]}),
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs={"2": [{"name": "vulncheck", "conclusion": "cancelled"}]}),
            # #3533 Security review: a cancelled base run, a rerun, or a run main did not push or schedule excuses nothing
            dict(wfs=self.WF_GREEN + [red_wf], base_wfs=[wf_("vulncheck", id=2, conclusion="cancelled")]),
            dict(wfs=self.WF_GREEN + [red_wf], base_wfs=[wf_("vulncheck", id=2, conclusion="failure", attempt=2)]),
            dict(wfs=self.WF_GREEN + [red_wf], base_wfs=[wf_("vulncheck", id=2, conclusion="failure", event="workflow_dispatch")]),
            dict(wfs=self.WF_GREEN + [red_wf], base_wfs=[wf_("vulncheck", id=2, conclusion="failure", branch="side")]),
            # #3533 delta reviews: a check run any branch workflow posts on the base sha, even one GitHub files in
            # main's failed run's suite, is not one of that run's jobs and excuses nothing
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs={"2": []},
                 base_runs=[run_("vulncheck", id=9, conclusion="failure", suite=8)]),
            dict(runs=self.GREEN + [run_("broker-race", conclusion="failure")], base_wfs=[base_wf], base_jobs=jobs,
                 base_runs=[run_("broker-race", id=9, conclusion="failure", suite=8)]),
            dict(runs=self.GREEN + [red_run], base_runs=[run_("vulncheck", id=9, conclusion="failure", suite=777)]),
            # only a head failure is excused: an unfinished or cancelled head run never is, nor a status
            dict(runs=self.GREEN + [run_("vulncheck", status="queued", conclusion=None)], base_wfs=[base_wf], base_jobs=jobs),
            dict(runs=self.GREEN + [run_("vulncheck", conclusion="cancelled")], base_wfs=[base_wf], base_jobs=jobs),
            dict(wfs=self.WF_GREEN + [wf_("vulncheck", id=5, status="in_progress", conclusion=None)], base_wfs=[base_wf]),
            dict(statuses=(("premerge", "success"), ("vulncheck", "failure")), base_wfs=[base_wf], base_jobs=jobs),
            # an unreadable base excuses nothing
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs=jobs, read="base"),
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs=jobs, read="bjobs"),
            dict(wfs=self.WF_GREEN + [red_wf], base_wfs=[base_wf], read="bwfs"),
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs=jobs, read="bwfs"),
            dict(runs=self.GREEN + [red_run], base_wfs=[base_wf], base_jobs=jobs, base="c" * 39),
            dict(runs=self.GREEN + [red_run], base_wfs=[wf_("vulncheck", id="2/x", conclusion="failure")], base_jobs=jobs),
        ]
        for kw in held:
            self.assertEqual(self.run_merge(**kw)[:2], (0, []), kw)

    def test_refusals_and_unreadable_checks_warn_without_red(self):
        # A comment-time run attaches to main's head, so a refusal must not read as main breaking (#1946).
        code, puts, out = self.run_merge(merge="refused")
        self.assertEqual((code, len(puts)), (0, 1))
        self.assertIn("merge refused", out)
        # A failed read is never an empty list of checks.
        self.assertEqual(self.run_merge(read="fail")[:2], (0, []))
        self.assertEqual(self.run_merge(read="fail", runs=[])[:2], (0, []))
        self.assertEqual(self.run_merge(read="stat", statuses=())[:2], (0, []))
        self.assertEqual(self.run_merge(read="wfs", wfs=())[:2], (0, []))
        self.assertEqual(self.run_merge(read="suite")[:2], (0, []))

    def test_only_this_prs_runs_and_their_check_runs_hold(self):
        # PREMERGE-merge-bind (#5384): a fork PR opened on this head commit, or a PR from another branch, writes runs and
        # check runs on the same sha; their red or pending state must not stall this PR's merge.
        merged = (0, ["api -X PUT repos/o/r/pulls/7/merge -f merge_method=merge -f sha=" + self.SHA])
        foreign = [wf_("lane-gate", id=5, conclusion="failure", repo="f/r", event="pull_request_target", suite=55),
                   wf_("ci", id=6, status="in_progress", conclusion=None, branch="other", event="pull_request", suite=56),
                   wf_("vulncheck", id=7, status="queued", conclusion=None, repo=None, suite=57)]
        runs = [run_("lane-gate", conclusion="failure", suite=55), run_("checks", status="in_progress", conclusion=None, suite=56),
                run_("vulncheck", status="queued", conclusion=None, suite=57)]
        self.assertEqual(self.run_merge(wfs=self.WF_GREEN + foreign, runs=self.GREEN + runs)[:2], merged)
        held = [
            # this PR's own red or pending run, and a check run in its suite
            dict(wfs=self.WF_GREEN + foreign + [wf_("lane-gate", id=8, conclusion="failure", suite=58)]),
            dict(wfs=self.WF_GREEN + foreign, runs=self.GREEN + [run_("lane-gate", conclusion="failure", suite=1)]),
            # a check run no run on the head claims (another App's) still holds
            dict(wfs=self.WF_GREEN + foreign, runs=self.GREEN + [run_("ext", status="queued", conclusion=None, suite=777)]),
            # a foreign run newer than this PR's red run of the same workflow does not mask it
            dict(wfs=self.WF_GREEN + [wf_("vulncheck", id=8, conclusion="failure"), wf_("vulncheck", id=9, repo="f/r")]),
            # a fork PR's own red run holds it
            dict(wfs=self.WF_GREEN + [wf_("image", id=8, conclusion="failure", repo="f/r", branch="x")], head_repo="f/r",
                 head_ref="x", runs=self.GREEN),
            # without the PR's head repository and branch nothing binds, so nothing merges
            dict(head_repo=""), dict(head_ref=""),
        ]
        for kw in held:
            self.assertEqual(self.run_merge(**kw)[:2], (0, []), kw)
        # a fork PR's own runs bind by the fork's repository and branch
        self.assertEqual(self.run_merge(wfs=[wf_("ci", repo="f/r", branch="x")], head_repo="f/r", head_ref="x")[:2], merged)

    def test_no_token_or_bad_head_never_merges(self):
        self.assertEqual(self.run_merge(token="")[:2], (0, []))
        code, puts, _ = self.run_merge(sha="b" * 39)
        self.assertEqual((code != 0, puts), (True, []))


if __name__ == "__main__":
    unittest.main()
