#!/bin/bash
# Prints the `--runs` document `tools/premerge.py --check` reads (PREMERGE-runs-local, #5386): the PR head's
# Actions runs and the merge base's main push and scheduled runs, each failed run with its jobs (the head's latest
# attempt, the base's first), plus the PR's number, head repository and branch, which bind each head run to this PR
# (another PR can share the commit). premerge.yml runs main's copy of this script, so a local check reads exactly
# what the gate reads. Needs gh (signed in) and jq.
#
#   tools/premerge_runs.sh <owner/repo> <pr.json> <merge-base sha> > runs.json
#
# <pr.json> is `gh api repos/<owner/repo>/pulls/<N>` as read when the head was taken. A local check:
#
#   gh api repos/ghbmrk/agentOS/pulls/N > pr.json && head=$(jq -r .head.sha pr.json)
#   git fetch origin main "pull/N/head" && onto=$(git merge-base origin/main "$head")
#   gh api --paginate repos/ghbmrk/agentOS/issues/N/comments \
#     --jq '.[] | {author_association, created_at, updated_at, body}' | jq -s . > comments.json
#   tools/premerge_runs.sh ghbmrk/agentOS pr.json "$onto" > runs.json
#   python3 tools/premerge.py --check comments.json N --runs runs.json --base origin/main "$head"
#
# Any failed read exits non-zero with nothing usable on stdout, never a partial document.
set -u -o pipefail
[ $# -eq 3 ] || { echo "usage: premerge_runs.sh <owner/repo> <pr.json> <merge-base sha>" >&2; exit 2; }
repo=$1 pr=$2 onto=$3
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "not a repository: $repo" >&2; exit 2; }
[[ "$onto" =~ ^[0-9a-f]{40}$ ]] || { echo "not a merge-base sha: $onto" >&2; exit 2; }
head=$(jq -r .head.sha "$pr") || exit 1
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "pr.json names no head sha" >&2; exit 1; }
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

runs() { # $1: the runs query, $2: the jobs route under a failed run
  gh api --paginate "repos/$repo/actions/runs?$1&per_page=100" --jq '.workflow_runs[]' | jq -s . > "$tmp/r.json" || return 1
  jq -r '.[] | select(.conclusion == "failure") | .id' "$tmp/r.json" | while read -r id; do
    gh api --paginate "repos/$repo/actions/runs/$id/$2?per_page=100" --jq '.jobs[]' || exit 1
  done | jq -s --slurpfile r "$tmp/r.json" '. as $j | $r[0] | map(.id as $id | . + {jobs: [$j[] | select(.run_id == $id)]})'
}
runs "head_sha=$head" jobs > "$tmp/head.json" || exit 1
runs "head_sha=$onto&event=push" attempts/1/jobs > "$tmp/push.json" || exit 1
runs "head_sha=$onto&event=schedule" attempts/1/jobs > "$tmp/schedule.json" || exit 1
jq -n --slurpfile h "$tmp/head.json" --slurpfile p "$tmp/push.json" --slurpfile s "$tmp/schedule.json" \
  --slurpfile pr "$pr" --arg repo "$repo" \
  '{repo: $repo, pr: {number: $pr[0].number, repo: $pr[0].head.repo.full_name, branch: $pr[0].head.ref},
    head: $h[0], base: ($p[0] + $s[0])}' > "$tmp/runs.json" || exit 1
cat "$tmp/runs.json"
