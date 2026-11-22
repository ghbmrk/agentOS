#!/usr/bin/env python3
"""Cancel queued or pending PR runs for a commit that is no open PR's head (CI-cancel-stale-sha, #6529).

A `pull_request` or `pull_request_target` run checks the PR head its event carried (the run's
`head_sha`). Once the PR moves on, that run's checks sit on a commit neither the ruleset nor
premerge reads for the new head, so the run only holds a runner slot. The per-PR concurrency
groups cancel a superseded first attempt; a rerun attempt has its own `run-<id>` group on purpose
(tools/ASSUMPTIONS.md CI-cancel-superseded), and a first attempt escapes when no newer run of its
workflow enters the group. This sweep cancels, by run id, each such run that is still queued or
pending. A run is cancelled only when all of these hold: it is planned on one read of the open PRs,
kept only if a second read gives each of its PRs the same head, and the run itself is read again
and checked against the second read just before its cancel:
  - its status is `queued` or `pending` (never `in_progress`, `waiting` or anything else);
  - its event is `pull_request` or `pull_request_target`;
  - its workflow is not premerge.yml: premerge reads the PR's head from the API when its job
    starts, so its run's `head_sha` (main's, or an old head) never names the head it gates;
  - it names at least one PR and every PR it names is open (a run naming no PR, or a closed or
    unknown one, is left alone);
  - its `head_sha` is a full sha and is not the head of any open PR, whatever its base.
Any read that fails or is malformed before the plan is final (an open PR whose head is not a full
sha, a listing past PAGES pages) cancels nothing and exits 1. A refused cancel only warns.

  cancel_stale.py --repo o/r [--dry-run]   print each run cancelled (or, with --dry-run, that
                                           would be) with its workflow, event, attempt, sha and PRs
"""
import argparse
import json
import re
import subprocess
import sys

SHA = re.compile(r"[0-9a-f]{40}")
WAITING = ("queued", "pending")
PR_EVENTS = ("pull_request", "pull_request_target")
GATE = ".github/workflows/premerge.yml"
PER_PAGE = 100
PAGES = 30


class Unreadable(Exception):
    pass


def gh(method, path):
    """Call the REST API through `gh api`; return the parsed body or raise Unreadable."""
    r = subprocess.run(["gh", "api", "-X", method, "-H", "Accept: application/vnd.github+json", path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise Unreadable(f"{method} {path}: {r.stderr.strip()[:200]}")
    try:
        return json.loads(r.stdout or "{}")
    except ValueError as e:
        raise Unreadable(f"{method} {path}: {e}") from None


def listing(api, path, key=None):
    """Return every item of a paged listing; a short page ends it, more than PAGES pages is Unreadable."""
    items = []
    for page in range(1, PAGES + 1):
        body = api("GET", f"{path}{'&' if '?' in path else '?'}per_page={PER_PAGE}&page={page}")
        got = body.get(key) if key and isinstance(body, dict) else body
        if not isinstance(got, list):
            raise Unreadable(f"{path}: page {page} is not a list")
        items += got
        if len(got) < PER_PAGE:
            return items
    raise Unreadable(f"{path}: more than {PAGES} pages")


def open_heads(api, repo):
    """Return {PR number: head sha} for every open PR; any head that is not a full sha is Unreadable."""
    heads = {}
    for pr in listing(api, f"repos/{repo}/pulls?state=open"):
        n = pr.get("number") if isinstance(pr, dict) else None
        head = pr.get("head") if isinstance(pr, dict) else None
        sha = head.get("sha") if isinstance(head, dict) else None
        if type(n) is not int or not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise Unreadable(f"open PR {n!r}: head {sha!r} unreadable")
        heads[n] = sha
    return heads


def prs_of(run):
    """Return the PR numbers a run names, or None when any entry is malformed."""
    prs = run.get("pull_requests")
    if not isinstance(prs, list):
        return None
    nums = [p.get("number") if isinstance(p, dict) else None for p in prs]
    return nums if all(type(n) is int for n in nums) else None


def stale(run, heads):
    """Return True only for a queued or pending PR run, not premerge's, whose PRs are all open and
    whose head_sha is no open PR's head (the module docstring's rules)."""
    if not isinstance(run, dict) or type(run.get("id")) is not int:
        return False
    path = run.get("path")
    if run.get("status") not in WAITING or run.get("event") not in PR_EVENTS or not isinstance(path, str):
        return False
    if path == GATE or path.startswith(GATE + "@"):
        return False
    sha, nums = run.get("head_sha"), prs_of(run)
    if not isinstance(sha, str) or not SHA.fullmatch(sha) or not nums:
        return False
    return all(n in heads for n in nums) and sha not in heads.values()


def sweep(api, repo, dry_run=False, out=print):
    """Cancel each stale run by id; return the ids cancelled (or, dry, that would be)."""
    first = open_heads(api, repo)
    runs = {}
    for status in WAITING:
        for run in listing(api, f"repos/{repo}/actions/runs?status={status}", "workflow_runs"):
            if isinstance(run, dict) and type(run.get("id")) is int:
                runs[run["id"]] = run
    plan = [runs[i] for i in sorted(runs) if stale(runs[i], first)]
    if not plan:
        return []
    second = open_heads(api, repo)
    plan = [r for r in plan if all(first[n] == second.get(n) for n in prs_of(r))]
    done = []
    for run in plan:
        rid = run["id"]
        try:
            now = api("GET", f"repos/{repo}/actions/runs/{rid}")
        except Unreadable as e:
            out(f"::warning::run {rid}: not re-read, left alone: {e}")
            continue
        if not isinstance(now, dict) or now.get("id") != rid or prs_of(now) != prs_of(run) or not stale(now, second):
            continue
        line = (f"run {rid} ({now.get('name')}, {now.get('event')}, attempt {now.get('run_attempt')}, "
                f"{now['head_sha'][:12]}, PR {', '.join('#%d' % n for n in prs_of(now))}): "
                f"no open PR's head")
        if dry_run:
            out("would cancel " + line)
            done.append(rid)
            continue
        try:
            api("POST", f"repos/{repo}/actions/runs/{rid}/cancel")
        except Unreadable as e:
            out(f"::warning::cancel refused for run {rid}: {e}")
            continue
        out("cancelled " + line)
        done.append(rid)
    return done


def main(argv=None, api=gh, out=print):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--repo", required=True)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_-][A-Za-z0-9_.-]*", a.repo):
        out(f"::error::not a repository: {a.repo!r}")
        return 1
    try:
        done = sweep(api, a.repo, a.dry_run, out)
    except Unreadable as e:
        out(f"::error::nothing cancelled: {e}")
        return 1
    out(f"{'Would cancel' if a.dry_run else 'Cancelled'} {len(done)} stale run(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
