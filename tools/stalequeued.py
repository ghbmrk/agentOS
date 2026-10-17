#!/usr/bin/env python3
"""List state:queued work items whose package a merged PR already names (read-only).

A PR that never links its issue leaves the row queued after the work merged, so a dispatcher
that lists queued rows starts a build for finished work. A merged PR counts when it names the
package (its title starts with the ID, board.py stale's rule, or its body has the line
`Record: PR #N · package <ID> · head <SHA>`) and changed code, tests, the image or spikes: PRs
that only add a brief, a BOARD row, spec or docs name IDs they have not built. An open PR that
names the ID too means more is owed, so the row is not listed.

  stalequeued.py --repo o/r      print "<ID> (#issue): merged PR #N (title|body)" per row; exit 0
                                 whether or not any is found. GETs only: never relabels or comments.
"""
import argparse
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import board  # noqa: E402


def _token(row_id):
    return rf"(?<![A-Za-z0-9-]){re.escape(row_id)}(?![A-Za-z0-9-])"


def names(pr, row_id):
    """How the PR names the package: 'title', 'body' or None. A title names it only as its
    prefix (board.stale's rule): brief and BOARD-row PRs mention IDs they have not built. A body
    names it only in a `Record: PR #N · package <ID> · head <SHA>` line."""
    if re.match(_token(row_id), pr.get("title") or ""):
        return "title"
    if re.search(rf"^Record: PR #\d+ · package {_token(row_id)} · head ", pr.get("body") or "", re.M):
        return "body"
    return None


BUILD_DIRS = ("broker/", "guest/", "image/", "spikes/", "tests/", "tools/")


def builds(files):
    """True when any changed file is code, a test, the image or a spike."""
    return any(f.startswith(BUILD_DIRS) for f in files)


def stale_queued(items, prs, files=lambda pr: ["tools/x"]):
    """(issue, merged PR, how) for each queued row a merged PR names, with a build change
    (files(pr) lists its changed paths), and no open PR names."""
    out = []
    for item in items:
        if "pull_request" in item:
            continue
        row = board.readable_row(item)
        if row is None or row["state"] != "queued":
            continue
        hits = [(p, names(p, row["id"])) for p in prs]
        hits = [(p, how) for p, how in hits if how]
        if any(p["state"] == "open" for p, _ in hits):
            continue
        merged = [(p, how) for p, how in hits if p.get("merged_at") and builds(files(p))]
        if merged:
            pr, how = max(merged, key=lambda h: h[0]["merged_at"])
            out.append((item, pr, how))
    return out


def main(argv=None, fetch=board.github):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", required=True, help="owner/name")
    args = ap.parse_args(argv)
    try:
        items = board.work_items(fetch, args.repo)
        found = stale_queued(items, fetch(f"/repos/{args.repo}/pulls?state=all"),
                             lambda pr: [f["filename"] for f in fetch(f"/repos/{args.repo}/pulls/{pr['number']}/files")])
    except ValueError as e:
        print(f"stalequeued: {e}", file=sys.stderr)
        return 1
    for item, pr, how in found:
        print(f"{board.row_of(item)['id']} (#{item['number']}): merged PR #{pr['number']} ({how})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
