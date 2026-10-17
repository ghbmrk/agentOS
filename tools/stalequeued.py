#!/usr/bin/env python3
"""List state:queued work items whose package a merged PR already names (read-only).

A PR that never links its issue leaves the row queued after the work merged, so a dispatcher
that lists queued rows starts a build for finished work. A merged PR names a row's package
when its title carries the ID as a whole token (anywhere, not only as the prefix board.py
stale reads) or its body carries `package <ID>` (the `Record: PR #N · package <ID> · head <SHA>`
line). An open PR that names the ID too means more is owed, so the row is not listed.

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
    """How the PR names the package: 'title', 'body' or None."""
    if re.search(_token(row_id), pr.get("title") or ""):
        return "title"
    if re.search(rf"\bpackage {_token(row_id)}", pr.get("body") or ""):
        return "body"
    return None


def stale_queued(items, prs):
    """(issue, merged PR, how) for each queued row a merged PR names and no open PR names."""
    out = []
    for item in items:
        if "pull_request" in item:
            continue
        row = board.row_of(item)
        if row["state"] != "queued":
            continue
        hits = [(p, names(p, row["id"])) for p in prs]
        hits = [(p, how) for p, how in hits if how]
        if any(p["state"] == "open" for p, _ in hits):
            continue
        merged = [(p, how) for p, how in hits if p.get("merged_at")]
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
        found = stale_queued(items, fetch(f"/repos/{args.repo}/pulls?state=all"))
    except ValueError as e:
        print(f"stalequeued: {e}", file=sys.stderr)
        return 1
    for item, pr, how in found:
        print(f"{board.row_of(item)['id']} (#{item['number']}): merged PR #{pr['number']} ({how})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
