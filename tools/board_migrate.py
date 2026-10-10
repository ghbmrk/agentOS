#!/usr/bin/env python3
"""One-time migration: one GitHub issue per live BOARD.md row (SIM-repo-1; run by SIM-repo-2).

Dry run by default: prints the issues and labels it would create and checks that they render
back to BOARD.md's live rows (tools/board.py). With --apply --repo owner/name (GITHUB_TOKEN)
it first creates the labels in board.LABELS that the repository lacks, then one issue per live
row in BOARD order, skipping any ID that already has a work-item issue, so a rerun after a
partial failure resumes where it stopped. Delete this script once the migration has run.
"""
import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import board  # noqa: E402


def main(argv=None, read=lambda: (board.ROOT / "BOARD.md").read_text(), api=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true", help="create the labels and issues (default: dry run)")
    ap.add_argument("--repo", help="owner/name, required with --apply")
    args = ap.parse_args(argv)
    if args.apply and not args.repo:
        print("board_migrate: --apply needs --repo owner/name", file=sys.stderr)
        return 2
    text = read()
    try:
        planned = board.plan(text)
        ok = board.render(text, [dict(i, number=n) for n, i in enumerate(planned, 1)]) == board.live(text)
    except ValueError as e:
        print(f"board_migrate: {e}", file=sys.stderr)
        return 1
    if not ok:
        print("board_migrate: round trip: FAILED; run tools/board.py check for the diff", file=sys.stderr)
        return 1
    if not args.apply:
        for i in planned:
            print(f"{', '.join(i['labels']):60}  {i['title'][:100]}")
        print(f"dry run: {len(planned)} issues, {len(board.LABELS)} labels; round trip: ok")
        return 0
    api = api or (lambda method, path, payload=None: board.github(path, method, payload))
    repo = f"/repos/{args.repo}"
    have = {x["name"] for x in api("GET", f"{repo}/labels")}
    for name, description in board.LABELS.items():
        if name not in have:
            api("POST", f"{repo}/labels", {"name": name, "description": description, "color": "ededed"})
    existing = {board.issue_id(i) for i in api("GET", f"{repo}/issues?state=all&labels={board.MARKER}")
                if "pull_request" not in i}
    made = 0
    for i in planned:
        if board.issue_id(i) not in existing:
            api("POST", f"{repo}/issues", i)
            made += 1
    print(f"created {made} issues; {len(planned) - made} already existed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
