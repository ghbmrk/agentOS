#!/usr/bin/env python3
"""One-time migration: one GitHub issue per live BOARD.md row (SIM-repo-1; run by SIM-repo-2).

Dry run by default: prints the issues and labels it would create and checks that they render
back to BOARD.md's live rows (tools/board.py). With --apply --repo owner/name (GITHUB_TOKEN)
it first creates the labels in board.LABELS that the repository lacks, then one issue per live
row in BOARD order, skipping any ID that already has a work-item issue, so a rerun after a
partial failure resumes where it stopped. It waits out GitHub's rate limits (board.call) and
pauses a second between issues, as GitHub asks of content-creating calls. Last it reads the
issues back and checks that they render BOARD.md's live rows (the SIM-repo-2 acceptance).

Each new issue notifies everyone watching the repository once: about 270 notifications to the
owner. Tell them before running --apply, so the burst is expected.

LATER.md's rows (archived as docs/LATER-HISTORY.md) reach the issues as labels: an ID in its Release table gets class:release and
one in its Later table class:later, unless the BOARD row already names a class (SIM-repo-2b;
LATER.md is then archived).

After it passes, add board.GENERATED below BOARD.md's title and move the merged and dropped
rows to the history file (SIM-repo-2b). Delete this script once the migration has run.
"""
import argparse
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import board  # noqa: E402


def later_classes(text):
    """{ID: class:release or class:later} from LATER.md's Release and Later tables."""
    out, cls = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            cls = "class:release" if line.startswith("## Release") else "class:later" if line.startswith("## Later") else None
        elif cls and line.startswith("| ") and not line.startswith("| ID |"):
            out.setdefault(board._cells(line)[0], cls)
    return out


def with_later(planned, classes):
    """planned, each issue labelled with its LATER.md class when it has none."""
    out = []
    for i in planned:
        cls = classes.get(board.issue_id(i))
        has = any(x.startswith("class:") for x in i["labels"])
        out.append(dict(i, labels=i["labels"] + [cls]) if cls and not has else i)
    return out


def _later():
    path = board.ROOT / "docs/LATER-HISTORY.md"
    return path.read_text() if path.is_file() else ""


def main(argv=None, read=lambda: (board.ROOT / "BOARD.md").read_text(), api=None, pause=time.sleep, later=_later):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--apply", action="store_true", help="create the labels and issues (default: dry run)")
    ap.add_argument("--repo", help="owner/name, required with --apply")
    args = ap.parse_args(argv)
    if args.apply and not args.repo:
        print("board_migrate: --apply needs --repo owner/name", file=sys.stderr)
        return 2
    text = read()
    try:
        planned = with_later(board.plan(text), later_classes(later()))
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
        print(f"--apply sends each repository watcher {len(planned)} notifications, one per issue")
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
            if made:
                pause(1)
            api("POST", f"{repo}/issues", i)
            made += 1
    print(f"created {made} issues; {len(planned) - made} already existed")
    try:
        ok = board.render(text, board.work_items(lambda path: api("GET", path), args.repo)) == board.live(text)
    except ValueError as e:
        print(f"board_migrate: read back: {e}", file=sys.stderr)
        return 1
    if not ok:
        print(f"board_migrate: read back: the issues do not render BOARD.md's live rows; "
              f"diff tools/board.py render --repo {args.repo} against BOARD.md", file=sys.stderr)
        return 1
    print("read back: every live row has one issue and the issues render BOARD.md's live rows")
    return 0


if __name__ == "__main__":
    sys.exit(main())
