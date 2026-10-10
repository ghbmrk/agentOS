#!/usr/bin/env python3
"""Work items as GitHub issues; BOARD.md generated from them (SIM-repo-1, briefs/SIM.md).

One issue per live BOARD row. The issue is the record; its labels are the queryable index:
  work-item        marks the issue as a BOARD row
  state:<state>    the row's state, one of metrics.STATES; the only label rendering reads
  tier:A|B|C       risk tier, when the row names one ("tier A", or "(B; ..." in its state)
  class:<class>    blocker, release or later (OPERATING §2); release rows as doclint finds them
  lane:<team>      the docs/LANES.md team that builds it; primary unless the row names another
  gate:mark        merge waits on Mark beyond the reviews ("Mark approves", "owner to confirm")
The title is "<ID>: <package text>" and is the row's key. The body carries the row itself in a
fenced `board-row` JSON block: its section heading, its middle cells and the text after the
state word. Rows render in issue-number order within their section, so the migration creates
issues in BOARD order and a new issue lands at the end of its section.

BOARD.md's headings, prose and table headers stay in the file as the skeleton; rendering
replaces its rows with the live issues. merged and dropped rows are terminal and leave the
board (SIM-repo-2 archives them). Each section holds at most one table.

  board.py check                 the planned issues of BOARD.md render back to its live rows
  board.py render [--repo o/r]   print BOARD.md from the planned issues, or from GitHub's
                                 issues and PRs (GITHUB_TOKEN); PR disagreements go to stderr
"""
import argparse
import difflib
import json
import os
import pathlib
import re
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from doclint import RELEASE_CLASS, RELEASE_STATE  # noqa: E402
from metrics import OPEN_STATES, STATES  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
MARKER = "work-item"
ID = r"[A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*(?: [a-z][A-Za-z0-9]*)*"  # "P2-2w c3 r1" too
BLOCK = re.compile(r"```board-row\n(.*?)\n```", re.S)
TIER = re.compile(r"\btier ([ABC])\b|\(([ABC])[;)]")
GATE = re.compile(r"\bMark approves\b|\bowner to confirm\b|\bwithout Mark\b|\bMark's approval\b")


def _lanes():
    """Team names from docs/LANES.md's Lanes table (first word of the Team cell)."""
    path, teams = ROOT / "docs" / "LANES.md", []
    if path.is_file():
        for line in path.read_text().splitlines():
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if line.startswith("|") and len(cells) == 3 and cells[1] not in ("Team", "---"):
                teams.append(cells[1].split()[0])
    return tuple(teams) or ("primary",)


LANES = _lanes()
LANE = re.compile(r"\blane (" + "|".join(map(re.escape, LANES)) + r")\b")


def state_label(state):
    return f"state:{state}"


LABELS = {
    MARKER: "A BOARD.md row (tools/board.py)",
    **{state_label(s): f"BOARD state: {s}" for s in STATES},
    **{f"tier:{t}": f"Risk tier {t} (OPERATING §3)" for t in "ABC"},
    **{f"class:{c}": f"Finding class: {c} (OPERATING §2)" for c in ("blocker", "release", "later")},
    **{f"lane:{lane}": f"Built in the {lane} lane (docs/LANES.md)" for lane in LANES},
    "gate:mark": "Merge waits on Mark beyond the reviews",
}


def _cells(line):
    """A table line's cells; an escaped pipe (\\|) stays inside its cell, as GitHub renders it."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip()[1:-1])]


def _table_lines(text):
    """Yield (line number, kind, section) for each line; kind is text, header, rule or row."""
    section, in_table, tables = "", False, {}
    for n, line in enumerate(text.splitlines()):
        if line.startswith("## "):
            section = line[3:]
        if not line.startswith("|"):
            in_table = False
            yield n, "text", section
        elif not in_table:
            in_table = True
            if "| State |" not in line:
                raise ValueError(f"BOARD.md:{n + 1}: a table without a State column")
            tables[section] = tables.get(section, 0) + 1
            if tables[section] > 1:
                raise ValueError(f"BOARD.md:{n + 1}: section {section!r} has a second table")
            yield n, "header", section
        elif set(line) <= set("|-: "):
            yield n, "rule", section
        else:
            yield n, "row", section


def rows(text):
    """Every BOARD row as {id, section, cells, state, rest}; cells are the middle columns."""
    lines, out = text.splitlines(), []
    for n, kind, section in _table_lines(text):
        if kind != "row":
            continue
        cells = _cells(lines[n])
        state = next((s for s in STATES if cells[-1].startswith(s)), None)
        if state is None:
            raise ValueError(f"BOARD.md:{n + 1}: {cells[0]}: state {cells[-1]!r} is not one of {', '.join(STATES)}")
        out.append({"id": cells[0], "section": section, "cells": cells[1:-1],
                    "state": state, "rest": cells[-1][len(state):]})
    return out


def _plain(markdown):
    return re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", markdown).replace("`", "")


def issue(row):
    """The planned issue for one row: title, labels and body (no number until created)."""
    if not re.fullmatch(ID, row["id"]):
        raise ValueError(f"BOARD.md: row ID {row['id']!r} is not an ID")
    text, state_cell = " ".join(row["cells"]), row["state"] + row["rest"]
    labels = [MARKER, state_label(row["state"])]
    tier = TIER.search(f"{text} {state_cell}")
    if tier:
        labels.append(f"tier:{tier.group(1) or tier.group(2)}")
    if RELEASE_STATE.search(state_cell) or RELEASE_CLASS.search(text):
        labels.append("class:release")
    lane = LANE.search(f"{text} {state_cell}")
    labels.append(f"lane:{lane.group(1) if lane else 'primary'}")
    if GATE.search(f"{text} {state_cell}"):
        labels.append("gate:mark")
    block = json.dumps({"section": row["section"], "cells": row["cells"], "rest": row["rest"]},
                       ensure_ascii=False, indent=1)
    return {"title": f"{row['id']}: {_plain(row['cells'][0])}"[:256], "labels": labels,
            "body": f"{row['cells'][0]}\n\n```board-row\n{block}\n```\n"}


def plan(text):
    """The issues a migration creates: one per live row, in BOARD order."""
    return [issue(r) for r in rows(text) if r["state"] in OPEN_STATES]


def _names(labels):
    return [x if isinstance(x, str) else x["name"] for x in labels]


def issue_id(item):
    m = re.match(rf"({ID}): ", item["title"])
    if not m:
        raise ValueError(f"issue #{item.get('number')}: title {item['title']!r} does not start with '<ID>: '")
    return m.group(1)


def row_of(item):
    """The row an issue renders as; raises ValueError naming the issue if it is malformed."""
    where = f"issue #{item.get('number')}"
    states = [x[len("state:"):] for x in _names(item["labels"]) if x.startswith("state:")]
    if len(states) != 1 or states[0] not in STATES:
        raise ValueError(f"{where}: needs exactly one state label of {', '.join(STATES)}, has {states}")
    m = BLOCK.search(item.get("body") or "")
    if not m:
        raise ValueError(f"{where}: body has no board-row block")
    try:
        data = json.loads(m.group(1))
        section, cells, rest = data["section"], data["cells"], data["rest"]
    except (ValueError, KeyError) as e:
        raise ValueError(f"{where}: board-row block: {e}") from None
    return {"id": issue_id(item), "number": item["number"], "section": section,
            "cells": cells, "state": states[0], "rest": rest}


def render(skeleton, items):
    """BOARD.md: the skeleton's text with its rows replaced by the live rows of items."""
    lines = skeleton.splitlines()
    widths = {s: len(_cells(lines[n])) - 2 for n, kind, s in _table_lines(skeleton) if kind == "header"}
    by_section, seen = {}, set()
    for item in items:
        row = row_of(item)
        if row["id"] in seen:
            raise ValueError(f"issue #{row['number']}: a second issue for {row['id']}")
        seen.add(row["id"])
        if row["section"] not in widths:
            raise ValueError(f"issue #{row['number']}: no section {row['section']!r} in BOARD.md")
        if len(row["cells"]) != widths[row["section"]]:
            raise ValueError(f"issue #{row['number']}: {len(row['cells'])} middle cells, its table has {widths[row['section']]}")
        if row["state"] in OPEN_STATES:
            by_section.setdefault(row["section"], []).append(row)
    out = []
    for n, kind, section in _table_lines(skeleton):
        if kind == "row":
            continue
        out.append(lines[n])
        if kind == "rule":
            for row in sorted(by_section.get(section, []), key=lambda r: r["number"]):
                out.append("| " + " | ".join([row["id"], *row["cells"], row["state"] + row["rest"]]) + " |")
    return "\n".join(out) + ("\n" if skeleton.endswith("\n") else "")


def live(text):
    """BOARD.md with its terminal rows removed, line for line: what rendering must give."""
    lines = text.splitlines()
    keep = [lines[n] for n, kind, _ in _table_lines(text)
            if kind != "row" or _cells(lines[n])[-1].startswith(OPEN_STATES)]
    return "\n".join(keep) + ("\n" if text.endswith("\n") else "")


def pr_notes(items, prs):
    """Where an issue's state label and the PRs naming its ID (title prefix) disagree."""
    notes = []
    for item in items:
        if "pull_request" in item:
            continue
        row = row_of(item)
        if row["state"] not in OPEN_STATES:
            continue
        mine = [p for p in prs if re.match(rf"{re.escape(row['id'])}(?![A-Za-z0-9-])", p["title"])]
        opened = [p for p in mine if p["state"] == "open"]
        merged = [p for p in mine if p.get("merged_at")]
        if row["state"] in ("queued", "building") and opened:
            notes.append(f"{row['id']}: state {row['state']} but PR #{opened[0]['number']} is open")
        elif row["state"] == "in review" and not opened:
            notes.append(f"{row['id']}: state in review but no open PR names it")
        elif merged and not opened:
            notes.append(f"{row['id']}: state {row['state']} but PR #{merged[0]['number']} merged")
    return notes


def github(path, method="GET", payload=None):
    """One GitHub REST call with GITHUB_TOKEN; GET follows pagination and returns the full list."""
    token = os.environ.get("GITHUB_TOKEN") or sys.exit("GITHUB_TOKEN is not set")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if method != "GET":
        req = urllib.request.Request("https://api.github.com" + path, method=method, headers=headers,
                                     data=json.dumps(payload).encode())
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    out, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        req = urllib.request.Request(f"https://api.github.com{path}{sep}per_page=100&page={page}", headers=headers)
        with urllib.request.urlopen(req) as resp:
            batch = json.load(resp)
        out += batch
        if len(batch) < 100:
            return out
        page += 1


def main(argv=None, read=lambda: (ROOT / "BOARD.md").read_text(), fetch=github):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("command", choices=("check", "render"))
    ap.add_argument("--repo", help="owner/name: render from its issues and PRs instead of the plan")
    args = ap.parse_args(argv)
    text = read()
    try:
        if args.command == "render" and args.repo:
            items = [i for i in fetch(f"/repos/{args.repo}/issues?state=open&labels={MARKER}")
                     if "pull_request" not in i]
            for note in pr_notes(items, fetch(f"/repos/{args.repo}/pulls?state=all")):
                print(f"board: {note}", file=sys.stderr)
            sys.stdout.write(render(text, items))
            return 0
        items = [dict(i, number=n) for n, i in enumerate(plan(text), start=1)]
        generated = render(text, items)
    except ValueError as e:
        print(f"board: {e}", file=sys.stderr)
        return 1
    if args.command == "render":
        sys.stdout.write(generated)
        return 0
    expected = live(text)
    if generated != expected:
        diff = difflib.unified_diff(expected.splitlines(), generated.splitlines(), "live rows", "generated", lineterm="")
        print("board: BOARD.md does not round-trip through its planned issues:", *diff, sep="\n", file=sys.stderr)
        return 1
    print(f"board: {len(items)} live rows round-trip through their planned issues")
    return 0


if __name__ == "__main__":
    sys.exit(main())
