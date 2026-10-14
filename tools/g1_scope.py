#!/usr/bin/env python3
"""G1 freeze (G1-freeze, #1687): fail a new PR that touches paths outside the G1 list.

Until G1-e2e (#1688) passes in QEMU, work goes to the G1 path (A1, SPEC.md:653, D-104):
controller boot, phone control and one model-backed task. `tools/g1_scope.txt` lists the
paths a PR may touch; a PR whose diff leaves the list fails, naming the paths outside it.

A PR passes when any of these holds, checked in order:
  1. the freeze is off (`freeze off` in g1_scope.txt: the single switch, flipped by a PR
     that cites the passing #1688 run);
  2. it is exempt in `tools/g1_scope_exempt.txt`: its number is a `pr` line (open when
     the freeze merged), or it builds an `issue` line's row (in state:building when the
     freeze merged), recognised by a `pkg/<issue>-` head branch or a title starting with
     the row's ID;
  3. its diff is empty, or every path is a record document (tools/ci_scope.is_record);
  4. every path is inside the list.
A G1 fix touches only listed paths, so it passes. A G1 fix that needs a frozen path first
amends the list in its own reviewed PR: the check reads the base copy of the list.

The g1-freeze workflow runs the BASE commit's copy of this file and its two lists, so a
PR cannot widen the list, flip the switch or exempt itself in the same change. An
unreadable list fails closed. Standard library only, so the base copy runs on its own.

Usage:
  tools/g1_scope.py --git BASE HEAD [--pr N] [--pr-branch B] [--pr-title T]
  tools/g1_scope.py PATH...           check the listed paths (no exemptions apply)
  tools/g1_scope.py --snapshot        rewrite g1_scope_exempt.txt from GitHub (merge prep)
Exit 0 on pass, 1 on a path outside the list, 2 on an unreadable list or diff.
"""
import argparse
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
LIST = HERE / "g1_scope.txt"
EXEMPT = HERE / "g1_scope_exempt.txt"
REPO = "ghbmrk/agentos"


class ListError(Exception):
    pass


def _ci_scope():
    # `python3 -I` leaves the script's directory off sys.path, so load the sibling
    # module by file path.
    spec = importlib.util.spec_from_file_location("ci_scope", HERE / "ci_scope.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _clean(path):
    parts = path.split("/")
    p = path[:-1] if path.endswith("/") else path
    if not p or path.startswith("/") or any(x in ("", ".", "..") for x in p.split("/")):
        raise ListError(f"bad path {path!r}")
    return path


def parse_list(text):
    """Return (freeze_on, allow, frozen_imports). Raises ListError on any doubt."""
    freeze, allow, frozen = None, [], []
    for n, line in enumerate(text.splitlines(), 1):
        w = line.split("#", 1)[0].split()
        if not w:
            continue
        try:
            if w[0] == "freeze" and len(w) == 2 and w[1] in ("on", "off"):
                if freeze is not None:
                    raise ListError("second freeze line")
                freeze = w[1] == "on"
            elif w[0] == "allow" and len(w) == 2:
                allow.append(_clean(w[1]))
            elif w[0] == "frozen-import" and len(w) == 2 and w[1].endswith("/"):
                frozen.append(_clean(w[1]))
            else:
                raise ListError(f"unreadable line {line.strip()!r}")
        except ListError as e:
            raise ListError(f"g1_scope.txt:{n}: {e}") from None
    if freeze is None:
        raise ListError("g1_scope.txt: no freeze line")
    for f in frozen:
        if any(covers(a, f) for a in allow):
            raise ListError(f"g1_scope.txt: {f} is both allowed and frozen")
    return freeze, allow, frozen


def parse_exempt(text):
    """Return (pr numbers, {issue number: row ID})."""
    prs, issues = set(), {}
    for n, line in enumerate(text.splitlines(), 1):
        w = line.split("#", 1)[0].split()
        if not w:
            continue
        if w[0] == "pr" and len(w) == 2 and w[1].isdigit():
            prs.add(int(w[1]))
        elif w[0] == "issue" and len(w) == 3 and w[1].isdigit() and re.fullmatch(r"[A-Za-z0-9][\w.-]*", w[2]):
            issues[int(w[1])] = w[2]
        else:
            raise ListError(f"g1_scope_exempt.txt:{n}: unreadable line {line.strip()!r}")
    return prs, issues


def covers(entry, path):
    """A trailing "/" makes an entry a directory prefix; otherwise it is one file."""
    return path.startswith(entry) if entry.endswith("/") else path == entry


def exemption(pr, branch, title, prs, issues):
    """Return why a PR is exempt, or None."""
    if pr is not None and pr in prs:
        return f"PR #{pr} was open when the freeze merged"
    branch, title = branch or "", (title or "").lstrip()
    for num, rid in sorted(issues.items()):
        if branch.startswith(f"pkg/{num}-"):
            return f"branch {branch} builds #{num} ({rid}), started before the freeze"
        if title.startswith(rid) and title[len(rid):len(rid) + 1] in (":", " "):
            return f"title builds {rid} (#{num}), started before the freeze"
    return None


def check(paths, list_text, exempt_text="", pr=None, branch="", title=""):
    """Return (ok, message lines)."""
    freeze, allow, _ = parse_list(list_text)
    if not freeze:
        return True, ["g1 freeze: off (g1_scope.txt)"]
    why = exemption(pr, branch, title, *parse_exempt(exempt_text))
    if why:
        return True, [f"g1 freeze: exempt: {why}"]
    paths = [p for p in paths if p]
    is_record = _ci_scope().is_record
    if all(is_record(p) for p in paths):
        return True, ["g1 freeze: records only" if paths else "g1 freeze: empty change"]
    outside = []
    for p in paths:
        bad = p.startswith("/") or any(x in ("", ".", "..") for x in p.split("/"))
        if bad or not (is_record(p) or any(covers(a, p) for a in allow)):
            outside.append(p)
    if not outside:
        return True, ["g1 freeze: every path is on the G1 list"]
    return False, ["g1 freeze: these paths are outside the G1 list (tools/g1_scope.txt):"] + [
        f"  {p}" for p in sorted(outside)
    ] + [
        "Until G1-e2e (#1688) passes in QEMU, PRs touch only the G1 path (#1687). If this is",
        "a G1 fix, amend tools/g1_scope.txt in its own PR first; otherwise park the row.",
    ]


def changed_paths(base, head):
    # --no-renames lists a moved file under its old path too; -z keeps names unquoted.
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    return out.decode("utf-8", "surrogateescape").split("\0")


def gh_pages(endpoint, run=subprocess.run):
    """Every item of a REST list endpoint, one page at a time (no --paginate, no GraphQL)."""
    items, page = [], 1
    while True:
        sep = "&" if "?" in endpoint else "?"
        out = run(["gh", "api", f"{endpoint}{sep}per_page=100&page={page}"],
                  check=True, capture_output=True, text=True).stdout
        batch = json.loads(out)
        items += batch
        if len(batch) < 100:
            return items
        page += 1


def snapshot(fetch):
    """Render g1_scope_exempt.txt from fetch(endpoint) -> list of items."""
    prs = sorted(p["number"] for p in fetch(f"repos/{REPO}/pulls?state=open"))
    rows = []
    for i in fetch(f"repos/{REPO}/issues?state=open&labels=state:building"):
        if "pull_request" in i:
            continue
        rid = i["title"].split(":", 1)[0].strip()
        if ":" in i["title"] and re.fullmatch(r"[A-Za-z0-9][\w.-]*", rid):
            rows.append((i["number"], rid))
    lines = [
        "# G1-freeze exemptions (#1687): written by `tools/g1_scope.py --snapshot` at merge prep.",
        "# `pr N`: open when the freeze merged. `issue N ID`: in state:building when the freeze",
        "# merged; its PR is recognised by a pkg/N- branch or a title starting with ID.",
        "# Hand edits are reviewed like the list; the check reads the base copy.",
    ] + [f"pr {n}" for n in prs] + [f"issue {n} {rid}" for n, rid in sorted(rows)]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--git", nargs=2, metavar=("BASE", "HEAD"))
    ap.add_argument("--pr", type=int)
    ap.add_argument("--pr-branch", default="")
    ap.add_argument("--pr-title", default="")
    ap.add_argument("--snapshot", action="store_true")
    a = ap.parse_args(argv)
    if a.snapshot:
        EXEMPT.write_text(snapshot(gh_pages))
        print(f"wrote {EXEMPT.relative_to(HERE.parent)}")
        return 0
    try:
        list_text = LIST.read_text()
        exempt_text = EXEMPT.read_text() if a.git else ""
        paths = changed_paths(*a.git) if a.git else a.paths
        ok, msg = check(paths, list_text, exempt_text, a.pr, a.pr_branch, a.pr_title)
    except (OSError, subprocess.CalledProcessError, ListError) as e:
        print(f"g1 freeze: cannot decide ({e}); failing closed", file=sys.stderr)
        return 2
    print("\n".join(msg), file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
