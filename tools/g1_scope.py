#!/usr/bin/env python3
"""Gate freeze (G1-freeze #1687, D-128): fail a new PR that touches paths outside a gate's list.

Until a gate passes, work goes to that gate's path. Each gate in GATES has its own list; today
only G2 (`tools/g1_scope_g2.txt`: A4, A5, A9 and A14 on a VM; D-128). G1's list was deleted
once G1 passed (D-128; G1-retire): a passed gate's list only drew amends. A PR must pass every
gate's list; a list whose diff check fails names the paths outside it.

Against one list, a PR passes when any of these holds, checked in order:
  1. the freeze is off (`freeze off` in that list: the single switch, flipped by a PR that
     cites the gate's passing run);
  2. it was opened before the freeze began: its `created_at` (from the pull_request
     event, which the author cannot set) is earlier than the list's `since` time, so work
     in flight when the freeze merged finishes (Mark 2026-10-14: "let current PRs finish"),
     unless its timeline shows it reopened, force-pushed or retargeted at or after `since`
     (#1717): `created_at` belongs to the PR, not to its work, so a PR reused that way is
     checked like a new one. The timeline's times are GitHub's, which the author cannot set;
     a PR whose history cannot be read gets no time exemption (fail closed);
  3. its number is an `exempt-pr` line: an amend for in-flight work the time rule misses
     (a re-opened split or rebuild of a row that was already under way);
  4. its diff is empty, or every path is a record document (tools/ci_scope.is_record);
  5. every path is inside the list.
A gate fix touches only listed paths, so it passes. A fix that needs a frozen path first
amends the list in its own reviewed PR: the check reads the base copy of the list.

The g1-freeze workflow runs the BASE commit's copy of this file and its lists, so a PR
cannot widen a list, flip a switch, move `since` or exempt itself in the same change.
An unreadable list or time fails closed, as does a list holding any character other than
printable ASCII and "\n", so every line reads as a diff shows it. Standard library only, so
the base copy runs on its own.

Usage:
  tools/g1_scope.py --git BASE HEAD [--pr N] [--pr-created ISO-TIME --timeline FILE]
  tools/g1_scope.py PATH...           check the listed paths (no exemptions apply)
FILE holds the PR's issue timeline, one `EVENT<TAB>CREATED_AT` line per item (the
g1-freeze workflow writes it with `gh api`). Exit 0 on pass, 1 on a path outside a list, 2 on an unreadable list or diff.
"""
import argparse
import datetime
import importlib.util
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

# (name, list file, what lifts the freeze, where the freeze was set). The first is the
# default for parse_list and check. A gate that passes leaves this tuple with its list.
GATES = (
    ("G2", "g1_scope_g2.txt", "A4, A5, A9 and A14 pass on a VM (SPEC.md, Gates)", "D-128"),
)


# Timeline events that reuse a PR for work other than what was in flight when it opened.
REUSE = ("reopened", "head_ref_force_pushed", "base_ref_changed")


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


def when(text):
    """Parse a UTC time written as GitHub writes it (2026-10-14T19:35:25Z)."""
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise ListError(f"bad time {text!r}") from None


def parse_list(text, name=GATES[0][1]):
    """Return (freeze_on, since, allow, frozen_imports, exempt_prs). Raises ListError on any doubt.
    name is the list's file name, for messages."""
    freeze, since, allow, frozen, prs = None, None, [], [], set()
    # Printable ASCII and "\n" only, comments included: a lookalike digit (strptime and
    # isdigit read "1\u0665" as 15) or a line break git does not split on (str.splitlines
    # also splits on "\r", U+2028 and others) could make a line mean other than it shows.
    for n, line in enumerate(text.split("\n"), 1):
        bad = [c for c in line if not " " <= c <= "~"]
        if bad:
            raise ListError(f"{name}:{n}: character {bad[0]!r} outside printable ASCII")
        w = line.split("#", 1)[0].split()
        if not w:
            continue
        try:
            if w[0] == "freeze" and len(w) == 2 and w[1] in ("on", "off"):
                if freeze is not None:
                    raise ListError("second freeze line")
                freeze = w[1] == "on"
            elif w[0] == "since" and len(w) == 2:
                if since is not None:
                    raise ListError("second since line")
                since = when(w[1])
            elif w[0] == "allow" and len(w) == 2:
                allow.append(_clean(w[1]))
            elif w[0] == "frozen-import" and len(w) == 2 and w[1].endswith("/"):
                frozen.append(_clean(w[1]))
            elif w[0] == "exempt-pr" and len(w) == 2 and w[1].isascii() and w[1].isdigit():
                prs.add(int(w[1]))
            else:
                raise ListError(f"unreadable line {line.strip()!r}")
        except ListError as e:
            raise ListError(f"{name}:{n}: {e}") from None
    if freeze is None:
        raise ListError(f"{name}: no freeze line")
    if since is None:
        raise ListError(f"{name}: no since line")
    for f in frozen:
        if any(covers(a, f) for a in allow):
            raise ListError(f"{name}: {f} is both allowed and frozen")
    return freeze, since, allow, frozen, prs


def covers(entry, path):
    """A trailing "/" makes an entry a directory prefix; otherwise it is one file."""
    return path.startswith(entry) if entry.endswith("/") else path == entry


def reuse(history, since):
    """Return the first REUSE event at or after since as "EVENT at TIME", or None.

    history is the timeline text (EVENT<TAB>CREATED_AT lines); other events are skipped,
    and a REUSE line without a readable time raises ListError.
    """
    for line in history.splitlines():
        w = line.split("\t")
        if w[0] not in REUSE:
            continue
        if len(w) != 2:
            raise ListError(f"timeline: unreadable line {line!r}")
        if when(w[1]) >= since:
            return f"{w[0]} at {w[1]}"
    return None


def check(paths, list_text, pr=None, created="", history=None, gate=GATES[0]):
    """Return (ok, message lines) for one gate's list. created is the PR's created_at, empty
    outside a PR; history its timeline text, needed when created is before the freeze."""
    gname, file, lift, origin = gate
    tag = f"{gname.lower()} freeze:"
    freeze, since, allow, _, prs = parse_list(list_text, file)
    if not freeze:
        return True, [f"{tag} off ({file})"]
    reused = None
    if created and when(created) < since:
        if history is None:
            raise ListError("no PR timeline to confirm the time exemption")
        reused = reuse(history, since)
        if reused is None:
            return True, [f"{tag} exempt: opened {created}, before the freeze began ({since:%Y-%m-%dT%H:%M:%SZ})"]
    if pr is not None and pr in prs:
        return True, [f"{tag} exempt: PR #{pr} is an exempt-pr line"]
    paths = [p for p in paths if p]
    is_record = _ci_scope().is_record
    if all(is_record(p) for p in paths):
        return True, [f"{tag} records only" if paths else f"{tag} empty change"]
    outside = []
    for p in paths:
        bad = p.startswith("/") or any(x in ("", ".", "..") for x in p.split("/"))
        if bad or not (is_record(p) or any(covers(a, p) for a in allow)):
            outside.append(p)
    if not outside:
        return True, [f"{tag} every path is on the {gname} list"]
    return False, [f"{tag} these paths are outside the {gname} list (tools/{file}):"] + [
        f"  {p}" for p in sorted(outside)
    ] + ([
        f"It was opened before the freeze began ({since:%Y-%m-%dT%H:%M:%SZ}), but its timeline shows {reused}:",
        "the time exemption covers only the work in flight when the freeze began (#1717).",
    ] if reused else []) + [
        f"Until {lift}, PRs touch only the {gname}",
        f"path ({origin}). If this is a {gname} fix, amend tools/{file} in its own PR first.",
        "If this PR carries work that was already under way when the freeze began (a split or",
        f"rebuild of a row in flight), add `exempt-pr {pr if pr is not None else 'N'}` to tools/{file} in its own PR.",
        "Otherwise park the row until the freeze lifts. Once the amend merges, push a commit or",
        "edit this PR's title or body to re-run the check: a plain Re-run replays the old event",
        "and reads the old base's list.",
    ]


def changed_paths(base, head):
    # --no-renames lists a moved file under its old path too; -z keeps names unquoted.
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    return out.decode("utf-8", "surrogateescape").split("\0")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--git", nargs=2, metavar=("BASE", "HEAD"))
    ap.add_argument("--pr", type=int)
    ap.add_argument("--pr-created", default="")
    ap.add_argument("--timeline", help="the PR's timeline, EVENT<TAB>CREATED_AT per line")
    a = ap.parse_args(argv)
    try:
        history = pathlib.Path(a.timeline).read_text() if a.timeline else None
        paths = changed_paths(*a.git) if a.git else a.paths
        results = [
            check(paths, (HERE / gate[1]).read_text(), a.pr, a.pr_created, history, gate)
            for gate in GATES
        ]
    except (OSError, ValueError, subprocess.CalledProcessError, ListError) as e:
        print(f"freeze: cannot decide ({e}); failing closed", file=sys.stderr)
        return 2
    ok = all(r[0] for r in results)
    for r_ok, msg in results:
        print("\n".join(msg), file=sys.stdout if r_ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
