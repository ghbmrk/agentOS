#!/usr/bin/env python3
"""Session lookups that sessions kept redoing by hand (#4358): the next free decision ID, why a
CI job failed, and which open PRs no longer merge with main.

    tools/lookup.py next-id [--range LO[-HI]] [--prefix D] [--pr N ...]   next free ID, open PRs counted
    tools/lookup.py ci-why LOG | --job ID              the failing test lines of a job log
    tools/lookup.py conflicts [--pr N ...]             open PR heads that conflict with main

next-id reads the IDs in DECISIONS.md's table rows (`| D-NNN |`) and the decisions/D-NNN.md
files on origin/main, then the same in every open PR's head: an ID a head holds that main does
not is that PR's claim. It prints the next ID above all of them, and any ID claimed twice (by two
PRs, or by a PR and main): five PRs took D-245 in one week. `--range 300` (or `248-299`) counts
only IDs in that range, for a lane's own block (D-247: sub B from D-300, sub A from D-248). Only
trees are compared, so a PR behind main claims nothing main added since.

ci-why prints the failure lines of a saved job log: Go's `--- FAIL`/`FAIL`/`panic:` lines with
the test's indented message lines, unittest's `FAIL:`/`ERROR:` headers with their exception
line, and `##[error]` annotations. GitHub's timestamp prefixes are stripped. `--job ID` fetches
the log first (REST via gh api).

conflicts runs `git merge-tree --write-tree` of each open PR head onto its base branch, the
same three-way merge GitHub runs, and prints each PR that conflicts with its conflicted paths.
A shallow clone is unshallowed first, since merge-tree needs the merge base.

Open PRs come from `gh api` (REST); `--pr` names them instead. PR heads are fetched from
origin's refs/pull/N/head into refs/lookup/N. Standard library and git only. Exit 0 on
success (conflicts: 1 if any PR conflicts), 2 on a failed git or gh call.
"""
import argparse
import json
import re
import subprocess
import sys

REPO = "ghbmrk/agentOS"
TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ")


class Failed(Exception):
    pass


def run(cmd, cwd=".", ok=(0,)):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode not in ok:
        raise Failed(f"{' '.join(cmd[:4])}: {r.stderr.strip()[:300]}")
    return r


def git(cwd, *args, ok=(0,)):
    return run(["git", "-c", "core.quotePath=false", *args], cwd, ok)


# next-id

def table_ids(text, prefix="D"):
    """IDs of the table rows (`| D-12 | ...`) in a DECISIONS.md text."""
    return {int(m) for m in re.findall(rf"^\|\s*{re.escape(prefix)}-(\d+)\s*\|", text, re.M)}


def file_ids(names, prefix="D"):
    """IDs of decisions/D-12.md style file names."""
    return {int(m.group(1)) for n in names if (m := re.fullmatch(rf"(?:.*/)?{re.escape(prefix)}-(\d+)\.md", n))}


def tree_ids(cwd, rev, prefix="D"):
    r = git(cwd, "show", f"{rev}:DECISIONS.md", ok=(0, 128))
    files = git(cwd, "ls-tree", "--name-only", rev, "decisions/").stdout.split()
    return table_ids(r.stdout if r.returncode == 0 else "", prefix) | file_ids(files, prefix)


def claims(main_ids, heads):
    """heads: {pr: ids in its head}. Returns ({pr: ids it adds}, {id: [owners]} for IDs held twice)."""
    added = {pr: ids - main_ids for pr, ids in heads.items()}
    owners = {}
    for pr, ids in sorted(added.items()):
        for i in ids:
            owners.setdefault(i, ["main"] if i in main_ids else []).append(pr)
    return added, {i: o for i, o in sorted(owners.items()) if len(o) > 1}


def next_free(main_ids, added, lo=1, hi=None):
    """One above the highest ID in [lo, hi] on main or claimed by a PR; lo if none is."""
    held = [i for i in set(main_ids).union(*added.values()) if i >= lo and (hi is None or i <= hi)]
    n = max(held, default=lo - 1) + 1
    if hi is not None and n > hi:
        raise Failed(f"range {lo}-{hi} is full")
    return n


def parse_range(text):
    m = re.fullmatch(r"(\d+)(?:-(\d+))?", text or "1")
    if not m:
        raise argparse.ArgumentTypeError("range is LO or LO-HI")
    return int(m.group(1)), (int(m.group(2)) if m.group(2) else None)


def next_id(cwd, prefix, prs, rng=(1, None)):
    main = tree_ids(cwd, "origin/main", prefix)
    heads = {n: tree_ids(cwd, ref, prefix) for n, ref in fetch_heads(cwd, prs).items()}
    added, dup = claims(main, heads)
    for pr, ids in sorted(added.items()):
        if ids:
            print(f"#{pr} claims " + ", ".join(f"{prefix}-{i}" for i in sorted(ids)))
    for i, owners in dup.items():
        print(f"collision: {prefix}-{i} held by " + ", ".join(o if o == "main" else f"#{o}" for o in owners))
    print(f"next: {prefix}-{next_free(main, added, *rng)}")
    return 0


# ci-why

GO_HEAD = re.compile(r"^\s*--- FAIL: ")
GO_LINE = re.compile(r"^(FAIL\s|FAIL$|panic: |fatal error: )")
PY_HEAD = re.compile(r"^(FAIL|ERROR): \S")
GH_ERR = re.compile(r"^##\[error\]")
RULE = re.compile(r"^(=+|-+)$")
PY_END = re.compile(r"^(=+$|Ran \d+ tests? in )")


def why(lines, context=6):
    """The failure lines of a job log, in order, each once."""
    lines = [TS.sub("", l.rstrip("\n")) for l in lines]
    out, i = [], 0
    while i < len(lines):
        l = lines[i]
        if GO_HEAD.match(l):
            out.append(l)
            depth = len(l) - len(l.lstrip())
            j = i + 1
            while j < len(lines) and j - i <= context and lines[j].strip() \
                    and len(lines[j]) - len(lines[j].lstrip()) > depth and not GO_HEAD.match(lines[j]):
                out.append(lines[j])
                j += 1
            i = j
            continue
        if PY_HEAD.match(l):
            out.append(l)
            j, last = i + 1, None
            while j < len(lines) and not PY_END.match(lines[j]) and not PY_HEAD.match(lines[j]):
                if lines[j].strip() and not RULE.match(lines[j]):
                    last = lines[j]
                j += 1
            if last:
                out.append("    " + last.strip())
            i = j
            continue
        if GO_LINE.match(l) or GH_ERR.match(l):
            out.append(l)
        i += 1
    seen = set()
    return [l for l in out if not (l in seen or seen.add(l))]


def ci_why(log, job, context):
    if job:
        try:
            text = run(["gh", "api", f"repos/{REPO}/actions/jobs/{job}/logs"]).stdout
        except Failed as e:  # the log redirects to blob storage, which some networks deny
            raise Failed(f"{str(e)[:120]}; save the job log to a file and pass its path") from None
    else:
        with open(log, encoding="utf-8", errors="replace") as f:
            text = f.read()
    found = why(text.splitlines(), context)
    print("\n".join(found) if found else "ci-why: no failure lines found")
    return 0


# conflicts

def conflicted(cwd, head, base):
    """Paths that conflict when head merges onto base; [] when it merges cleanly."""
    r = git(cwd, "merge-tree", "--write-tree", "--name-only", "--no-messages", base, head, ok=(0, 1))
    if r.returncode == 0:
        return []
    return [p for p in r.stdout.splitlines()[1:] if p] or ["(conflict)"]


def conflicts(cwd, prs):
    if git(cwd, "rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        git(cwd, "fetch", "-q", "--unshallow", "origin")
    bases = {p["number"]: p["base"] for p in prs}
    heads = fetch_heads(cwd, prs)
    hit = 0
    for n, ref in sorted(heads.items()):
        paths = conflicted(cwd, ref, f"origin/{bases[n]}")
        if paths:
            hit = 1
            print(f"#{n} conflicts with {bases[n]}: " + ", ".join(paths))
    if not hit:
        print(f"conflicts: none of {len(heads)} open PRs conflict")
    return hit


# shared

def open_prs():
    prs, page = [], 1
    while True:
        r = run(["gh", "api", f"repos/{REPO}/pulls?state=open&per_page=100&page={page}"])
        batch = json.loads(r.stdout)
        prs += [{"number": p["number"], "base": p["base"]["ref"]} for p in batch]
        if len(batch) < 100:
            return prs
        page += 1


def fetch_heads(cwd, prs):
    """Fetch each PR's head into refs/lookup/N; returns {N: ref}."""
    refs = {p["number"]: f"refs/lookup/{p['number']}" for p in prs}
    bases = sorted({p["base"] for p in prs} | {"main"})
    specs = [f"+refs/pull/{n}/head:{r}" for n, r in refs.items()]
    specs += [f"+refs/heads/{b}:refs/remotes/origin/{b}" for b in bases]
    git(cwd, "fetch", "-q", "--no-tags", "origin", *specs)
    return refs


def main(argv):
    ap = argparse.ArgumentParser(prog="tools/lookup.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("next-id")
    a.add_argument("--prefix", default="D")
    a.add_argument("--range", type=parse_range, default=(1, None), help="LO or LO-HI: a lane's block")
    a.add_argument("--pr", type=int, action="append", help="PR numbers instead of all open PRs")
    a = sub.add_parser("ci-why")
    g = a.add_mutually_exclusive_group(required=True)
    g.add_argument("log", nargs="?")
    g.add_argument("--job", type=int)
    a.add_argument("--context", type=int, default=6, help="message lines kept per Go failure")
    a = sub.add_parser("conflicts")
    a.add_argument("--pr", type=int, action="append", help="PR numbers instead of all open PRs")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "ci-why":
            return ci_why(args.log, args.job, args.context)
        prs = [{"number": n, "base": "main"} for n in args.pr] if args.pr else open_prs()
        if args.cmd == "next-id":
            return next_id(".", args.prefix, prs, args.range)
        return conflicts(".", prs)
    except Failed as e:
        print(f"lookup: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
