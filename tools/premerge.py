#!/usr/bin/env python3
"""Check that the diff about to merge equals the diff its L3 accept reviewed (OPERATING §7).

  tools/premerge.py [--base origin/main] <reviewed-sha> [head]
  tools/premerge.py --needs-mark [--base origin/main] [head]   (--needs-mark in any position)
  tools/premerge.py --check <comments.json> <pr-number> [--base origin/main] [head]

Replays the reviewed commit onto the base content `head` carries (`git merge-tree` of the reviewed
commit with the merge-base of `base` and `head`) and compares that tree with `head`'s, file by file:
bytes, binary content and modes count, except that an ASSUMPTIONS.md differing only in its rows' first-cell ids (a renumbering after a main-merge) reads as same. Main merged into the branch therefore reads as same, even next
to a PR hunk, while any other change reads as changed: a later push, a moved hunk, a side branch merged
in, or a merge resolution that edits a PR line. Not a diff fingerprint: diff context lines carry
neighbouring base changes (#1580, #1592), and a -U0 diff reads a hunk moved elsewhere as same. Not
`git patch-id`: it ignores whitespace. Prints `same` and exits 0, or `changed <files>` and exits 1:
those files need a delta review. Git 2.38 or later, no network; fetch first.

`--needs-mark` lists the files of base..head that make the PR one that merges only on Mark's own approval of
it (it changes how Claude is permitted or reviewed): prints `mark <files>` and exits 1, or `agent` and exits 0 (OPERATING §7).

`--check` is the gate form: it reads a PR's issue comments (a JSON list as the GitHub API returns it), takes
the newest L3 verdict comment from a repository owner, member or collaborator, and prints `same` (exit 0) only
when that verdict is `accept` and the diff it reviewed (its `Record:` line head) equals `head`'s. Otherwise it
prints `changed <files>`, `not-accepted` or `no-verdict` and exits 1, so a push after the accept, a later
fix-list and a PR never reviewed all fail (PREMERGE-required, #1834).
"""
import json
import re
import subprocess
import sys

# Pinned so local config (renames, external drivers, colour) cannot change the file list.
DIFF = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z"]


# A PR touching any of these goes to Mark, never to an agent's auto-merge (OPERATING §7).
# CLAUDE*.md, AGENTS.md, .mcp.json and .claude/ count at any depth; broker/core/core.txt sets risk tiers
# (risk_tier.py); the tests that pin the merge gates count too (PREMERGE-paths, #1835). Matched with
# fullmatch and DOTALL, so a path with a newline in it cannot slip past `$`-style matching.
_CFG = r"(?:.*/)?"
MARK_PATHS = re.compile(rf"{_CFG}CLAUDE(?:\.local)?\.md|{_CFG}AGENTS\.md|{_CFG}\.mcp\.json|{_CFG}\.claude/.*|"
                        r"docs/OPERATING\.md|docs/LANES\.md|\.github/.*|broker/core/core\.txt|"
                        r"tools/(risk_tier|premerge)\.py|tools/(ci_scope|g1_scope)[^/]*|reviews/[^/]+/README[^/]*|"
                        r"tests/test_(premerge|risk_tier|ci_scope|g1_scope|workflows|merge_queue|lane)[^/]*",
                        re.DOTALL)


def mark_paths(files):
    return sorted(f for f in files if MARK_PATHS.fullmatch(f))


TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
_L3 = re.compile(r"^<!-- record: (?:l3|combined) -->$", re.M)


def verdict(comments, pr):
    """(verdict, reviewed-sha) of the newest trusted L3 verdict comment for PR `pr`, or None."""
    found = None
    for c in sorted(comments, key=lambda c: c.get("created_at") or ""):
        body = c.get("body") or ""
        rec = re.search(rf"^Record: PR #{int(pr)} · package \S+ · head ([0-9a-f]{{7,40}})\s*$", body, re.M)
        first = body.split("\n", 1)[0].strip()
        if (c.get("author_association") in TRUSTED and first.startswith("Verdict:") and rec and _L3.search(body)):
            found = (first.split(":", 1)[1].strip().lower(), rec.group(1))
    return found


def _git(cwd, *args, ok=(0,)):
    r = subprocess.run(["git", "-c", "core.quotePath=true", *args], cwd=cwd, capture_output=True)
    if r.returncode not in ok:
        raise subprocess.CalledProcessError(r.returncode, r.args, r.stdout, r.stderr)
    return r.stdout


def _replayed(cwd, reviewed, onto):
    """Tree of the reviewed commit merged with `onto`; conflicts keep their markers, so they read as changed."""
    out = _git(cwd, "merge-tree", "--write-tree", "--no-messages", reviewed, onto, ok=(0, 1))
    return out.split(b"\n", 1)[0].decode()


ROW_ID = re.compile(rb"^\| *[A-Za-z]+-?\d+[a-z]? *\|", re.M)


def _renumbered_only(cwd, tree, head, path):
    """True when an ASSUMPTIONS.md differs between `tree` and `head` only in the first-cell row ids."""
    if path.rsplit("/", 1)[-1] != "ASSUMPTIONS.md":
        return False
    a, b = (_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (tree, head))
    return bool(a) and bool(b) and ROW_ID.sub(b"| # |", a) == ROW_ID.sub(b"| # |", b)


def compare(cwd, reviewed, head="HEAD", base="origin/main"):
    onto = _git(cwd, "merge-base", base, head).decode().strip()
    tree = _replayed(cwd, reviewed, onto)
    out = _git(cwd, *DIFF, tree, head).decode(errors="surrogateescape")
    return sorted(f for f in out.split("\0") if f and not _renumbered_only(cwd, tree, head, f))


def main(argv):
    args, base = argv[1:], "origin/main"
    needs_mark = "--needs-mark" in args  # in any position
    args = [a for a in args if a != "--needs-mark"]
    if args[:1] == ["--check"]:
        if len(args) < 3:
            print(__doc__)
            return 2
        comments, pr, args = json.load(open(args[1])), args[2], args[3:]
        if args[:1] == ["--base"]:
            base, args = args[1], args[2:]
        v = verdict(comments, pr)
        if v is None or v[0] != "accept":
            print("no-verdict" if v is None else "not-accepted")
            return 1
        changed = compare(".", v[1], args[0] if args else "HEAD", base)
        print("changed " + " ".join(changed) if changed else "same")
        return 1 if changed else 0
    if args[:1] == ["--base"]:
        base, args = args[1], args[2:]
    if needs_mark:
        head = args[0] if args else "HEAD"
        onto = _git(".", "merge-base", base, head).decode().strip()
        out = _git(".", *DIFF, onto, head).decode(errors="surrogateescape")
        hit = mark_paths(f for f in out.split("\0") if f)
        print("mark " + " ".join(hit) if hit else "agent")
        return 1 if hit else 0
    if not 1 <= len(args) <= 2:
        print(__doc__)
        return 2
    changed = compare(".", args[0], args[1] if len(args) > 1 else "HEAD", base)
    print("changed " + " ".join(changed) if changed else "same")
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
