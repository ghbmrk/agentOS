#!/usr/bin/env python3
"""Check that the diff about to merge equals the diff its L3 accept reviewed (OPERATING §7).

  tools/premerge.py [--base origin/main] <reviewed-sha> [head]
  tools/premerge.py --needs-mark [--base origin/main] [head]   (--needs-mark in any position)

Replays the reviewed commit onto the base content `head` carries (`git merge-tree` of the reviewed
commit with the merge-base of `base` and `head`) and compares that tree with `head`'s, file by file:
bytes, binary content and modes count. Main merged into the branch therefore reads as same, even next
to a PR hunk, while any other change reads as changed: a later push, a moved hunk, a side branch merged
in, or a merge resolution that edits a PR line. Not a diff fingerprint: diff context lines carry
neighbouring base changes (#1580, #1592), and a -U0 diff reads a hunk moved elsewhere as same. Not
`git patch-id`: it ignores whitespace. Prints `same` and exits 0, or `changed <files>` and exits 1:
those files need a delta review. Git 2.38 or later, no network; fetch first.

`--needs-mark` lists the files of base..head that make the PR one Mark presses Merge on (it changes how
Claude is permitted or reviewed): prints `mark <files>` and exits 1, or `agent` and exits 0 (OPERATING §7).
"""
import re
import subprocess
import sys

# Pinned so local config (renames, external drivers, colour) cannot change the file list.
DIFF = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z"]


# A PR touching any of these goes to Mark, never to an agent's auto-merge (OPERATING §7).
# CLAUDE.md and CLAUDE.local.md count at any depth; broker/core/core.txt sets risk tiers (risk_tier.py).
MARK_PATHS = re.compile(r"^((?:.*/)?CLAUDE(?:\.local)?\.md|AGENTS\.md|\.mcp\.json|docs/OPERATING\.md|docs/LANES\.md|"
                        r"\.claude/.*|\.github/.*|broker/core/core\.txt|tools/(risk_tier|premerge)\.py|"
                        r"tools/(ci_scope|g1_scope)[^/]*|reviews/[^/]+/README[^/]*)$")


def mark_paths(files):
    return sorted(f for f in files if MARK_PATHS.match(f))


def _git(cwd, *args, ok=(0,)):
    r = subprocess.run(["git", "-c", "core.quotePath=true", *args], cwd=cwd, capture_output=True)
    if r.returncode not in ok:
        raise subprocess.CalledProcessError(r.returncode, r.args, r.stdout, r.stderr)
    return r.stdout


def _replayed(cwd, reviewed, onto):
    """Tree of the reviewed commit merged with `onto`; conflicts keep their markers, so they read as changed."""
    out = _git(cwd, "merge-tree", "--write-tree", "--no-messages", reviewed, onto, ok=(0, 1))
    return out.split(b"\n", 1)[0].decode()


def compare(cwd, reviewed, head="HEAD", base="origin/main"):
    onto = _git(cwd, "merge-base", base, head).decode().strip()
    out = _git(cwd, *DIFF, _replayed(cwd, reviewed, onto), head).decode(errors="surrogateescape")
    return sorted(f for f in out.split("\0") if f)


def main(argv):
    args, base = argv[1:], "origin/main"
    needs_mark = "--needs-mark" in args  # in any position
    args = [a for a in args if a != "--needs-mark"]
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
