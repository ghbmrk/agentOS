#!/usr/bin/env python3
"""Check that the diff about to merge equals the diff its L3 accept reviewed (OPERATING §7).

  tools/premerge.py [--base origin/main] <reviewed-sha> [head]
  tools/premerge.py --needs-mark [--base origin/main] [head]   (--needs-mark in any position)
  tools/premerge.py --check <comments.json> <pr-number> [--base origin/main] [head]
  tools/premerge.py --bot <head-ref> [--base origin/main] [head]

Replays the reviewed commit onto the base content `head` carries (`git merge-tree` of the reviewed
commit with the merge-base of `base` and `head`) and compares that tree with `head`'s, file by file:
bytes, binary content and modes count, except that an ASSUMPTIONS.md differing only in its rows' first-cell ids (a renumbering after a main-merge) reads as same,
and so does a DECISIONS.md whose only replay conflicts are table rows both sides appended at one spot, resolved by
keeping both sides' rows verbatim, either side first (#3224, #3233). Main merged into the branch therefore reads as same, even next
to a PR hunk, while any other change reads as changed: a later push, a moved hunk, a side branch merged
in, or a merge resolution that edits a PR line. Not a diff fingerprint: diff context lines carry
neighbouring base changes (#1580, #1592), and a -U0 diff reads a hunk moved elsewhere as same. Not
`git patch-id`: it ignores whitespace. Prints `same` and exits 0, or `changed <files>` and exits 1:
those files need a delta review. Git 2.38 or later, no network; fetch first.

`--needs-mark` lists the files of merge-base..head, plus those the merge changes on base (a criss-cross merge,
#2138), that make the PR a gate-file PR (it changes how Claude is permitted or reviewed): prints `mark <files>` and
exits 1, or `agent` and exits 0 (OPERATING §7). It takes at most one positional
(the head); a base goes after `--base`, so a second positional, or a base..head with no changed files, is a
usage error (exit 2).

`--check` is the gate form: it reads a PR's issue comments (a JSON list as the GitHub API returns it), takes
the newest L3 verdict comment from a repository owner, member or collaborator, and prints `same` (exit 0) only
when that verdict is `accept` and the diff it reviewed (its `Record:` line head) equals `head`'s. Otherwise it
prints `changed <files>`, `not-accepted`, `edited-verdict <kind>` or `no-verdict` and exits 1, so a push after the accept, a later
fix-list and a PR never reviewed all fail (PREMERGE-required, #1834). A gate-file PR (the `--needs-mark` list)
also needs a separate Security accept (D-137): the newest trusted verdict comment marked `security` and not
`l3` or `combined` is `accept` and its reviewed diff equals `head`'s; otherwise it prints `needs-security <files>`
and exits 1. Before that, the lens screen the PR's tier needs (OPERATING §3-§4, PREMERGE-lens #2644; tier from
tools/risk_tier.py over the same file list, read from the checkout, which in the workflow is the base): on tier A
the newest trusted verdicts marked `ux` and `potency` (one comment may carry both), on tier B the newest marked
`combined`, each an `accept` whose reviewed diff equals `head`'s. A tier-A diff confined to assurance tooling owes
`potency` only (D-086). Otherwise it prints `needs-lens <lens,...>` and exits 1. A verdict comment edited after posting never accepts: while it is the newest of
its kind the check prints `edited-verdict <kind>` (l3, a lens or security; #3105), until a newer comment supersedes
it. Never edit a posted verdict, post a new comment instead. SPEC.md needs nothing extra (D-137 supersedes D-130's `Transcribes:` and `Mark-approved:` lines).

`--bot` is the gate form for the generated-file bot PRs, which carry no verdict (PREMERGE-wire, #1860): it
prints `bot` (exit 0) only when `head-ref` is one of the BOT branches and base..head changes nothing but that
bot's output. Otherwise it
prints `not-bot <files>` and exits 1. The caller checks that the branch is this repository's, not a fork's.
"""
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

# By path: the workflow runs `python3 -I`, which keeps tools/ off sys.path.
_spec = importlib.util.spec_from_file_location("risk_tier", pathlib.Path(__file__).resolve().parent / "risk_tier.py")
risk_tier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(risk_tier)

# Pinned so local config (renames, external drivers, colour) cannot change the file list.
DIFF = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z"]


# Gate files: a PR touching any of these also needs a separate Security accept (D-137, OPERATING §7).
# CLAUDE*.md, AGENTS.md, .mcp.json and .claude (a directory or a symlink, #2138) count at any depth;
# broker/core/core.txt sets risk tiers (risk_tier.py); tools/trace.py and tools/old_core.txt are the old-core ratchet (D-139); tools/trusted_base.py and tools/trusted_core.txt are the trusted core's budget (KRN-2cap, #2935); the tests that pin the merge gates count too
# (PREMERGE-paths, #1835), as do this gate's own tests and the lens rules, so a PR cannot weaken them on L3 alone (#2438). Matched with fullmatch and DOTALL, so a path with a newline in it cannot slip past `$`-style matching.
_CFG = r"(?:.*/)?"
MARK_PATHS = re.compile(rf"{_CFG}CLAUDE(?:\.local)?\.md|{_CFG}AGENTS\.md|{_CFG}\.mcp\.json|{_CFG}\.claude(?:/.*)?|"
                        r"docs/OPERATING\.md|docs/LANES\.md|\.github/.*|broker/core/core\.txt|"
                        r"tools/(risk_tier|premerge|trace|trusted_base)\.py|tools/(old_core|trusted_core)\.txt|tools/(ci_scope|g1_scope)[^/]*|"
                        r"tests/test_premerge[^/]*|reviews/[^/]+/README[^/]*",
                        re.DOTALL)


def mark_paths(files):
    return sorted(f for f in files if MARK_PATHS.fullmatch(f))


def mark_range(cwd, base, head):
    """Files the PR changes (merge-base..head) plus the files its merge changes on base (base..merge result).

    The second list catches a criss-cross merge (two merge bases), where `git merge-base` can pick the one at
    which head's Mark-only file is unchanged although the merge reverts base's copy of it (#2138). A conflicted
    merge-tree keeps its markers, so a conflicted file reads as changed."""
    def names(a, b):
        return {f for f in _git(cwd, *DIFF, a, b).decode(errors="surrogateescape").split("\0") if f}
    onto = _git(cwd, "merge-base", base, head).decode().strip()
    return sorted(names(onto, head) | names(base, _replayed(cwd, base, head)))


TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
_L3 = re.compile(r"^<!-- record: (?:l3|combined) -->$", re.M)
# D-137: a gate-file PR also needs a Security accept in a comment of its own, so one review cannot count twice.
_SECURITY = re.compile(r"^<!-- record: security -->$", re.M)


# A tier-A diff confined to assurance tooling gets no UX pass (OPERATING §4 step 2, D-086).
ASSURANCE = re.compile(r"(?:tools/|tests/test_)(?:depaudit|canary|risk_tier)[^/]*|assurance/.*", re.DOTALL)


def lenses_owed(files):
    """The lens verdicts the tier of `files` needs besides L3 (OPERATING §3-§4)."""
    tier, _ = risk_tier.tier_of_change(files)
    if tier == "A":
        return ["potency"] if all(ASSURANCE.fullmatch(f) for f in files) else ["ux", "potency"]
    return ["combined"] if tier == "B" else []


def verdict(comments, pr, security=False, lens=None):
    """(verdict, reviewed-sha) of the newest trusted L3 verdict comment for PR `pr`, or None.

    With `security`, of the newest trusted Security verdict comment that carries no L3 marker instead;
    with `lens`, of the newest trusted verdict comment carrying that lens's marker.
    A qualifying comment edited after posting (updated_at missing or different from created_at) reads as verdict
    `edited`, which is never an accept, until a later comment supersedes it: a verdict is the text that was reviewed."""
    found = None
    for c in sorted(comments, key=lambda c: c.get("created_at") or ""):
        body = c.get("body") or ""
        rec = re.search(rf"^Record: PR #{int(pr)} · package \S+ · head ([0-9a-f]{{7,40}})\s*$", body, re.M)
        first = body.split("\n", 1)[0].strip()
        if lens:
            marked = re.search(rf"^<!-- record: {re.escape(lens)} -->$", body, re.M)
        else:
            marked = (_SECURITY.search(body) and not _L3.search(body)) if security else _L3.search(body)
        if c.get("author_association") in TRUSTED and first.startswith("Verdict:") and rec and marked:
            edited = c.get("updated_at") != c.get("created_at") or not c.get("created_at")
            found = ("edited" if edited else first.split(":", 1)[1].strip().lower(), rec.group(1))
    return found


def _git(cwd, *args, ok=(0,)):
    r = subprocess.run(["git", "-c", "core.quotePath=true", *args], cwd=cwd, capture_output=True)
    if r.returncode not in ok:
        raise subprocess.CalledProcessError(r.returncode, r.args, r.stdout, r.stderr)
    return r.stdout


def _replayed(cwd, reviewed, onto):
    """Tree of the reviewed commit merged with `onto`; conflicts keep their markers, so they read as changed.

    diff3 markers, pinned, so `_appends_kept` can see that a conflict's base section is empty."""
    out = _git(cwd, "-c", "merge.conflictStyle=diff3", "merge-tree", "--write-tree", "--no-messages", reviewed, onto,
               ok=(0, 1))
    return out.split(b"\n", 1)[0].decode()


# Bot branch -> (pattern every changed path must fullmatch, git statuses allowed). Writers: trace.yml,
# metrics.yml, board.yml. bot/records left with records.yml (cut 4, #2234; #2235).
BOT = {
    "bot/trace": (re.compile(r"TRACE\.md"), "AM"),
    "bot/metrics": (re.compile(r"METRICS\.md"), "AM"),
    "bot/board": (re.compile(r"BOARD\.md"), "AM"),
}


def bot_outside(cwd, ref, head="HEAD", base="origin/main"):
    """Paths of base..head outside bot branch `ref`'s output; None when `ref` is not a bot branch or the diff is empty."""
    if ref not in BOT:
        return None
    pattern, statuses = BOT[ref]
    onto = _git(cwd, "merge-base", base, head).decode().strip()
    out = _git(cwd, *DIFF[:-2], "--name-status", "-z", onto, head).decode(errors="surrogateescape").split("\0")
    pairs = list(zip(out[0::2], out[1::2]))
    if not pairs:
        return None
    return [f for st, f in pairs if st not in statuses or not pattern.fullmatch(f)]


ROW_ID = re.compile(rb"^\| *[A-Za-z]+-?\d+[a-z]? *\|", re.M)


def _same_mode(cwd, tree, head, path):
    """True when `path` has the same mode and object type in `tree` and `head` (#3266: the row exemptions compare
    text, so they need this to keep a chmod or a symlink swap reading as changed)."""
    a, b = (_git(cwd, "--literal-pathspecs", "ls-tree", "--full-tree", t, "--", path).split(b" ", 2)[:2] for t in (tree, head))
    return a == b


def _renumbered_only(cwd, tree, head, path):
    """True when an ASSUMPTIONS.md differs between `tree` and `head` only in the first-cell row ids."""
    if path.rsplit("/", 1)[-1] != "ASSUMPTIONS.md":
        return False
    a, b = (_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (tree, head))
    return (bool(a) and bool(b) and ROW_ID.sub(b"| # |", a) == ROW_ID.sub(b"| # |", b)
            and _same_mode(cwd, tree, head, path))


def _appends_kept(cwd, tree, head, path, reviewed, onto):
    """True when DECISIONS.md conflicted in the replay only where both sides appended table rows at one spot (an
    empty base section), and `head` keeps both sides' rows verbatim, every conflict in the same order: the
    reviewed rows first or main's first. Any other conflict, line or order reads as changed."""
    if path != "DECISIONS.md":
        return False
    text, want = (_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (tree, head))
    if not text or not want:
        return False
    out, block, side, conflicts = ([], []), None, 0, 0
    for line in text.splitlines(keepends=True):
        bare = line.rstrip(b"\n")
        if block is None:
            if bare == b"<<<<<<< " + reviewed.encode():
                block, side = ([], []), 0
            else:
                for o in out:
                    o.append(line)
        elif side == 0 and bare.startswith(b"||||||| "):
            side = 1  # base section: must stay empty
        elif side == 1 and bare == b"=======":
            side = 2
        elif side == 2 and bare == b">>>>>>> " + onto.encode():
            out[0].extend(block[0] + block[1])
            out[1].extend(block[1] + block[0])
            block, conflicts = None, conflicts + 1
        elif side in (0, 2) and line.startswith(b"|"):
            block[side // 2].append(line)
        else:
            return False
    return (block is None and conflicts > 0 and want in (b"".join(out[0]), b"".join(out[1]))
            and _same_mode(cwd, tree, head, path))


def compare(cwd, reviewed, head="HEAD", base="origin/main"):
    onto = _git(cwd, "merge-base", base, head).decode().strip()
    tree = _replayed(cwd, reviewed, onto)
    out = _git(cwd, *DIFF, tree, head).decode(errors="surrogateescape")
    return sorted(f for f in out.split("\0") if f and not _renumbered_only(cwd, tree, head, f)
                  and not _appends_kept(cwd, tree, head, f, reviewed, onto))


def _same(reviewed, head, base):
    """True when the reviewed head's diff equals `head`'s; an unknown SHA never matches."""
    try:
        return not compare(".", reviewed, head, base)
    except subprocess.CalledProcessError:
        return False


def _accepted(v, head, base):
    return bool(v) and v[0] == "accept" and _same(v[1], head, base)


# #3105: an edited accept read as a bare `not-accepted`, which looked like a gate bug; name the cause instead.
EDITED = "edited-verdict {}: a verdict edited after posting never counts, post a new comment"


def _edited(v):
    return bool(v) and v[0] == "edited"


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
            print("no-verdict" if v is None else EDITED.format("l3") if _edited(v) else "not-accepted")
            return 1
        head = args[0] if args else "HEAD"
        changed = compare(".", v[1], head, base)
        if changed:
            print("changed " + " ".join(changed))
            return 1
        files = mark_range(".", base, head)
        owed = {x: verdict(comments, pr, lens=x) for x in lenses_owed(files)}
        lenses = [x for x, lv in owed.items() if not _accepted(lv, head, base)]
        if any(_edited(owed[x]) for x in lenses):
            print(EDITED.format(",".join(x for x in lenses if _edited(owed[x]))))
            return 1
        if lenses:
            print("needs-lens " + ",".join(lenses))
            return 1
        gate = mark_paths(files)
        sec = verdict(comments, pr, security=True)
        if gate and not _accepted(sec, head, base):
            print(EDITED.format("security") if _edited(sec) else "needs-security " + " ".join(gate))
            return 1
        print("same")
        return 0
    if args[:1] == ["--bot"]:
        if len(args) < 2:
            print(__doc__)
            return 2
        ref, args = args[1], args[2:]
        if args[:1] == ["--base"]:
            base, args = args[1], args[2:]
        outside = bot_outside(".", ref, args[0] if args else "HEAD", base)
        print("bot" if outside == [] else " ".join(["not-bot", *(outside or [])]))
        return 0 if outside == [] else 1
    if args[:1] == ["--base"]:
        base, args = args[1], args[2:]
    if needs_mark:
        if len(args) > 1:  # `--needs-mark origin/main pr` would read origin/main as the head: pass --base
            print(__doc__)
            return 2
        head = args[0] if args else "HEAD"
        files = mark_range(".", base, head)
        if not files:  # `--needs-mark origin/main` reads origin/main as the head: an empty range is never `agent`
            print(f"empty range {base}..{head}: name the PR head", file=sys.stderr)
            return 2
        hit = mark_paths(files)
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
