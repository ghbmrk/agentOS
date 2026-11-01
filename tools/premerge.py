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
keeping both sides' rows verbatim, either side first (#3224, #3233), the PR's rows renumbered or not when no other PR file names an old ID (#4030),
and so does a `*_allow.txt` whose lines are main's plus the PR's line changes, in any order (#3991). A replay file that fails a cheap gate never reads
same as is: a duplicate row ID (doclint) in an ASSUMPTIONS.md or DECISIONS.md, or an ASSUMPTIONS.md row that
`merge=union` brought back (in the merge base and main, not in the reviewed commit). A head that resolves each union
hunk without those rows, keeping its rows inside the hunk, reads same (#3400, #3401), unless `git merge-file`
aligns the file unlike the replay: then every head reads changed and is resolved by hand. Main merged into the branch therefore reads as same, even next
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
or tier-A PR also needs a separate Security accept (D-137, #3817): the newest trusted verdict comment marked `security` and not
`l3` or `combined` is `accept` and its reviewed diff equals `head`'s; otherwise it prints `needs-security <files>`
and exits 1, naming the gate and tier-A files. Before that, the lens screen the PR's tier needs (OPERATING §3-§4, PREMERGE-lens #2644; tier from
tools/risk_tier.py over the same file list, read from the checkout, which in the workflow is the base): on tier A
the newest trusted verdicts marked `ux` and `potency` (one comment may carry both), on tier B the newest marked
`combined`, each an `accept` whose reviewed diff equals `head`'s. A tier-A diff confined to assurance tooling owes
`potency` only (D-086). Otherwise it prints `needs-lens <lens,...>` and exits 1. A verdict comment edited after posting never accepts: while it is the newest of
its kind the check prints `edited-verdict <kind>` (l3, a lens or security; #3105), until a newer comment supersedes
it. Likewise a verdict comment whose `Record:` line does not parse (a package ID with spaces, a missing line;
#3611) prints `unparsed-record <kind>` until a newer comment supersedes it. An accept whose Record head names no commit here prints
`unresolved-record <kind>` the same way (#3856). Never edit a posted verdict, post a new comment instead. SPEC.md needs nothing extra (D-137 supersedes D-130's `Transcribes:` and `Mark-approved:` lines).

`--bot` is the gate form for the generated-file bot PRs, which carry no verdict (PREMERGE-wire, #1860): it
prints `bot` (exit 0) only when `head-ref` is one of the BOT branches and base..head changes nothing but that
bot's output. Otherwise it
prints `not-bot <files>` and exits 1. The caller checks that the branch is this repository's, not a fork's.
"""
import collections
import importlib.util
import json
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

# By path: the workflow runs `python3 -I`, which keeps tools/ off sys.path.
_spec = importlib.util.spec_from_file_location("risk_tier", pathlib.Path(__file__).resolve().parent / "risk_tier.py")
risk_tier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(risk_tier)

# Pinned so local config (renames, external drivers, colour) cannot change the file list.
DIFF = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z"]


# Gate files: a PR touching any of these also needs a separate Security accept (D-137, OPERATING §7).
# CLAUDE*.md, AGENTS.md, .mcp.json and .claude (a directory or a symlink, #2138) count at any depth;
# broker/core/core.txt sets risk tiers (risk_tier.py); tools/trace.py and tools/old_core.txt are the old-core ratchet (D-139); tools/trusted_base.py and tools/trusted_core.txt are the trusted core's budget (KRN-2cap, #2935); tools/mutgate.py is the mutation gate, which the mutgate workflow decides with once it is on the base (#3955, #4106); the tests that pin the merge gates count too
# (PREMERGE-paths, #1835), as do this gate's own tests and the lens rules, so a PR cannot weaken them on L3 alone (#2438). Matched with fullmatch and DOTALL, so a path with a newline in it cannot slip past `$`-style matching.
_CFG = r"(?:.*/)?"
MARK_PATHS = re.compile(rf"{_CFG}CLAUDE(?:\.local)?\.md|{_CFG}AGENTS\.md|{_CFG}\.mcp\.json|{_CFG}\.claude(?:/.*)?|"
                        r"docs/OPERATING\.md|docs/LANES\.md|\.github/.*|broker/core/core\.txt|"
                        r"tools/(risk_tier|premerge|trace|trusted_base|mutgate)\.py|tools/(old_core|trusted_core)\.txt|tools/(ci_scope|g1_scope)[^/]*|"
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
# D-137: a gate-file or tier-A PR also needs a Security accept in a comment of its own, so one review cannot count twice.
_SECURITY = re.compile(r"^<!-- record: security -->$", re.M)
# A well-formed Record line for some PR: one for another PR is that PR's record, not an unparsed one.
_RECORD = re.compile(r"^Record: PR #\d+ · package \S+ · head [0-9a-f]{7,40}\s*$", re.M)
_MARKER = re.compile(r"^<!-- record: \S+ -->$", re.M)
# The lines a record block runs on under its Record line; a fenced block is quoted text (#4261).
_HEADER = re.compile(r"<!-- record: \S+ -->$|\s*$")
_FENCE = re.compile(r"(`{3,}|~{3,})[^`]*$")


def _record_block(body):
    """(text, placed): where a comment's Record line and markers are read from, and whether that is its record block.

    The record block is the comment's first `Record:` line outside a code fence and the run of marker and blank lines
    under it. When it carries a marker, an accept's markers and Record lines anywhere else are quoted text: they
    neither hide the review's own record nor lend it one (#4261). Otherwise `placed` is false and the whole comment is
    returned."""
    lines, fence = [], None
    for line in body.split("\n"):  # one pass: a fence left open runs to the end, as Markdown renders it
        if fence is None and _FENCE.match(line):
            fence = _FENCE.match(line).group(1)
        elif fence is None:
            lines.append(line)
        elif line.rstrip(" \t") == fence:
            fence = None
    at = next((n for n, line in enumerate(lines) if line.startswith("Record:")), None)
    if at is None:
        return body, False
    end = at + 1
    while end < len(lines) and _HEADER.match(lines[end]):
        end += 1
    own = "\n".join(lines[at:end])
    return (own, True) if _MARKER.search(own) else (body, False)


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
    An accept's markers and Record line count only in the comment's record block, and an accept whose marker is only
    outside it reads as `unparsed` (`_record_block`, #4261); any other verdict reads the whole comment, so it fails closed.
    A qualifying comment edited after posting (updated_at missing or different from created_at) reads as verdict
    `edited`, which is never an accept, until a later comment supersedes it: a verdict is the text that was reviewed.
    A qualifying comment with no well-formed Record line for any PR reads as `unparsed` the same way (#3611)."""
    found = None
    for c in sorted(comments, key=lambda c: c.get("created_at") or ""):
        body = c.get("body") or ""
        first = body.split("\n", 1)[0].strip()
        if c.get("author_association") not in TRUSTED or not first.startswith("Verdict:"):
            continue
        own, placed = _record_block(body)
        # Only an accept is held to its record block (#4261); any other verdict reads the whole comment, as before, so a
        # quoted or misplaced marker or record can only make it count, which fails closed.
        accept = first.split(":", 1)[-1].strip().lower() == "accept"
        read = own if accept else body
        rec = re.search(rf"^Record: PR #{int(pr)} · package \S+ · head ([0-9a-f]{{7,40}})\s*$", read, re.M)
        if lens:
            marked = re.search(rf"^<!-- record: {re.escape(lens)} -->$", read, re.M)
        else:
            marked = _SECURITY.search(read) if security else _L3.search(read)
            if security and placed and _L3.search(own):
                marked = None
        misplaced = accept and not placed
        if marked and (misplaced or not rec):
            if misplaced or not _RECORD.search(read):
                found = ("unparsed", None)
        elif marked:
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


def _renumbered_only(cwd, tree, head, path, reviewed, onto):
    """True when an ASSUMPTIONS.md differs between `tree` and `head` only in the first-cell row ids, and the
    replay resurrected no row (a renumbered stale row is still a stale row, #3400)."""
    if path.rsplit("/", 1)[-1] != "ASSUMPTIONS.md":
        return False
    a, b = (_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (tree, head))
    return (bool(a) and bool(b) and ROW_ID.sub(b"| # |", a) == ROW_ID.sub(b"| # |", b)
            and not _stale(cwd, a, path, reviewed, onto) and _same_mode(cwd, tree, head, path))


FIRST_CELL = re.compile(rb"^\|[ \t]*([^|\s][^|]*?)[ \t]*\|")


def _duplicate_id(text):
    """True when a table of `text` repeats a first-cell row ID: doclint's assumption_ids rule (tools/doclint.py)."""
    seen, in_table = set(), False
    for line in text.decode(errors="surrogateescape").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|"):
            in_table = False
        elif cells[0] in ("ID", "#"):
            in_table = True
        elif in_table and not set(cells[0]) <= set("-: "):
            if cells[0] in seen:
                return True
            seen.add(cells[0])
    return False


def _merge_file(cwd, path, reviewed, base, onto):
    """`git merge-file -p --diff3` of `path` in the reviewed commit, `base` and `onto`, without `merge=union`, and
    the random label its conflict markers carry."""
    texts = [_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (reviewed, base, onto)]
    mark = secrets.token_hex(16)  # labels no file can carry, so its text never reads as a marker
    with tempfile.TemporaryDirectory() as d:
        names = [pathlib.Path(d, n) for n in ("pr", "base", "main")]
        for n, t in zip(names, texts):
            n.write_bytes(t)
        merged = subprocess.run(["git", "merge-file", "-p", "--diff3", *(f"-L{mark}{i}" for i in range(3)), *map(str, names)],
                                cwd=cwd, capture_output=True).stdout
    return merged, mark


def _stale(cwd, text, path, reviewed, onto):
    """The table rows of an ASSUMPTIONS.md replay `text` that `merge=union` (.gitattributes) brought back, counted
    in copies, per conflict of the merge without the union: of a row in its base section, the copies beyond the
    merge's own (main's plus the reviewed commit's, less the base's), so a copy one side edited or deleted and the
    other left alone (#3369, #1912, #3441, #3502). A copy both sides deleted outside a conflict is gone from the
    merge too (#3534). Where `git merge-file` aligns the file unlike the replay, the whole file counts as one
    conflict. Empty for any other file or a criss-cross merge."""
    if path.rsplit("/", 1)[-1] != "ASSUMPTIONS.md":
        return collections.Counter()
    bases = _git(cwd, "merge-base", "--all", reviewed, onto).decode().split()
    if len(bases) != 1:
        return collections.Counter()
    merged, mark = _merge_file(cwd, path, reviewed, bases[0], onto)
    hunks, union, hunk, side = [], [], None, 0
    for line in merged.splitlines(keepends=True):
        bare = line.rstrip(b"\r\n")
        if hunk is None and bare == f"<<<<<<< {mark}0".encode():
            hunk, side = ([], [], []), 0
        elif hunk is None:
            union.append(line)
        elif bare == f"||||||| {mark}1".encode() and side == 0:
            side = 1
        elif bare == b"=======" and side == 1:
            side = 2
        elif bare == f">>>>>>> {mark}2".encode() and side == 2:
            union.extend(hunk[0] + hunk[2])
            hunks.append(hunk)
            hunk = None
        else:
            hunk[side].append(line)
    if hunk is not None or b"".join(union) != text:  # the whole file, the replay's copies in place of the union's
        hunks = [[_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (reviewed, bases[0], onto)] + [text]]
    else:
        hunks = [(b"".join(h[0]), b"".join(h[1]), b"".join(h[2]), b"".join(h[0] + h[2])) for h in hunks]
    out = collections.Counter()
    for pr, mb, kept, rows in hunks:
        pr, mb, kept, rows = (collections.Counter(t.splitlines()) for t in (pr, mb, kept, rows))
        out += collections.Counter({x: n - max(kept[x] + pr[x] - mb[x], 0) for x, n in rows.items()
                                    if FIRST_CELL.match(x) and x in mb})
    return out


def _broken(cwd, tree, path, reviewed, onto):
    """True when the replay's `path` fails a cheap gate, so a head that keeps it never reads same (#3400): a
    duplicate row ID in an ASSUMPTIONS.md or DECISIONS.md (doclint), or a row `merge=union` brought back."""
    if path != "DECISIONS.md" and path.rsplit("/", 1)[-1] != "ASSUMPTIONS.md":
        return False
    text = _git(cwd, "show", f"{tree}:{path}", ok=(0, 128))
    return _duplicate_id(text) or bool(_stale(cwd, text, path, reviewed, onto))


def _less(rows, drop):
    """`rows` less the first drop[x] copies of each row x, in order: a multiset difference."""
    drop, out = drop.copy(), []
    for x in rows:
        if drop[x] > 0:
            drop[x] -= 1
        else:
            out.append(x)
    return out


def _stale_dropped(cwd, tree, head, path, reviewed, onto):
    """True when an ASSUMPTIONS.md replay conflicts without `merge=union` (.gitattributes) only in hunks of table
    rows, and `head` is that merge with each hunk resolved as the PR's rows plus main's, less each row the merge base
    shares with one side only (main deleted it, or the PR dropped it: the stale rows the union kept, #3369, #1912),
    or as main's rows with each stale row replaced by the PR's row of its ID, the rest of the PR's rows after them
    (e842a58 on #3369). Every hunk the
    same way, no duplicate ID left. A row never leaves its hunk, so nothing moves to another table (#3401)."""
    if path.rsplit("/", 1)[-1] != "ASSUMPTIONS.md":
        return False
    bases = _git(cwd, "merge-base", "--all", reviewed, onto).decode().split()
    if len(bases) != 1:
        return False
    merged, mark = _merge_file(cwd, path, reviewed, bases[0], onto)
    key = lambda line: FIRST_CELL.match(line) and FIRST_CELL.match(line).group(1)
    out, hunk, side, conflicts = ([], [], []), None, 0, 0  # resolutions 0 and 1; 2 is the union, to match the replay
    for line in merged.splitlines(keepends=True):
        bare = line.rstrip(b"\r\n")
        if hunk is None:
            if bare == f"<<<<<<< {mark}0".encode():
                hunk, side = ([], [], []), 0
            else:
                for o in out:
                    o.append(line)
        elif bare == f"||||||| {mark}1".encode() and side == 0:
            side = 1
        elif bare == b"=======" and side == 1:
            side = 2
        elif bare == f">>>>>>> {mark}2".encode() and side == 2:
            pr, base, main = hunk
            n = [collections.Counter(h) for h in hunk]  # copies, not set membership: a row can repeat (#3441)
            gone = collections.Counter({x: min(n[2][x], c - n[0][x]) for x, c in n[1].items() if c > n[0][x]})
            cut = collections.Counter({x: min(n[0][x], c - n[2][x]) for x, c in n[1].items() if c > n[2][x]})  # main deleted it: the union kept it too (#3401 L3)
            edit = {key(x): x for x in pr if key(x) in {key(g) for g in +gone}}
            out[0].extend(_less(pr, cut) + _less(main, gone))
            left, moved = gone.copy(), []
            for x in main:
                moved.append(edit.get(key(x), b"") if left[x] > 0 else x)
                left[x] -= 1
            out[1].extend(moved + _less([x for x in pr if x not in edit.values()], cut))
            out[2].extend(pr + main)
            hunk, conflicts = None, conflicts + 1
        elif FIRST_CELL.match(line):
            hunk[side].append(line)
        else:
            return False  # a hunk that is not all table rows, or a marker out of order
    want = _git(cwd, "show", f"{head}:{path}", ok=(0, 128))
    # merge-file's diff can align the file unlike merge-tree's: the union of its hunks must be the replay (#3401)
    replay = _git(cwd, "show", f"{tree}:{path}", ok=(0, 128))
    return (hunk is None and conflicts > 0 and b"".join(out[2]) == replay and want in (b"".join(out[0]), b"".join(out[1]))
            and not _duplicate_id(want) and _same_mode(cwd, tree, head, path))


def _appends_kept(cwd, tree, head, path, reviewed, onto):
    """True when DECISIONS.md conflicted in the replay only where both sides appended table rows at one spot (an
    empty base section), and `head` keeps both sides' rows, every conflict in the same order: the reviewed rows
    first or main's first. Main's rows stay verbatim; a reviewed row may differ only in its first-cell ID (a
    renumbering past main's rows, #4030), when no other file the PR changes, and no line of this one outside main's
    rows and ID cells, names its old ID. Any other conflict, line or order reads as changed."""
    if path != "DECISIONS.md":
        return False
    text, want = (_git(cwd, "show", f"{t}:{path}", ok=(0, 128)) for t in (tree, head))
    if not text or not want:
        return False
    out, block, side, conflicts = ([], []), None, 0, 0  # (line, side) pairs: True reviewed, False main's, None outside
    for line in text.splitlines(keepends=True):
        bare = line.rstrip(b"\n")
        if block is None:
            if bare == b"<<<<<<< " + reviewed.encode():
                block, side = ([], []), 0
            else:
                for o in out:
                    o.append((line, None))
        elif side == 0 and bare.startswith(b"||||||| "):
            side = 1  # base section: must stay empty
        elif side == 1 and bare == b"=======":
            side = 2
        elif side == 2 and bare == b">>>>>>> " + onto.encode():
            out[0].extend(block[0] + block[1])
            out[1].extend(block[1] + block[0])
            block, conflicts = None, conflicts + 1
        elif side in (0, 2) and line.startswith(b"|"):
            block[side // 2].append((line, side == 0))
        else:
            return False
    if block is not None or conflicts == 0 or _duplicate_id(want) or not _same_mode(cwd, tree, head, path):
        return False
    lines = want.splitlines(keepends=True)
    for o in out:
        old = set()
        if len(o) == len(lines) and all(x == y or (mine and ROW_ID.match(x) and ROW_ID.match(y)
                                                   and ROW_ID.sub(b"|#|", x) == ROW_ID.sub(b"|#|", y)
                                                   and not old.add(ROW_ID.match(x).group().strip(b"| ")))
                                        for (x, mine), y in zip(o, lines)):
            # The PR's rows and lines outside main's rows, read without ID cells, must not name an old ID (#4041).
            rest = b"".join(ROW_ID.sub(b"|#|", y) for (_, mine), y in zip(o, lines) if mine is not False)
            return not old or not (_names(old, rest) or _cited(cwd, onto, head, old, path))
    return False


def _cited(cwd, onto, head, ids, path):
    """True when a file other than `path` that onto..head changes names one of `ids` as a word in `head`."""
    files = [f for f in _git(cwd, *DIFF, onto, head).decode(errors="surrogateescape").split("\0") if f and f != path]
    return any(_names(ids, _git(cwd, "show", f"{head}:{f}", ok=(0, 128))) for f in files)


def _names(ids, text):
    """True when `text` names one of `ids` as a word."""
    return bool(re.search(rb"(?<![\w-])(?:" + b"|".join(map(re.escape, sorted(ids))) + rb")(?![\w-])", text))


def _lines_kept(cwd, tree, head, path, reviewed, onto):
    """True when `path` is an allowlist (`*_allow.txt`, one entry per line, order free) and `head`'s lines, as a
    multiset, are main's plus the lines the reviewed commit added less those it removed: a main-merge that kept
    both sides of a conflict at one spot (#3991) reads as same in any order. Any other line reads as changed."""
    if not path.endswith("_allow.txt"):
        return False
    bases = _git(cwd, "merge-base", "--all", reviewed, onto).decode().split()
    if len(bases) != 1 or not _same_mode(cwd, tree, head, path):
        return False
    # Split on \n only, as the readers do: bytes.splitlines() also splits on \r and would count unread entries (#4041).
    pr, mb, main, want = (collections.Counter(_git(cwd, "show", f"{t}:{path}", ok=(0, 128)).split(b"\n"))
                          for t in (reviewed, bases[0], onto, head))
    return main + (pr - mb) - (mb - pr) == want


def compare(cwd, reviewed, head="HEAD", base="origin/main"):
    onto = _git(cwd, "merge-base", base, head).decode().strip()
    tree = _replayed(cwd, reviewed, onto)
    out = _git(cwd, *DIFF, tree, head).decode(errors="surrogateescape")
    differ = {f for f in out.split("\0") if f}
    # The files the PR or the replay touched: a union can undo a PR's change, leaving tree equal to onto (#1912).
    pr = _git(cwd, "merge-base", reviewed, onto).decode().strip()
    touched = (_git(cwd, *DIFF, onto, tree) + b"\0" + _git(cwd, *DIFF, pr, reviewed)).decode(errors="surrogateescape")
    kept = {f for f in touched.split("\0") if f and f not in differ and _broken(cwd, tree, f, reviewed, onto)}
    return sorted(kept | {f for f in differ if not _renumbered_only(cwd, tree, head, f, reviewed, onto)
                          and not _appends_kept(cwd, tree, head, f, reviewed, onto)
                          and not _lines_kept(cwd, tree, head, f, reviewed, onto)
                          and not _stale_dropped(cwd, tree, head, f, reviewed, onto)})


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


# #3611: a Record line with a spaced package never parsed, so the accept read as absent; name that too.
UNPARSED = 'unparsed-record {}: Record line must be "Record: PR #{} · package <ID-without-spaces> · head <sha>"'


# #3856 (seen on #3842): a Record head no `git rev-parse` resolves crashed --check with a traceback; name it as never accepting.
UNRESOLVED = "unresolved-record {}: Record head {} resolves to no single commit here, post a new verdict naming the reviewed head"


def _resolves(sha):
    return subprocess.run(["git", "rev-parse", "-q", "--verify", f"{sha}^{{commit}}"], capture_output=True).returncode == 0


def _named(v, kind, pr):
    """The named cause a verdict `v` of `kind` never accepts, or None."""
    if v and v[0] == "accept" and not _resolves(v[1]):
        return UNRESOLVED.format(kind, v[1])
    if v and v[0] == "edited":
        return EDITED.format(kind)
    if v and v[0] == "unparsed":
        return UNPARSED.format(kind, int(pr))
    return None


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
        if v is None or v[0] != "accept" or _named(v, "l3", pr):
            print("no-verdict" if v is None else _named(v, "l3", pr) or "not-accepted")
            return 1
        head = args[0] if args else "HEAD"
        changed = compare(".", v[1], head, base)
        if changed:
            print("changed " + " ".join(changed))
            return 1
        files = mark_range(".", base, head)
        owed = {x: verdict(comments, pr, lens=x) for x in lenses_owed(files)}
        lenses = [x for x, lv in owed.items() if not _accepted(lv, head, base)]
        for state in ("edited", "unparsed"):
            hit = [x for x in lenses if owed[x] and owed[x][0] == state]
            if hit:
                print(_named((state,), ",".join(hit), pr))
                return 1
        hit = [m for m in (_named(owed[x], x, pr) for x in lenses) if m]
        if hit:
            print(hit[0])
            return 1
        if lenses:
            print("needs-lens " + ",".join(lenses))
            return 1
        tier, top = risk_tier.tier_of_change(files)
        owed = sorted(set(mark_paths(files)) | set(top if tier == "A" else []))  # #3817: tier A too (OPERATING §4 4a)
        sec = verdict(comments, pr, security=True)
        if owed and not _accepted(sec, head, base):
            print(_named(sec, "security", pr) or "needs-security " + " ".join(owed))
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
