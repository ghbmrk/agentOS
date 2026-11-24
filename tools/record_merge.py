#!/usr/bin/env python3
"""Merge driver for the record and allow files (CLASSES): lines merge by key (#6316, #6358, #6375).

  tools/record_merge.py --install            once per clone: this clone's merges of the record files use the driver
  tools/record_merge.py BASE OURS THEIRS [PATH]   git's driver call (%O %A %B %P); writes the merge to OURS

CLASSES lists the record and allow files by class, the one list `--install`, doclint's `record_files` and
`.gitattributes` follow (a test holds `.gitattributes` to it; doclint reports a record or allow file outside it).
Every allow or exit list a gate tool reads goes through `listed` or `read_list`, which refuse a file CLASSES does not
declare (#6441); a `list` file is declared by its path and merged by git as text, never by this driver.
A `row` line's key is the row ID of an ASSUMPTIONS.md table row and an `entry` line's, in a MUTANTS-EQUIVALENT, the
entry less its proof (`reason`, `accepted`: premerge's `_entry_keys`), so two lines with one key name one row or
one mutant twice. An allow file's `line` is its own key, and the driver merges only hunks where both sides appended
at one spot and neither appended a section header: an allow line edited or deleted beside the other side's change
stays a conflict, since a union could bring back an exit one side closed, and so does a header, which would move
the other side's appends into its section. `.gitattributes` gives the row and entry files `merge=union`, which CI's merges
(premerge's replay, trusted-base, lookup) keep reading, and every class `text eol=lf`, so git commits a CRLF line as
its LF twin. Git runs no command a repository names until the clone's own config does, so `--install` sets
`merge.records.driver` and puts `<pattern> merge=records` for each class in `info/attributes`, which outranks
`.gitattributes` for this clone only. A clone without it merges as before; doclint and mutgate still fail one key on
two different lines, and doclint's error names the install (OPERATING §7).

The driver runs `git merge-file --diff3` on the three versions and resolves each conflict hunk whose lines are
all record lines as union by key: the ours lines, then the theirs lines, less each base line the other side changed
or deleted. That is premerge's first resolution of a union hunk (`_stale_dropped`, `_records_kept`), so CI reads
the result as `same` beside the reviewed commit. A record line both sides add word for word (two PRs carrying one
proof) is kept once: an identical duplicate is a no-op here, in doclint, in mutgate and in premerge (#6358). A line
both sides changed, differently, or one side changed and the other deleted, and any hunk holding a line that is no
record line, keep conflict markers; a result with one key on two different lines (both sides added one ID, or two
proofs of one mutant) keeps both and prints them. Either exits 1, so git stops the merge for the builder to
resolve (renumber the PR's row, or keep main's proof and drop the PR's), which premerge reads as `same`
(#6472); keeping the PR's proof edits a main line and reads `changed`. A side holding a carriage
return is refused, as doclint and mutgate refuse one: record and allow files end lines in LF only, so every reader
reads one line the same way (#6375). Standard library only.
"""
import collections
import fnmatch
import json
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

FIRST_CELL = re.compile(rb"^\|[ \t]*([^|\s][^|]*?)[ \t]*\|")  # premerge.py's FIRST_CELL
LABELS = ("ours", "base", "theirs")
DRIVER = "python3 tools/record_merge.py %O %A %B %P"
RECORD = "MUTANTS-EQUIVALENT"  # tools/mutgate.py's RECORD: one JSON entry per line, `#` and blank lines comments
# The record, allow and exit files by class (#6375, #6441): see the module docstring. A key without a `/` is a
# file-name pattern; one with a `/` declares one repository path. A `list` is an allow or exit list a gate tool reads
# whole (read_list): LF text, merged by git as text, never by the driver and never read as same by premerge.
CLASSES = {"broker/core/core.txt": "list", "tools/trusted_core.txt": "list", "tools/ceilings.txt": "list",
           "tools/trusted_base_parsers.txt": "list", "tools/trusted_base_reasons.txt": "list",
           "tools/word_budget_reasons.txt": "list",
           "tools/old_core.txt": "list", "tools/assumptions_legacy_ids.txt": "list",
           "tools/brief_acceptance_baseline.txt": "list", "tools/hostcheck_hw8.json": "list",
           "ASSUMPTIONS.md": "row", RECORD: "entry", "*_allow.txt": "line", "*.allow": "line", "allow*.txt": "line"}
DRIVEN = ("row", "entry", "line")  # the classes the driver merges; --install points only these at it


def record_class(path):
    """The class of `path` in CLASSES, or None for a file in none: a declared path matches the path or its end (a
    tree checked out elsewhere), a pattern the file name."""
    p = pathlib.PurePosixPath(path)
    return next((c for k, c in CLASSES.items() if (f"/{p.as_posix()}".endswith(f"/{k}") if "/" in k
                                                   else fnmatch.fnmatchcase(p.name, k))), None)


def listed(path):
    """The class of an allow or exit list a gate tool reads, or SystemExit naming the file when CLASSES declares it
    in no class (#6441): a list cannot escape its class rules by having a new name."""
    cls = record_class(path)
    if cls is None:
        raise SystemExit(f"{path}: read as an allow or exit list, but in no class of tools/record_merge.py's CLASSES; "
                         "declare it there and in .gitattributes")
    return cls


def read_list(path, name=None):
    """The text of the declared list at `path` (looked up as `name` when given: a copy of that list checked out
    elsewhere), line ends untranslated; SystemExit when it is in no class (listed)."""
    listed(name or path)
    return pathlib.Path(path).read_bytes().decode("utf-8", "replace")


def _section(line):
    """True for an allow file's section header (`[cipher]` in image/import_sweep.allow): the lines after it are
    read in its section, so a hunk holding one never merges by line (#6418 Security: a header one side appended
    would take in the other side's appends)."""
    return line.lstrip().startswith(b"[")


def _is_record(path):
    return record_class(path) == "entry"


def _row_key(line):
    m = FIRST_CELL.match(line)
    return m and m.group(1)


def entry_key(line):
    """A MUTANTS-EQUIVALENT line's key: its entry less `reason` and `accepted` (premerge's `_entry_keys`), or None
    for a comment, a blank line or a line that is no JSON object."""
    if not line.strip() or line.lstrip().startswith(b"#"):
        return None
    try:
        e = json.loads(line)
    except ValueError:
        return None
    if not isinstance(e, dict):
        return None
    return json.dumps({k: v for k, v in e.items() if k not in ("reason", "accepted")}, sort_keys=True)


def _less(rows, drop):
    """`rows` less the first drop[x] copies of each row x, in order."""
    drop, out = drop.copy(), []
    for x in rows:
        if drop[x] > 0:
            drop[x] -= 1
        else:
            out.append(x)
    return out


def resolve(ours, base, theirs, key=_row_key):
    """The lines of one conflict hunk merged by key, or None when it stays a conflict."""
    if not all(key(x) for x in ours + base + theirs):
        return None
    for k in {key(x) for x in base}:
        o, b, t = (collections.Counter(x for x in side if key(x) == k) for side in (ours, base, theirs))
        if o != b and t != b and o != t:
            return None  # changed differently on both sides, or changed on one and deleted on the other
    n = [collections.Counter(h) for h in (ours, base, theirs)]
    gone = collections.Counter({x: min(n[2][x], c - n[0][x]) for x, c in n[1].items() if c > n[0][x]})
    cut = collections.Counter({x: min(n[0][x], c - n[2][x]) for x, c in n[1].items() if c > n[2][x]})
    both = (n[0] - n[1]) & (n[2] - n[1])  # a line both sides added word for word is one addition (#6358, #6375)
    return _less(ours, cut) + _less(_less(theirs, gone), both)


def keyed(text, path="ASSUMPTIONS.md"):
    """[(line, key or None)] for `text`'s lines, ends kept: a MUTANTS-EQUIVALENT entry's key, or the row ID of a table
    row, doclint's assumption_ids rule (premerge `_duplicate_id`). An allow file's lines are keyed only inside a
    hunk: one may repeat a line in another section, so none is dropped or compared file-wide."""
    if record_class(path) == "line":
        return [(line, None) for line in text.splitlines(keepends=True)]
    if _is_record(path):
        return [(line, entry_key(line)) for line in text.splitlines(keepends=True)]
    out, in_table = [], False
    for line in text.splitlines(keepends=True):
        cells = [c.strip() for c in line.decode(errors="surrogateescape").strip().strip("|").split("|")]
        k = None
        if not line.startswith(b"|"):
            in_table = False
        elif cells[0] in ("ID", "#"):
            in_table = True
        elif in_table and not set(cells[0]) <= set("-: "):
            k = cells[0]
        out.append((line, k))
    return out


def once(text, path="ASSUMPTIONS.md"):
    """`text` less each keyed line that repeats an earlier one word for word: an identical duplicate (#6358)."""
    seen, out = set(), []
    for line, k in keyed(text, path):
        bare = line.rstrip(b"\r\n")
        if k is None or bare not in seen:
            out.append(line)
        if k is not None:
            seen.add(bare)
    return b"".join(out)


def duplicates(text, path="ASSUMPTIONS.md"):
    """Keys `text` holds on two different lines, each with its distinct lines; an identical duplicate is none."""
    lines = collections.defaultdict(list)
    for line, k in keyed(text, path):
        bare = line.rstrip(b"\r\n").decode(errors="surrogateescape")
        if k is not None and bare not in lines[k]:
            lines[k].append(bare)
    return {k: v for k, v in lines.items() if len(v) > 1}


def merge(base, ours, theirs, path="ASSUMPTIONS.md"):
    """(merged bytes, clean) for three versions of a record file; (None, False) when `git merge-file` fails, a
    version holds a carriage return (#6375) or the file is in no class the driver merges (DRIVEN, #6441)."""
    cls = record_class(path)
    if cls not in DRIVEN or any(b"\r" in text for text in (base, ours, theirs)):
        return None, False
    mark = secrets.token_hex(16)  # labels no file can carry
    with tempfile.TemporaryDirectory() as d:
        names = [pathlib.Path(d, n) for n in LABELS]
        for name, text in zip(names, (ours, base, theirs)):
            name.write_bytes(text)
        run = subprocess.run(["git", "merge-file", "-p", "--diff3", *(f"-L{mark}{i}" for i in range(3)),
                              *map(str, names)], cwd=d, capture_output=True)  # no repository read (records_audit)
    if not 0 <= run.returncode <= 127:  # merge-file counts conflicts up to 127; above is an error (a binary file)
        return None, False
    merged = run.stdout
    out, hunk, side, clean = [], None, 0, True
    for line in merged.splitlines(keepends=True):
        bare = line.rstrip(b"\r\n")
        if hunk is None and bare == f"<<<<<<< {mark}0".encode():
            hunk, side = ([], [], []), 0
        elif hunk is None:
            out.append(line)
        elif bare == f"||||||| {mark}1".encode() and side == 0:
            side = 1
        elif bare == b"=======" and side == 1:
            side = 2
        elif bare == f">>>>>>> {mark}2".encode() and side == 2:
            rows = (None if cls == "line" and (hunk[1] or any(map(_section, hunk[0] + hunk[2])))
                    else resolve(*hunk, key={"row": _row_key, "entry": entry_key, "line": bytes}[cls]))
            if rows is None:
                clean = False
                out += [b"<<<<<<< ours\n", *hunk[0], b"||||||| base\n", *hunk[1], b"=======\n", *hunk[2],
                        b">>>>>>> theirs\n"]
            else:
                out += rows
            hunk = None
        else:
            hunk[side].append(line)
    # Conflict markers stay as git wrote them; a clean merge drops each identical duplicate (#6358).
    return (once(b"".join(out), path) if clean else b"".join(out)), clean


def install(cwd="."):
    """Point this clone's merges of the record files at the driver; running it again changes nothing."""
    git = lambda *a: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
    git("config", "merge.records.name", "record lines by key (tools/record_merge.py)")
    git("config", "merge.records.driver", DRIVER)
    attrs = pathlib.Path(cwd, git("rev-parse", "--git-path", "info/attributes"))
    old = attrs.read_text() if attrs.exists() else ""
    if new := [f"{name} merge=records" for name, c in CLASSES.items()
               if c in DRIVEN and f"{name} merge=records" not in old.splitlines()]:
        attrs.parent.mkdir(parents=True, exist_ok=True)
        attrs.write_text(old + ("" if not old or old.endswith("\n") else "\n") + "".join(x + "\n" for x in new))


def main(argv):
    if argv == ["--install"]:
        install()
        return 0
    if len(argv) not in (3, 4):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    path = argv[3] if len(argv) == 4 else argv[1]
    if record_class(path) not in DRIVEN:
        print(f"{path}: no record or allow file the driver merges (tools/record_merge.py CLASSES); ours is left as it was",
              file=sys.stderr)
        return 1
    base, ours, theirs = (pathlib.Path(a).read_bytes() for a in argv[:3])
    text, clean = merge(base, ours, theirs, path)
    if text is None:  # Security on #6341: a NUL byte made merge-file fail and the driver wrote an empty file
        print(f"{path}: a version holds a carriage return (record and allow files end lines in LF only), or git "
              "merge-file could not merge it (a binary byte?); ours is left as it was", file=sys.stderr)
        return 1
    pathlib.Path(argv[1]).write_bytes(text)
    if not clean:
        print(f"{path}: a line both sides changed, or a non-record line, is left in conflict markers", file=sys.stderr)
    for k, lines in sorted(duplicates(text, path).items()):
        clean = False
        what = "one mutant proved twice, keep one proof" if _is_record(path) else f"row ID {k} twice, renumber the PR's row"
        print(f"{path}: {what}:", *lines, sep="\n  ", file=sys.stderr)
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
