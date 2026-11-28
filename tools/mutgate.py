#!/usr/bin/env python3
"""Mutation testing on the tier-A and tier-B broker packages (MUT-tierA, #1814; REV-PROOF-mut, #4908).

Runs gremlins (github.com/go-gremlins/gremlins, an existing Go mutation tool) per package,
reports the surviving mutants, and fails a PR where a mutant survives on a line it changes.

  tools/mutgate.py packages                  list the tier-A and tier-B broker packages
  tools/mutgate.py claimed --git BASE [HEAD] [--json]
                                             the listed packages where the diff BASE...HEAD adds or
                                             changes a line of a .go file or changes the package's
                                             MUTANTS-EQUIVALENT record: the only ones the gate can
                                             fail, so the only ones CI runs gremlins on
  tools/mutgate.py plan --git BASE [--targets-out FILE]
                                             the `mutants` matrix as JSON: K shards for each claimed
                                             package, K from its target lines, deletion sites and
                                             suite time (#4961, #5069), one job each, or past 256
                                             jobs several a job (#6170); FILE gets the lines each
                                             package's changed tests cover
  tools/mutgate.py run [PKG...] [--out DIR] [--git BASE [--shard I --of K] [--targets FILE]]
                                             run gremlins per package (default: all listed),
                                             one JSON file per package in DIR (default mutants/);
                                             with --git, only on the package's target lines (below),
                                             and with --shard, only on shard I of K of them; with
                                             --targets, changed tests' lines are plan's FILE's
  tools/mutgate.py delete PKG... [--out DIR] --git BASE [--jobs N]
                                             delete each statement a target line belongs to, alone,
                                             on N parallel workers (default: one per usable CPU; a
                                             detected verdict is confirmed alone), run the tests that
                                             cover it (#6172), or a listed source lint where
                                             they pass (LINTS, #6346), and
                                             add the verdicts to `run`'s JSON in DIR (#4573, #4603, #4633);
                                             only the sites of the result's own shard
  `plan`, `delete` and `run --git` run in a copy of the working tree (scratch, #6456), without every
  broker/ Markdown file whose edit changes no test (hide_docs, #6373).
  tools/mutgate.py report DIR                survivors per package, from the JSON in DIR
  tools/mutgate.py gate DIR --git BASE [HEAD] [--body FILE [--body-from SHA]] [--summary FILE]
                                             exit 1 if a LIVED mutant sits on a target line that no
                                             entry of its package's record names, or a record
                                             entry is stale; FILE (the PR body) waives nothing (#6379)
  tools/mutgate.py verify DIR --git BASE [HEAD] [--body FILE [--body-from SHA]] [--summary FILE]
                                             `gate`, after checking that DIR/*/ (and DIR/*/*/) holds exactly
                                             one readable result for each shard of every package
                                             `claimed` names, as `run` and `delete` check it, with
                                             one deletion verdict for each site it lists itself,
                                             then joining the shards: CI's trusted job (#4106,
                                             #4602, #4961)
  tools/mutgate.py waive FILE --accepted '#PR' write the `Mutant-equivalent:` lines in FILE into
                                             their packages' records, keyed by statement (#5776)
  tools/mutgate.py records [PKG...]          each record entry's line at the working tree, or why
                                             it names none (default: every gated package's record)

Target lines. A package's target lines are the lines the diff adds or changes in its non-test .go
files (no `REQ:` marker is needed, #4908). When the diff also changes or deletes the package's
_test.go files, they include the lines of its non-test files that the test functions reaching the
changed lines run, even beside an added line, which would otherwise hide a deleted test's lines (#5762):
`run` names them with one `go test -run '^(T1|T2)$' -coverprofile` run and records them in the result.
A changed helper, type or import reaches the tests that name it, transitively, read as text
(reaching_tests, D-319), and a declaration that only moved, within or across the package's .go files, reaches
none, nor does an import change that rebinds no name (moved, #6369); a change every test may run (TestMain, init, a package var's initializer)
runs every test, so the set is at most the package's covered lines. A weakened test (a t.Skip, an early
return, a build tag, a deletion) runs nothing at the head, so the base's version of the tests reaching
the changed base lines (every base test when either side reaches every test) also runs, on a `git archive` of
the base, its lines moved to the head's; the record holds both. A mutant NOT COVERED on any target
line fails the gate, in every gated package (#5762; #5779 for packages whose tests the diff leaves
alone): a weakened test plus an edit to the lines it ran, or a moved file, drops those lines from the
base record's mapping, and new code no test runs (code moved in with its test left behind) is unchecked.
A changed file of a package that is not its Go code (anything under testdata/, and a non-.go file a
.go file of the package can name, such as an embedded or read file) changes its tests, every one of
them (data_owner, #5779): emptying a test's table weakens it with no _test.go line changed. So does
any file, in the repository or another package, that a package's .go file names by its exact path
from the package's directory ("../../SPEC.md"; readers, #6436). Only the tests reaching its namer
change when that is an embedding var or recognised read calls alone (narrowing, #6458, #6657). vendor/ changes no test: CI rebuilds
it with `go mod vendor` and fails any difference (is_vendored). Coverage can differ from run to run
(a timing branch, a retry), so in CI `plan` measures it once and every shard reads that one record
(`--targets`), never a coverage run of its own: K shards of one package then name the same lines (#4970). Gremlins mutates a package's target
lines only: its `-D` reads `git diff --merge-base`, so for a package whose tests changed `run` points HEAD for
that one call at a commit whose parent differs from the tree on exactly those lines.
A LIVED mutant on a target line is code the package's tests run (gremlins mutates only covered
code) but do not check, and fails the gate, unless its package's record, broker/<pkg>/MUTANTS-EQUIVALENT
(see RECORD below), holds an entry for it: one mutant, one reason the reviewer checks, never a range or
pattern. `waive` writes entries from lines `Mutant-equivalent: broker/<pkg>/<file>.go:<line>[:<col>][:<KIND>]
<reason>` (spelled `Mutant-uncovered:` for a NOT COVERED one no test can reach, #5779; the two are one
waiver), keyed by statement, so a run that widens the targets reads it and a moved line keeps it; an
entry whose statement changed is stale and fails (#5776). A waiver that matches more than one mutant of
the result on its line (two comparisons of one kind, or a deletion and a comparison, with no column
or kind to tell them apart) waives none of them (#5792). The PR body waives nothing (#6379): it can change
after a review without changing the head, so a waiver lives only in the record the head holds.
Gremlins' coverage run is the only judge of "covered".
Go's cover blocks hold no `case` expression, so that run's profile, and covered_by's, gains a ran block
for each clause expression a ran clause body shows evaluated (with_cases, #5822): gremlins runs those
mutants rather than reading them NOT COVERED. Nor do they hold a statement's code after a func literal
(`IndexFunc(s, func(r rune) bool {...}) >= 0`), so the profile also gains a ran block for that code
wherever the statement's block ran (literal_tails, #5909).
The gate reads no other line, and gremlins tests each mutant alone, so `run --git` mutates only
target lines (60-minute timeouts on #4014) and the gate decides the same; `run` fails if gremlins
skipped a mutant on a target line, so a diff gremlins reads differently cannot pass the gate empty.
Gremlins v0.6.0 has no mutator that deletes a statement, and the survivors that broke a bound on
#4525 and #4560 were deleted statements (a state reset, a ctx check), so `delete` adds that one
mutant kind itself: each statement in a covered statement list that a target line of its own
syntax is in (not only its first, #4603) is deleted alone, the package's tests run, and the verdict
joins gremlins' JSON as a STATEMENT_DELETION mutant on the first such line, with the test that
failed first, which the gate reads as it reads gremlins' own (#4573). The sites run on parallel
workers (#4633). `verify --summary` writes one table of every mutant on a target line and its
verdict, so a reviewer reads it rather than re-running mutants.
Shards (#4961). A package's mutants can take longer than one CI job may run, so its target lines
and deletion sites are split round-robin into K shards (`shard_lines`, `deletion_sites`' order), one
`mutants` job each, or past GitHub's 256 jobs a matrix, up to 5 a job one after another, each in its
own result directory and stopped at its own 60 minutes (`pack`, #6170). Gremlins tests every mutant alone with the whole package suite, and `delete`
deletes every statement alone and runs the tests whose runs alone cover it, or the whole suite (#6172),
so a mutant's verdict does not depend on which other mutants share its job: the joined shards give the
verdicts one job would. K is only a
schedule, so it may come from the untrusted `plan` job: `verify` refuses a package unless its
results agree on K and hold each shard 0..K-1 exactly once, each with only its own lines' and
sites' mutants, so a missing or overlapping shard fails and the join covers every target.
CI runs the PR's tests in the `mutants` jobs, and a test can write anything there, so those jobs
only hand their JSON on as data; the `mutgate` job, which runs no PR code, takes this file from the
base commit and decides with `verify` (#4106), which lists the deletion sites itself (#4602) and
names the changed test functions itself; the lines they cover come from the result, as data, as
every verdict does.
Install: go install github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0
"""
import argparse
import bisect
import codecs
import collections
import concurrent.futures
import contextlib
import ctypes
import fnmatch
import functools
import glob
import hashlib
import json
import math
import os
import pathlib
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import risk_tier  # noqa: E402

BROKER = ROOT / "broker"
HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
GATED_TIERS = ("A", "B")
# Go source holds a top-level declaration only at column 0 (gofmt), so these lines split a file
# into declarations; a test function is one of them whose name `go test -run` selects.
DECL = re.compile(r"^(?:func|type|var|const|import|package)\b")
TEST_FUNC = re.compile(r"^func ((?:Test|Fuzz|Example)(?![a-z])\w*)\(")
# A waiver line, as `waive` reads it, for one mutant: an exact repo path and line, optionally the mutant's column and
# kind, then a reason. A waiver that matches more than one mutant of the result waives none (#5792).
EQUIVALENT = re.compile(r"^Mutant-(?:equivalent|uncovered): (broker/[^\s:*?\[\]]+\.go):([1-9]\d*)(?::([1-9]\d*))?(?::([A-Z][A-Z_]{0,63}))?"
                        r" +(\S.*?)\s*$")
# A reason that says its mutant is not equivalent is no proof (#5891, from #5863 and #5883): waive refuses it, so a real survivor never becomes a
# record entry that later gates read as proved. A record entry holding one fails `records` and the gate,
# and waive writes nothing to its record (#5909). Case and the space or hyphen between the words are ignored.
NOT_EQUIVALENT = re.compile(r"\bnot[\s-]+equivalent", re.IGNORECASE)
# The kinds a waiver can name (#5828): gremlins v0.6.0's mutator types (internal/mutator/mutator.go, the
# version the workflow installs) and delete's STATEMENT_DELETION. A line naming another proves nothing.
KINDS = frozenset({"ARITHMETIC_BASE", "CONDITIONALS_BOUNDARY", "CONDITIONALS_NEGATION", "INCREMENT_DECREMENT",
                   "INVERT_ASSIGNMENTS", "INVERT_BITWISE", "INVERT_BWASSIGN", "INVERT_LOGICAL", "INVERT_LOOPCTRL",
                   "INVERT_NEGATIVES", "REMOVE_SELF_ASSIGNMENTS", "STATEMENT_DELETION"})
# A line where no letter precedes a waiver's start (a checked task-list box aside): an indent or any Markdown
# a file wraps lines in, a backtick, bullet, task box, quote, heading, bold or table cell, which waivers
# does not read (L3 on #5976). Prose that names one after a word is not a waiver line.
WAIVER_START = re.compile(r"^(?:[^A-Za-z]|\[[xX]\])*Mutant-(?:equivalent|uncovered):", re.IGNORECASE)


# A package name that reaches the workflow's matrix: path segments of plain characters only.
PKG_NAME = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def gated_packages(broker=BROKER):
    """Package paths under broker/ that hold Go source with a file risk_tier.tier_of puts in tier A or B, sorted.

    Every .go file is classed by tier_of, so packages under a prefix line (kernel/privfile,
    clerk/inbox/imapsmtp) and unlisted ones count, as risk_tier counts them (#3948). A listed
    package whose path PKG_NAME refuses raises, rather than dropping out of the gate unseen.
    """
    files = {}
    for f in broker.rglob("*.go"):
        rel = f.parent.relative_to(broker).as_posix()
        if rel != "." and not {"vendor", "testdata"} & set(rel.split("/")):
            files.setdefault(rel, []).append(f"broker/{rel}/{f.name}")
    out = sorted(rel for rel, fs in files.items() if any(risk_tier.tier_of(p)[0] in GATED_TIERS for p in fs))
    bad = [rel for rel in out if not PKG_NAME.fullmatch(rel)]
    if bad:
        raise ValueError(f"mutgate: package path(s) outside {PKG_NAME.pattern}: {bad}")
    return out


def result_name(pkg):
    """The JSON file name of a package's result: `/` as `+`, which PKG_NAME never holds, so no two
    packages share one (`a/b` and `a__b` did, and one's result stood in for the other's, #4106)."""
    return pkg.replace("/", "+") + ".json"


def survivors(results_dir):
    """{package: [(file, line, type, column)]} of LIVED mutants in the per-package JSON files."""
    out = {}
    for f in sorted(pathlib.Path(results_dir).glob("*.json")):
        pkg = f.stem.replace("+", "/")
        out[pkg] = survivors_of(json.loads(f.read_text()))
    return out


def uncovered_of(data):
    """[(file, line, type, column)] of NOT COVERED mutants in one package's JSON, sorted: on a target line,
    no test runs it at the head (#5762, #5779), which no LIVED mutant shows."""
    return mutants_of(data, "NOT COVERED")


def survivors_of(data):
    """[(file, line, type, column)] of LIVED mutants in one package's gremlins JSON, sorted."""
    return mutants_of(data, "LIVED")


_ESC = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _unquote(name):
    """Git's C-style quoted file name (`"b/h\\303\\251.go"`) as text."""
    out, i = bytearray(), 1
    while i < len(name) - 1:
        c = name[i]
        if c != "\\":
            out += c.encode()
        elif name[i + 1] in _ESC:
            out.append(_ESC[name[i + 1]])
            i += 1
        else:
            out.append(int(name[i + 1:i + 4], 8))
            i += 3
        i += 1
    return out.decode("utf-8", "replace")


def _header_path(raw, prefix="b/"):
    """The repo path a `+++ ` (or, with prefix a/, `--- `) header names, or None for /dev/null or
    another prefix (#4105)."""
    name = raw[4:].rstrip("\t")  # git appends a TAB after a name that holds a space
    if name.startswith('"'):
        name = _unquote(name)
    return name[2:] if name.startswith(prefix) else None


def is_source(path):
    return path.endswith(".go") and not path.endswith("_test.go")


def is_test(path):
    return path.startswith("broker/") and path.endswith("_test.go")


def is_vendored(path):
    """Whether a path is under broker/'s vendor/ tree, which no edit can change on its own: the
    required `checks` job reruns `go mod vendor` and fails on any difference, so its content is
    fixed by go.sum's modules and the local replace directories (third_party/, gated packages of
    their own). A test that reads it reads those, and an edit to it claims no package (#6436)."""
    parts = path.split("/")
    return parts[0] == "broker" and "vendor" in parts[1:-1]


def is_data(path):
    """Whether a broker/ path is a package's file but not its Go code: anything under a testdata/
    directory, or a non-.go file other than a MUTANTS-EQUIVALENT record (read by records_changed)."""
    parts = path.split("/")
    return (parts[0] == "broker" and len(parts) > 2 and not is_vendored(path) and parts[-1] != RECORD
            and ("testdata" in parts[1:-1] or not parts[-1].endswith(".go")))


# Edits that set Go's defaults for a whole package or module (MUT-go-debug-every-fu, #6420): a package-wide
# `//go:` line (not LOCAL_DIRECTIVES) of a non-test file, which go reads in a main package (a GODEBUG default of
# its binaries and tests), and a broker/go.mod line that is a `go` or `godebug` directive or entry. Either is a
# change of every test there, as #6377's test-file line is. A -U0 hunk shows no enclosing block, so a go.mod line
# sets no default only when it is placed: blank, a comment, `)`, a directive of GO_MOD_QUIET (requirements and
# replacements are go.sum's and vendor/'s, is_vendored), or an
# indented entry of a module path or a retracted version, or a patch-level `go` swap (GO_VERSION); any other
# line fails closed to every test.
# A changed `toolchain` line is every test of each package holding such a `//go:` line (directive_packages):
# a new release can satisfy its file's `//go:build go1.N` line.
# A change anywhere in a non-test file holding such a `//go:` line on either side is one too (dormant).
MODULE_FILE = "broker/go.mod"
EVERY_TEST = "\0every-test"  # the name of added_lines' key for every test of a directory; no git path holds a NUL
DORMANT_TEST = "\0dormant-test"  # added_lines' key for every test of each package directive_packages names
GO_MOD_QUIET = {"module", "require", "exclude", "replace", "retract", "toolchain", "tool"}
GO_MOD_ENTRY = re.compile(r"[^\s/]*\.[^\s/]*(?:/\S*)?|\[?v\d\S*")
# One hunk that deletes one `go` line and adds one of the same major.minor (go_line) sets no default: the
# language version and the GODEBUG defaults follow go1.N (MUT-go-patch-quiet, #6567); any other shape widens.
GO_VERSION = re.compile(r"go\s+(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))?")


def _mod_line(text):
    """A go.mod line text with its comment, edge space and ` => ` separators dropped."""
    return re.sub(r"\s=>\s", " ", text.split("//", 1)[0].strip())


def go_line(path, text):
    """The (major, minor) of a changed line text of MODULE_FILE that is an unindented `go` directive,
    False for one whose version is not `N.N` or `N.N.N` (no leading zeros), None for any other line."""
    if path != MODULE_FILE or text[:1] in " \t" or re.match(r"[^\s(]*", _mod_line(text))[0] != "go":
        return None
    m = GO_VERSION.fullmatch(_mod_line(text))
    return m and (m[1], m[2])


def widened(path, text):
    """The added_lines key (a directory's EVERY_TEST) whose packages' tests a changed line text of path
    changes, every one, or None when it changes only its own code's."""
    if path == MODULE_FILE:
        s = _mod_line(text)
        first = re.match(r"[^\s(]*", s)[0]
        if first == "toolchain" and s != first:
            return f"broker/{DORMANT_TEST}"  # a new release tag can build a dormant directive's file (Security on #6558)
        if (s in ("", ")") or first in GO_MOD_QUIET and s != first
                or text[:1] in " \t" and "=" not in s and GO_MOD_ENTRY.fullmatch(first)):
            return None
        return f"broker/{EVERY_TEST}"
    m = DIRECTIVE.match(text.removeprefix("\ufeff"))  # go skips a file's leading BOM (go_text, L3 on #6558)
    if (path and path.startswith("broker/") and is_source(path) and not is_data(path) and not is_vendored(path)
            and m and m[1] not in LOCAL_DIRECTIVES):
        return f"{posixpath.dirname(path)}/{EVERY_TEST}"
    return None


def dormant(diff_text, base, head):
    """{key: None} of widened keys for the non-test broker .go files the diff changes in any way whose
    text at the merge base or at head holds a package-wide `//go:` line (not LOCAL_DIRECTIVES), read
    from git, comments included: an edit around an unchanged one (its file's `//go:build` line, a
    `/* */` pair) can switch it on (Security on #6558). A file absent on a side holds nothing there."""
    mb, paths, in_hunk = merge_base(base, head), set(), False
    for raw in diff_text.split("\n"):
        if raw.startswith("diff "):
            in_hunk = False
            paths.add(_diff_git_path(raw) if raw.startswith("diff --git ") else None)
        elif HUNK.match(raw):
            in_hunk = True
        elif not in_hunk and raw.startswith(("--- ", "+++ ")):
            paths.add(_header_path(raw, "a/" if raw.startswith("-") else "b/"))
    out = {}
    for path in paths:
        if path and path.startswith("broker/") and is_source(path) and not is_data(path) and not is_vendored(path):
            if any(m not in LOCAL_DIRECTIVES for rev in (mb, head)
                   for m in DIRECTIVE.findall(base_text(rev, path) or "")):
                out[f"{posixpath.dirname(path)}/{EVERY_TEST}"] = None
    return out


@functools.lru_cache(maxsize=None)
def directive_packages(broker):
    """The broker/ packages holding a non-test, non-vendored .go file whose text has a package-wide `//go:` line
    (not LOCAL_DIRECTIVES), comments included; a file go would not compile (go_text) counts, failing closed."""
    out = set()
    for d, dirs, files in os.walk(broker):
        dirs[:] = sorted(x for x in dirs if x not in ("vendor", "testdata") and x[0] not in "._")
        rel = pathlib.Path(d).relative_to(broker).as_posix()
        for f in files:
            if rel != "." and is_source(f):
                text = go_text(pathlib.Path(d, f).read_bytes())
                if text is None or any(m not in LOCAL_DIRECTIVES for m in DIRECTIVE.findall(text)):
                    out.add(rel)
    return frozenset(out)


@functools.lru_cache(maxsize=None)
def go_packages(broker):
    """The broker/ packages (as package_of names them) holding a .go file, vendor/ and testdata/ left out."""
    return frozenset(rel for f in broker.rglob("*.go")
                     if (rel := f.parent.relative_to(broker).as_posix()) != "."
                     and not {"vendor", "testdata"} & set(rel.split("/")))


def _diff_git_path(raw):
    """The repo path a `diff --git a/P b/P` header names (--no-renames: both sides are one path), or
    None when it does not parse. It names a change with no hunk (an empty file added or deleted, a
    mode change), which the ---/+++ headers do not."""
    rest = raw[len("diff --git "):]
    if rest.startswith('"'):
        i = 1
        while i < len(rest) and rest[i] != '"':
            i += 2 if rest[i] == "\\" else 1
        name = _unquote(rest[:i + 1])
    else:
        name = rest[:2 + max(0, (len(rest) - 5) // 2)]
        if rest != f"{name} b/{name[2:]}":
            return None
    return name[2:] if name.startswith("a/") else None


def added_lines(diff_text, moved=None):
    """({path: set(line)} of the lines the diff adds, {path: set(line) or None} of the broker/
    _test.go files it changes). A test file's set holds the lines it adds and, for a hunk that only
    deletes, the line either side; it is None when the diff deletes the file. What a deleted line
    reached is read at the base (base_test_lines). A changed data file (is_data) is in the second
    map too, as None, as is any other changed file a package names by path (readers, #6436): owners
    names the packages whose tests it changes (data_owner for a package's own data, #5779). moved is
    moved()'s pair: a test line it names at the head is no change, nor is a hunk or file deletion
    whose every base line it names (#6369). A hunk deleting any other base line always changes the
    file: when moved() names all its added lines, the line either side of them is touched (L3 and
    Security on #6378: a deleted test beside a moved-in declaration is one replace hunk)."""
    added, tests, path, old, line, in_hunk = {}, {}, None, None, 0, False
    at_head, at_base = moved or ({}, {})

    def gone(m):  # the hunk's base lines are all moved() lines: deleting them changes no test
        o = HUNKS.match(m.string)
        return bool(o) and o[2] != "0" and set(range(int(o[1]), int(o[1]) + int(o[2] or 1))) <= at_base.get(old, set())

    def touch(p, lines):
        if tests.get(p, ()) is not None:
            tests.setdefault(p, set()).update(lines)

    go_lines = []  # the current hunk's (sign, go_line) of MODULE_FILE `go` lines

    def settle():  # a hunk's go lines widen unless they are one patch-level swap (MUT-go-patch-quiet)
        signs, versions = sorted(x for x, _ in go_lines), {v for _, v in go_lines}
        if go_lines and not (signs == ["+", "-"] and len(versions) == 1 and all(versions)):
            tests[f"broker/{EVERY_TEST}"] = None
        go_lines.clear()

    def data(*paths):
        for p in paths:
            if p is not None and (is_data(p) or not is_test(p) and readers(p)) and not is_vendored(p):
                tests[p] = None

    # split("\n"), not splitlines(): that also breaks on \r, \x0b, \x0c, \x1c-\x1e, \x85, U+2028 and
    # U+2029, which a Go comment can carry, and every later added line would be numbered one low (#4028).
    for raw in diff_text.split("\n"):
        # Every line inside a hunk starts with space, + , - or \, so `diff ` can only be a file
        # header and a `+++ ` line is a header only before the first @@ (an added `++ x` is not one).
        if raw.startswith("diff "):
            settle()
            in_hunk, path, old = False, None, None
            if raw.startswith("diff --git "):
                data(_diff_git_path(raw))
            continue
        m = HUNK.match(raw)
        if m:
            settle()
            in_hunk, line = True, int(m.group(1))
            if path is None and old is not None and is_test(old):
                if not gone(m):
                    tests[old] = None  # the file is deleted
            elif path is not None and is_test(path) and not gone(m) and HUNKS.match(raw)[2] != "0":
                new = int(m.group(2) or 1)
                if new == 0:
                    touch(path, {line, line + 1})  # git numbers a deletion after new line `line`
                elif set(range(line, line + new)) <= at_head.get(path, set()):
                    touch(path, {n for n in (line - 1, line + new) if n > 0})
            continue
        if not in_hunk:
            if raw.startswith("--- "):
                old = _header_path(raw, "a/")
            elif raw.startswith("+++ "):
                path = _header_path(raw)
            data(old if raw.startswith("--- ") else path if raw.startswith("+++ ") else None)
            continue
        if raw[:1] in ("+", "-") and (go := go_line(path if raw[0] == "+" else old, raw[1:])) is not None:
            go_lines.append((raw[0], go))
        elif raw[:1] in ("+", "-") and (key := widened(path if raw[0] == "+" else old, raw[1:])):
            tests[key] = None
        if path is None or raw.startswith("\\"):  # "\ No newline at end of file" is no line (#4103)
            continue
        if raw.startswith("+"):
            added.setdefault(path, set()).add(line)
            if is_test(path) and line not in at_head.get(path, ()):
                touch(path, {line})
            line += 1
        elif not raw.startswith("-"):
            line += 1
    settle()
    return added, tests


def package_of(path):
    """The broker/ package directory of a repo path, as survivors() names it, or None."""
    parts = path.split("/")
    if parts[0] != "broker" or len(parts) < 3:
        return None
    return "/".join(parts[1:-1])


LITERAL = re.compile(r'"(?:[^"\\\n]|\\.)*"|`[^`]*`')
# A Go interpreted string's escapes (the spec's list), so "ASSUMPTIONS\x2emd" names ASSUMPTIONS.md.
ESCAPE = re.compile(r"\\(?:([0-7]{3})|x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|(.))", re.S)
# A literal of wildcards and slashes alone ("*", "*/*", "?") matches every name, so for a Markdown
# file it names none (_naming).
WILDCARDS = re.compile(r"[*?/]+")
SIMPLE = {"a": b"\a", "b": b"\b", "f": b"\f", "n": b"\n", "r": b"\r", "t": b"\t", "v": b"\v"}


def _go_string(lit):
    """The value of a literal _literals gave: an interpreted one's escapes decoded, a raw one as is."""
    def one(m):
        if m[1] or m[2]:
            return bytes([min(int(m[1] or m[2], 8 if m[1] else 16), 255)])  # Go refuses \400 and up
        if m[3] or m[4]:
            return chr(min(int(m[3] or m[4], 16), 0x10FFFF)).encode("utf-8", "replace")
        return SIMPLE.get(m[5], m[5].encode())
    out, at = b"", 0
    for m in ESCAPE.finditer(lit):
        out, at = out + lit[at:m.start()].encode() + one(m), m.end()
    return (out + lit[at:].encode()).decode("utf-8", "replace")


def _literals(text):
    """The values of a Go file's string literals, comments left out: what a test can name a file by."""
    return [_go_string(m[0][1:-1]) if m[0][0] == '"' else m[0][1:-1] for m in LITERAL.finditer(_uncommented(text))]


def _embeds(text):
    """The patterns of a Go file's //go:embed directives, an `all:` prefix dropped."""
    out = []
    for m in re.finditer(r"^[ \t]*//go:embed[ \t]+(.*)$", text, re.M):
        out += [w.strip('"`').removeprefix("all:") for w in m[1].split()]
    return out


def names_file(pkg_dir, rel):
    """Whether a .go file of pkg_dir names rel (a path below it) as text: a string literal (escapes
    decoded; one of wildcards alone left out, _naming) or //go:embed pattern holding its base name or
    first directory, or holding a glob (`*?[`) that matches its base name, rel or a leading directory of it, or whose last path part
    matches its base name (dir + "/*.md", "**/*.md"). A link or an unreadable file names anything.
    A file no code names this way is absent from every tree the gate runs tests in (hide_docs), so
    a read of it by any other means (a listing, a child process, a path built from runes, another
    package) fails the gate's run rather than going unseen (#6373)."""
    texts = []
    for f in sorted(pkg_dir.glob("*.go")):
        if f.is_symlink() or not f.is_file():
            return True
        if (text := go_text(f.read_bytes())) is None:
            return True
        texts.append(text)
    return any(_names(lit, rel) for text in texts for lit in _naming(text) + _embeds(text))


def _naming(text):
    """The string literals of a .go file that can name a file (_literals). One of wildcards alone
    (WILDCARDS) names nothing: a table's "*" or a DNS wildcard claimed every Markdown file of its
    package (#6584), and a listing by one reads only what a listing by "." reads, which hide_docs
    keeps the gate closed on (#6373). A //go:embed pattern of wildcards still names: it holds the bytes.
    Only Markdown files are hidden, so only names_file (read for those alone) drops them: embedded_by
    keeps every literal, as another data file a "*" lists stays in the tree."""
    return [x for x in _literals(text) if not WILDCARDS.fullmatch(x)]


def _names(lit, rel):
    """Whether one literal or embed pattern names rel, as names_file reads it."""
    parts = rel.split("/")
    names = [parts[-1]] + ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    if parts[-1] in lit or parts[0] in lit:
        return True
    return bool(re.search(r"[*?\[]", lit)) and (
        any(fnmatch.fnmatchcase(n, lit) for n in names)
        or fnmatch.fnmatchcase(parts[-1], lit.rstrip("/").rsplit("/", 1)[-1]))


# A //go:embed line and the package-level `var name Type` gofmt puts at column 0 under it, comment
# lines between (Go's rule: only blank lines and line comments may come between them). The name is
# unexported: another package's test could read an exported one, and read_index sees only literals.
EMBED_VAR = re.compile(r"^//go:embed[ \t]+(.*)\n(?://.*\n)*var ([a-z_]\w*)[ \t]+[^=\n(]+\n", re.M)


def _pkg_texts(pkg, texts=None):
    """{file name: text, or None for a link or unreadable file} of broker/<pkg>/'s .go files: texts
    when given (base_changed_tests passes the base's), else the tree's."""
    if texts is not None:
        return texts
    return {f.name: None if f.is_symlink() or not f.is_file() else go_text(f.read_bytes())
            for f in sorted((BROKER / pkg).glob("*.go"))}


def embedded_by(pkg, rel, texts=None):
    """{repo path: {line}} of the package-level var declarations whose //go:embed directive is the
    only way broker/<pkg>/'s .go files name rel, a path below it (names_file), or None. Each such
    directive lists rel alone (quoted or `all:` too), no glob, right above a plain `var name Type`
    at column 0 (comment lines between), name unexported, so the var holds that file's bytes and nothing else. Any
    other namer (a string literal, a glob, a directive listing more or on another shape, a link or
    unreadable file) is None. A change to rel then changes only what reads that var: the tests
    reaching it (head_tests, #6458). texts is _pkg_texts'."""
    out = {}
    for name, text in sorted(_pkg_texts(pkg, texts).items()):
        if text is None:
            return None
        if any(_names(lit, rel) for lit in _literals(text)):
            return None
        path, bare, held = f"broker/{pkg}/{name}", _uncommented(text, False).split("\n"), 0
        for m in EMBED_VAR.finditer(text):
            pats = [w.strip('"`').removeprefix("all:") for w in m[1].split()]
            if not any(_names(x, rel) for x in pats):
                continue
            line = text.count("\n", 0, m.end())
            if pats != [rel] or re.search(r"[*?\[]", rel) or not bare[line - 1].startswith(f"var {m[2]} ") or not any(
                    k == "var" and names == {m[2]} and first <= line <= last
                    for _, k, names, _r, _w, _e, first, last, _c in _decls(path, text)):
                return None
            out.setdefault(path, set()).add(line)
            held += 1
        if held != sum(1 for x in _embeds(text) if _names(x, rel)):
            return None  # a directive naming rel that is not on such a var
    return out or None



# A read call whose path is written in place (MUT-read-reach, #6657): os.ReadFile, os.Open or filepath.Glob of one
# literal or of filepath.Join over literals alone, or fs.ReadFile of os.DirFS of such a path, with such a name.
# Matched on _uncommented(text, False), whose literals keep their spans with contents blanked.
_LIT = r'(?:"[^"\n]*"|`[^`]*`)'
_PATH = rf'(?:{_LIT}|filepath\.Join\(\s*{_LIT}(?:\s*,\s*{_LIT})*\s*,?\s*\))'
READ_CALL = re.compile(rf'(?<![\w.])(?:(os\.ReadFile|os\.Open|filepath\.Glob)\(\s*({_PATH})\s*,?\s*\)'
                       rf'|fs\.ReadFile\(\s*os\.DirFS\(\s*({_PATH})\s*,?\s*\)\s*,\s*({_PATH})\s*,?\s*\))')
# The import each recognised call's qualifier must bind; a file binding one of them to anything else reads nothing.
READ_IMPORTS = {"os": "os", "filepath": "path/filepath", "fs": "io/fs"}
READ_ALIAS = re.compile(r'(?<![\w.])(os|filepath|fs)\s+"([^"\n]*)"')
# A message literal, the first argument of a testing.T, B or TB report (t, b or tb by name): it reads no file.
REPORT = re.compile(rf'(?<![\w.])(?:t|b|tb)\.(?:Fatal|Fatalf|Error|Errorf|Log|Logf|Skip|Skipf)\(\s*({_LIT})')


def _joined(pkg, values):
    """The repo path a read call's literals name from broker/<pkg>/ (Go's filepath.Join: empty parts
    dropped, then cleaned), or None for an absolute path, a NUL or one climbing out of the repository."""
    joined = "/".join(v for v in values if v)
    if not joined or joined.startswith("/") or "\x00" in joined:
        return None
    path = posixpath.normpath(posixpath.join("broker", pkg, joined))
    return None if path == ".." or path.startswith("../") else path


def _read_names(v, pkg, path):
    """Whether literal v of broker/<pkg>/ may name path, a repo path, for read_by: as names_file reads
    one below the package (a literal of wildcards alone aside, _naming), or holding its base name, or
    resolving to it or to a directory of it below what it shares with the package's directory."""
    rel = posixpath.relpath(path, f"broker/{pkg}")
    if WILDCARDS.fullmatch(v):
        return False
    if not rel.startswith("../") and _names(v, rel):
        return True
    base = path.rsplit("/", 1)[-1]
    if base in v or (re.search(r"[*?\[]", v) and fnmatch.fnmatchcase(base, v.rstrip("/").rsplit("/", 1)[-1])):
        return True
    shared = posixpath.commonpath([path, f"broker/{pkg}"])
    r = _joined(pkg, [v])
    return r is not None and (r == path or (len(r) > len(shared) and path.startswith(r + "/")))


def _globbed(pattern, path):
    """Whether filepath.Glob's pattern (a repo path, as _joined gives it) matches path part by part."""
    a, b = pattern.split("/"), path.split("/")
    return len(a) == len(b) and all(fnmatch.fnmatchcase(y, x) for x, y in zip(a, b))


def read_by(pkg, path, texts=None):
    """{repo path: {line}} of the recognised read calls (READ_CALL) through which broker/<pkg>/'s .go
    files read path, a repo path (its own data file or another package's, owners), or None. Every
    literal that may name path (_read_names) must be a path argument of one of them: a literal held
    anywhere else (a variable, a table, a const, a non-literal filepath.Join, an unrecognised read
    function or a child process; a test's report message, REPORT, aside) is a read this does not trace, and so is a call opening a directory of
    path, a //go:embed pattern naming it, a file binding os, filepath or fs to another import, or a
    link or unreadable file. A call reading another file (its literal holds path's name only) reads
    nothing of path. A change to path then changes only the tests reaching those calls (head_tests),
    and a read at run time by any other test fails the gate (record_for, #6657). texts is _pkg_texts'."""
    out = {}
    for name, text in sorted(_pkg_texts(pkg, texts).items()):
        if text is None:
            return None
        rel = path[len(f"broker/{pkg}/"):] if path.startswith(f"broker/{pkg}/") else None
        if rel is not None and any(_names(x, rel) for x in _embeds(text)):
            return None
        bare, code = _uncommented(text, False), _uncommented(text)
        value = {m.start(): _go_string(code[m.start() + 1:m.end() - 1]) if code[m.start()] == '"'
                 else code[m.start() + 1:m.end() - 1] for m in LITERAL.finditer(bare)}
        named = {at for at, v in value.items() if _read_names(v, pkg, path)} - {
            m.start(1) for m in REPORT.finditer(bare)}
        if not named:
            continue
        if any(imp != READ_IMPORTS[q] for q, imp in READ_ALIAS.findall(code)):
            return None
        for m in READ_CALL.finditer(bare):
            lits = {g: [x.start() for x in LITERAL.finditer(bare, m.start(g), m.end(g))] for g in (2, 3, 4) if m.group(g)}
            held = named & {at for ats in lits.values() for at in ats}
            if not held:
                continue
            named -= held
            if m.group(1) == "filepath.Glob":
                got = _joined(pkg, [value[a] for a in lits[2]])
                reads = got is not None and _globbed(got, path)
            else:
                got = _joined(pkg, [value[a] for g in sorted(lits) for a in lits[g]])
                if got is None or path.startswith(got + "/"):
                    return None
                reads = got == path
            if reads:
                out.setdefault(f"broker/{pkg}/{name}", set()).add(bare.count("\n", 0, m.start()) + 1)
        if named:
            return None  # a literal naming path outside every recognised read
    return out or None

# inotify's open and read events (inotify(7)), and its event header: wd, mask, cookie, name length.
IN_ACCESS, IN_OPEN, IN_EVENT = 0x1, 0x20, 16


@functools.cache
def _inotify():
    """libc with inotify_init1 and inotify_add_watch, or None where there is none (not Linux):
    head_tests then narrows no embedded file, since no run could watch it (#6518)."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if not (hasattr(libc, "inotify_init1") and hasattr(libc, "inotify_add_watch")):
            return None
    except OSError:
        return None
    return libc


@contextlib.contextmanager
def watched_at_run(broker, paths, tmp):
    """Yield (flags, opened) for a run of broker's tests with paths (repo paths, embedded files:
    embedded_by) in place, bytes unchanged: flags build the tests reading each from a copy under
    tmp through -overlay (which go reads for //go:embed too), so the build never opens them, and
    opened(), called once the run ends, lists the paths some process opened or read meanwhile
    (inotify on each file's inode: the test binary, a child process, through any link). A test that
    reads one at run time is then seen whether or not it tolerates the file's absence, which hiding
    it was not (Security on #6518, #6458). Only regular files (ValueError otherwise); no inotify
    or a watch refused is OSError."""
    tree = pathlib.Path(broker).resolve().parent
    if not paths:
        yield [], lambda: []
        return
    if (libc := _inotify()) is None:
        raise OSError("inotify is unavailable")
    store, files = pathlib.Path(tmp).resolve() / "embedded", {}
    store.mkdir(exist_ok=True)
    for n, path in enumerate(paths):
        src = tree / path
        if src.is_symlink() or not src.is_file():
            raise ValueError(f"{path} is not a regular file")
        shutil.copyfile(src, store / str(n))  # before the watch: this copy opens src
        files[path] = (src, store / str(n))
    (store / "overlay.json").write_text(json.dumps({"Replace": {str(a): str(b) for a, b in files.values()}}))
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1")
    try:
        wds = {}
        for path, (src, _) in files.items():
            if (wd := libc.inotify_add_watch(fd, os.fsencode(src), IN_OPEN | IN_ACCESS)) < 0:
                raise OSError(ctypes.get_errno(), f"inotify_add_watch {path}")
            wds[wd] = path

        def opened():
            got = set()
            while True:
                try:
                    buf = os.read(fd, 1 << 16)
                except BlockingIOError:
                    return sorted(got)
                at = 0
                while at + IN_EVENT <= len(buf):
                    wd = int.from_bytes(buf[at:at + 4], sys.byteorder, signed=True)
                    # A full queue (wd -1, IN_Q_OVERFLOW) may have lost any path's event: all.
                    got |= {wds[wd]} if wd in wds else set(wds.values())
                    at += IN_EVENT + int.from_bytes(buf[at + 12:at + 16], sys.byteorder)
        yield [f"-overlay={store / 'overlay.json'}"], opened
    finally:
        os.close(fd)


# The trees this process made (scratch's worktree, base_covered's archive): the only ones hide_docs deletes in.
MADE = set()


def hide_docs(broker, *also):
    """Delete, under broker (a tree the gate is about to run tests in), each Markdown file an edit to
    which changes no package's tests (owners names none in broker or any broker of also: its
    data_owner or a package naming it by path, readers; vendor/ is kept: is_vendored), and return
    their paths. Every gate run then measures the suite without them, so no verdict can depend on
    them and an edit to one changes no test (#6373); a test that needs one fails the run, closed.
    It refuses (ValueError) a tree this process did not make, so no working tree loses a file (#6456)."""
    if pathlib.Path(broker).resolve().parent not in MADE:
        raise ValueError(f"mutgate: {broker} is no tree mutgate made; it hides docs only in its own copies")
    gone = []
    for d, dirs, files in os.walk(broker):
        dirs.sort()
        for f in sorted(files):
            path = pathlib.Path(d, f)
            rel = "broker/" + path.relative_to(broker).as_posix()
            if (f.endswith(".md") and not is_vendored(rel)
                    and not any(owners(rel, b) for b in (broker, *also))):
                path.unlink()
                gone.append(rel)
    return gone


@contextlib.contextmanager
def scratch():
    """Run the block with ROOT and BROKER a copy of the working tree (a detached `git worktree` of
    HEAD, with each file that differs from HEAD or is untracked and not ignored copied over it), its
    docs hidden (hide_docs), and remove it after: plan, delete and run --git read what is on disk as
    before, but delete, write or move nothing in the working tree, its index or its HEAD
    (marked_base moves the copy's own; #6456)."""
    global ROOT, BROKER
    repo, broker = ROOT, BROKER
    with tempfile.TemporaryDirectory() as tmp:
        tree = pathlib.Path(tmp).resolve() / "tree"
        # No hook runs: a post-checkout hook is the clone's code, not the commit's.
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "worktree", "add", "--quiet", "--detach", str(tree),
                        "HEAD"], cwd=repo, check=True)
        MADE.add(tree)
        try:
            for name in sorted(set(_git_names(repo, "diff", "--name-only", "--no-renames", "HEAD"))
                               | set(_git_names(repo, "ls-files", "--others", "--exclude-standard"))):
                src, dst = repo / name, tree / name
                if dst.is_symlink() or dst.is_file():
                    dst.unlink()
                if src.is_symlink() or src.is_file():  # else deleted: gone from the copy too
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst, follow_symlinks=False)
            ROOT, BROKER = tree, tree / "broker"
            hide_docs(BROKER)
            yield
        finally:
            ROOT, BROKER = repo, broker
            MADE.discard(tree)
            subprocess.run(["git", "worktree", "remove", "--force", str(tree)], cwd=repo, capture_output=True)


def _git_names(repo, *args):
    """The repo-relative paths a `git <args> -z` run in repo prints."""
    out = subprocess.run(["git", *args, "-z"], cwd=repo, capture_output=True, check=True).stdout
    return [n for n in out.decode("utf-8", "surrogateescape").split("\0") if n]


def data_owner(path, broker=None):
    """The package (as package_of names one) whose tests a changed data file (is_data) changes, or
    None: the nearest directory above it, testdata/ left out, that holds .go files at the head. A
    Markdown file outside testdata/ that no .go file there can name (names_file; an ASSUMPTIONS.md
    mostly, which 9 of the 30 broker merges before #5779 edited) has none; any other file has one."""
    broker = BROKER if broker is None else broker
    dirs, rel = path.split("/")[1:-1], path.split("/")[-1]
    testdata = "testdata" in dirs
    if testdata:
        rel = "/".join(dirs[dirs.index("testdata"):] + [rel])
        dirs = dirs[:dirs.index("testdata")]
    while dirs and not any(broker.joinpath(*dirs).glob("*.go")):
        rel, dirs = f"{dirs[-1]}/{rel}", dirs[:-1]
    if not dirs or (not testdata and rel.endswith(".md") and not names_file(broker.joinpath(*dirs), rel)):
        return None
    return "/".join(dirs)


def owners(path, broker=None):
    """The packages (as package_of names them) every one of whose tests a changed file changes:
    its own package's when it is that package's data (data_owner), and every other package that
    names it by path (readers). A vendored file has none (is_vendored). A package's own _test.go
    file changes only the tests that reach its changed lines (owners_of, head_tests)."""
    if path == f"broker/{DORMANT_TEST}":
        return set(directive_packages((BROKER if broker is None else pathlib.Path(broker)).resolve()))
    if path.rsplit("/", 1)[-1] == EVERY_TEST:
        d = BROKER if broker is None else pathlib.Path(broker)
        return set(go_packages(d.resolve())) if path == f"broker/{EVERY_TEST}" else {package_of(path)}
    if is_vendored(path):
        return set()
    own = data_owner(path, broker) if is_data(path) else None
    return ({own} - {None}) | readers(path, broker)


@functools.lru_cache(maxsize=None)
def read_index(broker):
    """{repo path: {package}} of the paths each broker/ package's .go files name with a string
    literal (escapes decoded, comments left out; _literals), read as a relative path from the
    package's directory, as `go test` runs there: "../../SPEC.md" in broker/enforcer/page names
    SPEC.md. An absolute literal, one that climbs out of the repository, or one naming a vendored
    file (is_vendored) names nothing. vendor/,
    testdata/ and the directories Go skips (`.` or `_` first) hold no package. The tree is read once
    per broker directory per process: the gate reads its claims before it changes a file."""
    broker = pathlib.Path(broker)
    index = collections.defaultdict(set)
    for d, dirs, files in os.walk(broker):
        dirs[:] = sorted(x for x in dirs if x not in ("vendor", "testdata") and x[0] not in "._")
        rel = pathlib.Path(d).relative_to(broker).as_posix()
        if rel == ".":
            continue
        for f in sorted(files):
            if not f.endswith(".go"):
                continue
            text = pathlib.Path(d, f).read_bytes().decode("utf-8", "replace")
            for lit in _literals(text):
                if lit and not lit.startswith("/") and "\x00" not in lit:
                    path = posixpath.normpath(posixpath.join("broker", rel, lit))
                    if path != ".." and not path.startswith("../") and not is_vendored(path):
                        index[path].add(rel)
    return dict(index)


def readers(path, broker=None):
    """The packages other than the file's own (package_of, data_owner) whose .go files name a
    changed file by its exact path (read_index): a test that reads SPEC.md or another package's
    fixture changes when it does, though no line of its own package changed (#6436). A read by a
    path built at run time, or through a directory it names, is not one of these."""
    broker = BROKER if broker is None else pathlib.Path(broker)
    found = set(read_index(broker.resolve()).get(path, ()))
    return found - {package_of(path), data_owner(path, broker) if is_data(path) else None}


def owners_of(path):
    """The packages whose tests a path of added_lines' second map changes: owners, and the
    package of its own _test.go file (head_tests reads which of them)."""
    return owners(path) | ({package_of(path)} if is_test(path) and not is_data(path) else set())


def touched(added, tests):
    """The broker/ packages where the diff adds a line to a non-test .go file or changes a test file
    or a file one reads (owners_of)."""
    return ({package_of(p) for p in added if is_source(p) and not is_data(p) and not is_vendored(p)}
            | {o for p in tests for o in owners_of(p)}) - {None}


def records_changed(diff_text):
    """The broker/ packages whose MUTANTS-EQUIVALENT record the diff adds, changes or deletes (#5786)."""
    out, in_hunk = set(), False
    for raw in diff_text.split("\n"):
        if raw.startswith("diff "):
            in_hunk = False
        elif HUNK.match(raw):
            in_hunk = True
        elif not in_hunk and raw.startswith(("--- ", "+++ ")):
            path = _header_path(raw, "a/" if raw.startswith("-") else "b/")
            if path and path.rsplit("/", 1)[-1] == RECORD:
                out.add(package_of(path))
    return out - {None}


def claimed(diff_text, packages=None, base=None, head=None):
    """Tier-A and tier-B packages where the diff adds or changes a .go line, or changes the package's
    MUTANTS-EQUIVALENT record, sorted (#4908). A record-only claim has no target line; it is claimed so
    verify resolves the record and lists its new entries in the summary for review (#5786). A `REQ:`
    marker is no longer needed; violations() reads no other package. With base and head, a file holding a
    package-wide directive claims its package (dormant)."""
    added, tests = added_lines(diff_text)
    if base is not None:
        tests = _widen(tests, dormant(diff_text, base, head))
    return sorted((touched(added, tests) | records_changed(diff_text))
                  & set(gated_packages() if packages is None else packages))


def diff_targets(added, pkg):
    """{path: lines} the diff adds to non-test .go files directly in broker/<pkg>/."""
    return {p: ls for p, ls in added.items() if is_source(p) and package_of(p) == pkg}


def tests_changed(tests, pkg):
    """Whether the diff changes or deletes a _test.go file of broker/<pkg>/, or a file its tests
    read (owners)."""
    return any(pkg in owners_of(p) for p in tests)


def union(*parts):
    """{path: lines} holding every line of each {path: lines} part."""
    out = {}
    for part in parts:
        for p, ls in part.items():
            out.setdefault(p, set()).update(ls)
    return out


def base_test_lines(diff_text, moved=None):
    """{path: set(base line) or None} of the broker/ _test.go files the base has and a -U0 diff
    changes: the base lines it deletes or changes; None when the diff deletes the file. The base
    side of added_lines' tests (#5762). Returns (that, gaps): gaps is {path: set(base line)} of
    where a hunk only adds, after that base line, for base_changed_tests to place by the file's text.
    moved is moved()'s pair, read as added_lines reads it (#6369)."""
    out, gaps, old, path, in_hunk, line = {}, {}, None, None, False, 0
    at_head, at_base = moved or ({}, {})

    def touch(lines):
        if out.get(old, ()) is not None:
            out.setdefault(old, set()).update(lines)

    for raw in diff_text.split("\n"):
        if raw.startswith("diff "):
            in_hunk, path, old = False, None, None
            continue
        m = HUNKS.match(raw)
        if m:
            in_hunk, line = True, int(m[1])
            if old is not None and is_test(old):
                if path is None:
                    if not set(range(line, line + int(m[2] or 1))) <= at_base.get(old, set()):
                        out[old] = None  # the file is deleted
                elif m[2] == "0" and not set(range(int(m[3]), int(m[3]) + int(m[4] or 1))) <= at_head.get(path, set()):
                    gaps.setdefault(old, set()).add(line)  # the hunk adds after base line `line`
            continue
        if not in_hunk:
            if raw.startswith("--- "):
                old = _header_path(raw, "a/")
            elif raw.startswith("+++ "):
                path = _header_path(raw)
            continue
        if raw.startswith("-"):
            if old is not None and is_test(old) and line not in at_base.get(old, ()):
                touch({line})
            line += 1
    return out, gaps


def head_line_of(diff_text):
    """{path: f} for a -U0 diff, where f(n) is the head line of the base's line n of path, or None
    when the diff deletes or changes that line (or the file). Paths the diff leaves alone keep theirs."""
    hunks, gone, old, path, in_hunk = {}, set(), None, None, False
    for raw in diff_text.split("\n"):
        if raw.startswith("diff "):
            old, path, in_hunk = None, None, False
        elif m := HUNKS.match(raw):
            in_hunk = True
            if old is not None:
                if path is None:
                    gone.add(old)
                o, oc, nc = int(m[1]), int(m[2] or 1), int(m[4] or 1)
                hunks.setdefault(old, []).append((o, oc, nc - oc))
        elif not in_hunk:
            if raw.startswith("--- "):
                old = _header_path(raw, "a/")
            elif raw.startswith("+++ "):
                path = _header_path(raw)

    def mover(hs):
        def f(n):
            if any(oc and o <= n < o + oc for o, oc, _ in hs):
                return None
            # A hunk changing oc lines from o, or adding after line o when oc is 0, ends before n here.
            return n + sum(d for o, oc, d in hs if (o + oc if oc else o + 1) <= n)
        return f
    return {**{p: mover(hs) for p, hs in hunks.items()}, **{p: (lambda n: None) for p in gone}}


def merge_base(base, head):
    """The commit `git diff BASE...HEAD` diffs from."""
    return subprocess.run(["git", "merge-base", base, head], cwd=ROOT, capture_output=True, text=True,
                          check=True).stdout.strip()


def go_text(raw):
    """Go source bytes as the go toolchain reads them: one leading byte order mark skipped (go/scanner,
    go/build), so a directive behind it is read; None for bytes go refuses to compile (not UTF-8, a NUL,
    a BOM anywhere else), so every caller fails closed instead of reading a text go never builds (#6377)."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text[1:] if text.startswith("\ufeff") else text
    return None if "\ufeff" in text or "\0" in text else text


def base_text(mb, path):
    """The text of path in commit mb when it is a regular file there, else None (a link is not read);
    a .go file is read by go_text."""
    r = subprocess.run(["git", "ls-tree", mb, "--", path], cwd=ROOT, capture_output=True, text=True, check=True)
    if not r.stdout.startswith(("100644 ", "100755 ")):
        return None
    blob = subprocess.run(["git", "cat-file", "blob", f"{mb}:{path}"], cwd=ROOT, capture_output=True, check=True)
    return go_text(blob.stdout) if path.endswith(".go") else blob.stdout.decode("utf-8", "replace")


def _body(bare, d):
    """(head line, closing brace line or None) of the func or method declaration d, read from the
    text with comments blanked, so `} // note` is `}` plus spaces. None: no closing brace found."""
    head = next(i for i in range(d[6], d[7] + 1) if DECL.match(bare[i - 1]))
    return head, max((i for i in range(head, d[7] + 1) if bare[i - 1].rstrip() == "}"), default=None)


def _gap_lines(text, after):
    """The base lines a hunk adding after line `after` of a test file's text touches: the line
    either side, except that a function's doc comment, closing brace and the blank lines after it
    belong to no function body, so an addition between functions touches none (#5832). An addition
    inside a body, even right after its head or before its closing brace, still touches it."""
    bare, out = _uncommented(text, False).split("\n"), set()
    spans = [(d[6], d[7], *_body(bare, d)) for d in _decls("", text) if d[1] in ("func", "method")]
    for n, inside in ((after, lambda h, c: h <= n < c), (after + 1, lambda h, c: h < n <= c)):
        span = next(((h, c) for a, b, h, c in spans if a <= n <= b), None)
        if span is None or span[1] is None or inside(*span):
            out.add(n)
    return out


def base_changed_tests(btests, pkg, mb, tests=()):
    """Sorted names of the base's test functions that reach the base lines btests names in
    broker/<pkg>/ (every line of a deleted file), or None for every test (reaching_tests).
    btests is base_test_lines' pair. A file of tests (added_lines' second map) the package reads
    (owners) adds the lines narrowing names in the base's .go files, so the base's run of its
    readers shows what they checked before the file changed (#6657); none there is every test."""
    touched_lines, gaps = btests
    changed = {p: ls for p, ls in touched_lines.items() if package_of(p) == pkg}
    files, texts = {}, {}
    listing = subprocess.run(["git", "ls-tree", "-z", mb, "--", f"broker/{pkg}/"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
    for entry in filter(None, listing.split("\0")):
        meta, path = entry.split("\t", 1)
        if not path.endswith(".go") or meta.split()[1] != "blob":
            continue
        text = base_text(mb, path)
        texts[path.rsplit("/", 1)[-1]] = text
        if not path.endswith("_test.go"):
            continue
        if text is None:
            return None  # a link: its tests are unread, so any of them may reach the change
        files[path] = text
    held, state = {}, {}
    for p in tests:
        if pkg in owners(p):
            if (got := narrowing(pkg, p, texts)) is None:
                return None
            held = union(held, got[1])
            state = union(state, got[1]) if got[0] == "read" else state
    for name, text in texts.items() if held else ():
        if not name.endswith("_test.go") and text is not None and not unbuilt(name, text):
            files[f"broker/{pkg}/{name}"] = text
    for path, lines in changed.items():
        if lines is None:
            if path not in files:
                return None
            changed[path] = set(range(1, files[path].count("\n") + 2))
    for path, afters in gaps.items():
        if package_of(path) == pkg and changed.get(path, ()) is not None and path in files:
            for after in afters:
                changed.setdefault(path, set()).update(_gap_lines(files[path], after))
    changed = union({p: ls for p, ls in changed.items() if ls}, held)
    return reaching_tests(files, changed, state)


def bases_for(diff_text, base, head, tests, pkgs):
    """{pkg: base_changed_tests} for each of pkgs whose tests the diff changes; None (every test)
    when either side's change reaches every test, so neither side hides what the other runs.
    changed_tests reads the same None for its head side."""
    pkgs = [pkg for pkg in pkgs if tests_changed(tests, pkg)]
    if not pkgs:
        return {}
    mb = merge_base(base, head)
    pair, later = moved(diff_text, mb, head)
    lines, gaps = base_test_lines(diff_text, pair)
    btests = (_widen(lines, later[1]), gaps)
    return {pkg: None if head_tests(tests, pkg) is None else base_changed_tests(btests, pkg, mb, tests) for pkg in pkgs}


def changes(diff_text, base, head):
    """added_lines with what moved() reads as moved left out of the test files' lines (#6369), and the
    tests whose run order the diff changes in (#6385)."""
    pair, later = moved(diff_text, merge_base(base, head), head)
    added, tests = added_lines(diff_text, pair)
    return added, _widen(_widen(tests, later[0]), dormant(diff_text, base, head))


# Moved declarations (TOOL-mutgate-moved-lines, #6369). The diffs ignore renames (#4147), so code moved
# unchanged reads as deleted and added: #6305 moved 248 lines of kernelsock.go into a new clients_test.go,
# and every test reaching them became a changed test. A package-level declaration means the same in any
# order and any file of its package, so a declaration of a test file is no change when its whole text
# (doc comment to the next declaration, trailing blank lines left out), package clause and build context
# (_constraint: the `//go:build` line go/build reads and file-name GOOS and GOARCH, compared by meaning)
# are those of exactly one declaration of the package's .go files at the base and of exactly one at the
# head. What hangs on order or file stays a change: init, TestMain, a var with an initializer, any
# declaration of a file with a linkname or cgo (_decls' every), a move out of a test file into a non-test
# one or into a file go ignores, and any edit, one token or a comment. `go test` runs tests in file then
# source order, so every test at or after the first place the package's run list (RUNNABLE) changes is a
# change, a new file named first or a moved test included, and every test when the package or one it
# imports names Parallel (_parallel, #6385).
# What moved() reads assumes gofmt's layout: a package with a file gofmt would change moves nothing, and
# one with such a test file has its run order unread, so every test is a change. Across two files each name the declaration qualifies a selector with
# (`q.X`) must have the same binding imports in both, by name: an explicit one, a standard library path's
# last element, or the package clause this module's package has at that side; an import of a name not known
# so must be in both files. A test file's header change (an import, a plain comment; a new or deleted
# file's package clause and build lines) is no change when nothing else of its header changes, no added or
# removed import is blank or dot, every added import path was imported at the base by a file of the
# directory built with it (no build constraint, or the same) or is the package itself, and every removed
# one still is at the head (no init changes), and, in a file on both sides, the added and removed imports
# have known names, none shared or a universe name, no added one a package-level name at the base and no
# removed one at the head: an unchanged line of the file then binds each name as before. Both sides are read
# from git (the merge base and the diff's head), never the working tree. Anything unread fails closed.
GOOS = set("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris "
           "wasip1 windows zos".split())
GOARCH = set("386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 "
             "mips64p32le ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm".split())
IMPORT_SPEC = re.compile(r'(?:([A-Za-z_]\w*|\.)\s+)?(?:"([^"\\\n]*)"|`([^`\n]*)`)')
QUALIFIER = re.compile(r"\b([A-Za-z_]\w*)\s*\.")
MOVABLE = ("func", "method", "type", "var", "const")
# What `go test` runs by name, in file then source order: moving one changes the run order.
RUNNABLE = re.compile(r"^func ((?:Test|Fuzz|Example|Benchmark)(?![a-z])\w*)[(\[]")
# Go's universe block: an import of one of these names would shadow it in its file (L3 on #6378).
UNIVERSE = set("any append bool byte cap clear close comparable complex complex128 complex64 copy delete error false "
               "float32 float64 imag int int16 int32 int64 int8 iota len make max min new nil panic print println "
               "real recover rune string true uint uint16 uint32 uint64 uint8 uintptr".split())


def _name_tags(path):
    """The GOOS and GOARCH a .go file's name constrains it to, as go/build reads them; ("ignored",) for a
    name go ignores (a leading `_` or `.`)."""
    if path.rsplit("/", 1)[-1].startswith(("_", ".")):
        return ("ignored",)
    name = path.rsplit("/", 1)[-1].split(".", 1)[0]
    parts = name[name.find("_"):].split("_") if "_" in name else []
    if len(parts) >= 2 and parts[-1] == "test":
        parts = parts[:-1]
    if len(parts) >= 2 and parts[-2] in GOOS and parts[-1] in GOARCH:
        return tuple(parts[-2:])
    return (parts[-1],) if parts and (parts[-1] in GOOS or parts[-1] in GOARCH) else ()


def _constraint(path, text):
    """A .go file's build context as go/build reads it, canonical so that equivalent constraints are
    equal: "ignored" for a file go ignores, else (the tags it hangs on, its truth table over them) for
    its `//go:build` line (the one before the package clause outside a /* comment, go/build's
    parseFileHeader) and file-name GOOS and GOARCH; None when not read: two such lines, a `+build` line
    with no `//go:build` one, an expression go/build/constraint does not parse (it skips only spaces and
    tabs; a tag here is ASCII), over 12 tags, or a character Go and Python split differently (NOT_GO_SPACE)
    (fail closed, #6385)."""
    tags = _name_tags(path)
    if tags == ("ignored",):
        return "ignored"
    if NOT_GO_SPACE.search(text):
        return None
    line, plus, star = None, False, False
    for raw in text.split("\n"):
        s = raw.strip()
        if not s:
            continue
        if not star and s.startswith("//go:build") and (len(s) == 10 or s[10].isspace()):
            if line is not None or (len(s) > 10 and s[10] not in " \t"):
                return None  # two lines, or one constraint.Parse refuses
            line = s[10:].strip()
        plus = plus or "+build" in s
        rest = s
        while rest:
            if star:
                i = rest.find("*/")
                star, rest = (True, "") if i < 0 else (False, rest[i + 2:].strip())
            elif rest.startswith("//"):
                rest = ""
            elif rest.startswith("/*"):
                star, rest = True, rest[2:].strip()
            else:
                break
        if rest:
            break  # code: the header ends
    if line is None and plus:
        return None
    tokens, at = [], 0
    while at < len(line or ""):
        m = re.compile(r"[ \t]*(\(|\)|!|&&|\|\||[A-Za-z0-9_.]+)[ \t]*").match(line, at)
        if m is None:
            return None  # a character go/build/constraint's lexer refuses, or one read otherwise here
        tokens.append(m[1])
        at = m.end()
    pos = 0

    def take(t):
        nonlocal pos
        if pos < len(tokens) and tokens[pos] == t:
            pos += 1
            return True
        return False

    def expr(level):  # level 0: ||, 1: &&, 2: ! and atoms; a node is ("or"|"and", a, b), ("not", a) or a tag
        nonlocal pos
        if level == 2:
            if take("!"):
                return ("not", expr(2))
            if take("("):
                node = expr(0)
                if not take(")"):
                    raise ValueError
                return node
            if pos < len(tokens) and re.fullmatch(r"[A-Za-z0-9_.]+", tokens[pos]):
                pos += 1
                return tokens[pos - 1]
            raise ValueError
        node = expr(level + 1)
        while take(("||", "&&")[level]):
            node = (("or", "and")[level], node, expr(level + 1))
        return node
    try:
        node = expr(0) if line is not None else True
    except (ValueError, RecursionError):
        return None
    if pos != len(tokens):
        return None
    for t in tags:
        node = ("and", node, t)

    def words(n):
        return {n} if isinstance(n, str) else set().union(*map(words, n[1:])) if isinstance(n, tuple) else set()

    def ev(n, on):
        if isinstance(n, str):
            return n in on
        if not isinstance(n, tuple):
            return n
        return (not ev(n[1], on)) if n[0] == "not" else (any if n[0] == "or" else all)(ev(c, on) for c in n[1:])
    names = sorted(words(node))
    if len(names) > 12:
        return None
    rows = lambda ns: [{n for i, n in enumerate(ns) if k >> i & 1} for k in range(1 << len(ns))]
    used = tuple(n for n in names if any(ev(node, on) != ev(node, on | {n}) for on in rows(names)))
    return used, tuple(ev(node, on) for on in rows(used))


ALWAYS = ((), (True,))  # _constraint of a file with no constraint
# Python's str.strip, isspace and \s read U+001C-U+001F as space and Go (unicode.IsSpace, bytes.TrimSpace)
# does not; every other character both read alike. A file holding one is not read (Security on #6421).
NOT_GO_SPACE = re.compile("[\x1c-\x1f]")


def _facts(path, text):
    """What moved() reads of one .go file: its declarations (_decls), package clause, build context,
    header lines, the header's other code and directives (skeleton), its import specs [(name or None,
    path)] (None when a header line is not read), whether it holds a linkname, and each declaration's text."""
    decls, rows, code = _decls(path, text), text.split("\n"), _uncommented(text).split("\n")
    header, skeleton, specs, group = set(), [], [], False
    for d in decls:
        for n in range(d[6], d[7] + 1) if d[1] == "header" else ():
            header.add(n)
            raw, c = rows[n - 1].strip(), code[n - 1].strip()
            if not c:
                if raw and (not raw.startswith("//") or raw.startswith(("//go:", "//line", "// +build"))):
                    skeleton.append(raw)  # a directive, or a /* comment: not read as plain
            elif group and c == ")":
                group = False
            elif not group and re.fullmatch(r"import\s*\(", c):
                group = True
            elif group or re.match(r"import\b", c):
                m = IMPORT_SPEC.fullmatch(c if group else c[len("import"):].strip())
                if m is None or specs is None:
                    specs = None  # a spec not read: no import of this file is known
                else:
                    specs.append((m[1], m[2] if m[2] is not None else m[3]))
            else:
                skeleton.append(c)
    bare = _uncommented(text, False).split("\n")

    def run(d):
        """The name `go test` runs d by (RUNNABLE), or None."""
        at = next((rows[i - 1] for i in range(d[6], d[7] + 1) if DECL.match(bare[i - 1])), "")
        return d[1] == "func" and (m := RUNNABLE.match(at)) and m[1] or None
    return types.SimpleNamespace(run=run, parallel=bool(re.search(r"\bParallel\b", "\n".join(code))),
        decls=decls, clause=decls[0][8] if decls else None, build=_constraint(path, text),
        header=header, skeleton=skeleton, specs=specs, linked=_tied(text),
        text=lambda d: "\n".join(rows[d[6] - 1:d[7]]).rstrip())


def _go_files(pkg, commit):
    """{path: text} of broker/<pkg>/'s .go files at commit, or None when one is a link or not a regular
    file. Both sides are read from git, never the working tree, so `verify --head` reads the head it names."""
    out, prefix = {}, f"broker/{pkg}/" if pkg else "broker/"
    listing = subprocess.run(["git", "ls-tree", "-z", commit, "--", prefix], cwd=ROOT, capture_output=True,
                             text=True, check=True).stdout
    for entry in filter(None, listing.split("\0")):
        meta, path = entry.split("\t", 1)
        if path.endswith(".go"):
            if (text := base_text(commit, path)) is None:
                return None
            out[path] = text
    return out


# The go.mod whose toolchain line pins Go, read where mutgate lives (tests move BROKER, not the pin).
GO_MOD_PIN = BROKER / "go.mod"


@functools.cache
def gofmt():
    """The path of the toolchain's own gofmt: GOROOT/bin/gofmt of the Go that broker/go.mod selects, whose
    build info names go.mod's toolchain version. Raises instead, never taking gofmt from PATH: another
    gofmt's layout can read a reformat as a move or hide one (#6442)."""
    pin = re.search(r"^toolchain\s+(go\S+)\s*$", GO_MOD_PIN.read_text(), re.M)
    if not pin:
        raise RuntimeError(f"mutgate: {GO_MOD_PIN} names no toolchain, so no gofmt is pinned")
    run = lambda *a: subprocess.run(["go", *a], cwd=GO_MOD_PIN.parent, capture_output=True, text=True,
                                    env={**os.environ, "GOWORK": "off"})
    try:
        r = run("env", "GOROOT")
        binary = pathlib.Path(r.stdout.strip()) / "bin" / "gofmt"
        if r.returncode or not r.stdout.strip() or not binary.is_absolute() or not binary.is_file():
            raise RuntimeError(f"mutgate: no gofmt in the toolchain's GOROOT ({r.stdout.strip()!r}): {r.stderr.strip()[:300]}")
        v = run("version", str(binary))
    except OSError as e:
        raise RuntimeError(f"mutgate: cannot run go to find the toolchain's gofmt: {e}") from e
    if v.returncode or v.stdout.strip() != f"{binary}: {pin[1]}":
        raise RuntimeError(f"mutgate: {binary} is not {pin[1]}'s gofmt: {(v.stdout + v.stderr).strip()[:300]}")
    return str(binary)


def _unformatted(files):
    """The paths of {path: text} that the pinned gofmt would change, every one when it fails on them: what
    moved() reads assumes gofmt's layout (`func TestB (t` hides a test from RUNNABLE; Security on #6378)."""
    binary = gofmt()
    with tempfile.TemporaryDirectory() as d:
        names = {p.rsplit("/", 1)[-1]: p for p in files}
        for name, p in names.items():
            (pathlib.Path(d) / name).write_text(files[p])
        try:
            r = subprocess.run([binary, "-l", "."], cwd=d, capture_output=True, text=True)
        except OSError as e:
            raise RuntimeError(f"mutgate: cannot run the toolchain's gofmt {binary}: {e}") from e
        if r.returncode or r.stderr.strip():
            return set(files)
        return {names.get(n.strip().removeprefix("./"), n) for n in r.stdout.split("\n") if n.strip()}


def _side(pkg, mb, module):
    """One side (commit mb) of broker/<pkg>/ as moved() reads it, or None."""
    files = _go_files(pkg, mb)
    if files is None:
        return None
    rough = _unformatted(files) | {p for p, t in files.items() if NOT_GO_SPACE.search(t)}
    facts, clauses = {p: _facts(p, t) for p, t in files.items()}, {}

    def name(spec):
        """The name an import spec binds, or None when not known for certain."""
        alias, path = spec
        if alias:
            return alias
        if module and (path == module or path.startswith(module + "/")):
            if path not in clauses:
                clauses[path] = _clause(path, module, mb)
            return clauses[path]
        parts = path.split("/")
        if "." in parts[0]:
            return None
        return parts[-2] if len(parts) > 1 and re.fullmatch(r"v\d+", parts[-1]) else parts[-1]

    def imports(path, build):
        """Whether a file of the directory built with build (or with no constraint) imports path."""
        if module and path == f"{module}/{pkg}":
            return True
        rel = [f for f in facts.values() if f.build in (ALWAYS, build)]
        return all(f.specs is not None for f in rel) and any(path == s[1] for f in rel for s in f.specs)

    def names(clause):
        return {n for f in facts.values() if f.clause == clause for d in f.decls if d[1] != "header" for n in d[2]}

    keyed = collections.defaultdict(list)
    for p, f in facts.items():
        for d in f.decls:
            if d[1] in MOVABLE and not d[5] and f.build is not None:
                keyed[(f.clause, f.build, f.text(d))].append((p, d))
    return types.SimpleNamespace(facts=facts, name=name, imports=imports, names=names, keyed=keyed, rough=rough)


def _same_header(bf, hf, b, h):
    """Whether a test file's header change (bf at the base, hf at the head, either None when absent)
    changes nothing a line of it binds or any init that runs (see Moved declarations above)."""
    if any(f is not None and (f.linked or f.specs is None or f.build is None) for f in (bf, hf)):
        return False
    was, now = set(bf.specs) if bf else set(), set(hf.specs) if hf else set()
    added, removed = now - was, was - now
    if any(a in ("_", ".") for a, _ in added | removed):
        return False
    if bf and hf:
        if bf.skeleton != hf.skeleton or bf.build != hf.build:
            return False
    elif not all(s.startswith(("package ", "//go:build", "// +build")) for s in (bf or hf).skeleton):
        return False
    if not (all(b.imports(p, hf.build) for _, p in added) and all(h.imports(p, bf.build) for _, p in removed)):
        return False
    if bf and hf:
        an, rn = {h.name(s) for s in added}, {b.name(s) for s in removed}
        if None in an | rn or an & rn or (an | rn) & UNIVERSE or an & b.names(bf.clause) or rn & h.names(hf.clause):
            return False
    return True


def _same_binding(sf, df, text, b, h):
    """Whether each name text qualifies a selector with binds the same import in sf (a base file) as in df
    (a head file)."""
    if sf.specs is None or df.specs is None or any(a == "." for a, _ in sf.specs + df.specs):
        return False
    was, now = {s: b.name(s) for s in sf.specs}, {s: h.name(s) for s in df.specs}
    if any(n is None and s not in now for s, n in was.items()) or any(n is None and s not in was for s, n in now.items()):
        return False
    return all({s for s, n in was.items() if n == q} == {s for s, n in now.items() if n == q}
               for q in set(QUALIFIER.findall(_uncommented(text, False))))


def _package_reads(rel, commit, tests=True, module=None):
    """(why, module import paths) of broker/<rel>/'s .go files at commit, its _test.go files left out
    unless tests, or None when a file or an import spec is not read. why is the first file:line that may
    reorder or rerun its tests (_order_risk, or a Parallel; with tests, not one _subtests_only reads as
    a subtest's), or None."""
    files = _go_files(rel, commit)
    if files is not None and not tests:
        files = {p: t for p, t in files.items() if not is_test(p)}
    if files is None or any(NOT_GO_SPACE.search(t) for t in files.values()):
        return None
    facts = {p: _facts(p, t) for p, t in files.items()}
    if any(f.specs is None for f in facts.values()):
        return None
    clause = lambda path: _clause(path, module, commit)
    decls = {p: _decls(p, t) for p, t in files.items()}
    why = _order_risk(files, facts, decls, clause, lambda path: _outside_marks(path, module, commit))
    # A linkname (in a comment, which f.parallel leaves out) may bind testing's Parallel under another name.
    par = [p for p, f in sorted(facts.items()) if f.parallel or ("go:linkname" in files[p] and "Parallel" in files[p])]
    if why is None and par:
        why = _subtests_only(files, facts, decls, clause) if tests else f"{par[0]}: Parallel"
    return why, frozenset(path for f in facts.values() for _, path in f.specs)


# A Parallel only on subtests (TOOL-mutgate-subtest-parallel, #6675). A parallel subtest pauses until its
# parent's function returns, then runs beside its parallel siblings only; the parent ends after they do,
# and top-level tests that call no Parallel run one at a time in source order. So a Parallel called only
# on a subtest's own *testing.T moves no other top-level test: it reorders the parent's own subtests,
# which are already of the parent's reach. _subtests_only reads that from gofmt's layout and nothing
# looser: each Parallel (any word of the code, string literals too) is `t.Parallel()` alone as the first
# statement of a `func(t *testing.T) {` literal that is the second and last argument of a `t.Run(` call,
# in a top-level `func TestX(t *testing.T) {` of a _test.go file, the same name t throughout, and t is
# bound in that test's body only by those literals (any other use of it is `t.` or a call argument).
# It fails closed (every test) for anything else: a Parallel in a non-test file, a helper, a method value,
# a string, another name or another literal; a package with a linkname or a file where `testing` may bind another
# package; and a literal naming a package-level var (parallel siblings may interleave on it). A Parallel
# in an imported package fails closed as before (_parallel), and so does every package _order_risk reads.
#
# Order before and around m.Run (TOOL-mutgate-testmain-order, #6682). With or without Parallel, `go test`
# runs top-level tests once each in source order only if nothing changes the flags or reruns them. What
# runs first is TestMain, every init and every package var initializer, of the package and of each one it
# imports; and a subtest started by a `go` statement may outlive its parent into the next test. So
# _order_risk fails closed (every test) for: a TestMain other than `func TestMain(m *testing.M) {` that
# names m only in one `m.Run()`, no package-level name, none of MAIN_BARRED, no label, and qualifies only
# by its file's standard library imports other than ORDER_PATHS; an init or a package var whose text names
# ORDER_WORDS, a qualifier of an ORDER_PATHS import, or a package-level declaration that does, transitively
# by name; and, in a file importing testing, a `go` statement that calls a *testing.T or *testing.B
# parameter's Run or passes one to a call, or a method value of one's Run.
SUBTEST_HEAD = re.compile(r"func\(([A-Za-z_]\w*) \*testing\.T\) \{")
TEST_HEAD = re.compile(r"func Test\w*\(([A-Za-z_]\w*) \*testing\.T\) \{")
MAIN_HEAD = re.compile(r"func TestMain\(([A-Za-z_]\w*) \*testing\.M\) \{")
# A word that may change test flags or rerun the binary (flag set, os.Args, a re-exec with -test.shuffle;
# Security on #6677), and imports whose qualifier may: one in a TestMain, init or package var fails closed.
ORDER_WORDS = {"shuffle", "linkname"}  # string contents too: "-test.shuffle=on"
ORDER_PATHS = {"flag", "os/exec", "unsafe"}
# Calls of flag that only define a flag of a built-in kind (#6687): no -test.* value changes, and no
# code of the package runs (flag.Var, Func, BoolFunc and TextVar call its methods or funcs, so seed).
FLAG_DEFINES = {"Bool", "BoolVar", "Duration", "DurationVar", "Float64", "Float64Var", "Int", "IntVar", "Int64",
                "Int64Var", "String", "StringVar", "Uint", "UintVar", "Uint64", "Uint64Var"}
DOT_BARRED = {"flag", "os/exec", "unsafe", "os", "syscall", "golang.org/x/sys/unix"}
ORDER_SELECTORS = {("os", "Args"), ("os", "Executable"), ("os", "StartProcess"), ("syscall", "Exec"),
                   ("syscall", "ForkExec"), ("syscall", "StartProcess"), ("golang.org/x/sys/unix", "Exec")}
# A TestMain naming one of these may also run one m.Run() more than once (for, goto, func: a loop, a jump
# back, a literal called twice; L3 and Potency on #6677), or Parallel; it names no selector's word either.
MAIN_BARRED = ORDER_WORDS | {"flag", "unsafe", "Parallel", "for", "goto", "func"} | {w for _, w in ORDER_SELECTORS}
LABEL = re.compile(r"^\s*[A-Za-z_]\w*\s*:(?!=)", re.M)  # a label (a `default:` too, which is safe to refuse)
BRACKETS = {"(": ")", "[": "]", "{": "}"}


CLAUSES = {}  # (path, module, commit): _clause's, cleared by moved() as OUTSIDE is


def _clause(path, module, commit):
    """The package clause of this module's package at import path, or None when not read."""
    if (path, module, commit) not in CLAUSES:
        CLAUSES[(path, module, commit)] = _read_clause(path, module, commit)
    return CLAUSES[(path, module, commit)]


def _read_clause(path, module, commit):
    """_clause, not memoized."""
    if not module or not (path == module or path.startswith(module + "/")):
        return None
    rel = path[len(module) + 1:] if path != module else ""
    got = _go_files(rel, commit) if ".." not in rel.split("/") else None
    found = {(m := re.search(r"^package\s+(\w+)", _uncommented(t, False), re.M)) and m[1]
             for p, t in (got or {}).items() if not p.endswith("_test.go")}
    return found.pop() if len(found) == 1 else None


def _closer(bare, i):
    """The index of the bracket closing bare[i] (comments and literal contents blanked), or None."""
    stack = []
    for j in range(i, len(bare)):
        c = bare[j]
        if c in BRACKETS:
            stack.append(BRACKETS[c])
        elif c in ")]}":
            if not stack or stack.pop() != c:
                return None
            if not stack:
                return j
    return None


def _opener(bare, lo, hi):
    """The index of the innermost bracket of bare[lo:hi] still open at hi, or None."""
    stack = []
    for j in range(lo, hi):
        if bare[j] in BRACKETS:
            stack.append(j)
        elif bare[j] in ")]}":
            if not stack or BRACKETS[bare[stack.pop()]] != bare[j]:
                return None
    return stack[-1] if stack else None


def _std_names(specs, clause):
    """{name: path} of a file's standard library imports, or None when an import may bind `testing`
    to another package: so named, or of a path whose name is not known for certain (clause)."""
    std = {}
    for alias, path in specs:
        if alias in ("_", "."):
            continue
        known = "." not in path.split("/")[0]
        parts = path.split("/")
        name = alias or (parts[-1] if known else clause(path))
        # Defence in depth (Security r1 on #6677): Go refuses a file that binds `testing` twice, and a
        # standard path's name is its last element, so no compiling file reaches the second clause.
        if name is None or (name == "testing" and path != "testing"):
            return None
        if known:
            std[name] = path
    return std


def _bodies(p, text, decls):
    """[(declaration, its line, head row, offset of its body's `{`, offset of its `}`)] of p's funcs, or
    None when a body runs past its declaration (a layout not read). open_ or close is None where the head
    does not end in `{` or the brace does not close."""
    bare = _uncommented(text, False)
    rows = bare.split("\n")
    starts = [0]
    for r in rows:
        starts.append(starts[-1] + len(r) + 1)
    out = []
    for d in decls[p]:
        if d[1] not in ("func", "method"):
            continue
        at = next((i for i in range(d[6], d[7] + 1) if DECL.match(rows[i - 1])), None)
        head = rows[at - 1] if at else ""
        open_ = starts[at - 1] + len(head) - 1 if at else None
        close = _closer(bare, open_) if at and head.endswith("{") else None
        if close is not None and close >= starts[d[7]]:
            return None
        out.append((d, at or d[6], head, open_, close))
    return out


def _order_risk(files, facts, decls, clause, outside):
    """The first file:line of a package's .go files ({path: text}) that may change test flags or rerun or
    outlive a test (see above), or None. outside(import path) is _outside_marks'."""
    names = {n for ds in decls.values() for d in ds if d[1] != "header" for n in d[2]}
    marked, refs = _marks(files, facts, decls, clause, outside)
    rough = None  # _unformatted(files), read once a var calling nothing would otherwise widen
    for p in sorted(files):
        f, text = facts[p], files[p]
        quals = {a or path.split("/")[-1] for a, path in f.specs if path in ORDER_PATHS}
        bodies = _bodies(p, text, decls)
        if bodies is None:
            return f"{p}: a body past its declaration"
        code, bare = _uncommented(text), _uncommented(text, False)
        for d, at, head, open_, close in bodies:
            if d[1] == "func" and "TestMain" in d[2] and is_test(p):
                std = _std_names(f.specs, clause)
                m = MAIN_HEAD.fullmatch(head)
                if (std is None or m is None or close is None or any(a == "." for a, _ in f.specs) or not _plain_main(
                        m[1], code[open_:close + 1], bare[open_:close + 1], names - {"TestMain"}, std)):
                    return f"{p}:{at}: TestMain"
        rows = bare.split("\n")
        for i, d in enumerate(decls[p]):
            if d[1] not in ("func", "var") or (d[1] == "func" and "init" not in d[2]):
                continue
            what = f"{p}:{_decl_line(d, rows)}: " + ("package var" if d[1] == "var" else "init")
            hit = refs[(p, i)] & marked.keys()
            if not hit and not _order_seed(d, quals, f.specs, _decl_text(bare, d), refs[(p, i)], clause, outside):
                continue
            # A var whose initializer calls nothing runs nothing; what it holds is marked (_marks), so
            # what calls it is still read (#6687). Read from gofmt's layout only (_calls_nothing).
            if d[1] == "var" and not d[4] & ORDER_WORDS and _calls_nothing(_decl_text(bare, d)):
                if rough is None:
                    rough = _unformatted(files)
                if p not in rough:
                    continue
            return f"{what} via {marked[min(hit)]}" if hit else what
        if (go := _go_risk(f.specs, bare)) is not None:
            return f"{p}:{bare.count(chr(10), 0, go[0]) + 1}: {go[1]}"
    return None


def _calls_nothing(bare):
    """Whether a package var declaration (its text, comments and literal contents blanked) runs no call
    and changes no state when initialized (#6687): no `(` but a func literal's or func type's own, and no
    `<-` outside a func literal's body (a channel receive, the one Go expression that changes state
    without a call; L3 on #6762), gofmt's layout read. A func
    literal is `func(params)`, results, then ` {` and its body; a func type is the same with no ` {`
    (`func() error{` opens a composite literal). Anything else with a `(` (a call, a conversion, a method
    expression, a called literal's `}(`) reads as a call."""
    at = re.search(r"\bvar\b", bare)
    if at is None:
        return False
    text, i = bare[at.end():], 0
    if text.lstrip().startswith("("):
        open_ = len(text) - len(text.lstrip())
        if (close := _closer(text, open_)) is None:
            return False
        text = text[open_ + 1:close] + text[close + 1:]
    while m := re.search(r"\bfunc\(", text):
        if (end := _closer(text, m.end() - 1)) is None:
            return False
        rest = text[end + 1:]
        if (results := re.match(r"\s*\(", rest)) is not None:
            if (shut := _closer(rest, results.end() - 1)) is None:
                return False
            end, rest = end + 1 + shut, rest[shut + 1:]
        kind = re.match(r"[\w \t.*\[\]]*", rest)
        if rest[kind.end():kind.end() + 1] == "{" and rest[kind.end() - 1:kind.end()] == " ":
            if (end := _closer(text, end + 1 + kind.end())) is None:  # a literal: its body runs later
                return False
        text = text[:m.start()] + text[end + 1:]
    return "(" not in text and "<-" not in text  # a receive takes a value another reader would get (#6762)


def _order_seed(d, quals, specs, bare, refs, clause, outside):
    """Whether a declaration (bare: its text, comments and literal contents blanked; refs: _refs') names
    ORDER_WORDS (string contents too), a qualifier of an ORDER_PATHS import, an ORDER_SELECTORS selector,
    or what another package marks (outside, _outside_marks): `lib.F` for its marked F, any `x.m` for a
    marked method m of a package the file imports, and any selector of a non-standard import not read
    (Security on #6686: `func init() { lib.Shuffle() }`)."""
    paths, unknown = _import_names(specs, clause)
    if d[4] & ORDER_WORDS:
        return True
    for q in set(WORD.findall(bare)) & quals:  # a qualifier in a string is none (L3 on #6686)
        # A flag qualifier seeds unless each use is `q.F(` for a FLAG_DEFINES F (#6687).
        if not (q in {a or path for a, path in specs if path == "flag"}
                and len(re.findall(rf"\b{q}\b", bare)) == len(re.findall(rf"(?<![\w.]){q}\.(?:{'|'.join(FLAG_DEFINES)})\(", bare))):
            return True
    for q, w in re.findall(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)", bare):
        if (paths.get(q), w) in ORDER_SELECTORS:
            return True
        if q in paths and not _std(paths[q]) and ((got := outside(paths[q])) is None or ("", w) in got):
            return True
        if q not in paths and unknown:
            return True  # q may be an import whose name is not read (Security on #6686: `go-lib`, `lib/v2`)
    methods = set()
    for path in {p for p in paths.values() if not _std(p)}:
        methods |= {n for n in outside(path) or () if n[0] == "."}
    # A dot import names its package's declarations bare (`On()`, `s.M()`; L3 and Security on #6686): one
    # of a standard package whose names may change flags, or of any non-standard one, seeds.
    if any(a == "." and (path in DOT_BARRED or not _std(path)) for a, path in specs):
        return True
    return bool(refs & methods)


def _import_names(specs, clause):
    """({name: path} of a file's imports, whether one's name is not known): an alias; a standard path's
    last element (the one before a `/vN`, as `math/rand/v2`'s rand); a module package's own clause; any
    other path's name is not known, since its clause need not be its last element (`go-imap`, `lib/v2`)."""
    out, unknown = {}, False
    for alias, path in specs:
        if alias in ("_", "."):
            continue
        parts = path.split("/")
        if alias:
            out[alias] = path
        elif _std(path):
            out[parts[-2] if len(parts) > 1 and re.fullmatch(r"v\d+", parts[-1]) else parts[-1]] = path
        elif name := clause(path):
            out[name] = path
        else:
            unknown = True
    return out, unknown


def _std(path):
    """Whether an import path is the standard library's: no dot in its first element."""
    return "." not in path.split("/")[0]


def _marks(files, facts, decls, clause, outside):
    """(marked, refs): marked {(kind, name): file:line} of a package's declarations whose text may change
    test flags (_order_seed), transitively by name; kind "." is a method's (named after a `.`), "" any
    other's (named bare). refs {(path, index): _refs} of each declaration."""
    marked, own, refs = {}, {}, {}
    for p in sorted(files):
        rows = _uncommented(files[p], False).split("\n")
        quals = {a or path.split("/")[-1] for a, path in facts[p].specs if path in ORDER_PATHS}
        imports = set(_import_names(facts[p].specs, clause)[0])
        for i, d in enumerate(decls[p]):
            if d[1] != "header":
                # A type or const runs no code: naming one runs nothing it declares (a method runs
                # only when named after a `.`, which marks it).
                kind = "." if d[1] == "method" else ""
                own[(p, i)] = {(kind, n) for n in _own_names(d, rows) - {"_", "init"}}  # no code names either
                text = "\n".join(rows[d[6] - 1:d[7]])
                refs[(p, i)] = _refs(text, imports)
                if d[1] in ("type", "const"):
                    own[(p, i)] = set()
                elif _order_seed(d, quals, facts[p].specs, text, refs[(p, i)], clause, outside):
                    for n in own[(p, i)]:
                        marked.setdefault(n, f"{p}:{_decl_line(d, rows)}")
    grew = True
    while grew:  # a declaration naming a marked one is marked: by name, so a shadow counts too
        grew = False
        for k, ns in own.items():
            for n in ns - marked.keys():
                if got := refs[k] & (marked.keys() - {n}):
                    marked[n], grew = marked[min(got)], True
    return marked, refs


OUTSIDE = {}  # (import path, module, commit): _outside_marks'


def _outside_marks(path, module, commit):
    """The marked names (_marks) of the non-test files of this module's package at import path, or None
    (everything marked) when it is not this module's or a file of it is not read. Memoized; a cycle,
    which Go refuses, reads as None."""
    key = (path, module, commit)
    if key in OUTSIDE:
        return OUTSIDE[key]
    OUTSIDE[key] = None
    if not module or not (path == module or path.startswith(module + "/")):
        return None
    rel = path[len(module) + 1:] if path != module else ""
    files = _go_files(rel, commit) if ".." not in rel.split("/") else None
    if files is None:
        return None
    files = {p: t for p, t in files.items() if not is_test(p)}
    facts = {p: _facts(p, t) for p, t in files.items()}
    if any(f.specs is None for f in facts.values()):
        return None
    decls = {p: _decls(p, t) for p, t in files.items()}
    OUTSIDE[key] = frozenset(_marks(files, facts, decls, lambda q: _clause(q, module, commit),
                                    lambda q: _outside_marks(q, module, commit))[0])
    return OUTSIDE[key]


def _decl_line(d, rows):
    """A declaration's own line (its doc comment aside) of its file's rows."""
    return next((i for i in range(d[6], d[7] + 1) if DECL.match(rows[i - 1])), d[6])


def _decl_text(bare, d):
    """A declaration's lines of a file's text."""
    return "\n".join(bare.split("\n")[d[6] - 1:d[7]])


def _refs(bare, imports):
    """{(kind, name)} code (comments and literal contents blanked) may use of its package's own
    declarations: ("", w) for each word w not after a `.`, (".", w) for one after a `.` whose base is
    not an import's name (`x.setup()`, never `errors.New`)."""
    out = set()
    for w in re.finditer(r"(?:([A-Za-z_]\w*)?(\s*\.\s*))?\b([A-Za-z_]\w*)", bare):
        if w[1]:
            out.add(("", w[1]))
        if not w[2]:
            out.add(("", w[3]))
        elif w[1] not in imports:  # None: the base is a call, an index or a literal (`f().x`)
            out.add((".", w[3]))
    return out


def _own_names(d, rows):
    """The names a declaration binds: a method's own name (its receiver's type aside), read from its
    head row (rows: its file's lines), where _decls names none."""
    if d[1] != "method":
        return d[2]
    at = next((rows[i - 1] for i in range(d[6], d[7] + 1) if DECL.match(rows[i - 1])), "")
    m = re.match(r"func\s*\([^)]*\)\s*([A-Za-z_]\w*)", at)
    return {m[1]} if m else set(d[4])  # not read: every word, which marks more, never less


def _go_risk(specs, bare):
    """(offset, what) of the first `go` statement of a file (bare: comments and literal contents blanked)
    that calls Run on a *testing.T or *testing.B parameter or passes one to a call (which may), or of a
    method value of one's Run; None when the file imports no testing. A subtest a goroutine starts may
    outlive its parent (#6682); `t.Error` from a goroutine reorders nothing."""
    alias = [a or "testing" for a, path in specs if path == "testing"]
    if not alias:
        return None
    if "." in alias:
        return 0, "testing dot-imported"  # its T is named bare: not read
    ts = set()
    for a in alias:
        for names in re.findall(rf"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+\*\s*{a}\s*\.\s*[TB]\b", bare):
            ts |= set(WORD.findall(names))  # each name of `a, b *testing.T` (L3 on #6686); a type before too
    for t in sorted(ts):
        if v := re.search(rf"(?<!\w){t}\s*\.\s*Run\b(?!\s*\()", bare):
            return v.start(), "Run method value"
    for g in re.finditer(r"\bgo\b", bare):
        depth, j = 0, g.end()
        while j < len(bare) and not (depth == 0 and bare[j] in "\n;}"):
            depth += bare[j] in BRACKETS
            depth -= bare[j] in ")]}"
            j += 1
        seg = bare[g.end():j]
        if any(re.search(rf"(?<!\w){t}\s*\.\s*Run\b|[(,]\s*{t}\s*[,)]", seg) for t in ts):
            return g.start(), "go statement"
    return None


def _subtests_only(files, facts, decls, clause):
    """None when every Parallel of a package's .go files ({path: text}) is a subtest's (see above), else
    the first file:line read otherwise."""
    pkg_vars = {n for ds in decls.values() for d in ds if d[1] == "var" for n in d[2]} - {"_"}  # `_` names no var
    for p, text in sorted(files.items()):
        if "go:linkname" in text:
            return f"{p}: linkname"
    for p, text in sorted(files.items()):
        f = facts[p]
        if not f.parallel:
            continue
        if not is_test(p):
            return f"{p}: Parallel in a non-test file"
        if _std_names(f.specs, clause) is None:
            return f"{p}: testing may bind another package"
        code, bare = _uncommented(text), _uncommented(text, False)
        bodies = _bodies(p, text, decls)
        if bodies is None:
            return f"{p}: a body past its declaration"
        safe = set()
        for d, at, head, open_, close in bodies:
            if not (m := TEST_HEAD.fullmatch(head)) or close is None:
                continue
            got = _subtest_calls(m[1], bare, code, open_, close, pkg_vars)
            if got is None:
                return f"{p}:{at}: {d[2] and min(d[2])} binds t otherwise, or a subtest names a package var"
            safe |= got
        for w in re.finditer(r"\bParallel\b", code):
            if w.start() not in safe:
                return f"{p}:{code.count(chr(10), 0, w.start()) + 1}: Parallel not a subtest's first statement"
    return None


def _subtest_calls(t, bare, code, open_, close, pkg_vars):
    """The offsets of the subtest Parallel calls of one top-level test (its param t, body bare[open_:close]),
    or None when its body binds t otherwise or a subtest literal names a package var."""
    safe, heads = set(), []
    for fn in re.finditer(r"\bfunc\b", bare[:close]):
        if fn.start() <= open_:
            continue
        paren = fn.end() + len(bare[fn.end():]) - len(bare[fn.end():].lstrip(" \t"))
        end = _closer(bare, paren) if bare[paren:paren + 1] == "(" else None
        if end is None:
            return None
        if not re.search(rf"(?<![\w.]){t}\b", bare[paren:end]):
            continue
        h = SUBTEST_HEAD.match(bare, fn.start())
        # h[1] != t is defence in depth (Security r1 on #6677): the parameters name t, and a
        # `func(x *testing.T)` head names only x, testing and T; t == "testing" would not compile.
        if h is None or h[1] != t:
            return None  # t bound by another function's parameter
        brace = h.end() - 1
        last = _closer(bare, brace)
        call = _opener(bare, open_ + 1, fn.start())
        if last is None or last > close or not re.match(r"\s*\)", bare[last + 1:]) or call is None:
            return None
        args = bare[call + 1:fn.start()]
        # _top_commas(args) != 1 is defence in depth (Security r1 on #6677): T.Run takes two arguments,
        # so a compiling `t.Run(` call with the literal last has exactly one comma before it.
        if (bare[call] != "(" or not re.search(rf"(?<![\w.]){t}\s*\.\s*Run$", bare[:call])
                or not args.rstrip().endswith(",") or _top_commas(args) != 1):
            return None
        if set(WORD.findall(code[brace:last + 1])) & pkg_vars:
            return None
        if first := re.match(rf"\{{[ \t]*\n\s*{t}\.(Parallel)\(\)[ \t]*\n", bare[brace:]):
            safe.add(brace + first.start(1))
        heads.append((fn.start(), h.end()))
    for w in re.finditer(rf"(?<![\w.]){t}\b", bare[open_:close]):
        at = open_ + w.start()
        if any(a <= at < b for a, b in heads):
            continue
        after, before = bare[at + len(t):], bare[:at]
        if re.match(r"\s*\.", after) or (re.search(r"[(,]\s*$", before) and re.match(r"\s*[,)]", after)):
            continue
        return None
    return safe


def _top_commas(args):
    """The number of commas of args outside any bracket."""
    depth, n = 0, 0
    for c in args:
        depth += c in BRACKETS
        depth -= c in ")]}"
        n += c == "," and depth == 0
    return n


def _plain_main(m, code, bare, names, std):
    """Whether a TestMain's body (param m) runs m.Run once and names nothing that may change what it runs:
    m only in one `m.Run()`, and no loop, jump, label or func literal that could run it again."""
    if LABEL.search(bare[bare.index("{") + 1:]):
        return False
    uses = [w.start() for w in re.finditer(rf"(?<![\w.]){m}\b", bare)]
    if len(uses) != 1 or not re.match(rf"{m}\.Run\(\)", bare[uses[0]:]):
        return False
    words = set(WORD.findall(code[bare.index("{"):]))
    if words & (names | MAIN_BARRED):
        return False
    return all(q == m or (q in std and std[q] not in ORDER_PATHS) for q in QUALIFIER.findall(bare))


def _parallel(pkg, commit, module, cache):
    """Why a test of broker/<pkg>/ may run out of source order (a file:line, see _order_risk), or None:
    whether it may call Parallel: the word in a .go file of it (test or not) or of
    a package of this module it imports, transitively; True when one is not read (L3 and Security on
    #6421: a helper may call t.Parallel()). An imported package's own _test.go files, and what only they
    import, are not built into pkg's test binary, so they are not read (#6372: journal's model_test.go
    made every cmd/agentosd test a change)."""
    seen, todo = {pkg}, [pkg]
    while todo:
        rel = todo.pop()
        if (rel, commit, rel == pkg) not in cache:
            cache[(rel, commit, rel == pkg)] = _package_reads(rel, commit, tests=rel == pkg, module=module)
        got = cache[(rel, commit, rel == pkg)]
        if got is None or got[0]:
            return got[0] if got else f"broker/{rel}/ not read"
        for path in got[1]:
            if module and (path == module or path.startswith(module + "/")):
                rel = path[len(module) + 1:] if path != module else ""
                if ".." in rel.split("/"):
                    return f"{path} outside broker/"
                if rel not in seen:
                    seen.add(rel)
                    todo.append(rel)
    return None


SAID = set()  # (package, why) already reported, since moved() runs once per side


def _run_list(side):
    """[(path, name, build, first line)] of what `go test` runs by name in one side of a package, in its
    order: the package's own _test.go files, then its _test package's, each in name then source order;
    None when a test file's build context, package clause or layout (not gofmt's) is not read."""
    files = sorted(((f.clause or "").endswith("_test"), p) for p, f in side.facts.items()
                   if is_test(p) and f.build != "ignored")
    out = []
    for _, p in files:
        f = side.facts[p]
        if f.build is None or f.clause is None or p in side.rough:
            return None
        out += [(p, n, f.build, d[6]) for d in f.decls if (n := f.run(d))]
    return out


def moved(diff_text, mb, head):
    """(moved, later): moved is ({path: head lines}, {path: base lines}) of the broker/ _test.go lines
    that the diff changes, or any other, which are no change of the package's tests: a declaration moved
    or left unchanged, or a header change, as Moved declarations above reads them (#6369); a package with
    a link or a file not read moves nothing. later is the same pair of the first lines of each test `go
    test` runs, in a package whose tests the diff changes, at or after the first place its run list
    differs, every one when _parallel (a parallel test resumes after every other); a
    path's lines are None (every test) where a side's run list is not read (#6385)."""
    tests, btests = added_lines(diff_text)[1], base_test_lines(diff_text)[0]
    now, then, later_now, later_then, reads = {}, {}, {}, {}, {}
    OUTSIDE.clear()  # keyed by commit names such as HEAD, which only this call's tree fixes
    CLAUSES.clear()
    module = (m := re.search(r"^module\s+(\S+)", base_text(head, "broker/go.mod") or "", re.M)) and m[1]
    for pkg in sorted({package_of(p) for p in [*tests, *btests] if is_test(p)} - {None}):
        b, h = _side(pkg, mb, module), _side(pkg, head, module)
        runs = (_run_list(b), _run_list(h)) if b and h else (None, None)
        if None in runs:
            later_now.update({p: None for p in tests if is_test(p) and package_of(p) == pkg})
            later_then.update({p: None for p in btests if is_test(p) and package_of(p) == pkg})
            continue
        was, now_runs = ([r[:3] for r in rs] for rs in runs)
        if was != now_runs:
            why = _parallel(pkg, mb, module, reads) or _parallel(pkg, head, module, reads)
            if why and (pkg, why) not in SAID:
                SAID.add((pkg, why))
                print(f"mutgate: broker/{pkg}/'s run list changes, so every test is a change ({why})",
                      file=sys.stderr)
            k = 0 if why else next(
                i for i in range(len(was) + 1) if i == len(was) or i == len(now_runs) or was[i] != now_runs[i])
            for side, rs in ((later_then, runs[0]), (later_now, runs[1])):
                for p, _, _, first in rs[k:]:
                    side.setdefault(p, set()).add(first)
        if b.rough or h.rough:
            continue  # a file not in gofmt's layout: nothing moves
        for p in sorted(set(b.facts) | set(h.facts)):
            bf, hf = b.facts.get(p), h.facts.get(p)
            if is_test(p) and _same_header(bf, hf, b, h):
                for side, f in ((then, bf), (now, hf)):
                    if f is not None:
                        side.setdefault(p, set()).update(f.header)
        for key, at in h.keyed.items():
            was = b.keyed.get(key, ())
            if len(at) != 1 or len(was) != 1:
                continue
            (hp, hd), (bp, bd) = at[0], was[0]
            if is_test(bp) and not is_test(hp):
                continue  # `go test` runs no test function of a non-test file
            if hp == bp or _same_binding(b.facts[bp], h.facts[hp], key[2], b, h):
                now.setdefault(hp, set()).update(range(hd[6], hd[7] + 1))
                then.setdefault(bp, set()).update(range(bd[6], bd[7] + 1))
    return (({p: ls for p, ls in now.items() if is_test(p)}, {p: ls for p, ls in then.items() if is_test(p)}),
            (later_now, later_then))


def _widen(lines, extra):
    """lines ({path: set or None}) with extra's lines added; None (the whole file) wins."""
    for p, ls in extra.items():
        if ls is None:
            lines[p] = None
        elif lines.get(p, ()) is not None:
            lines.setdefault(p, set()).update(ls)
    return lines


# Lexical reach over a package's _test.go files (D-319, #5826). A declaration (_decls) reaches every
# declaration whose name is a word of its code (string literals too: more is safe), and a type
# reaches its methods. A test reaches what it reaches, transitively; what every test may run
# (TestMain, init, a package var with an initializer that may run code (_quiet_vars), a blank or dot import, a method on a type no
# test file of its package clause declares, which package code may call through an interface, a
# file with a linkname, a directive go reads package-wide, such as go:debug) reaches all of them, as
# does a line no test reaches (fail closed). A named import reaches its file's declarations' tests (D-319).
WORD = re.compile(r"[A-Za-z_]\w*")
FUNC_HEAD = re.compile(r"^func\s*(?:\(\s*(?:\w+\s+)?\*?\s*(\w+)[^)]*\)\s*)?(\w+)")
NAMED = re.compile(r"^(?:var|const|type)\s+(\w+(?:\s*,\s*\w+)*)")
GROUPED = re.compile(r"^(?:var|const|type)\s*\(")
GROUP_NAMES = re.compile(r"(\w+(?:\s*,\s*\w+)*)")
SIDE_IMPORT = re.compile(r'(?:^|[\s(;])[_.]\s*["`]', re.M)
# A `//go:` directive reaches the declaration it sits on, or for a build line its own file, only when
# go reads it so; any other, `//go:debug` (a GODEBUG default of the whole test binary, Go 1.21+) or one
# not read here, is a setting of every test (#6377).
DIRECTIVE = re.compile(r"^\s*//go:(\w*)", re.M)
LOCAL_DIRECTIVES = {"build", "embed", "generate", "noinline", "nosplit", "norace", "noescape", "nocheckptr",
                    "uintptrescapes", "fix"}
EVERY = None


def _uncommented(text, literals=True):
    """Go source with its comments blanked (newlines kept, so lines keep their numbers); string and
    rune literals stay, since a name in one can reach code (reflect's MethodByName), or with
    literals False have their contents blanked too, so a column-0 line inside a raw string is no
    declaration (Security on #5838)."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in text[i:j]))
        elif c in "\"'`":
            j = i + 1
            while j < n and text[j] != c and not (c != "`" and text[j] == "\n"):
                j += 2 if c != "`" and text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(text[i:j] if literals else
                       c + "".join(ch if ch == "\n" else " " for ch in text[i + 1:j - 1]) + text[j - 1:j])
        else:
            j = i + 1
            out.append(c)
        i = j
    return "".join(out)


def _tied(text):
    """Whether a file ties its code to itself: a go:linkname, or cgo (`import "C"`, whose preamble is the
    file's own; #6385). Go takes imports only before a file's first other declaration, so a "C" literal
    from the start of the file to the first column-0 `func`, `type`, `var` or `const` (comments and,
    for finding that line, literal contents left out) is read as cgo; a later one, such as a test's
    `"C"` argument, is none (TOOL-mutgate-test-var-scope)."""
    if "go:linkname" in text:
        return True
    code, bare = _uncommented(text).split("\n"), _uncommented(text, False).split("\n")
    end = next((i for i, row in enumerate(bare) if DECL.match(row) and not row.startswith(("import", "package"))),
               len(bare))
    return bool(re.search(r'"C"|`C`', "\n".join(code[:end])))


def _decls(path, text):
    """[(path, kind, names, receiver, words, every, first, last, package clause)] of one test file's declarations,
    each from its doc comment (the `//` lines right above it, directives such as go:embed too) to
    the next one's; words are its code's, comments left out. The lines before the first declaration,
    the package clause and the imports are kind 'header'. A group's names are read from gofmt's
    layout; a shape not read so names every word of it, which reaches more, never less."""
    # Declarations are split and read on a copy without comments or literal contents; words come
    # from one with literals (code), line for line the same.
    rows, code, bare = text.split("\n"), _uncommented(text).split("\n"), _uncommented(text, False).split("\n")
    starts, prev = [], 0  # (first line, declaration line)
    for i, row in enumerate(bare):
        if DECL.match(row):
            k = i
            while k > prev and rows[k - 1].startswith("//"):
                k -= 1
            starts.append((k + 1, i + 1))
            prev = i + 1
    if not starts or starts[0][0] > 1:
        starts.insert(0, (1, None))
    linked = _tied(text)
    # x and x_test share a directory: a type is the test type of its own package clause only.
    clause = (m := re.search(r"^package\s+(\w+)", "\n".join(bare), re.M)) and m.group(1)
    out = []
    for n, (first, at) in enumerate(starts):
        last = starts[n + 1][0] - 1 if n + 1 < len(starts) else len(rows)
        if last < first:
            continue
        body, plain = "\n".join(code[first - 1:last]), "\n".join(bare[first - 1:last])
        head = bare[at - 1] if at else ""
        kind, names, recv, every = "header", set(), None, linked or any(
            m not in LOCAL_DIRECTIVES for m in DIRECTIVE.findall("\n".join(rows[first - 1:last])))
        if head.startswith("import"):
            every = every or bool(SIDE_IMPORT.search(body[body.index("import") + len("import"):]))
        elif head.startswith("func"):
            m = FUNC_HEAD.match(head)
            recv, name = (m.group(1), m.group(2)) if m else (None, None)
            kind = "method" if recv else "func"
            names = {name} if name and not recv else set()
            if m is None or (not recv and name in ("TestMain", "init")):
                every = True
        elif head.startswith(("var", "const", "type")):
            kind = head.split()[0].split("(")[0]
            every = every or (kind == "var" and "=" in plain)
            names = set(re.split(r"\s*,\s*", NAMED.match(head).group(1))) if NAMED.match(head) else set()
            inner = [r for r in bare[at:last] if r.strip()]
            if GROUPED.match(head) and head.rstrip().endswith("(") and inner and inner[-1] == ")":
                # gofmt's group: one name list per line at the group's indent, `)` alone at column 0.
                indent = min(len(r) - len(r.lstrip()) for r in inner[:-1]) if inner[:-1] else 0
                names = {n for r in inner[:-1] if len(r) - len(r.lstrip()) == indent
                         if (g := GROUP_NAMES.match(r.lstrip())) for n in re.split(r"\s*,\s*", g.group(1))}
            elif not names:
                names = set(WORD.findall(body))  # a shape not read here: every word stands in (more is safe)
        out.append((path, kind, names, recv, set(WORD.findall(body)), every, first, last, clause))
    return out


def _quiet_vars(files, decls):
    """decls with every test-file package var whose initializer runs nothing read as an ordinary
    declaration, reached by the tests that name it (TOOL-mutgate-test-var-scope): its file in gofmt's
    layout, no linkname or cgo, no directive go reads package-wide on it, and its text (comments and
    literal contents blanked) holding no `(` but a func literal's or func type's own and no receive
    outside one's body (_calls_nothing, #6687). Such an initializer runs no statement and changes no
    state before a test starts, and only test code, which names it, can read what it holds; what a
    reached test later writes through it (an alias of another var) is the static-reach bound every
    helper and test body has (MUT-test-helper-scope-1). Any other initialized var stays every test."""
    bare = {p: _uncommented(t, False) for p, t in files.items()}
    maybe = [i for i, d in enumerate(decls) if d[1] == "var" and d[5] and d[0].endswith("_test.go")
             and not _tied(files[d[0]]) and _calls_nothing(_decl_text(bare[d[0]], d))
             and all(m in LOCAL_DIRECTIVES for m in DIRECTIVE.findall(
                 "\n".join(files[d[0]].split("\n")[d[6] - 1:d[7]])))]
    if not maybe:
        return decls
    rough = _unformatted({d[0]: files[d[0]] for d in (decls[i] for i in maybe)})
    out = list(decls)
    for i in maybe:
        if decls[i][0] not in rough:
            out[i] = decls[i][:5] + (False,) + decls[i][6:]
    return out


def reaching_tests(files, changed, state=None):
    """Sorted names of the test functions in files ({path: text}, every _test.go file of one
    package) that reach the lines changed names ({path: set(line)}), or None when one of those lines
    is in a declaration every test may run (see WORD above) or that no test reaches. A line of a file's header (before its
    first declaration, the package clause, an import) reaches what that file's declarations reach.
    A line of state ({path: set(line)}, read_by's calls) also reaches the tests that reach any
    package var the declaration holding it reaches, an init's or TestMain's reach aside: a test
    can read what a reader left there without reaching the reader (#6657)."""
    decls = _quiet_vars(files, [d for path, text in sorted(files.items()) for d in _decls(path, text)])
    by_name, types = collections.defaultdict(list), {(d[8], n) for d in decls if d[1] == "type" for n in d[2]}
    methods = collections.defaultdict(list)
    for i, (_, kind, names, recv, *_rest) in enumerate(decls):
        for n in names:
            by_name[n].append(i)
        if kind == "method":
            methods[recv].append(i)
    edges = [{j for w in d[4] for j in by_name.get(w, ())}
             | {j for n in (d[2] if d[1] == "type" else ()) for j in methods.get(n, ())} for d in decls]
    reach = [set() for _ in decls]
    for i, (_, kind, names, recv, _w, every, *_rest) in enumerate(decls):
        test = kind == "func" and not every and decls[i][0].endswith("_test.go") and TEST_FUNC.match(
            f"func {next(iter(names), '')}(")
        if kind == "method" and (decls[i][8] is None or (decls[i][8], recv) not in types):
            every = True
        if not (test or every):
            continue
        mark = EVERY if every else next(iter(names))
        seen, todo = {i}, [i]
        while todo:
            for j in edges[todo.pop()] - seen:
                seen.add(j)
                todo.append(j)
        for j in seen:
            reach[j].add(mark)
    out = set()
    for path, lines in changed.items():
        mine = [i for i, d in enumerate(decls) if d[0] == path]
        if path not in files:
            return None
        bare = _uncommented(files[path], False).split("\n")
        for line in lines:
            hit = [i for i in mine if decls[i][6] <= line <= decls[i][7]]
            if len(hit) == 1 and decls[hit[0]][1] in ("func", "method") and (
                    (close := _body(bare, decls[hit[0]])[1]) is not None and line > close):
                continue  # the blank lines after a function's closing brace are no code of it
            if not hit or decls[hit[0]][1] == "header":
                hit = mine if not hit or not decls[hit[0]][5] else hit
            got = set().union(*(reach[i] for i in hit))
            if line in (state or {}).get(path, ()):
                seen, todo = set(hit), list(hit)
                while todo:
                    for j in edges[todo.pop()] - seen:
                        seen.add(j)
                        todo.append(j)
                got |= set().union(*(reach[j] - {EVERY} for j in seen if decls[j][1] == "var"))
            # No test reaches it (dead code, a benchmark, or a shape this reading missed): fail closed.
            if not got or EVERY in got or any(decls[i][1] == "header" and decls[i][5] for i in hit):
                return None
            out |= got
    return sorted(out)


def head_tests(tests, pkg):
    """Sorted names of the head's test functions that reach the lines the diff changes in
    broker/<pkg>/'s _test.go files, or None for every test (reaching_tests). Every _test.go file of
    the package is read as text from the tree, never run; a link is not followed, so one in the
    package is every test (L3 on #4643). A deleted file has no head lines: its base side runs. A
    changed file the package reads (owners) changes the lines narrowing names, read over every .go
    file of the package so a test reaching them through package code counts; an init or initialized
    var reaching them is every test (reaching_tests)."""
    d = BROKER / pkg
    if not tests_changed(tests, pkg):
        return []
    if d.is_symlink():
        return None
    held, state = {}, {}
    for p in tests:
        if pkg in owners(p):
            if (got := narrowing(pkg, p)) is None:
                return None
            held = union(held, got[1])
            state = union(state, got[1]) if got[0] == "read" else state
    files = {}
    for f in sorted(d.glob("*.go" if held else "*_test.go")) if d.is_dir() else ():
        if f.is_symlink():
            return None
        if f.is_file():
            if (text := go_text(f.read_bytes())) is None:
                return None
            if is_test(f"broker/{pkg}/{f.name}") or not unbuilt(f.name, text):
                files[f"broker/{pkg}/{f.name}"] = text
    changed = {p: ls for p, ls in tests.items() if package_of(p) == pkg and is_test(p) and p in files}
    if any(ls is None for ls in changed.values()):
        return None
    return reaching_tests(files, union(changed, held), state)


def narrowing(pkg, path, texts=None):
    """("embed", held) when broker/<pkg>/'s only namer of path, its own data file, is an embedding var
    (embedded_by, #6458); else ("read", held) when only recognised read calls name it (read_by,
    #6657); else None, every test (#5779, #6436). held is {repo path: {line}} for reaching_tests.
    The whole-suite run watches an embedded file, and a run of the other tests a read one, for
    run-time reads (record_for), so with no inotify nothing is narrowed. texts is _pkg_texts'."""
    if not _inotify():
        return None
    if is_data(path) and pkg == data_owner(path) and (
            got := embedded_by(pkg, path[len(f"broker/{pkg}/"):], texts)):
        return "embed", got
    return None if (got := read_by(pkg, path, texts)) is None else ("read", got)


# The build tags the go toolchain itself may set (go/build's Context and cmd/go's -race, -msan, -asan):
# any other tag is on only when a -tags flag sets it, and no `go` command the gate runs passes one.
TOOLCHAIN_TAGS = {"unix", "cgo", "gc", "gccgo", "race", "msan", "asan", "boringcrypto"}


def unbuilt(name, text):
    """Whether a non-test .go file is in no build the gate's `go test` runs: a name go ignores, or a
    build constraint false whatever the toolchain's own tags (TOOLCHAIN_TAGS, any GOOS, GOARCH or
    feature level, go1.N, goexperiment.X) hold, with every other tag off. A constraint not read, or a
    GOFLAGS naming tags, keeps the file (#6458)."""
    c = _constraint(name, text)
    if c == "ignored":
        return True
    if c is None or "tags" in os.environ.get("GOFLAGS", ""):
        return False
    used, table = c
    own = [t in TOOLCHAIN_TAGS | GOOS | GOARCH or t.split(".")[0] in GOARCH or t.startswith(("go1.", "goexperiment."))
           for t in used]
    return not any(v for k, v in enumerate(table) if all(own[i] for i in range(len(used)) if k >> i & 1))


def changed_tests(tests, pkg, bases):
    """head_tests, or None when the base side's change reaches every test (bases_for)."""
    return None if pkg in bases and bases[pkg] is None else head_tests(tests, pkg)


def _recorded_lines(pkg, lines):
    """({path: lines}, None) of a record's {name: [line]}, or (None, problem)."""
    out = {}
    for name, ls in lines.items():
        f = BROKER / pkg / name if isinstance(name, str) else None
        if (f is None or "/" in name or "\\" in name or not is_source(name) or f.is_symlink() or not f.is_file()
                or not isinstance(ls, list) or not all(type(n) is int and n > 0 for n in ls)):
            return None, f"records covered lines {str(name)[:80]!r}: {str(ls)[:80]}, not lines of a non-test .go file in broker/{pkg}/"
        out[f"broker/{pkg}/{name}"] = set(ls)
    return out, None


def targets_for(pkg, added, tests, data, bases):
    """({path: lines}, None) of a claimed package's target lines, or (None, problem): the lines the
    diff adds to its non-test files there and, when the diff changes or deletes a test there, the
    lines those tests cover, from the record `run` wrote in data, which must name exactly the tests
    changed_tests names here. A diff that also adds a non-test line keeps that widening (#5762).
    The record's `base` part is the same for the base's version of the changed tests, run on the
    base tree, its lines moved to the head's (bases[pkg] names the tests): a weakened or deleted test
    covers nothing at the head, so only the base's run shows what it checked."""
    own = diff_targets(added, pkg)
    if not tests_changed(tests, pkg):
        return own, None
    rec = data.get("targets") if isinstance(data, dict) else None
    base = rec.get("base") if isinstance(rec, dict) else None
    for part, want, where in ((rec, changed_tests(tests, pkg, bases), ""), (base, bases.get(pkg, ()), " at the base")):
        if not isinstance(part, dict) or part.get("tests") != want or not isinstance(part.get("lines"), dict):
            return None, (f"holds no record of the lines that {'every test' if want is None else want} covers{where}, "
                          f"the tests this diff changes in broker/{pkg}/ (`mutgate.py run --git` writes it)")
    out, problem = _recorded_lines(pkg, rec["lines"])
    was, problem = (None, problem) if problem else _recorded_lines(pkg, base["lines"])
    return (None, problem) if problem else (union(own, out, was), None)


def waivers(body):
    """{(path, line, kind, col): reason} of a waiver file's `Mutant-equivalent:` lines, kind and col None
    where the line names none. The body is text only."""
    out = {}
    for row in (body or "").replace("\r\n", "\n").split("\n"):
        m = EQUIVALENT.match(row)
        if m and re.search(r"[A-Za-z]{2}", m.group(5)) and not placeholder(m.group(5)):
            out[(m.group(1), int(m.group(2)), m.group(4), int(m.group(3)) if m.group(3) else None)] = m.group(5)
    return out


def placeholder(reason):
    """Whether a waiver's reason still holds the <reason> the gate's messages print, unfilled: no proof
    holds that text (L3 on #5976)."""
    return "<reason>" in reason.lower()


def malformed_waivers(body):
    """A warning for each line that starts like a waiver (behind any indent, backtick, bullet or quote
    mark) but waivers does not read, holding the <reason> placeholder, or naming a kind no mutant has
    (#5828, L3 on #5976). Each waives nothing, so its mutant still fails (fail closed);
    the warning says why, rather than leaving the line unread or listed only as unused."""
    out = []
    for row in (body or "").replace("\r\n", "\n").split("\n"):
        if not WAIVER_START.match(row):
            continue
        m = EQUIVALENT.match(row)
        if not m or not re.search(r"[A-Za-z]{2}", m.group(5)):
            out.append(f"the line {row.strip()[:200]!r} is not read as a waiver, so it waives nothing: write it "
                       "Mutant-equivalent: <path>:<line>[:<col>][:<KIND>] <reason> at the start of its own line, with "
                       "nothing before it (no indent, bullet, box, quote mark, heading, bold, table bar or backtick; line and column from 1, the kind in capitals as the "
                       "summary's Mutant cell gives it, a reason in words)")
        elif placeholder(m.group(5)):
            out.append(f"the waiver {site_text((m.group(1), int(m.group(2)), m.group(4), int(m.group(3)) if m.group(3) else None))} "
                       "still holds the <reason> placeholder, so it waives nothing: replace it with why no test can tell the "
                       "mutant apart")
        elif m.group(4) and m.group(4) not in KINDS:
            out.append(f"the waiver {site_text((m.group(1), int(m.group(2)), m.group(4), int(m.group(3)) if m.group(3) else None))} "
                       f"names the kind {m.group(4)}, which no mutant has, so it waives nothing: use the kind the "
                       "summary's Mutant cell gives")
    return out


def not_equivalent(rows):
    """The sites, as site_text spells them and sorted, of waivers' rows whose reason says not equivalent."""
    return sorted(site_text(w) for w, reason in rows.items() if NOT_EQUIVALENT.search(reason))


def refuse_not_equivalent(sites, out=None):
    """Print why each `Mutant-equivalent:` line of sites is refused; True when sites holds one."""
    for site in sites:
        print(f"mutgate: the Mutant-equivalent line {site} says its mutant is not equivalent, so it proves "
              "nothing: delete the line, or reword it only if the mutant is in fact equivalent; kill a real "
              "survivor with a test, or open a work-item row for it (a row does not pass the gate); a mutant "
              "gremlins misreads is a tools/mutgate.py defect for its own row", file=out)
    return bool(sites)


def site_text(w):
    """A waiver key (path, line, kind, col) as a waiver line spells it: `<path>:<line>[:<col>][:<KIND>]`."""
    path, line, kind, col = w
    return f"{path}:{line}" + (f":{col}" if col else "") + (f":{kind}" if kind else "")


def mutants_of(data, status=None):
    """[(file, line, type, column)] of one package's mutants in its result (those of status only, when
    given), sorted; column is None where the result gives none."""
    return sorted(
        (m_file["file_name"], m["line"], m["type"], m["column"] if type(m.get("column")) is int else None)
        for m_file in data.get("files") or []
        for m in m_file.get("mutations") or []
        if status is None or m.get("status") == status
    )


def covering(waived, mutants):
    """({(path, line, kind, col): waiver} of each mutant some waiver names alone, [(waiver, [mutant])] of
    each waiver that matches more than one). A waiver (path, line, kind, col) matches each mutant of
    mutants ({pkg: [(file, line, type, column)]}) on its line whose kind and column it names or leaves
    None. One waiver is one proof, so it waives a mutant only when that mutant is the one it matches:
    one naming a line of several mutants waives none of them (#5792, Security on #5774)."""
    by_line = collections.defaultdict(list)
    for pkg, items in mutants.items():
        for fname, line, kind, col in items:
            by_line[(f"broker/{pkg}/{fname}", line)].append((kind, col))
    cover, ambiguous = {}, []
    for w in waived:
        path, line, kind, col = w
        hit = [(path, line, k, c) for k, c in by_line.get((path, line), []) if kind in (None, k) and col in (None, c)]
        if len(hit) > 1:
            ambiguous.append((w, sorted(hit, key=lambda m: (m[3] or 0, m[2]))))
        elif hit:
            cover[hit[0]] = w
    return cover, ambiguous


# The waiver record (MUT-waiver-store, #5776). A reviewed `Mutant-equivalent:` proof lives on in
# broker/<pkg>/MUTANTS-EQUIVALENT, keyed by its statement rather than its line number, so a run whose
# targets widen past the PR's own lines (a test-only change, #5743) does not bring back survivors
# already proven, and a line moved by an edit above it keeps its proof. One JSON object per line
# (a `#` line or a blank one is a comment): file (a non-test .go file of the package), mutant (the one
# mutant kind proven: STATEMENT_DELETION or a gremlins type; the entry waives no other kind on its
# line), func (the top-level declaration the line sits in, as `mutgate_stmts.go -decls` names it:
# `Recv.Name` for a method; "" outside any), decl (sha256 of that declaration's whole text from
# go/parser's span, whitespace runs as one space; "" outside any), stmt (the text
# of each line of the statement's own syntax, as `mutgate_stmts.go` lists them, or the line alone
# when it is in no listed statement, whitespace runs as one space), at (which of stmt's lines),
# after (the code line before the statement's first), occurrence ([i, n]: the i-th of the n lines
# of the file with that same key), reason, accepted (`#<PR>`, the PR that adds the entry), and
# optionally col (the mutant's column on its line, as the result gives it, #5792): an entry waives a
# mutant only when no other mutant of its kind on its line (at its col, when it names one) is in the
# result, so a line of several such mutants needs col.
# The head's statements are resolved to lines each run; an entry whose key is now on no line, or
# whose count n differs, is stale and fails the gate, so any edit inside the enclosing declaration
# (the statement, the code after it that a proof cites, a twin of it) needs the proof read again,
# while lines moved outside it keep it (Security on #5780). The record is the PR's
# text, read as data: a new or changed entry shows as such in the summary, for review.
# A proof that rests on code outside its own declaration names that code in optionally deps
# (MUT-record-deps, #6282): a list of {file (a non-test .go file under broker/, from the repository
# root, any package), func (a name the top-level declaration declares, as `-decls` lists its names:
# `Recv.Name` for a method, any name of a var, const or type group), decl (that declaration's digest,
# as decl)}. An entry is stale, as when its own decl changed, while a dep's file is gone, declares no
# such name or declares it twice, or holds it with another digest; so an edit to code a proof cites,
# in any file, needs the proof read again. An entry without deps reads as before. `waive --dep` writes them.
RECORD = "MUTANTS-EQUIVALENT"
RECORD_KEYS = {"file", "mutant", "func", "decl", "stmt", "at", "after", "occurrence", "reason", "accepted"}
RECORD_OPTIONAL = {"col", "deps"}
DEP_KEYS = {"file", "func", "decl"}
DEP_FILE = re.compile(r"broker(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+\.go")  # no `.`, `..` or hidden segment
DEP_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?")
DIGEST = re.compile(r"[0-9a-f]{64}")
MUTANT_KIND = re.compile(r"[A-Z][A-Z_]{0,63}")
RECORD_MAX = 1 << 20
RECORD_FILE = re.compile(r"[A-Za-z0-9_.-]+\.go")


def _norm(text):
    return re.sub(r"\s+", " ", text).strip()


def _code(text):
    """Whether a source line holds code: not blank, not only a `//` comment."""
    s = text.strip()
    return bool(s) and not s.startswith("//")


def _digest(lines, d):
    """sha256 of declaration d's lines (`-decls`' start and end) of a file's lines, whitespace runs as one space."""
    lo, hi = d["start"] - 1, min(d["end"], len(lines))
    return hashlib.sha256("\n".join(_norm(t) for t in lines[lo:hi]).encode()).hexdigest()


def dep_file_ok(path):
    """Whether path can be a dep's file: a non-test .go file under broker/, named from the repository root."""
    return isinstance(path, str) and bool(DEP_FILE.fullmatch(path)) and not path.endswith("_test.go")


def deps_ok(deps):
    """Whether a record entry's deps has RECORD's shape: a non-empty list of distinct {file, func, decl}."""
    return (isinstance(deps, list) and len(deps) > 0
            and all(isinstance(x, dict) and set(x) == DEP_KEYS and dep_file_ok(x["file"])
                    and isinstance(x["func"], str) and DEP_NAME.fullmatch(x["func"]) is not None
                    and isinstance(x["decl"], str) and DIGEST.fullmatch(x["decl"]) is not None for x in deps)
            and len({(x["file"], x["func"]) for x in deps}) == len(deps))


def statement_keys(src, sites, decls=()):
    """{line: key} for every line of one file's source src, sites being the lister's sites for that
    file and decls its top-level declarations (`-decls`, go/parser's spans, Security on #5780); a key
    is (func, decl, stmt, at, after) as the record holds them (see RECORD)."""
    lines = src.split("\n")
    funcs, decls_of = [""] * len(lines), [""] * len(lines)
    for d in decls:
        lo, hi, digest = d["start"] - 1, min(d["end"], len(lines)), _digest(lines, d)
        funcs[lo:hi] = [d["name"]] * (hi - lo)
        decls_of[lo:hi] = [digest] * (hi - lo)
    owner = {}
    for s in sorted(sites, key=lambda s: s["end"] - s["start"], reverse=True):
        for n in s["lines"]:
            owner[n] = s  # the innermost listed statement whose own syntax stands on n
    keys = {}
    for n in range(1, len(lines) + 1):
        own = owner.get(n, {}).get("lines") or [n]
        first = own[0]
        prev = next((lines[i - 1] for i in range(first - 1, 0, -1) if _code(lines[i - 1])), "")
        keys[n] = (funcs[first - 1], decls_of[first - 1], tuple(_norm(lines[i - 1]) for i in own if 0 < i <= len(lines)),
                   own.index(n), _norm(prev))
    return keys


def record_entries(text):
    """([entry], None) of a record's text, or (None, problem). Each entry is checked for shape only. A line that
    repeats an earlier one word for word is one entry (two PRs merged one proof, #6358). A carriage return fails the
    record: its lines end in LF only, so a CRLF repeat of an entry is never a second entry (#6375, .gitattributes)."""
    out, seen = [], set()
    for i, row in enumerate(text.split("\n"), 1):
        if "\r" in row:
            return None, f"line {i} holds a carriage return; a record's lines end in LF only"
        if not row.strip() or row.lstrip().startswith("#") or row in seen:
            continue
        seen.add(row)
        try:
            e = json.loads(row)
        except ValueError:
            return None, f"line {i} is not one JSON object"
        ok = (isinstance(e, dict) and RECORD_KEYS <= set(e) <= RECORD_KEYS | RECORD_OPTIONAL
              and ("col" not in e or (type(e["col"]) is int and e["col"] >= 1))
              and isinstance(e["file"], str) and RECORD_FILE.fullmatch(e["file"]) and not e["file"].endswith("_test.go")
              and isinstance(e["mutant"], str) and MUTANT_KIND.fullmatch(e["mutant"])
              and isinstance(e["func"], str)
              and isinstance(e["decl"], str) and re.fullmatch(r"[0-9a-f]{64}", e["decl"])
              and isinstance(e["stmt"], list) and e["stmt"] and all(isinstance(s, str) for s in e["stmt"])
              and type(e["at"]) is int and 0 <= e["at"] < len(e["stmt"])
              and isinstance(e["after"], str)
              and isinstance(e["occurrence"], list) and len(e["occurrence"]) == 2
              and all(type(x) is int for x in e["occurrence"]) and 1 <= e["occurrence"][0] <= e["occurrence"][1]
              and isinstance(e["reason"], str) and re.search(r"[A-Za-z]{2}", e["reason"])
              and isinstance(e["accepted"], str) and re.fullmatch(r"#[1-9]\d*", e["accepted"])
              and ("deps" not in e or deps_ok(e["deps"])))
        if not ok:
            return None, (f"line {i} is not an entry of {sorted(RECORD_KEYS)} (and optionally "
                          f"{sorted(RECORD_OPTIONAL)}) as tools/mutgate.py's RECORD says")
        out.append(e)
    return out, None


def _entry_key(e):
    return e["func"], e["decl"], tuple(e["stmt"]), e["at"], e["after"]


def file_keys(pkg, names, lister, pkg_dir=None):
    """({file: {line: key}}, None) for the named files of broker/<pkg>/ (those present), or (None, problem)."""
    pkg_dir = pkg_dir or BROKER / pkg
    files = [pkg_dir / n for n in sorted(set(names)) if (pkg_dir / n).is_file()]
    if links := [p.name for p in files if p.is_symlink()]:
        return None, f"broker/{pkg}/ holds .go files that are symbolic links, which mutgate does not follow: {links}"
    if not files:
        return {}, None
    r = subprocess.run([str(lister), *map(str, files)], capture_output=True)
    if r.returncode != 0:
        return None, f"cannot list the statements of broker/{pkg}/: {r.stderr.decode(errors='replace')}"
    d = subprocess.run([str(lister), "-decls", *map(str, files)], capture_output=True)
    if d.returncode != 0:
        return None, f"cannot list the declarations of broker/{pkg}/: {d.stderr.decode(errors='replace')}"
    sites, decls = collections.defaultdict(list), collections.defaultdict(list)
    for s in json.loads(r.stdout):
        sites[s["file"]].append(s)
    for s in json.loads(d.stdout):
        decls[s["file"]].append(s)
    texts = {p.name: go_text(p.read_bytes()) for p in files}
    if bad := sorted(n for n, t in texts.items() if t is None):
        return None, f"broker/{pkg}/ holds .go files go does not compile as text (not UTF-8, a NUL or a misplaced BOM): {bad}"
    return {n: statement_keys(t, sites[n], decls[n]) for n, t in texts.items()}, None


def list_dep_decls(paths, lister):
    """({path: [(names, digest)] of its top-level declarations, or None when it is no regular file}, None) for each
    dep file path (see RECORD) at the working tree, listed by lister (`-decls`, one run per directory), or (None,
    problem). The lister is Go's own parser, so a file it cannot parse is a problem, not an empty file."""
    out, by_dir = {}, collections.defaultdict(list)
    for p in sorted(set(paths)):
        parts = pathlib.PurePosixPath(p).parts[1:]
        if any(BROKER.joinpath(*parts[:i + 1]).is_symlink() for i in range(len(parts))):
            return None, f"{p}, which a record entry's deps name, is or is under a symbolic link, which mutgate does not follow"
        if not BROKER.joinpath(*parts).is_file():
            out[p] = None
            continue
        by_dir[BROKER.joinpath(*parts[:-1])].append(p)
    for d, ps in sorted(by_dir.items()):
        files = [d / pathlib.PurePosixPath(p).name for p in ps]
        r = subprocess.run([str(lister), "-decls", *map(str, files)], capture_output=True)
        if r.returncode != 0:
            return None, f"cannot list the declarations of {', '.join(ps)}: {r.stderr.decode(errors='replace')}"
        rows = collections.defaultdict(list)
        for s in json.loads(r.stdout):
            rows[s["file"]].append(s)
        for p, f in zip(ps, files):
            lines = f.read_bytes().decode("utf-8", "replace").split("\n")
            out[p] = [(s.get("names") or [s["name"]], _digest(lines, s)) for s in rows[f.name]]
    return out, None


def stale_deps(e, decls):
    """[(dep, why)] for each of entry e's deps that no longer holds at decls (list_dep_decls')."""
    out = []
    for x in e.get("deps", ()):
        have = decls.get(x["file"])
        named = [dg for names, dg in have or () if x["func"] in names]
        if have is None:
            out.append((x, "is no file now"))
        elif len(named) != 1:
            out.append((x, f"declares {x['func']} {len(named)} times now, not once"))
        elif named[0] != x["decl"]:
            out.append((x, f"has changed {x['func']}"))
    return out



# MUT-record-deps-audit (#6499, L3 on #6498): a reason that cites, as code, another top-level declaration of its own
# package names it in deps, so an edit there stales the proof. A citation is an identifier inside a backtick span,
# followed by `(` or `{`, or shaped as code (an uppercase letter, digit or `_` after its first character). A dotted
# X.Y cites the method X.Y when the package declares one, else X: Y is a member (a field, a foreign method, an
# imported package's name). `name.go` is a file. Bound: a citation in plain prose (`read`, `pair`), one to another
# package or to the standard library is not seen, so review still reads each reason against its deps.
CITED = re.compile(r"(?<![\w.])[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


def cited_names(reason, declared=frozenset()):
    """The identifiers reason cites as code (see CITED); a dotted one resolves its method against declared."""
    spans = [m.span() for m in re.finditer(r"`[^`]*`", reason)]
    out = set()
    for m in CITED.finditer(reason):
        parts, (s, e) = m.group().split("."), m.span()
        if parts[-1] == "go" and len(parts) > 1:  # a file: name.go
            continue
        if len(parts) > 1 and (method := f"{parts[0]}.{parts[1]}") in declared:
            out.add(method)
            continue
        x = parts[0]
        if (any(a < s and e <= b for a, b in spans) or reason[s + len(x):s + len(x) + 1] in ("(", "{")
                or re.search(r"[A-Z0-9_]", x[1:])):
            out.add(x)
    return out


def package_decls(pkg, lister, pkg_dir=None):
    """({name: [(path, digest)]} of every top-level name the non-test .go files of broker/<pkg>/ declare, None) or
    (None, problem). The paths are dep files (see RECORD)."""
    pkg_dir = pkg_dir or BROKER / pkg
    paths = sorted(f"broker/{pkg}/{p.name}" for p in pkg_dir.glob("*.go") if not p.name.endswith("_test.go"))
    decls, problem = list_dep_decls(paths, lister)
    if problem:
        return None, problem
    out = collections.defaultdict(list)
    for path, rows in sorted(decls.items()):
        for names, digest in rows or ():
            for n in names:
                if n and n != "_":
                    out[n].append((path, digest))
    return out, None


def undeclared_deps(pkg, entries, declared):
    """[problem] for each name an entry's reason cites (cited_names) that its package declares (declared,
    package_decls') outside the entry's own declaration while no dep of the entry names it."""
    problems = []
    for e in entries:
        own, named = (f"broker/{pkg}/{e['file']}", e["decl"]), {(x["file"], x["func"]) for x in e.get("deps", ())}
        for name in sorted(cited_names(e["reason"], declared)):
            where = sorted({p for p, dg in declared.get(name, ()) if (p, dg) != own})
            if where and not any((p, name) in named for p in where):
                problems.append(f"broker/{pkg}/{RECORD}: the entry for {e['file']} {e['func'] or '(top level)'} "
                                f"{e['stmt'][e['at']]!r} cites {name}, declared outside its own declaration in "
                                f"{', '.join(where)}, with no dep naming it: read the proof again and, if it holds, "
                                f"write it again with `mutgate.py waive --dep {where[0]}:{name}`")
    return problems


def read_record(pkg, pkg_dir=None):
    """(text or None, problem or None) of broker/<pkg>/MUTANTS-EQUIVALENT in the working tree."""
    path = (pkg_dir or BROKER / pkg) / RECORD
    if path.is_symlink():
        return None, f"broker/{pkg}/{RECORD} is a symbolic link, which mutgate does not follow"
    if not path.exists():
        return None, None
    if not path.is_file() or path.stat().st_size > RECORD_MAX:
        return None, f"broker/{pkg}/{RECORD} is not a regular file of at most {RECORD_MAX} bytes"
    return path.read_bytes().decode("utf-8", "replace"), None


def resolve_record(pkg, entries, keys, decls=None):
    """({(path, line, mutant, col): entry}, [problem]): each entry's line at the head, or why it names none; decls
    is list_dep_decls' for the entries' deps (an entry whose dep file it lacks is stale)."""
    found, problems = {}, []
    for e in entries:
        lines = sorted(n for n, k in keys.get(e["file"], {}).items() if k == _entry_key(e))
        i, n = e["occurrence"]
        where = f"broker/{pkg}/{RECORD}: the entry for {e['file']} {e['func'] or '(top level)'} {e['stmt'][e['at']]!r}"
        if stale := stale_deps(e, decls or {}):
            problems.append(f"{where} rests on " + "; ".join(f"{x['func']} in {x['file']}, which {why}" for x, why in stale)
                            + ": delete its line from the record, read the proof again, and if it holds add it back with "
                            "`mutgate.py waive --dep` naming what it rests on now")
        elif not lines:
            problems.append(f"{where} names no statement at the head: the statement or the func around it "
                            "changed; delete its line from the record, read the proof again, and if it holds add it "
                            "back with `mutgate.py waive` at its current line")
        elif len(lines) != n:
            problems.append(f"{where} was written for occurrence {i} of {n}, and the head has {len(lines)}: "
                            "delete its line from the record, read the proof again, and if it holds add it back with "
                            "`mutgate.py waive` at its current line")
        elif (site := (f"broker/{pkg}/{e['file']}", lines[i - 1], e["mutant"], e.get("col"))) in found:
            # Both versions, for the builder to keep one (#6358: an identical one never gets here).
            problems.append(f"{where} names the same line, column and mutant as another entry; keep one of:\n"
                            f"  {json.dumps(found[site], ensure_ascii=False)}\n  {json.dumps(e, ensure_ascii=False)}")
        else:
            found[site] = e
    return found, problems


def record_waivers(pkgs, lister, base=None, head="HEAD"):
    """({(path, line, mutant, col): (reason, accepted, new)}, [problem]) of the records of pkgs at the working
    tree; new is True for an entry that the merge base's record does not hold word for word."""
    mb = merge_base(base, head) if base else None
    out, problems = {}, []
    for pkg in sorted(pkgs):
        text, problem = read_record(pkg)
        if problem:
            problems.append(problem)
        if text is None:
            continue
        entries, problem = record_entries(text)
        if problem:
            problems.append(f"broker/{pkg}/{RECORD}: {problem}")
            continue
        keys, problem = file_keys(pkg, [e["file"] for e in entries], lister)
        if not problem:
            decls, problem = list_dep_decls([x["file"] for e in entries for x in e.get("deps", ())], lister)
        if problem:
            problems.append(problem)
            continue
        declared, problem = package_decls(pkg, lister)
        if problem:
            problems.append(problem)
            continue
        found, bad = resolve_record(pkg, entries, keys, decls)
        problems += bad + [refused_entry(pkg, e) for e in entries if NOT_EQUIVALENT.search(e["reason"])]
        problems += undeclared_deps(pkg, entries, declared)
        # An entry whose reason says not equivalent is no proof (#5909): it waives nothing and fails.
        found = {site: e for site, e in found.items() if not NOT_EQUIVALENT.search(e["reason"])}
        old = set()
        if mb and (prior := base_text(mb, f"broker/{pkg}/{RECORD}")) is not None:
            old = {json.dumps(e, sort_keys=True) for e in (record_entries(prior)[0] or [])}
        for site, e in found.items():
            out[site] = (e["reason"], e["accepted"], json.dumps(e, sort_keys=True) not in old)
    return out, problems


def refused_entry(pkg, e):
    """Why record entry e of broker/<pkg>/ is refused: its reason says its mutant is not equivalent (#5909)."""
    return (f"broker/{pkg}/{RECORD} holds an entry for {e['file']} {e['func'] or '(top level)'} {e['stmt'][e['at']]!r} "
            f"({e['mutant']}) whose reason says its mutant is not equivalent, so it proves nothing: delete its "
            "line, or reword it only if the mutant is in fact equivalent")


def record_entry(pkg, fname, line, reason, accepted, keys, mutant=None, col=None, deps=None):
    """The record entry for mutant (default: a statement deletion) at broker/<pkg>/<fname>:<line> (at
    column col, when given) at the working tree, keys being file_keys', resting on deps (see RECORD) when given."""
    mutant = mutant or DELETION
    k = keys[fname][line]
    same = sorted(n for n, o in keys[fname].items() if o == k)
    return {"file": fname, "mutant": mutant, "func": k[0], "decl": k[1], "stmt": list(k[2]), "at": k[3], "after": k[4],
            "occurrence": [same.index(line) + 1, len(same)], "reason": reason, "accepted": accepted,
            **({"col": col} if col else {}), **({"deps": deps} if deps else {})}


def waive_rows(pkg, text, new):
    """(lines, entry count) of record `text` with `new` entries written in. Every other line stays word for word in
    its place, since premerge reads a record as kept only with each side's entries in that side's order (#6314,
    #6573). The same site and mutant written again is rewritten in its line's place, not doubled; a new site goes
    after its file's last entry, or at the end."""
    site = lambda e: (e["file"], e["mutant"], e.get("col"), _entry_key(e), tuple(e["occurrence"]))
    todo = {site(e): json.dumps(e, ensure_ascii=False) for e in new}
    rows, files, done = [], [], set()  # files[i]: the file of rows[i]'s entry, or None
    for row in text.rstrip("\n").split("\n") if text.strip() else []:
        e = None if not row.strip() or row.lstrip().startswith("#") else json.loads(row)
        if e is not None and site(e) in todo:
            if site(e) in done:
                continue  # a word-for-word repeat of the entry already rewritten
            done.add(site(e))
            row = todo[site(e)]
        rows.append(row)
        files.append(e and e["file"])
    if not any(r.lstrip().startswith("#") for r in rows):
        rows.insert(0, f"# Mutant-equivalent proofs for broker/{pkg}, keyed by statement: see RECORD in tools/mutgate.py.")
        files.insert(0, None)
    for e in new:
        if site(e) not in done:
            done.add(site(e))
            at = max((i + 1 for i, f in enumerate(files) if f == e["file"]), default=len(rows))
            rows.insert(at, todo[site(e)])
            files.insert(at, e["file"])
    return rows, len(set(r for r, f in zip(rows, files) if f is not None))


def cmd_waive(args):
    """Append an entry to each named site's package record, from `Mutant-equivalent:` lines in FILE."""
    text = pathlib.Path(args.lines).read_text(encoding="utf-8", errors="replace")
    for problem in malformed_waivers(text):
        print(f"mutgate: {problem}", file=sys.stderr)
    rows = waivers(text)
    if not rows:
        print(f"mutgate: {args.lines} holds no `Mutant-equivalent: <path>:<line>[:<col>][:<KIND>] <reason>` line",
              file=sys.stderr)
        return 1
    if refuse_not_equivalent(not_equivalent(rows), sys.stderr):
        return 1
    if clash := [site_text(w) for w in rows if w[2] and args.mutant and w[2] != args.mutant]:
        print(f"mutgate: {', '.join(clash)} names another mutant kind than --mutant {args.mutant}", file=sys.stderr)
        return 1
    by_pkg = collections.defaultdict(list)
    for (path, line, kind, col), reason in sorted(rows.items(), key=lambda r: site_text(r[0])):
        by_pkg[package_of(path)].append((path.rsplit("/", 1)[1], line, reason, kind or args.mutant, col))
    with tempfile.TemporaryDirectory() as tmp:
        if (lister := build_lister(tmp)) is None:
            return 1
        named, deps = sorted(set(args.dep or ())), []
        decls, problem = list_dep_decls([f for f, _ in named], lister)
        if problem:
            print(f"mutgate: {problem}", file=sys.stderr)
            return 1
        for f, name in named:
            # A dep is one declaration the proof cites, so a name declared twice (or not at all) names none.
            if len(got := [dg for names, dg in decls[f] or () if name in names]) != 1:
                print(f"mutgate: --dep {f}:{name}: {f} " + ("is no file" if decls[f] is None else
                      f"declares {name} {len(got)} times, not once"), file=sys.stderr)
                return 1
            deps.append({"file": f, "func": name, "decl": got[0]})
        for pkg, sites in sorted(by_pkg.items()):
            keys, problem = file_keys(pkg, [f for f, *_ in sites], lister)
            missing = [f"broker/{pkg}/{f}:{n}" for f, n, *_ in sites if n not in (keys or {}).get(f, {})]
            # A column names a byte of its line (gremlins' and go/token's columns count bytes from 1).
            missing += [f"broker/{pkg}/{f}:{n}:{c}" for f, n, _, _, c in sites if not problem and n in keys.get(f, {})
                        and c and c > len((BROKER / pkg / f).read_bytes().split(b"\n")[n - 1])]
            if problem or missing:
                print(f"mutgate: {problem or 'no such line: ' + ', '.join(missing)}", file=sys.stderr)
                return 1
            text, problem = read_record(pkg)
            entries, bad = record_entries(text or "")
            if not problem and not bad:
                decls, problem = list_dep_decls([x["file"] for e in entries for x in e.get("deps", ())], lister)
            if problem or bad:
                print(f"mutgate: {problem or bad}", file=sys.stderr)
                return 1
            # Nor does it rewrite a record that holds an entry no gate reads as proved (#5909).
            if refused := [refused_entry(pkg, e) for e in entries if NOT_EQUIVALENT.search(e["reason"])]:
                for r in refused:
                    print(f"mutgate: {r}, then run waive again", file=sys.stderr)
                return 1
            new = [record_entry(pkg, f, n, reason, args.accepted, keys, kind, col, deps) for f, n, reason, kind, col in sites]
            declared, problem = package_decls(pkg, lister)
            if problem or (problem := "\n".join(undeclared_deps(pkg, new, declared))):
                print(f"mutgate: {problem}", file=sys.stderr)
                return 1
            # Every line of a parsed declaration has its digest; a line outside any has nothing to prove.
            if nodigest := [f"broker/{pkg}/{e['file']}: {e['stmt'][e['at']]!r}" for e in new if not e["decl"]]:
                print(f"mutgate: {', '.join(nodigest)} is in no top-level declaration, so no entry can key on one",
                      file=sys.stderr)
                return 1
            # waive never guesses which stale entry a new one rewrites (L3 and UX on #5780): while a file it
            # writes holds one, it writes nothing and names each, for the builder to delete by hand.
            if stale := [e for e in entries if e["file"] in keys and resolve_record(pkg, [e], keys, decls)[1]]:
                for e in stale:
                    print(f"mutgate: broker/{pkg}/{RECORD} holds a stale entry for {e['file']} {e['func'] or '(top level)'} "
                          f"{e['stmt'][e['at']]!r} ({e['mutant']}, occurrence {e['occurrence'][0]} of "
                          f"{e['occurrence'][1]}): delete its line, then run waive again", file=sys.stderr)
                return 1
            rows, total = waive_rows(pkg, text or "", new)
            (BROKER / pkg / RECORD).write_text("\n".join(rows) + "\n")
            print(f"broker/{pkg}/{RECORD}: {len(new)} entries written, {total} in all")
    return 0


def cmd_records(args):
    """Resolve every named package's record (default: every gated package's) at the working tree."""
    pkgs = args.pkg or [p for p in gated_packages() if (BROKER / p / RECORD).exists()]
    with tempfile.TemporaryDirectory() as tmp:
        if (lister := build_lister(tmp)) is None:
            return 1
        found, problems = record_waivers(pkgs, lister)
    for (path, line, mutant, col), (reason, accepted, _) in sorted(found.items(), key=lambda f: site_text(f[0])):
        print(f"{site_text((path, line, None, col))} {mutant} {accepted} {reason}")
    for problem in problems:
        print(f"mutgate: {problem}", file=sys.stderr)
    return 1 if problems else 0


def violations(targets, live, waived=None, mutants=None):
    """(pkg, path, line, kind, col) of each mutant of live ({pkg: [(file, line, type[, column])]}) on a
    package's target line that no waiver ({(path, line, kind, col): reason}) names alone among mutants
    (the package's every mutant, default live; see covering); targets is {pkg: {path: lines}}."""
    live = {pkg: [(*m, None)[:4] for m in items] for pkg, items in live.items()}
    cover, _ = covering(waived or {}, live if mutants is None else mutants)
    found = []
    for pkg in sorted(targets):
        for fname, line, kind, col in live.get(pkg, []):
            path = f"broker/{pkg}/{fname}"
            if line in targets[pkg].get(path, ()) and (path, line, kind, col) not in cover:
                found.append((pkg, path, line, kind, col))
    return found


# Shards (#4961). The budgets size K so one shard's gremlins and deletion runs fit a job's 60 minutes:
# localui's 1048 target lines (about 0.35 deletion sites a line) ran gremlins in 10 minutes and
# deletion past 48 on #4945. GitHub runs at most 256 jobs from one matrix and stops a hosted job at
# 360 minutes, so past 256 shards a job runs up to 5 shards of one package, one after another, each
# stopped at its own 60 minutes by the workflow (`timeout`), the job at 60 a shard plus 15 for its
# setup (pack, MUT-plan-overflow #6170): at most 1280 shards in all, fewer when several packages
# each leave a job part-filled.
LINES_PER_SHARD = 250
SITES_PER_SHARD = 100
MATRIX_MAX = 256
SHARD_MINUTES = 60
SETUP_MINUTES = 15
JOB_MINUTES_MAX = 360
JOB_SHARDS_MAX = (JOB_MINUTES_MAX - SETUP_MINUTES) // SHARD_MINUTES
SHARDS_MAX = MATRIX_MAX * JOB_SHARDS_MAX
# Every gremlins mutant runs the package's whole suite, and a deletion its covering tests' runs or
# the whole suite (site_costs, #6172), so a shard's time is its count times the suite's (#5069): kernel/sim's 48 s suite ran 6 shards of 89 sites past 60 minutes
# on #5006 (run 42368800375), where browser's 7 s suite ran 9 shards of 92 in 6 to 14. Seen there, a
# target line cost gremlins 0.1 to 0.2 suite runs and a site about 0.6 (its parallel run, then a
# detected one's run alone); the budget is half the job, as one package's shards took up to twice
# another's time.
LINE_RUNS = 0.25
SITE_RUNS = 1
SHARD_SECONDS = 1800


def shard_count(targets, sites, suite=0.0, costs=None, overhead=0.0, lint=(0.0, ())):
    """K for a package with these target lines ({path: lines}) and deletion sites, whose whole test
    suite takes suite seconds: at least one. With costs (seconds per site, site_costs), a site costs
    those, not a whole suite, and each shard first spends overhead on its per-test pass (#6172).
    That pass leaves a shard's sites at least half of SHARD_SECONDS, so a pass past a quarter of the
    job plans shards past the target, and one past 45 minutes past the job's 60 (#6217). lint is
    lint_budget's (setup, [seconds per site]): each shard spends setup, and each site its seconds (#6366)."""
    lines = sum(len(v) for v in targets.values())
    setup, each = lint
    if costs is None:
        work, budget = suite * (LINE_RUNS * lines + SITE_RUNS * len(sites)) + sum(each), SHARD_SECONDS - setup
    else:
        work = suite * LINE_RUNS * lines + sum(costs) + sum(each)
        budget = max(SHARD_SECONDS - overhead, SHARD_SECONDS / 2) - setup
    return max(1, -(-lines // LINES_PER_SHARD), -(-len(sites) // SITES_PER_SHARD), math.ceil(work / budget))


def pack(counts):
    """The `mutants` matrix for [(pkg, K)], or None when it cannot fit: one job per shard while the
    shards fit MATRIX_MAX jobs, else the fewest shards a job that fit, each package's shards dealt
    round-robin over ceil(K / per) jobs of its own (#6170). Each entry names its shards (indices joined
    by ", ", as the job's name shows them) and the job's minutes, 60 a shard plus its setup, so every
    shard of every package runs exactly once, alone; the workflow stops each shard at its own 60."""
    for per in range(1, JOB_SHARDS_MAX + 1):
        jobs = [(pkg, of, -(-of // per)) for pkg, of in counts]
        if sum(j for _, _, j in jobs) <= MATRIX_MAX:
            return [{"pkg": pkg, "shards": ", ".join(map(str, range(i, of, j))), "of": of,
                     "minutes": SHARD_MINUTES * len(range(i, of, j)) + SETUP_MINUTES}
                    for pkg, of, j in jobs for i in range(j)]
    return None


def suite_seconds(pkg, tmp):
    """(seconds, None) one run of broker/<pkg>/'s whole test suite takes, built as `delete` builds
    it (#5069), 0 for a package with no tests; or (None, problem)."""
    pkg_dir, binary = BROKER / pkg, pathlib.Path(tmp) / "suite.test"
    binary.unlink(missing_ok=True)
    # Output goes to stderr: `plan` prints the matrix on stdout (#4961).
    build = ["go", "test", "-c", "-cover", "-covermode=set", "-o", str(binary), "."]
    if subprocess.run(build, cwd=pkg_dir, stdout=sys.stderr).returncode:
        return None, f"broker/{pkg}/ does not build its tests"
    if not binary.exists():
        return 0.0, None
    began = time.monotonic()
    if subprocess.run([str(binary), "-test.failfast"], cwd=pkg_dir, stdout=sys.stderr).returncode:
        return None, f"broker/{pkg}/'s tests fail before any mutant runs, so its shards cannot be sized"
    return time.monotonic() - began, None


def shard_lines(targets, index, of):
    """{path: lines} of shard index of `of`: every of-th target line in (path, line) order, from the
    index-th. The of shards are disjoint and their union is targets."""
    out = {}
    for path, line in sorted((p, n) for p, ls in targets.items() for n in ls)[index::of]:
        out.setdefault(path, set()).add(line)
    return out


def shard_of(data):
    """(index, of) a result records, (0, 1) when it records none (an unsharded run), or None when
    the record is not two ints with 0 <= index < of <= SHARDS_MAX."""
    rec = data.get("shard", {"index": 0, "of": 1}) if isinstance(data, dict) else None
    if not isinstance(rec, dict) or set(rec) != {"index", "of"}:
        return None
    i, k = rec["index"], rec["of"]
    if type(i) is not int or type(k) is not int or not 0 <= i < k <= SHARDS_MAX:
        return None
    return i, k


# gremlins -D runs `git diff --merge-base BASE` in its own cwd and matches the file names to
# mutant paths relative to the package directory, one range per hunk from its first added line.
# Run from the package directory, relative names and no context lines make both exact.
# diff.renames=false: broker_diff passes --no-renames, so a moved file's lines are added lines there,
# and gremlins must mutate them too or `run` fails on its skips (#4147).
DIFF_GIT_CONFIG = {"GIT_CONFIG_COUNT": "3", "GIT_CONFIG_KEY_0": "diff.relative", "GIT_CONFIG_VALUE_0": "true",
                   "GIT_CONFIG_KEY_1": "diff.context", "GIT_CONFIG_VALUE_1": "0",
                   "GIT_CONFIG_KEY_2": "diff.renames", "GIT_CONFIG_VALUE_2": "false"}

# gremlins walks every directory below the one it is given and names a mutant by its path from
# there, so a subpackage's file carries a `/`. The gate joins bare names only (foreign_names), and a
# subpackage is its own package with its own claim: `run` mutates only the package's own files (#4025).
SUBDIRS = ["--exclude-files", "/"]


def skipped_added(data, pkg, added):
    """Added lines of non-test files directly in broker/<pkg>/ where gremlins skipped a mutant, sorted."""
    return sorted(
        (f["file_name"], m["line"])
        for f in data["files"] if not f["file_name"].endswith("_test.go")
        for m in f.get("mutations") or []
        if m["status"] == "SKIPPED" and m["line"] in added.get(f"broker/{pkg}/{f['file_name']}", ())
    )


def result_problem(data, pkg, pkg_dir, added, sites=None):
    """Why gremlins' JSON for pkg cannot be read as its verdicts, or None. `run` and `verify` both ask;
    verify also needs `delete`'s mutants in it, one for each of the deletion sites it lists."""
    if not shape_ok(data):
        # survivors() would read nothing from another shape and the gate would pass (ASSUMPTIONS D33).
        return "is not gremlins' files[].mutations[] shape"
    if sites is not None:
        got = collections.Counter((f["file_name"], m["line"], m.get("column")) for f in data["files"]
                                  for m in f.get("mutations") or [] if m.get("type") == DELETION)
        if type(data.get("statement_deletions")) is not int or data["statement_deletions"] != sum(got.values()):
            # Without the pass, a deleted statement on a claimed line would pass unseen (#4573).
            return "holds no statement-deletion pass (`mutgate.py delete`), or a count that is not its mutants'"
        if got != (want := site_keys(sites)):
            # A result short of a site, as one holding none, would pass the site unseen (#4602).
            return (f"holds statement-deletion verdicts that are not one for each site this diff touches: "
                    f"missing {sorted((want - got).elements())}, extra {sorted((got - want).elements())}; rerun the "
                    f"mutants job at this head, and if it repeats, that job's tests rewrote this result")
    if dry := dry_run(data):
        # RUNNABLE is a mutant gremlins found and did not run: no verdict, so no LIVED either (#4027).
        return f"holds {dry} mutants gremlins did not run (dry-run?)"
    if unknown := foreign_names(data, pkg_dir):
        # violations() joins broker/<pkg>/<file_name>; another name format would match no line (#3956).
        return f"names LIVED mutants in {unknown}, not files in broker/{pkg}/"
    if added is not None and (skipped := skipped_added(data, pkg, added)):
        # The gate reads these lines; a skip there means gremlins' diff is not this one.
        return f"gremlins skipped mutants on target lines in broker/{pkg}/: {skipped}"
    return None


def covered_by(pkg, names, tmp, broker=None):
    """({path: lines}, None) of the non-test .go files directly in broker/<pkg>/ that the named
    test functions (every test, for None) run, from one -coverprofile run of the PR's tests (so in
    the untrusted job only); or (None, problem). A block's lines from its start to its end count, an
    evaluated clause expression's among them (with_cases, #5822)."""
    out, _, problem = timed_cover(pkg, names, tmp, broker)
    return out, problem


# `go test`'s summary line for one package: `ok  <import path>  <seconds>s`, then its coverage.
GO_OK = re.compile(r"(?m)^ok \s*\S+\s+(\d+(?:\.\d+)?)s(?:\s|$)")


OK_KEEP = 4096  # bytes of a line echo_ok holds: an `ok` line's match ends within its first hundred


def echo_ok(stream):
    """Copies `go test`'s stdout to stderr as it arrives (`plan` prints the matrix on stdout, #4961)
    and returns its last `ok` line's seconds, or None. It holds one chunk and the first OK_KEEP bytes
    of the current line, so a test that floods its output costs no memory and shows live (#6232)."""
    text = codecs.getincrementaldecoder("utf-8")("replace")
    line, last = b"", None

    def scan(whole):
        nonlocal last
        if ok := GO_OK.search(whole.decode("utf-8", "replace")):
            last = ok[1]

    while chunk := stream.read1(1 << 16):
        sys.stderr.write(text.decode(chunk))
        sys.stderr.flush()
        *ends, rest = (line + chunk).split(b"\n")
        for part in filter(None, ends):  # a bare newline is no `ok` line: a flood of them stays cheap (#6236)
            scan(part)
        line = rest[:OK_KEEP]
    sys.stderr.write(text.decode(b"", final=True))
    sys.stderr.flush()
    scan(line)
    return last


def timed_cover(pkg, names, tmp, broker=None, code=None, watched=(), skip=None):
    """covered_by's (lines, seconds, problem): seconds is how long its test binary ran, so a plan
    that ran the whole suite under coverage sizes the shards from that run, not a fourth (#6155).
    A code dict gains {path: lines} of every block the profile lists, ran or not (#6216): the lines
    a test could run, whichever tests ran. watched names repo paths built in from copies and
    watched while the tests run: any read of one is a problem (watched_at_run). skip names tests
    the run leaves out (`-skip`), so a read by any other test is seen (record_for)."""
    broker = BROKER if broker is None else broker
    profile = pathlib.Path(tmp) / "tests.cover"
    profile.unlink(missing_ok=True)
    cmd = ["go", "test", "-count=1", "-covermode=count", f"-coverprofile={profile}"]
    if names is not None:
        cmd += ["-run", "^(" + "|".join(names) + ")$"]
    if skip:
        cmd += ["-skip", "^(" + "|".join(skip) + ")$"]
    began = time.monotonic()
    try:
        with watched_at_run(broker, watched, tmp) as (flags, opened):
            with subprocess.Popen([*cmd, *flags, "."], cwd=broker / pkg, stdout=subprocess.PIPE) as run:
                ran = echo_ok(run.stdout)
            read = opened()
    except (OSError, ValueError) as e:
        return None, None, f"broker/{pkg}/: cannot watch {', '.join(watched)} while its tests run: {e}"
    if read and skip:
        return None, None, (f"broker/{pkg}/: a test other than {', '.join(skip)} read {', '.join(read)} at run time, "
                            "which only those tests' read calls name: name the file in that test's own os.ReadFile, "
                            "os.Open, filepath.Glob or fs.ReadFile(os.DirFS(...)) call (read_by)")
    if read:
        return None, None, (f"broker/{pkg}/: a test read {', '.join(read)} at run time, which only its //go:embed "
                            "var names: name the file with a string literal in that test (every test is then a "
                            "changed test)")
    if run.returncode or not profile.exists():
        return None, None, f"broker/{pkg}/'s tests {'(all)' if names is None else names} fail under -coverprofile"
    # `go test`'s own `ok` line times the test binary's run alone, as suite_seconds times it: the wall
    # time adds the build and vet, which a cold cache makes many times a fast suite (#6162).
    seconds = float(ran) if ran else time.monotonic() - began
    if (lister := lister_in(tmp)) is None:
        return None, None, "cannot build tools/mutgate_stmts.go"
    try:
        text = with_cases(profile.read_text(), lister, broker / pkg)
    except RuntimeError as e:
        return None, None, f"broker/{pkg}/: {e}"
    out = {}
    for into, ran in ((out, True), *(((code, False),) if code is not None else ())):
        for name, blocks in covered_blocks(text, ran).items():
            f = broker / pkg / name
            if is_source(name) and f.is_file() and not f.is_symlink():
                for (first, _), (last, _) in blocks:
                    into.setdefault(f"broker/{pkg}/{name}", set()).update(range(first, last + 1))
    return out, seconds, None


HUNKS = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def base_line_of(diff_text):
    """{path: f} for a -U0 diff, where f(n) is the old line git pairs with new line n when n is in
    no hunk: n less the lines every hunk before it adds net (#5008)."""
    hunks, path, in_hunk = {}, None, False
    for raw in diff_text.split("\n"):
        if raw.startswith("diff "):
            path, in_hunk = None, False
        elif m := HUNKS.match(raw):
            in_hunk = True
            o, oc, n, nc = int(m[1]), int(m[2] or 1), int(m[3]), int(m[4] or 1)
            if path is not None:
                # A hunk adding nc lines from n, or deleting after line n when nc is 0, lies before n + max(nc, 1).
                hunks.setdefault(path, []).append((n + max(nc, 1), nc - oc))
        elif not in_hunk and raw.startswith("+++ "):
            path = _header_path(raw)
    return {p: (lambda n, hs=hs: n - sum(d for end, d in hs if end <= n)) for p, hs in hunks.items()}


def gremlins_diff(pkg, base):
    """The diff gremlins' -D reads for pkg against base: `git diff --merge-base` from the package
    directory under DIFF_GIT_CONFIG, its names pinned to repo paths (prefix and colour only)."""
    return subprocess.run(
        ["git", "diff", "--merge-base", "--src-prefix=a/broker/" + pkg + "/", "--dst-prefix=b/broker/" + pkg + "/",
         "--no-color", "--no-ext-diff", "--no-textconv", base],
        cwd=BROKER / pkg, env={**os.environ, **DIFF_GIT_CONFIG}, capture_output=True, check=True,
    ).stdout.decode("utf-8", errors="replace")


# marked_base's tries at a base whose diff holds every target line; each try marks one more line at least.
MARK_TRIES = 64


@contextlib.contextmanager
def marked_base(pkg, targets, tmp):
    """Yield a commit BASE for gremlins' `-D`, which runs `git diff --merge-base BASE`, such that the
    diff adds every target line: BASE's tree is the work tree with each target line changed,
    and HEAD points, until the context ends, at a child of BASE with HEAD's own tree. Nothing in the
    work tree or any branch moves; HEAD is put back as it was.

    A non-target line equal to a target line can be paired with it by git, leaving the target
    unchanged in the diff (#5008). Each such pair's base line is then marked too, until the diff
    gremlins reads adds every target; the extra lines it adds are no target, and `run` drops their
    mutants (outside_lines). Raises RuntimeError when no try gets there."""
    env = {**os.environ, "GIT_INDEX_FILE": str(pathlib.Path(tmp) / "marked.index"),
           "GIT_AUTHOR_NAME": "mutgate", "GIT_AUTHOR_EMAIL": "mutgate@example.invalid",
           "GIT_COMMITTER_NAME": "mutgate", "GIT_COMMITTER_EMAIL": "mutgate@example.invalid"}

    def git(*a, data=None, check=True):
        r = subprocess.run(["git", *a], cwd=ROOT, env=env, input=data, capture_output=True, check=check)
        return r.stdout.decode().strip()
    head, ref = git("rev-parse", "HEAD"), git("symbolic-ref", "-q", "HEAD", check=False)
    marks = {p: set(ls) for p, ls in targets.items()}
    try:
        for _ in range(MARK_TRIES):
            git("read-tree", head)
            for path, lines in sorted(marks.items()):
                rows = (ROOT / path).read_bytes().split(b"\n")
                for n in lines:
                    if n <= len(rows):
                        rows[n - 1] += b" //mutgate"
                blob = git("hash-object", "-w", "--stdin", data=b"\n".join(rows))
                git("update-index", "--add", "--cacheinfo", f"100644,{blob},{path}")
            base = git("commit-tree", git("write-tree"), "-m", "mutgate: the target lines, changed")
            git("update-ref", "--no-deref", "HEAD",
                git("commit-tree", f"{head}^{{tree}}", "-p", base, "-m", "mutgate: HEAD"))
            diff = gremlins_diff(pkg, base)
            added, pair = added_lines(diff)[0], base_line_of(diff)
            more = {(p, pair.get(p, lambda n: n)(n)) for p, ls in targets.items() for n in ls
                    if n not in added.get(p, ())}
            if not more:
                break
            if all(n in marks.get(p, ()) for p, n in more):
                raise RuntimeError(f"git pairs target lines with marked base lines: {sorted(more)[:20]}")
            for p, n in more:
                marks.setdefault(p, set()).add(n)
        else:
            raise RuntimeError(f"no base in {MARK_TRIES} tries has a diff that adds every target line")
        yield base
    finally:
        if ref:
            git("symbolic-ref", "HEAD", ref)
        else:
            git("update-ref", "--no-deref", "HEAD", head)


def outside_lines(data, pkg, mine):
    """Gremlins' JSON with each verdict on a line outside mine written SKIPPED, as gremlins writes
    one outside its diff, and its counts kept true: a marked base's diff can add lines that are no
    target of this run (#5008), and a verdict there could be another shard's (join_shards)."""
    for f in data.get("files") or []:
        lines = mine.get(f"broker/{pkg}/{f.get('file_name')}", ())
        for m in f.get("mutations") or []:
            if m.get("status") in ("SKIPPED", None) or m.get("line") in lines:
                continue
            # gremlins' total is lived + killed + not viable (v0.6.0 report.go:178).
            for key in (COUNTERS.get(m["status"]), "mutants_total" if m["status"] in TOTALLED else None):
                if key and type(data.get(key)) is int:
                    data[key] -= 1
            m["status"] = "SKIPPED"
    return data


def coverage_record(names, targets):
    """The record of the lines a package's changed tests cover that `run` writes and targets_for reads."""
    return {"tests": names, "lines": {p.rsplit("/", 1)[1]: sorted(ls) for p, ls in sorted(targets.items())}}


def base_member(member, dest):
    """tarfile's "data" filter, except that a member it refuses (a symlink to an absolute path or out
    of the tree, such as spikes/S1S2-testkit's systemd unit link, #5523) is left out of the base tree
    rather than failing every plan: such a link names no file of the base tree."""
    try:
        return tarfile.data_filter(member, dest)
    except tarfile.FilterError:
        return None


def base_covered(pkg, mb, names, tmp, diff_text):
    """({path: head lines}, None) that the base's named tests (None: every test) cover in the base
    tree's broker/<pkg>/, moved to their head lines (a line the diff changes or deletes is dropped:
    a changed one is the diff's own, and decide fails every unrun target line of the package); or
    (None, problem). The base's whole tree is `git archive`d to tmp."""
    tree = pathlib.Path(tmp) / "base-tree"
    shutil.rmtree(tree, ignore_errors=True)
    tree.mkdir()
    # The whole tree, not only broker/: tests read files beside it (guest/, image/, tools/; L3 on #5770).
    dropped, bad = [], None

    def member(m, dest):
        kept = base_member(m, dest)
        if kept is None:
            dropped.append(m.name)
        return kept
    with subprocess.Popen(["git", "archive", "--format=tar", mb], cwd=ROOT, stdout=subprocess.PIPE) as git:
        try:
            with tarfile.open(fileobj=git.stdout, mode="r|") as t:
                t.extractall(tree, filter=member)
        except tarfile.TarError as e:  # git's output is cut or no tar: its exit says why, read below (#5779)
            bad = e
            git.kill()
    if git.returncode or bad:
        why = f"exit {git.returncode}" if git.returncode else f"its output is no tar archive: {bad}"
        return None, f"`git archive {mb[:12]}` failed ({why})"
    for name in dropped:  # L3 on #5781: name what the base tree leaves out
        print(f"mutgate: the base tree leaves out {name}, a link tar's data filter refuses", file=sys.stderr)
    if not (tree / "broker" / pkg).is_dir():
        return {}, None
    # The head's names too (#6456): a doc either tree names is in both, so the base's run reads what the head's does.
    MADE.add(tree.resolve())
    try:
        hide_docs(tree / "broker", BROKER)
    finally:
        MADE.discard(tree.resolve())
    got, problem = covered_by(pkg, names, tmp, tree / "broker")
    if problem:
        return None, f"at the base ({mb[:12]}), {problem}"
    move, out = head_line_of(diff_text), {}
    for p, ls in got.items():
        f = BROKER / p.split("/", 1)[1]
        if f.is_file() and not f.is_symlink():
            out[p] = {h for n in ls if (h := move.get(p, lambda n: n)(n)) is not None}
    return {p: ls for p, ls in out.items() if ls}, None


def record_for(pkg, tests, bases, diff_text, base, tmp):
    """(record, seconds, None) of the lines the changed tests of broker/<pkg>/ cover at the head and,
    as its `base` part, at the base (#5762), with the seconds its whole-suite run at the head took;
    or (None, None, problem). Runs the PR's tests: untrusted jobs only."""
    names = changed_tests(tests, pkg, bases)
    code = {}
    covered, secs, problem = timed_cover(pkg, names, tmp, code=code)
    if problem:
        return None, None, problem
    was, problem = base_covered(pkg, merge_base(base, "HEAD"), bases[pkg], tmp, diff_text)
    if problem:
        return None, None, problem
    # Every target line runs (L1 on #5770, #5942): a line no mutant and no deletion names (a brace, a
    # bare `return g()`) has no NOT COVERED verdict, so a weakened test that stops running it was unseen.
    # One whole-suite run at the head (none more when the changed tests are every test) names it.
    # A data file read only through an embedding var (head_tests) is watched while the whole suite
    # runs: a test that opens or reads it at run time, by any path, fails the run (#6458, #6518).
    # A file read only through recognised read calls is watched while every other test runs: a
    # test outside the changed ones that opens or reads it fails that run (read_by, #6657).
    owned = {p: narrowing(pkg, p) for p in tests if pkg in owners(p)} if names is not None else {}
    reads = sorted(p for p, got in owned.items() if got and got[0] == "read")
    watched = sorted(set(owned) - set(reads))
    every, secs, problem = (covered, secs, None) if names is None else timed_cover(pkg, None, tmp, watched=watched)
    if problem:
        return None, None, problem
    if reads and (problem := timed_cover(pkg, None, tmp, watched=reads, skip=names)[2]):
        return None, None, problem
    if gone := unrun(was, every, code):
        return None, None, ("; ".join(f"{p}: {', '.join(map(str, ls))}" for p, ls in gone.items())
                            + f" ran under the base's version of the tests this diff changes, and no test of package {pkg} "
                            "runs them at the head: keep a test that runs each, or delete the code")
    return {**coverage_record(names, covered), "base": coverage_record(bases[pkg], was)}, secs, None


# A line that only closes blocks and the calls or literals around them: `}`, `})`, `},`, `}()`, `}}`.
CLOSER = re.compile(r"\}(?:[})\],]|\(\))*")


def unrun(was, every, code):
    """{path: sorted lines} of was ({path: head lines} the base's tests ran) that every ({path: lines}
    the head's whole suite runs) leaves out, holding code at the head. A blank or comment line between
    two cover blocks, which an edit beside it can open, is no code a test runs; nor is a CLOSER line
    in no block of code ({path: lines} of every block the head's profile lists, ran or not): Go's
    profile ends a block at its last statement or at a nested block ending it, so such a brace is in
    none once its block ends in an `if`, `for` or func literal (#6216). An `if` body's own `}` is in
    its block, so an unrun body still names it; a multi-line `case` expression is in no block until
    evaluated, so text alone, not the profile, decides the other lines."""
    out = {}
    for p, ls in sorted(was.items()):
        text = go_text((BROKER / p.split("/", 1)[1]).read_bytes())
        if text is None:  # not Go text: every line it ran and the head does not is code (fail closed)
            if left := sorted(ls - every.get(p, set())):
                out[p] = left
            continue
        rows = _uncommented(text, False).split("\n")
        held = code.get(p, set())
        if left := sorted(n for n in ls - every.get(p, set()) if n <= len(rows) and rows[n - 1].strip()
                          and (n in held or not CLOSER.fullmatch(rows[n - 1].strip()))):
            out[p] = left
    return out


def planned_targets(planned, pkg, added, tests, bases):
    """({path: lines}, None) of a package's target lines with plan's --targets-out record, or
    (None, problem). The record is checked as verify checks the one a result carries (targets_for).
    A package the plan does not name is a problem, never a coverage run here: that run could name
    other lines than the other shards' (#4970)."""
    rec = planned.get(pkg) if isinstance(planned, dict) else None
    if rec is None:
        return None, f"the plan names no target lines for broker/{pkg}/; rerun the mutgate workflow"
    targets, problem = targets_for(pkg, added, tests, {"targets": rec}, bases)
    return (None, f"the plan {problem}") if problem else (targets, None)


# What gremlins v0.6.0 prints, exiting 0 and writing no -o file, when it finds no mutant (#5173).
NO_RESULTS = "No results to report."


def unleash(cmd, **kw):
    """Run gremlins with its output shown as it runs; (.returncode, .none: it printed NO_RESULTS)."""
    none = False
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw) as p:
        for line in p.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            none = none or line.strip() == NO_RESULTS
    return types.SimpleNamespace(returncode=p.returncode, none=none)


def cmd_run(args):
    pkgs = args.pkg or gated_packages()
    # Absolute: gremlins runs in broker/, so a relative -o would name a directory there (#3947).
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    diff = broker_diff(args.git, "HEAD") if args.git else None
    added, tests = changes(diff, args.git, "HEAD") if args.git else (None, None)
    bases = bases_for(diff, args.git, "HEAD", tests, pkgs) if args.git else {}
    planned = None
    if args.targets is not None:
        try:
            planned = json.loads(pathlib.Path(args.targets).read_text())
        except (OSError, ValueError) as e:
            print(f"mutgate: no readable plan of target lines ({args.targets}: {e})", file=sys.stderr)
            return 1
    bad = 0
    # Gremlins reads .gremlins.yaml from broker/ and the package directory, and GREMLINS_* from the
    # environment: a PR-added file with `dry-run: true` would leave no LIVED mutant. An explicit
    # --config file is the only one it reads, and the environment is cleared of GREMLINS_* (#4027).
    env = {k: v for k, v in os.environ.items() if not k.startswith("GREMLINS_")}
    cfgdir = tempfile.TemporaryDirectory()
    cfg = pathlib.Path(cfgdir.name) / "gremlins.yaml"
    cfg.write_text("{}\n")
    (pathlib.Path(cfgdir.name) / REFUSED).touch()  # the shims' only channel: gone or unwritable is no verdict (refusal)
    # Gremlins' coverage run reads its profile through with_cases, so it runs case-expression mutants
    # (#5822); with no go on PATH, gremlins can run no test at all.
    # MUT-gremlins-memcap (#6388): each of gremlins' parallel mutant runs (one per usable CPU, as
    # runtime.NumCPU counts them) gets its share of half the memory free now, as `delete`'s do;
    # a package whose tests need a larger share runs on fewer workers (unleash_fitted, #6396).
    free = available_memory()
    alone = free // 2 if free else None
    if shim := go_shim(cfgdir.name, alone // default_jobs() if alone else None):
        env["PATH"] = f"{shim}{os.pathsep}{env.get('PATH', '')}"
    else:
        alone = None  # no shim: nothing to refit
    try:
        with cgroup_scope():
            bad += run_packages(args, pkgs, out, added, tests, bases, planned, diff, cfgdir.name, cfg, env, alone)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        bad += 1
    if refused := refusal(cfgdir.name):
        print(f"mutgate: gremlins ran go in a way its test binaries could not be capped: {refused}", file=sys.stderr)
        bad += 1
    cfgdir.cleanup()
    return 1 if bad else 0


HEADROOM = "headroom"  # go_cover's measured peak (empty: past its cap) where it failed the half-cap check


def unleash_fitted(cmd, tmp, alone, **kw):
    """unleash(cmd) on default_jobs() gremlins workers, each mutant run capped at its share of alone
    bytes (go_shim); where gremlins' coverage run held more than half a share (go_cover's HEADROOM),
    again on fewer workers with larger shares, down to one under all of alone (#6396: egress held
    1017 MB of a 1820 MB share). The share, never the half-cap check, gives way: workers times share
    stays alone, and every attempt's coverage run is checked against its own share."""
    workers, head = default_jobs(), pathlib.Path(tmp) / HEADROOM
    while True:
        if alone:
            go_shim(tmp, alone // workers)  # each package starts at the full count again
        head.unlink(missing_ok=True)
        r = unleash([*cmd, "--workers", str(workers)], **kw)
        if not alone or r.returncode == 0 or workers == 1 or not head.exists():
            return r
        peak = int(head.read_text() or 0)
        fit = max(1, min(workers - 1, alone // (2 * peak) if peak else 1))
        print(f"mutgate: gremlins' tests hold {peak >> 20 if peak else 'past'} MB of a {alone // workers >> 20} MB "
              f"share; again on {fit} workers, {alone // fit >> 20} MB each", file=sys.stderr)
        if "-o" in cmd:
            pathlib.Path(cmd[cmd.index("-o") + 1]).unlink(missing_ok=True)
        workers = fit


def run_packages(args, pkgs, out, added, tests, bases, planned, diff, tmp, cfg, env, alone=None):
    """`run`'s gremlins pass over pkgs, each package's result in out; the count of packages that failed.
    alone: the bytes gremlins' parallel mutant runs share (unleash_fitted), None for no cap."""
    bad, adv = 0, advisory()
    if CGROUP_ENV in os.environ:  # cgroup_scope's, for the shims' cap_exec
        env = {**env, CGROUP_ENV: os.environ[CGROUP_ENV]}
    for pkg in pkgs:
        dest = out / result_name(pkg)
        targets, record = (diff_targets(added, pkg) if args.git else None), None
        if args.git and tests_changed(tests, pkg):
            # A diff that changes or deletes tests (#4908): the lines its changed test functions run
            # are targets too, beside any line it adds (#5762), from plan's one coverage run when
            # given, so every shard names the same lines (#4970).
            if planned is not None:
                full, problem = planned_targets(planned, pkg, added, tests, bases)
                record = None if problem else planned[pkg]
            else:
                record, _, problem = record_for(pkg, tests, bases, diff, args.git, tmp)
                full, problem = (None, problem) if problem else targets_for(pkg, added, tests, {"targets": record}, bases)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                bad += 1
                continue
            targets = full
        if args.git:
            # #4961: this job's share of the target lines; the record keeps them all.
            mine = shard_lines(targets, args.shard, args.of)
            extra = {"shard": {"index": args.shard, "of": args.of}, **({"targets": record} if record else {})}
            if not mine:
                # Gremlins' -D mutates every line when its diff is empty; none is a target here.
                dest.write_text(json.dumps({"files": [], "mutants_total": 0, "mutants_lived": 0, **extra}))
                continue
            # The base's own diff marks exactly the target lines, so one unsharded run of a diff
            # that changes no test keeps it; a share or a test change marks its lines on a commit.
            marked = record or args.of > 1
            try:
                with marked_base(pkg, mine, tmp) if marked else contextlib.nullcontext(args.git) as base:
                    r = unleash_fitted(["gremlins", "unleash", str(BROKER / pkg), "-D", base, "--config", str(cfg),
                                        *SUBDIRS, "-o", str(dest)], tmp, alone, cwd=BROKER / pkg,
                                       env={**env, **DIFF_GIT_CONFIG})
            except RuntimeError as e:
                print(f"mutgate: no marked base for broker/{pkg}/: {e}", file=sys.stderr)
                bad += 1
                continue
        else:
            r = unleash_fitted(["gremlins", "unleash", f"./{pkg}", "--config", str(cfg), *SUBDIRS, "-o", str(dest)],
                               tmp, alone, cwd=BROKER, env=env)
        if r.returncode == 0 and r.none and not dest.exists():
            # Gremlins found no mutant, not even a SKIPPED one, and wrote no -o file (#5173): its zero.
            dest.write_text(json.dumps({"files": [], "mutants_total": 0, "mutants_lived": 0}))
        if r.returncode != 0 or not dest.exists():
            print(f"mutgate: gremlins failed on {pkg} (exit {r.returncode})", file=sys.stderr)
            bad += 1
        # A share's own lines only: gremlins marks the other shards' lines SKIPPED (#4961).
        elif problem := result_problem(data := json.loads(dest.read_text()), pkg, BROKER / pkg,
                                       mine if args.git else None):
            print(f"mutgate: {dest} {problem}", file=sys.stderr)
            bad += 1
        elif args.git:
            dest.write_text(json.dumps({**(outside_lines(data, pkg, mine) if marked else data), **extra}))
        if refused := refusal(tmp):  # a shim run failed in this package: no verdict (shim_entry)
            print(f"mutgate: {pkg} has no verdict: {refused}", file=sys.stderr)
            dest.unlink(missing_ok=True)
            return bad + 1
        if adv and dest.exists():
            dest.write_text(json.dumps({**json.loads(dest.read_text()), "advisory": True}))
    return bad


# MUTGATE-stmt-delete (#4573): the mutant kind gremlins v0.6.0 lacks. mutgate_stmts.go lists the
# statements (go/parser, data only); each one the diff adds a line of is replaced by its own line
# breaks (so no other line moves) through `go test -overlay`, which leaves the tree untouched.
DELETION = "STATEMENT_DELETION"
DETECTED = ("KILLED", "TIMED OUT")
STMTS = pathlib.Path(__file__).resolve().parent / "mutgate_stmts.go"
COVER = re.compile(r"^(.+):(\d+)\.(\d+),(\d+)\.(\d+) \d+ (\d+)$")
# Gremlins' own report fields for each status (internal/report, v0.6.0), kept equal so its totals stay true.
COUNTERS = {"LIVED": "mutants_lived", "KILLED": "mutants_killed", "NOT VIABLE": "mutants_not_viable",
            "NOT COVERED": "mutants_not_covered"}
TOTALLED = ("LIVED", "KILLED", "NOT VIABLE")


def covered_blocks(profile, ran=True):
    """{file base name: [((line, col), (line, col))]} of the blocks a `-coverprofile` ran (every
    block it lists, when not ran)."""
    out = {}
    for row in profile.split("\n")[1:]:
        m = COVER.match(row)
        if m and (int(m.group(6)) > 0 or not ran):
            out.setdefault(m.group(1).rsplit("/", 1)[-1], []).append(
                ((int(m.group(2)), int(m.group(3))), (int(m.group(4)), int(m.group(5)))))
    return out


def is_covered(blocks, site):
    """Whether a block that ran holds the site's cover position: its own start, or for a case or
    select clause, whose block starts after its colon, its switch's or select's start."""
    pos = (site["cover_line"], site["cover_col"])
    return any(start <= pos < end for start, end in blocks.get(site["file"], ()))


# MUT-case-clause-cover (#5822). Go's cover blocks hold no clause expression: a switch's header block
# ends at its `{` and each clause body's starts past its colon, so gremlins, whose only judge of
# "covered" is those blocks, read every mutant in a `case` expression as NOT COVERED and never ran it.
# with_cases adds a ran block for each clause expression the profile shows evaluated; covered_by reads
# its profile through it, and `run` gives gremlins a `go` (go_shim) whose -coverprofile runs go through
# go_cover, so gremlins runs those mutants and judges them KILLED or LIVED as any other.
def evaluated_clauses(switches, blocks):
    """[(file, (line, col), (line, col))]: a block from the `case` to just past the colon of each
    non-default clause of switches (the lister's -cases output for one directory) whose expression
    blocks ({file: {(line, col, line, col): count}}, a `-covermode=count` profile's) show evaluated.
    A switch evaluates its expressions in source order until one matches: one is evaluated when its own
    body or a later non-default clause's body ran, or the default's, or the switch ran more often than
    its bodies were entered (some run matched none; the block holding the switch's start counts its
    runs). A select evaluates every clause's operands on entry, so all are when it ran. A body entered
    by `fallthrough` is not a match, and the counts cannot tell it from one, so in a switch holding a
    `fallthrough` every non-default clause counts as evaluated once the switch ran (L3 on #5902): that
    runs a mutant which may then live (a false fail), never skips one (MUT-case-cover-1)."""
    out = []
    for sw in switches:
        bs = blocks.get(sw["file"], {})
        at = (sw["line"], sw["col"])
        runs = max((n for b, n in bs.items() if b[:2] <= at < b[2:]), default=0)
        entered = []
        for c in sw["clauses"]:
            body = [(b, n) for b, n in bs.items() if (c["colon_line"], c["colon_col"] + 1) <= b[:2] < (c["end_line"], c["end_col"])]
            entered.append(min(body)[1] if body else 0)  # the body's first block: one count per entry
        unmatched = runs > sum(entered) or any(n for c, n in zip(sw["clauses"], entered) if c["default"])
        for i, c in enumerate(sw["clauses"]):
            later = any(n for d, n in zip(sw["clauses"][i:], entered[i:]) if not d["default"])
            if not c["default"] and (runs > 0 or any(entered) if sw["select"] or sw["fallthrough"] else unmatched or later):
                out.append((sw["file"], (c["line"], c["col"]), (c["colon_line"], c["colon_col"] + 1)))
    return out


# MUT-legacy-not-equivalent-records (#5909). Go's cover ends the block of a statement holding a func
# literal at the literal (its body is a block of its own) and starts the next at the next statement or
# nested body, so the statement's code after the literal (`IndexFunc(s, func(r rune) bool {...}) >= 0`)
# is in no block and gremlins read its mutants NOT COVERED. literal_tails adds a ran block for that code
# up to the next block's start or its line's end, wherever a ran block ends at a block's start (how
# cover splits at a literal). It may mark code ran that a short circuit skipped: that runs a mutant
# that may then live (a false fail), never skips one; a tail past the literal's last line stays unread.
def literal_tails(blocks, lines):
    """[((line, col), (line, col))]: the code after each func literal whose statement's block ran, for one
    file's blocks ({(line, col, line, col): count}) and its source lines (bytes, from 1 at lines[0])."""
    starts = collections.defaultdict(list)
    for b in blocks:
        starts[b[:2]].append(b)
    out = []
    for b, n in sorted(blocks.items()):
        if not n or b[:2] == b[2:]:
            continue
        for f in starts.get(b[2:], []):
            line, col = f[2:]
            if f == b or not 0 < line <= len(lines):
                continue
            end = min([s for s in starts if s[0] == line and s[1] >= col] + [(line, len(lines[line - 1]) + 1)])
            if end > (line, col) and lines[line - 1][col - 1:end[1] - 1].strip():
                out.append(((line, col), end))
    return sorted(set(out))


def with_cases(text, lister, cwd):
    """text, a `-covermode=count` -coverprofile, with a ran block (`<file>:<line>.<col>,<line>.<col> 0 1`) appended for each
    clause expression evaluated_clauses finds in the files it names of the module holding cwd, and for the
    code after each func literal literal_tails finds there (#5909). Raises
    RuntimeError where the lister cannot read a file (a //line directive), so no run reads it as is."""
    cwd = pathlib.Path(cwd).resolve()
    root = next((d for d in (cwd, *cwd.parents) if (d / "go.mod").is_file()), None)
    m = root and re.search(r"^module\s+\"?([^\s\"]+)", (root / "go.mod").read_text(), re.M)
    if not m:
        return text
    # One test binary's profile can name a block twice (#5803): its counts add.
    module, files = m.group(1), collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for row in text.split("\n")[1:]:
        if (c := COVER.match(row)) and c.group(1).startswith(module + "/"):
            d, _, name = c.group(1)[len(module) + 1:].rpartition("/")
            files[d][name][tuple(int(c.group(i)) for i in range(2, 6))] += int(c.group(6))
    rows = []
    for d, named in sorted(files.items()):
        paths = [str(f) for n in sorted(named) if (f := root / d / n).is_file() and not f.is_symlink()]
        r = subprocess.run([str(lister), "-cases", *paths], capture_output=True, text=True) if paths else None
        if r is not None and r.returncode:
            raise RuntimeError(f"cannot list the switch clauses of {d or '.'}/: {r.stderr.strip()[:500]}")
        found = evaluated_clauses(json.loads(r.stdout) if r else [], named)
        for n in sorted(named):
            if (f := root / d / n).is_file() and not f.is_symlink():
                found += [(n, *t) for t in literal_tails(named[n], f.read_bytes().split(b"\n"))]
        for name, (line, col), (eline, ecol) in found:
            rows.append(f"{module}/{d + '/' if d else ''}{name}:{line}.{col},{eline}.{ecol} 0 1\n")
    return text if not rows else text.rstrip("\n") + "\n" + "".join(rows)


def lister_in(tmp):
    """tmp's built lister (build_lister), built once."""
    lister = pathlib.Path(tmp) / "stmts"
    return lister if lister.is_file() else build_lister(tmp)


def go_shim(tmp, mem=None):
    """A directory holding a `go` for gremlins' PATH: a run with -coverprofile goes through go_cover,
    every other (its mutant runs) to the real go, through go_capped where mem caps each test binary's
    memory; or None where no go is on PATH."""
    real = shutil.which("go")
    if real is None:
        return None
    q = shlex.quote
    bindir = pathlib.Path(tmp) / "gobin"
    bindir.mkdir(exist_ok=True)
    me = f"exec {q(sys.executable)} -I {q(str(pathlib.Path(__file__).resolve()))}"
    cover = f"{me} go-cover {q(real)} {q(str(tmp))} {int(mem or 0)}"
    rest = f"{me} go-capped {q(real)} {q(str(tmp))} {int(mem)}" if mem else f"exec {q(real)}"
    (bindir / "go").write_text(f"""#!/bin/sh
for a in "$@"; do
  case "$a" in -coverprofile|-coverprofile=*|--coverprofile|--coverprofile=*) {cover} "$@";; esac
done
{rest} "$@"
""")
    (bindir / "go").chmod(0o755)
    return bindir


# MUT-gremlins-memcap (#6388): a gremlins mutant that drops a bound can grow a test by gigabytes, as a
# deletion can (#5011), and took a runner down on #6000. Gremlins v0.6.0 reads its `go test`'s exit 1
# as KILLED (executor.go getTestFailedStatus), so a test binary past its cap is killed and exits 1, as
# run_tests' memory_cap is KILLED. Only the test binaries go under the cap, through `go test -exec`
# (cap_exec, #6392): a mutant changes what the tests do, not how much the compiler holds. The `go`
# driver would hold a mutant run's output (#6507), so none reaches it (cap_exec).
def capped_go(real, tmp, args, mem, exits=None):
    """args for the real go with each test binary run through cap_exec under mem bytes (its peak and
    end appended to the file exits, when given); None, with the reason printed and REFUSED written in
    tmp for `run` to read, unless args are a `go test` naming no -exec of their own."""
    if args[:1] != ["test"] or any(a in ("-exec", "--exec") or a.startswith(("-exec=", "--exec=")) for a in args):
        print(f"mutgate: gremlins ran `go {shlex.join(args[:1])}` with -exec or not as `go test`, so its test "
              "binaries cannot be put under their memory cap", file=sys.stderr)
        record(tmp, shlex.join(args))
        return None
    q = shlex.quote
    wrap = f"{q(sys.executable)} -I {q(str(pathlib.Path(__file__).resolve()))} cap-exec {q(str(tmp))} {int(mem)} {q(str(exits or '-'))}"
    return [args[0], f"-exec={wrap}", *args[1:]]


def past_half(peak, mem, over=False):
    """Why a base run's peak fails the half-cap check, naming the cap and the peak; a cgroup's memory.peak
    counts page cache, so a large read can pass half the cap with no leak (#6512)."""
    killed = ", where the cap killed them" if over else ""
    return (f"peaked at {peak >> 20} MB{killed}, more than half of their {mem >> 20} MB memory cap (in a cgroup "
            "the peak is memory.peak, which counts page cache, so a large file read can pass it without a leak)")


REFUSED = "refused"  # go_shim's runs that could not be capped: `run` gives no verdict unless it is there and empty
NO_VERDICT = 125  # a shim entry's own failure; the REFUSED marker, not this code, carries it (shim_entry)


def open_marker(tmp):
    """The REFUSED marker in tmp, opened to append, never created: only `run` makes it, before gremlins
    starts, so a marker a fault removed stays gone for every later mutant and `run` reads no verdict (#6512)."""
    return os.fdopen(os.open(pathlib.Path(tmp) / REFUSED, os.O_WRONLY | os.O_APPEND), "a")


def record(tmp, why, marker=None):
    """Append why to the REFUSED marker (through marker, else opened now); where that open or write fails
    (a full disk, an I/O error), remove the marker, so `run` reads it gone, not present and empty (refusal)."""
    try:
        marker = marker or open_marker(tmp)
        marker.write(why + "\n")
        marker.flush()
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(pathlib.Path(tmp) / REFUSED)


def refusal(tmp):
    """Why a shim run in tmp gives no verdict, or "" for none: the REFUSED marker's text, or that the
    marker `run` made before gremlins started is gone or cannot be written, so a failure could not be told."""
    try:
        os.close(os.open(pathlib.Path(tmp) / REFUSED, os.O_WRONLY | os.O_APPEND))
        return (pathlib.Path(tmp) / REFUSED).read_text().strip()
    except OSError as e:
        return f"its {REFUSED} marker cannot be written, so a shim's failure could not be recorded: {e!r}"


def shim_entry(tmp, fn, *args):
    """fn(*args) for one of go_shim's entries (go-cover, go-capped, cap-exec), which gremlins scores by
    exit code alone: any error of the entry itself (a cgroup file, a kill that did not empty its leaf)
    writes REFUSED in tmp, so `run` drops that package's result and gives no verdict (L3 and Security on
    #6423). The marker is the only channel. cap-exec is go test's -exec, and `go test` turns any failing
    -exec into its own exit 1, which gremlins reads as KILLED, so no exit code of cap_exec's can say "no
    verdict". go-capped and go-cover are the go gremlins runs, so their NO_VERDICT reaches it directly and
    reads LIVED, never a test failure. The marker is opened before fn runs, so a fault inside fn can always
    write it (#6512). Where it cannot be opened, fn still runs, since only a fault needs the marker; a fault
    then opens it once more, a failed write removes it (record), and `run` refuses a package whose marker is
    gone or cannot be written (refusal)."""
    try:
        marker = open_marker(tmp)
    except OSError as e:
        print(f"mutgate: {fn.__name__} cannot open its {REFUSED} marker: {e!r}", file=sys.stderr)
        marker = None
    try:
        return fn(*args)
    except BaseException as e:  # every class, an interrupt too: a verdict needs a run that ended as reported
        print(f"mutgate: {fn.__name__} failed, so this run gives no verdict: {e!r}", file=sys.stderr)
        record(tmp, f"{fn.__name__}: {e!r}", marker)  # opened once more where the first open failed
        return NO_VERDICT
    finally:
        with contextlib.suppress(OSError):
            marker and marker.close()


def go_cover(real, tmp, args, mem=None):
    """`go` args through the real go, with `-covermode=count` unless they name a mode (with_cases needs
    counts), then the -coverprofile it wrote read through with_cases. With mem, a mutant run's memory
    cap, each test binary runs under it, and the run fails unless their peaks together stay under half
    of it (MUT-gremlins-memcap): only then does a cap kill show the mutant changed the tests' memory."""
    if args[:1] == ["test"] and not any(a.lstrip("-").startswith("covermode") for a in args):
        args = ["test", "-covermode=count", *args[1:]]
    exits = pathlib.Path(tmp) / "exits"
    run = args
    if mem:
        exits.write_text("")
        if (run := capped_go(real, tmp, args, mem, exits)) is None:
            return 1
    end = subprocess.Popen([real, *run], preexec_fn=die_with_parent).wait()
    if mem:
        rows = [row.split() for row in exits.read_text().splitlines()]
        peak = sum(int(r[0]) for r in rows)
        if (over := any(r[1] == "over" for r in rows)) or 2 * peak > mem:
            (pathlib.Path(tmp) / HEADROOM).write_text("" if over else str(peak))  # for unleash_fitted
            print(f"mutgate: the tests {past_half(peak, mem, over)} before any mutant, so a cap kill of a gremlins "
                  "mutant run would not show a test failed", file=sys.stderr)
            return 1
    if code := exit_code(end):
        return code
    path = next((a.split("=", 1)[1] for a in args if a.startswith(("-coverprofile=", "--coverprofile="))), None)
    path = path or next((b for a, b in zip(args, args[1:]) if a in ("-coverprofile", "--coverprofile")), None)
    lister = lister_in(tmp)
    try:
        if path is None or lister is None:
            raise RuntimeError("no -coverprofile file or lister")
        f = pathlib.Path(path)
        f.write_text(with_cases(f.read_text(), lister, pathlib.Path.cwd()))
    except (OSError, RuntimeError, ValueError) as e:
        print(f"mutgate: cannot add the case clauses to the cover profile: {e}", file=sys.stderr)
        return 1
    return 0


def go_capped(real, tmp, mem, args):
    """`go` args through the real go, each test binary of a `go test` under mem bytes (cap_exec); go's
    exit code, or 1 when they cannot be capped (and REFUSED is written)."""
    if args[:1] == ["test"] and (args := capped_go(real, tmp, args, mem)) is None:
        return 1
    return exit_code(subprocess.Popen([real, *args], preexec_fn=die_with_parent).wait())


def cap_exec(mem, exits, argv):
    """go test's -exec: run the test binary argv contained under mem bytes; past it, print memory_cap's
    failure and exit 1, which gremlins reads as KILLED; else exit as it did. With exits not "-", append
    `PEAK END` (bytes, and "over" or its exit code) to that file for go_cover; with exits "-", a mutant
    run, the binary's output goes to /dev/null (MUT-gremlins-memcap-go): gremlins discards a mutant run's
    output and reads only its exit code, and given a package `go test` holds all of it in the driver."""
    die_with_parent()
    quiet = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL} if exits == "-" else {}
    end, peak = contained(argv, mem, **quiet)
    if exits != "-":
        with open(exits, "a") as f:
            f.write(f"{peak} {end}\n")
    if end == "over":
        print(f"\n--- FAIL: memory_cap\nmutgate: the tests passed this mutant run's {mem >> 20} MB memory cap "
              "and were killed", file=sys.stderr)
        return 1
    return exit_code(end)


def exit_code(end):
    """A shell's exit status for a Popen return code: 128 + N for a run killed by signal N."""
    return end if end >= 0 else 128 - end


def die_with_parent():
    """In a child before exec, or a process itself: SIGKILL it when its parent dies (Linux
    PR_SET_PDEATHSIG), so gremlins' kill of the shim at a mutant's timeout also ends what it started."""
    try:
        import ctypes
        ctypes.CDLL(None).prctl(1, signal.SIGKILL)
    except (OSError, AttributeError):
        pass  # no prctl (macOS): the test binary's own -test.timeout still ends it


def deleted(src, site, names=()):
    """src (bytes) with the statement at site deleted, its line breaks kept, and `_ = NAME` for
    each of names where a statement may stand: in its place, or for a clause (a switch or select
    body takes only clauses) where the site's keep_at says, or as a `default:` clause."""
    gone = b"\n" * src.count(b"\n", site["start"], site["end"])
    head, tail = src[:site["start"]], src[site["end"]:]
    if not names:
        return head + gone + tail
    keep = b"; ".join(b"_ = " + n.encode() for n in names)
    if site.get("keep_default"):
        return head + b"default: " + keep + gone + tail
    at = site.get("keep_at", -1)
    if at < 0:
        return head + keep + gone + tail
    keep = b" " + keep + b"; "  # valid after a clause's colon and before a statement alike
    if at < site["start"]:
        return src[:at] + keep + src[at:site["start"]] + gone + tail
    return head + gone + src[site["end"]:at] + keep + src[at:]


BUILD_ERROR = re.compile(r"^\S*?([^/\s:]+\.go):(\d+):(\d+): (.*)$")
UNUSED_VAR = re.compile(r"^declared and not used: (\w+)$|^(\w+) declared and not used$")  # the latter: a type-switch variable
UNUSED_IMPORT = re.compile(r'"[^"]+" imported (?:as \w+ )?and not used$')
UNUSED_LABEL = re.compile(r"label \w+ defined and not used$")


def fixes(stderr, file):
    """(names, [(line, col, kind)]) a failed build of file asks for, or None when another error
    stands: unused variables (kept with `_ = NAME`), imports (renamed `_`) and labels (dropped)."""
    names, spots = [], []
    for row in stderr.split("\n"):
        m = BUILD_ERROR.match(row)
        if not m:
            continue
        if m.group(1) != file:
            return None
        if var := UNUSED_VAR.search(m.group(4)):
            names.append(var.group(1) or var.group(2))
        elif UNUSED_IMPORT.search(m.group(4)):
            spots.append((int(m.group(2)), int(m.group(3)), "import"))
        elif UNUSED_LABEL.search(m.group(4)):
            spots.append((int(m.group(2)), int(m.group(3)), "label"))
        else:
            return None
    return (names, spots) if names or spots else None


def respelled(text, spots):
    """text with each unused import at (line, col) renamed `_` and each unused label blanked."""
    lines = text.split(b"\n")
    for line, col, kind in sorted(spots, reverse=True):
        head, rest = lines[line - 1][:col - 1], lines[line - 1][col - 1:]
        if kind == "label":
            rest = re.sub(rb"^\w+\s*:", lambda m: b" " * len(m.group(0)), rest)
        else:
            rest = b"_ " + rest if rest.startswith(b'"') else re.sub(rb"^\w+", b"_", rest)
        lines[line - 1] = head + rest
    return b"\n".join(lines)


def build_mutant(src, site, build, mutant, pkg_dir):
    """Whether the deletion at site builds, once the variables, imports and labels it left unused
    are kept in use or dropped (Security on #4597): deleting a variable's only use, the common
    guard `v, err := f(); if err != nil { ... }`, does not compile as it stands, and a NOT VIABLE
    guard would never be tested, so it is deleted as go-mutesting's statement remover deletes it.
    Each round reads the errors of the text it built; a third failure, or any other error, is NOT VIABLE."""
    names, text = [], deleted(src, site)
    for _ in range(3):
        mutant.write_bytes(text)
        built = subprocess.run(build, cwd=pkg_dir, capture_output=True)
        if built.returncode == 0:
            return True
        asked = fixes(built.stderr.decode(errors="replace"), site["file"])
        if asked is None:
            return False
        new = [n for n in asked[0] if n not in names]
        if new:
            names += new
            text = deleted(src, site, names)  # imports and labels it names again at their new spots
        elif asked[1]:
            text = respelled(text, asked[1])
        else:
            return False
    return False


def run_tests(binary, cwd, timeout, mem=None, names=None):
    """'KILLED', 'LIVED' or 'TIMED OUT' for one run of a compiled test binary, contained: everything it
    started is killed when it ends or at the timeout, so a test's child cannot outlive the verdict. Its
    output goes to BINARY.out, where failed_test reads which test failed. With mem, the run is also
    killed, and KILLED by `memory_cap`, once it passes mem bytes, as the Go runtime's own out of memory
    crash would end it: a deletion that drops a bound can grow a test by gigabytes in seconds, and on a
    CI runner that takes the runner down with the job (egress on #5011). That counts as detection only
    because deletion_mutants first shows the unmutated tests stay under half of it.
    With names, only those top-level tests run (#6172)."""
    out = pathlib.Path(binary).with_suffix(".out")
    only = [] if names is None else ["-test.run=^(" + "|".join(names) + ")$"]
    with open(out, "wb") as log:
        end, _ = contained([str(binary), "-test.failfast", *only, f"-test.timeout={timeout + 2}s"], mem, timeout,
                           cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        if end == "over":
            log.write(b"\n--- FAIL: memory_cap\n")  # failed_test's name for it, so the table says why
        return {"over": "KILLED", "timeout": "TIMED OUT"}.get(end) or ("LIVED" if end == 0 else "KILLED")


# MUT-memcap-cgroup (#6392): every run of tests goes in a cgroup v2 leaf of its own, under a delegated
# directory CI names in AGENTOS_MUTGATE_CGROUP: memory.max caps it with no swap, an OOM kills the whole
# leaf (memory.oom.group), cgroup.kill ends whatever is left, in any session or process group, and
# memory.peak is its exact peak. In CI (CI or GITHUB_ACTIONS set) a missing or unusable one is an error.
# Elsewhere a run is advisory (`watch`'s per-session reads) and its results never pass `verify`.
CGROUP_ENV = "AGENTOS_MUTGATE_CGROUP"


def cgroup_parent():
    """The delegated cgroup v2 directory whose children cap each run, or None for an advisory local
    run; raises in CI without one, and anywhere it names one without the memory controller for its children."""
    path = os.environ.get(CGROUP_ENV)
    if not path:
        if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
            raise RuntimeError(f"mutgate: in CI every run needs a delegated cgroup v2 directory in {CGROUP_ENV}")
        return None
    try:
        enabled = (pathlib.Path(path) / "cgroup.subtree_control").read_text().split()
    except OSError:
        enabled = []
    if "memory" not in enabled:
        raise RuntimeError(f"mutgate: {CGROUP_ENV}={path} is not a cgroup v2 directory giving its children the memory controller")
    return pathlib.Path(path)


def advisory():
    """Whether runs here are advisory (no delegated cgroup), saying so on stderr; raises as cgroup_parent does."""
    if cgroup_parent() is not None:
        return False
    print(f"mutgate: ADVISORY: no delegated cgroup ({CGROUP_ENV}), so memory caps are estimated from the "
          "session's processes; these results are not a verdict and `verify` refuses them", file=sys.stderr)
    return True


def contained(argv, mem=None, timeout=None, **popen):
    """(end, peak) of one run of argv: end is its exit code, or "timeout", or "over" (past mem bytes);
    peak its peak memory in bytes. In a cgroup leaf where there is one (cgroup_parent), else in a session
    of its own under `watch`. Whatever it started is killed once it ends."""
    parent = cgroup_parent()
    if parent is None:
        return watch(subprocess.Popen(argv, start_new_session=True, preexec_fn=die_with_parent, **popen), timeout, mem)
    leaf = parent / f"run-{os.getpid()}-{os.urandom(8).hex()}"
    leaf.mkdir()
    try:
        result = in_leaf(leaf, argv, mem, timeout, popen)
    except BaseException as first:
        try:
            empty(leaf)
            leaf.rmdir()
        except Exception as e:  # keep the first error as its cause, so the report says what went wrong (#6512)
            raise e from first
        raise
    empty(leaf)
    leaf.rmdir()
    return result


def in_leaf(leaf, argv, mem, timeout, popen):
    """contained's (end, peak) for one run of argv in cgroup leaf, which the caller removes."""
    for name, value in (("memory.max", str(mem) if mem else "max"), ("memory.swap.max", "0"), ("memory.oom.group", "1")):
        (leaf / name).write_text(value)
    # The shell moves itself into the leaf, then execs argv there: nothing argv starts runs outside it.
    # (No preexec_fn: `delete` starts runs from several threads.)
    p = subprocess.Popen(["/bin/sh", "-c", 'echo 0 > "$0" && exec "$@"', str(leaf / "cgroup.procs"), *argv], **popen)
    try:
        end = p.wait(timeout)
    except subprocess.TimeoutExpired:
        end = "timeout"
    empty(leaf)
    p.wait()
    if not (peak := int((leaf / "memory.peak").read_text())):
        raise RuntimeError(f"mutgate: {argv[0]} never ran in its cgroup leaf {leaf}")
    events = dict(row.split() for row in (leaf / "memory.events").read_text().splitlines())
    # memory.oom.group kills the whole leaf, argv included, so an OOM kill after argv exited 0 hit only
    # what argv left running, after its tests passed: that is no cap kill of the run (#6512).
    if end != 0 and (int(events.get("oom_kill", 0)) or int(events.get("oom_group_kill", 0))):
        end = "over"
    return end, peak


def empty(cg):
    """Kill every process in cgroup cg and its children (cgroup.kill) and wait until none is left;
    raises after KILL_WAIT seconds, so the run gives no verdict."""
    (cg / "cgroup.kill").write_text("1")
    deadline = time.monotonic() + KILL_WAIT
    while "populated 1" in (cg / "cgroup.events").read_text():
        if time.monotonic() > deadline:
            raise RuntimeError(f"mutgate: processes in {cg} outlived cgroup.kill")
        time.sleep(0.01)


@contextlib.contextmanager
def cgroup_scope():
    """For `run`: a cgroup under the delegated one that its runs' leaves go in (through the environment,
    which gremlins' shims inherit), killed and removed with every leaf left in it at the end: a shim
    gremlins kills at a mutant's timeout leaves its test binary's leaf behind."""
    parent = cgroup_parent()
    if parent is None:
        yield
        return
    scope = parent / f"scope-{os.getpid()}-{os.urandom(8).hex()}"
    scope.mkdir()
    try:
        (scope / "cgroup.subtree_control").write_text("+memory")
        with env_set(CGROUP_ENV, str(scope)):
            yield
    finally:
        empty(scope)
        for leaf in scope.iterdir():
            if leaf.is_dir():
                leaf.rmdir()
        scope.rmdir()


@contextlib.contextmanager
def env_set(name, value):
    """os.environ[name] = value for the block."""
    old = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if old is None:
            del os.environ[name]
        else:
            os.environ[name] = old


def watch(p, timeout=None, mem=None):
    """(end, peak) for Popen p started in its own session, an advisory run's containment (no cgroup):
    end is its exit code, or "timeout" or "over" (the session's resident memory, read every MEM_POLL
    seconds, past mem bytes); its session is killed (kill_session) once it ends. peak is the sum, over
    every process a read found, of the most it ever held (VmHWM, which a spike between two reads still
    raised), p's own from wait4 at its exit. A process that leaves the session (setsid) escapes both."""
    deadline = None if timeout is None else time.monotonic() + timeout
    peaks, end = {}, None
    while (done := reap(p, MEM_POLL if deadline is None else max(0, min(MEM_POLL, deadline - time.monotonic())))) is None:
        now = 0
        for key, (rss, hwm) in session_memory(p.pid).items():
            now += rss
            peaks[key] = max(peaks.get(key, 0), hwm)
        end = "over" if mem is not None and now > mem else "timeout" if deadline and time.monotonic() >= deadline else None
        if end:
            kill_session(p.pid)
            done = reap(p, float("inf"))
            break
    kill_session(p.pid)  # a child left running once p ends
    peaks = {k: v for k, v in peaks.items() if k[0] != p.pid} | {(p.pid, -1): done[1]}
    return end or done[0], sum(peaks.values())


MEM_POLL = 0.25  # seconds between memory reads: about 50 MB of growth at the 200 MB/s seen on #5011


def reap(p, wait):
    """(exit code, whole-life peak resident bytes) of Popen p once it exits within wait seconds, from
    wait4: the kernel's high-water mark at its exit, or its waited descendants' where higher; else None."""
    end, pause = time.monotonic() + wait, 0.001
    while True:
        pid, status, usage = os.wait4(p.pid, os.WNOHANG)
        if pid:
            p.returncode = os.waitstatus_to_exitcode(status)
            return p.returncode, usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
        if (left := end - time.monotonic()) <= 0:
            return None
        time.sleep(min(pause, left))
        pause = min(2 * pause, 0.05)


def kill_session(sid):
    """SIGKILL every process in session sid: its process group, then every live process session_procs
    finds there, in whatever group it moved itself to (setpgid), until none is left (#6392). Each is
    signalled through a pidfd taken before its stat is read again, so a pid reused meanwhile is never
    signalled. A process still alive after KILL_WAIT seconds raises: the run gives no verdict."""
    try:
        os.killpg(sid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    deadline = time.monotonic() + KILL_WAIT
    while procs := session_procs(sid):
        if time.monotonic() > deadline:
            raise RuntimeError(f"mutgate: processes {[pid for pid, _, _ in procs]} of session {sid} outlived SIGKILL")
        for pid, _, start in procs:
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                if (proc_stat(pid) or ())[2:] == (sid, start):
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        time.sleep(0.01)


KILL_WAIT = 30  # seconds: a process in uninterruptible sleep dies once its I/O returns


def proc_stat(pid):
    """(name, state, session, start time in clock ticks) from /proc/PID/stat, or None once it is gone."""
    try:
        name, rest = pathlib.Path(f"/proc/{pid}/stat").read_text().split("(", 1)[1].rsplit(")", 1)
        f = rest.split()
        return name, f[0], int(f[3]), int(f[19])
    except (OSError, IndexError, ValueError):
        return None


def session_procs(sid):
    """[(pid, name, start)] of every live process (not a zombie) in session sid, from /proc; [] where
    there is no /proc (macOS), so the cap there is the timeout alone."""
    try:
        pids = [int(n) for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return []
    return [(pid, st[0], st[3]) for pid in pids if (st := proc_stat(pid)) and st[2] == sid and st[1] not in "ZX"]


def session_memory(sid):
    """{(pid, start): (resident bytes, most resident bytes ever)} of each live process in session sid,
    from /proc/PID/status (VmRSS, VmHWM); a process gone meanwhile is left out."""
    got = {}
    for pid, _, start in session_procs(sid):
        try:
            text = pathlib.Path(f"/proc/{pid}/status").read_text()
        except OSError:
            continue
        m = dict(re.findall(r"^(VmRSS|VmHWM):\s+(\d+) kB$", text, re.M))
        if len(m) == 2:  # an exiting process has released its memory and lists neither
            got[(pid, start)] = (int(m["VmRSS"]) << 10, int(m["VmHWM"]) << 10)
    return got


def available_memory():
    """MemAvailable in bytes, or None where /proc/meminfo does not say (macOS): no cap there."""
    try:
        m = re.search(r"^MemAvailable:\s+(\d+) kB$", pathlib.Path("/proc/meminfo").read_text(), re.M)
    except OSError:
        return None
    return int(m.group(1)) * 1024 if m else None


FAILED = re.compile(rb"^\s*--- FAIL: ([A-Za-z_]\w{0,199})", re.M)
# How much of a run's output failed_test reads from each end (MUT-failed-test-bounded, #5834): a deletion
# can turn a handler into a loop logging each pass, filling the file with gigabytes, and a whole read
# then raised MemoryError (no OSError) and killed the shard with no verdict.
OUTPUT_READ = 1 << 20


def failed_test(binary):
    """The top-level test that failed first in run_tests' output for binary, or None. Only the first
    and last OUTPUT_READ bytes are read: a `--- FAIL:` line comes before a flood or after it, where
    run_tests writes memory_cap's."""
    try:
        with open(pathlib.Path(binary).with_suffix(".out"), "rb") as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(0)
            if size <= 2 * OUTPUT_READ:
                parts = [f.read()]
            else:  # whole lines only: a cut one could name a test by a prefix of its name
                head = f.read(OUTPUT_READ)
                f.seek(size - OUTPUT_READ)
                tail = f.read()
                parts = [head[:head.rfind(b"\n") + 1], tail[tail.find(b"\n") + 1:] if b"\n" in tail else b""]
    except OSError:
        return None
    m = next(filter(None, map(FAILED.search, parts)), None)
    return m.group(1).decode() if m else None


def build_lister(tmp):
    """tools/mutgate_stmts.go built into tmp, or None. Built outside any module (cwd tmp, GOFLAGS
    cleared): the standard library only, so the trusted job builds nothing of the PR's."""
    lister = pathlib.Path(tmp) / "stmts"
    if subprocess.run(["go", "build", "-o", str(lister), str(STMTS)], cwd=tmp,
                      env={**os.environ, "GOFLAGS": "", "GOWORK": "off"}).returncode:
        print("mutgate: cannot build tools/mutgate_stmts.go", file=sys.stderr)
        return None
    return lister


def deletion_sites(pkg, added, lister):
    """([site], None) for each statement in a non-test .go file directly in broker/<pkg>/ that the
    diff adds a line of its own syntax to (#4603), with `at`, the first such line, where its verdict
    is reported (the gate reads added lines only); or (None, problem). `delete` deletes these and
    `verify` recounts them (#4602)."""
    pkg_dir = BROKER / pkg
    files = sorted(p for p in pkg_dir.glob("*.go")
                   if p.is_file() and not p.name.endswith("_test.go") and added.get(f"broker/{pkg}/{p.name}"))
    if not files:
        return [], None
    # A link would have the trusted job read (and echo in an error) a file outside the PR's tree (L3 on #4643).
    if links := [p.name for p in files if p.is_symlink()]:
        return None, f"broker/{pkg}/ holds .go files that are symbolic links, which mutgate does not follow: {links}"
    r = subprocess.run([str(lister), *map(str, files)], capture_output=True)
    if r.returncode != 0:
        return None, f"cannot list the statements of broker/{pkg}/: {r.stderr.decode(errors='replace')}"
    sites = []
    for s in json.loads(r.stdout):
        if hit := set(s["lines"]) & added[f"broker/{pkg}/{s['file']}"]:
            sites.append({**s, "at": min(hit)})
    return sites, None


def site_keys(sites):
    """The (file, line, column) of each site's verdict, counted."""
    return collections.Counter((s["file"], s["at"], s["col"]) for s in sites)


# MUT-delete-covering (#6172). A deletion on line L changes only the runs that reach L, so `delete` runs
# each site with only the tests whose own run, alone, covers it (`selected`), in the suite's order, and
# a site no test covers alone, or every test covers, with the whole suite. A smaller run can only miss
# a kill (a LIVED that needs a proof: fails closed); a KILLED or TIMED OUT from it stands only once the
# same tests pass unmutated, alone, under the same timeout and memory cap (`passes`), else the mutant
# runs the whole suite and that verdict stands, so no test set's own failure reads as a kill.
TEST_NAME = re.compile(r"^(?:Test|Fuzz|Example)(?![a-z])\w*$")


def run_alone(binary, cwd, args, timeout, mem, counters=None):
    """(end, peak, seconds) of one run of a test binary, contained; with
    counters, a child it re-executes writes its coverage there too (#5803)."""
    env = {**os.environ, "GOCOVERDIR": str(counters)} if counters else None
    began = time.monotonic()
    end, peak = contained([str(binary), *args], mem, timeout, cwd=cwd, env=env, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    return end, peak, time.monotonic() - began


def per_test(binary, cwd, tmp, timeout, mem=None, jobs=1):
    """({test: (blocks, seconds)}, {test that fails alone: seconds}) for each top-level test of a
    -cover test binary, each run alone under -coverprofile; or None when it lists none. Runs share
    `jobs` workers, and a run that fails there runs again alone, since tests can collide on a fixed
    path or port; a test that still fails alone has no coverage of its own, so it is in every set."""
    try:
        listed = subprocess.run([str(binary), "-test.list", "."], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    names = [n for n in listed.stdout.split("\n") if TEST_NAME.match(n)] if listed.returncode == 0 else []
    if not names:
        return None
    root = pathlib.Path(tmp) / "per-test"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()

    def one(i, share):
        d = root / str(i)
        shutil.rmtree(d, ignore_errors=True)
        (d / "c").mkdir(parents=True)
        end, _, secs = run_alone(binary, cwd, [f"-test.run=^{names[i]}$", "-test.failfast", f"-test.gocoverdir={d / 'c'}",
                                               f"-test.coverprofile={d / 'p'}"], timeout, share, d / "c")
        ok = end == 0 and (d / "p").exists()
        return (covered_blocks((d / "p").read_text()) if ok else None), secs
    share = mem // max(1, jobs) if mem else None
    with concurrent.futures.ThreadPoolExecutor(max(1, jobs)) as pool:
        got = list(pool.map(lambda i: one(i, share), range(len(names))))
    got = [g if g[0] is not None else one(i, mem) for i, g in enumerate(got)]
    shutil.rmtree(root, ignore_errors=True)
    return ({n: g for n, g in zip(names, got) if g[0] is not None},
            {n: secs for n, (blocks, secs) in zip(names, got) if blocks is None})


def selected(site, tests):
    """The tests to run for a site with per_test's result: those whose run alone covers it and those
    that fail alone (`go test` runs them in the suite's order whatever their order here); or None
    for the whole suite: no per-test result, no test covers the site alone, or the set's runs alone
    take half the sum of every test's or more. A set costs its run and at most one unmutated run
    (`passes`), so under half it costs less than the suite's tests run one by one; with parallel
    tests (the whole suite's wall time below that sum) the bound is only an estimate."""
    if tests is None:
        return None
    ran, failing = tests
    if not (hit := {n for n, (blocks, _) in ran.items() if is_covered(blocks, site)}):
        return None
    out = [n for n in [*ran, *failing] if n in hit or n in failing]
    total = sum(secs for _, secs in ran.values()) + sum(failing.values())
    return out if 2 * set_seconds(out, tests) < total else None


def set_seconds(names, tests):
    """The seconds these tests take run alone, summed."""
    ran, failing = tests
    return sum(ran[n][1] if n in ran else failing[n] for n in names)


def site_costs(pkg, sites, suite, tmp):
    """(seconds per site, the per-test pass's seconds) `delete` spends on each site of broker/<pkg>/
    with the tests that cover it: its set's run plus at most one unmutated run of that set (`passes`),
    or the whole suite; or (None, 0.0) when the tests cannot be timed alone. The pass runs every test
    alone, and each that fails runs again (#6226). Only a schedule (`plan`)."""
    pkg_dir, binary = BROKER / pkg, pathlib.Path(tmp) / "suite.test"
    if not binary.exists() and subprocess.run(["go", "test", "-c", "-cover", "-covermode=set", "-o", str(binary), "."],
                                              cwd=pkg_dir, stdout=sys.stderr).returncode:
        return None, 0.0
    if not binary.exists() or (tests := per_test(binary, pkg_dir, tmp, 3 * suite + 10)) is None:
        return None, 0.0
    costs = [suite if (names := selected(s, tests)) is None else 2 * set_seconds(names, tests) for s in sites]
    return costs, sum(secs for _, secs in tests[0].values()) + 2 * sum(tests[1].values())


def deletion_mutants(pkg, added, tmp, lister, jobs=1, shard=(0, 1)):
    """([mutation dict], None) for each site deletion_sites lists in shard (index, of): every of-th
    site from the index-th (#4961); or (None, problem). The sites run
    on `jobs` parallel workers (#4633), each in its own directory, a batch at a time. A site a worker
    reads as detected (KILLED or TIMED OUT) runs its binary again alone once the batch is done, and
    that verdict stands: a loaded runner can fail a wall-clock bound or slow a run past its timeout,
    and other binaries can collide on a fixed path or port, which would pass a deletion that lives
    (Potency on #4643). A batch where most runs time out leaves the rest of the pass to one worker.
    Each run has a memory cap, smaller in parallel, so one mutant cannot exhaust the runner."""
    pkg_dir = BROKER / pkg
    sites, problem = deletion_sites(pkg, added, lister)
    if not sites:
        return sites, problem
    sites = sites[shard[0]::shard[1]]
    if not sites:
        return sites, None

    def mutation(site, status, killer=None):
        m = {"file": site["file"], "type": DELETION, "status": status, "line": site["at"], "column": site["col"]}
        return {**m, "killed_by": killer} if status == "KILLED" and killer else m
    # One coverage-instrumented build and run: the coverage judge (as gremlins' own coverage run is)
    # and the time a passing run takes, three times which (gremlins' coefficient) times a mutant out.
    base, profile = tmp / "base.test", tmp / "cover.out"
    if subprocess.run(["go", "test", "-c", "-cover", "-covermode=set", "-o", str(base), "."], cwd=pkg_dir).returncode:
        return None, f"broker/{pkg}/ does not build its tests"
    if not base.exists():  # `go test -c` writes nothing for a package with no test files: none covered
        return [mutation(s, "NOT COVERED") for s in sites], None
    # Memory caps (egress on #5011): a run alone may hold half the memory free now, and each of
    # `jobs` parallel runs its share of that half, leaving the rest to the builds beside it. A run
    # past its cap is KILLED; a parallel one is then confirmed alone, under the larger cap. A cap
    # kill counts as detection only if the unmutated tests stay under half of it (L3 on #5026: else
    # a deletion that lives reads KILLED), so the base run is measured under the same cap, and
    # fewer workers run when their share would leave a run less than that headroom.
    free = available_memory()
    alone_mem = free // 2 if free else None
    # A child the tests re-execute from the binary (proc.Main's driver) writes its counters only
    # into GOCOVERDIR, which it inherits; given that directory as -test.gocoverdir too, the binary
    # merges them into its profile, as `go test -cover` does (#5803). Else child-only lines read NOT COVERED.
    counters = tmp / "gocoverdir"
    shutil.rmtree(counters, ignore_errors=True)
    counters.mkdir()
    began = time.monotonic()
    end, peak = contained([str(base), "-test.failfast", f"-test.gocoverdir={counters}", f"-test.coverprofile={profile}"],
                          alone_mem, cwd=pkg_dir, env={**os.environ, "GOCOVERDIR": str(counters)})
    if alone_mem and (end == "over" or 2 * peak > alone_mem):
        return None, (f"broker/{pkg}/'s tests {past_half(peak, alone_mem, end == 'over')} before any statement "
                      "is deleted, so a cap kill would not show a test failed")
    if end != 0 or not profile.exists():
        return None, f"broker/{pkg}/'s tests fail before any statement is deleted"
    if alone_mem and peak:
        jobs = max(1, min(jobs, alone_mem // (2 * peak)))
    suite = time.monotonic() - began
    timeout = 3 * suite + 10
    blocks = covered_blocks(profile.read_text())
    # MUT-delete-covering (#6172): the tests each covered site runs (None: the whole suite).
    covered = [s for s in sites if is_covered(blocks, s)]
    tests = per_test(base, pkg_dir, tmp, timeout, alone_mem, jobs) if covered else None
    chosen = [selected(s, tests) for s in sites]
    plain, checked, texts = tmp / "plain.test", {}, {}

    def passes(names):
        """Whether these tests pass unmutated, alone, under their timeout and the memory cap with
        its headroom, run once per set: only then does their failure on a mutant show a kill."""
        key = tuple(names)
        if key not in checked:
            if not plain.exists() and subprocess.run(["go", "test", "-c", "-o", str(plain), "."], cwd=pkg_dir).returncode:
                checked[key] = False
            else:
                end, top, _ = run_alone(plain, pkg_dir, ["-test.failfast", "-test.run=^(" + "|".join(names) + ")$"],
                                        limit(names), alone_mem)
                checked[key] = end == 0 and not (alone_mem and 2 * top > alone_mem)
        return checked[key]

    def limit(names):
        return timeout if names is None else 3 * set_seconds(names, tests) + 10

    def cap(alone):
        return alone_mem if alone or not alone_mem else alone_mem // max(1, jobs)

    def verdict(i, alone):
        """The site's status, its binary when a detected verdict still needs confirming (alone, or
        that its tests pass unmutated), and the test that failed."""
        site = sites[i]
        if not is_covered(blocks, site):
            return "NOT COVERED", None, None
        src_path, work = pkg_dir / site["file"], tmp / f"site-{i}"
        work.mkdir()
        keep = False
        try:
            # The mutant keeps the file's name: the compiler names the overlay's file in its errors.
            mutant, overlay, binary = work / site["file"], work / "overlay.json", work / "mutant.test"
            overlay.write_text(json.dumps({"Replace": {str(src_path): str(mutant)}}))
            build = ["go", "test", "-c", "-overlay", str(overlay), "-o", str(binary), "."]
            if not build_mutant(src_path.read_bytes(), site, build, mutant, pkg_dir):
                return "NOT VIABLE", None, None
            texts[i] = mutant.read_bytes()  # the tree a listed lint reads if no test fails (lint_kills)
            status = run_tests(binary, pkg_dir, limit(chosen[i]), mem=cap(alone), names=chosen[i])
            keep = status in DETECTED and (not alone or chosen[i] is not None)
            return status, binary if keep else None, failed_test(binary)
        finally:
            if not keep:
                shutil.rmtree(work)  # a test binary per site would fill the runner's disk

    statuses = []
    with concurrent.futures.ThreadPoolExecutor(max(1, jobs)) as pool:
        while len(statuses) < len(sites):
            batch = range(len(statuses), min(len(sites), len(statuses) + 4 * jobs))
            alone = jobs <= 1
            results = [verdict(i, True) for i in batch] if alone else list(pool.map(lambda i: verdict(i, False), batch))
            for i, (status, binary, killer) in zip(batch, results):
                if binary is not None:
                    names = chosen[i]
                    if not alone:
                        status, killer = run_tests(binary, pkg_dir, limit(names), mem=alone_mem, names=names), failed_test(binary)
                    if status in DETECTED and names is not None and not passes(names):
                        status, killer = run_tests(binary, pkg_dir, timeout, mem=alone_mem), failed_test(binary)
                    shutil.rmtree(binary.parent)
                statuses.append((status, killer))
            if sum(st == "TIMED OUT" for st, _, _ in results) * 2 > len(batch):
                jobs = 1  # each run needs the runner to itself: the rest runs alone, once
    lived = [(i, sites[i]["file"], texts[i]) for i, (st, _) in enumerate(statuses) if st == "LIVED"]
    kills, problem = lint_kills(pkg, lived, tmp, alone_mem)
    if problem:
        return None, problem
    for i, name in kills.items():
        statuses[i] = ("KILLED", name)
    return [mutation(s, *st) for s, st in zip(sites, statuses)], None


# MUT-lint-held (#6346). A source lint holds statement shapes no test can observe (a key wiped right
# after its sealer takes it), and fails on a tree without them. A deletion its package's tests let
# live is KILLED when a listed lint test, run on a copy of broker/ with only that deletion in it (the
# text the tests ran), refuses it twice running, the same binary having passed on the unmutated copy:
# the lint read the mutated tree and refused it, and a lint that refuses once is flaky, not a kill
# (#6366). A refusal is the lint's own assertion: exit 1 with a `--- FAIL:` line naming the test and no
# panic. A panic, a timeout, the memory cap or any other end leaves the deletion LIVED, as does a lint
# that fails unmutated. Each entry is (package under broker/, top-level test, the files it reads: the
# packages under these broker/ directories, and any file holding this text). A deletion in a file no
# listed lint reads goes to no lint (#6366): a package with no sealer skips them, and no broker/ copy is made.
CLERK = "clerk"
LINTS = (("clerk/wipelint", "TestEverySealingKeyIsWipedRightAfterItsSealer", ((CLERK,), b'"github.com/ghbmrk/agentos/broker/clerk"')),
         ("clerk/wipelint", "TestEveryOpenedPlaintextIsWipedOnEveryPath", ((CLERK,), None)))
# Lint time has its own budget (#6366), which `plan` charges each shard and `delete` holds: SETUP for the
# broker/ copy, each lint's build and its unmutated run (a cold cache compiles all it loads), and RUN for
# each run on a deletion, which every lint reading its file may take, plus the refusal's confirming run.
# Measured on #6365's sites: 4 s an unmutated run, under 1 s a mutated one, about 13 s in all for two sites.
LINT_SETUP_SECONDS = 300
LINT_RUN_SECONDS = 10


def lints_for(pkg, text):
    """The LINTS entries that read a file of broker/<pkg>/ holding text (bytes)."""
    return [lint for lint in LINTS
            if any(pkg == d or pkg.startswith(d + "/") for d in lint[2][0]) or (lint[2][1] is not None and lint[2][1] in text)]


def lint_budget(pkg, sites):
    """(setup seconds, [seconds for each site]) the lints spend on deletions at these sites of broker/<pkg>/
    (each {"file": name, ...}): what `plan` charges a shard whose sites may all live and `delete` allows its LIVED ones."""
    texts = {f: (BROKER / pkg / f).read_bytes() for f in {s["file"] for s in sites}}
    runs = [len(n) + 1 if (n := lints_for(pkg, texts[s["file"]])) else 0 for s in sites]
    return (LINT_SETUP_SECONDS if any(runs) else 0.0), [LINT_RUN_SECONDS * r for r in runs]


def lint_kills(pkg, lived, tmp, mem=None):
    """({index: lint test}, None) for each (index, file, mutant text) of broker/<pkg>/ that a listed
    lint reading its file refuses, as above, the first in LINTS order that refuses naming it; or (None,
    problem) when the lints pass their budget (lint_budget), which names the lint time, not the tests'."""
    lived = [(i, f, t, ls) for i, f, t in lived if (ls := lints_for(pkg, (BROKER / pkg / f).read_bytes()))]
    if not lived:
        return {}, None
    setup, each = lint_budget(pkg, [{"file": f} for _, f, _, _ in lived])
    print(f"mutgate: broker/{pkg}/: {len(lived)} LIVED deletion(s) go to the lints, within {setup:.0f} s of lint setup "
          f"and {sum(each):.0f} s of lint runs", file=sys.stderr)
    began, deadline = time.monotonic(), time.monotonic() + setup

    def left():
        return deadline - time.monotonic()

    def spent(where):
        return None, (f"broker/{pkg}/'s lints passed their {where}, so no lint verdict was given; nothing was shown "
                      "to survive. Rerun; if it recurs, LINT_SETUP_SECONDS or LINT_RUN_SECONDS in tools/mutgate.py are too small")
    tree = pathlib.Path(tmp) / "lint-tree"
    shutil.rmtree(tree, ignore_errors=True)
    shutil.copytree(BROKER, tree / "broker", symlinks=True)
    try:
        lints = {}
        for n, lint in enumerate(LINTS):
            lpkg, name = lint[0], lint[1]
            if not any(lint in ls for _, _, _, ls in lived):
                continue
            cwd, binary = tree / "broker" / lpkg, pathlib.Path(tmp) / f"lint-{n}.test"
            if not cwd.is_dir() or subprocess.run(["go", "test", "-c", "-o", str(binary), "."], cwd=cwd,
                                                  stdout=sys.stderr).returncode or not binary.exists():
                print(f"mutgate: lint broker/{lpkg} {name} does not build; it kills nothing", file=sys.stderr)
                continue
            if left() <= 0:
                return spent(f"{setup:.0f} s setup budget building the lints")
            start = time.monotonic()
            end = lint_run(binary, cwd, left(), mem, name)
            if end == "timeout":
                return spent(f"{setup:.0f} s setup budget on {name}'s unmutated run")
            if end != "passed":
                print(f"mutgate: lint broker/{lpkg} {name} does not pass unmutated ({end}); it kills nothing", file=sys.stderr)
                continue
            lints[lint] = (cwd, binary, name, 3 * (time.monotonic() - start) + 10)
        out, deadline = {}, time.monotonic() + sum(each)  # the runs' own budget, after the setup's
        for i, fname, text, ls in lived:
            path = tree / "broker" / pkg / fname
            was = path.read_bytes()
            path.write_bytes(text)
            try:
                for cwd, binary, name, limit in (lints[lint] for lint in ls if lint in lints):
                    ends, over = [], f"{sum(each):.0f} s budget of runs on {len(lived)} deletion(s) at {fname}"
                    while len(ends) < 2 and (not ends or ends[-1] == "refused"):  # a refusal runs once more
                        if left() <= 0:
                            return spent(over)
                        ends.append(lint_run(binary, cwd, min(limit, left()), mem, name))
                        if ends[-1] == "timeout" and left() <= 0:  # the budget stopped it, not its own limit
                            return spent(over)
                    if ends == ["refused", "refused"]:
                        out[i] = name
                        break
                    if ends != ["passed"]:
                        print(f"mutgate: lint {name} on broker/{pkg}/{fname} ended {', then '.join(ends)}: "
                              "not a refusal twice, so it kills nothing", file=sys.stderr)
            finally:
                path.write_bytes(was)
        print(f"mutgate: broker/{pkg}/'s lints took {time.monotonic() - began:.0f} s", file=sys.stderr)
        return out, None
    finally:
        shutil.rmtree(tree, ignore_errors=True)


def lint_run(binary, cwd, timeout, mem, name):
    """How one run of lint test name ended: 'passed' (exit 0); 'refused' (exit 1, its own `--- FAIL:`
    line, and no line opening `panic: ` or `fatal error: `, which a panic or a crash prints and a test's
    message, indented, does not); 'timeout'; 'memory cap'; or 'exit N' (a panic is exit 2)."""
    out = pathlib.Path(binary).with_suffix(".out")
    with open(out, "wb") as log:
        end, _ = contained([str(binary), "-test.failfast", f"-test.run=^{name}$", f"-test.timeout={timeout + 2}s"],
                           mem, timeout, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
    if end == 0:
        return "passed"
    if end in ("timeout", "over"):
        return {"over": "memory cap"}.get(end, end)
    if end == 1 and failed_test(binary) == name:
        with open(out, "rb") as f:
            if not any(CRASHED.match(line) for line in f):
                return "refused"
        return "exit 1, with a panic"
    return f"exit {end}"


CRASHED = re.compile(rb"(panic: |fatal error: )")


def add_mutants(data, mutants):
    """Gremlins' JSON with the deletion mutants joined to its files and totals, and their count."""
    files = {f["file_name"]: f for f in data["files"]}
    for m in mutants:
        f = files.get(m["file"])
        if f is None:
            f = files[m["file"]] = {"file_name": m["file"], "mutations": []}
            data["files"].append(f)
        f["mutations"] = (f.get("mutations") or []) + [{k: v for k, v in m.items() if k != "file"}]
        for key in ("mutants_total", COUNTERS.get(m["status"])):
            if key:
                data[key] = data.get(key, 0) + 1
    data["statement_deletions"] = len(mutants)
    return data


def cmd_delete(args):
    out = pathlib.Path(args.out).resolve()
    diff = broker_diff(args.git, "HEAD")
    added, tests = changes(diff, args.git, "HEAD")
    bases = bases_for(diff, args.git, "HEAD", tests, args.pkg)
    bad = 0
    try:
        adv = advisory()
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        if (lister := build_lister(tmp)) is None:
            return 1
        for pkg in args.pkg:
            dest = out / result_name(pkg)
            try:
                data = json.loads(dest.read_text())
            except (OSError, ValueError) as e:
                print(f"mutgate: no gremlins result for {pkg} to add to ({dest}: {e}); `run` first", file=sys.stderr)
                bad += 1
                continue
            if not shape_ok(data) or "statement_deletions" in data:
                print(f"mutgate: {dest} is not one gremlins result without deletions", file=sys.stderr)
                bad += 1
                continue
            targets, problem = targets_for(pkg, added, tests, data, bases)
            if not problem and (shard := shard_of(data)) is None:
                problem = f"{dest} records a shard that is not 0 <= index < of <= {SHARDS_MAX}"
            mutants, problem = (None, problem) if problem else deletion_mutants(pkg, targets, tmp, lister, args.jobs, shard)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                bad += 1
                continue
            dest.write_text(json.dumps({**add_mutants(data, mutants), **({"advisory": True} if adv else {})}))
    return 1 if bad else 0


def read_results(pkgs, root, added, tests, lister, bases):
    """({pkg: (data, targets)}, problems) for each package's shards under root/*/ or root/*/*/, each rechecked as
    `run` and `delete` check it, with the deletion sites listed here (#4106, #4602), then joined (#4961)."""
    out, problems = {}, []
    for pkg in pkgs:
        # Each mutants job's artifact is its own directory, and each shard a job runs its own directory
        # in that (#6170), so a shard named twice (a job writing another's) is refused rather than one
        # copy picked.
        name = glob.escape(result_name(pkg))
        found = sorted([*pathlib.Path(root).glob(f"*/{name}"), *pathlib.Path(root).glob(f"*/*/{name}")])
        if not found:
            problems.append(f"0 results for {pkg} in {root}, not one for each shard")
            continue
        shards, problem = [], None
        for f in found:
            try:
                shards.append((f, json.loads(f.read_text())))
            except (OSError, ValueError) as e:
                problem = f"no readable result for {pkg} ({f}: {e})"
                break
        joined, problem = (None, problem) if problem else join_shards(pkg, shards, added, tests, lister, bases)
        if problem:
            problems.append(problem)
            continue
        out[pkg] = joined
    return out, problems


TOTALS = ("mutants_total", "mutants_killed", "mutants_lived", "mutants_not_viable", "mutants_not_covered",
          "statement_deletions")


def join_shards(pkg, shards, added, tests, lister, bases):
    """((data, targets), None) of one package's shards [(file, data)] joined, or (None, problem).
    The shards must agree on K and on the target lines, number 0..K-1 once each, and each must pass
    `run`'s and `delete`'s checks on its own lines and sites with no mutant on another shard's line."""
    seen, targets, sites = {}, None, None
    for f, data in shards:
        if not shape_ok(data):
            return None, f"{f} is not gremlins' files[].mutations[] shape"
        if data.get("advisory"):
            return None, f"{f} is an advisory local result (no delegated cgroup), not a verdict"
        if (shard := shard_of(data)) is None:
            return None, f"{f} records a shard that is not 0 <= index < of <= {SHARDS_MAX}"
        if shard in seen:
            if shard == (0, 1):
                return None, f"{f} and {seen[shard]} are both results for {pkg}: one run gives one result"
            return None, f"{f} and {seen[shard]} are both shard {shard[0]} of {shard[1]} for {pkg}: shards overlap"
        seen[shard] = f
        mine, problem = targets_for(pkg, added, tests, data, bases)
        if problem:
            return None, f"{f} {problem}"
        if targets is None:
            targets = mine
            sites, problem = deletion_sites(pkg, targets, lister)
            if problem:
                return None, f"{f} {problem}"
        elif mine != targets or data.get("targets") != shards[0][1].get("targets"):
            return None, f"{f} records other target lines than {shards[0][0]}: the shards of {pkg} disagree; rerun the mutgate workflow"
    counts = {of for _, of in seen}
    if len(counts) != 1:
        return None, f"the results for {pkg} disagree on the number of shards: {sorted(counts)}"
    of = counts.pop()
    if missing := sorted(set(range(of)) - {i for i, _ in seen}):
        return None, f"{pkg} is missing shard(s) {missing} of {of}"
    joined = {"files": [], **{k: 0 for k in TOTALS}}
    files = {}
    for (i, _), f in sorted(seen.items()):
        data = dict(shards)[f]
        mine = shard_lines(targets, i, of)
        if problem := result_problem(data, pkg, BROKER / pkg, mine, sites[i::of]):
            return None, f"{f} {problem}"
        # Gremlins writes every mutant outside its -D diff as SKIPPED (v0.6.0 engine.go:195), so a
        # shard reports the other shards' lines so: no verdict, dropped here. The owner's own lines
        # hold no SKIPPED (result_problem above). Any other mutant on a target line of another shard
        # is one that shard owns: an overlap.
        kept = [(m_file["file_name"], [m for m in m_file.get("mutations") or [] if m.get("type") == DELETION
                 or m.get("status") != "SKIPPED" or m["line"] in mine.get(f"broker/{pkg}/{m_file['file_name']}", ())])
                for m_file in data["files"]]
        if other := sorted({(name, m["line"]) for name, muts in kept for m in muts if m.get("type") != DELETION
                            and m["line"] in targets.get(f"broker/{pkg}/{name}", ())
                            and m["line"] not in mine.get(f"broker/{pkg}/{name}", ())}):
            return None, f"{f} holds mutants on lines of another shard of {pkg}: {other[:20]}: shards overlap"
        for name, muts in kept:
            g = files.get(name)
            if g is None:
                g = files[name] = {"file_name": name, "mutations": []}
                joined["files"].append(g)
            g["mutations"] += muts
        for k in TOTALS:
            joined[k] += data.get(k) if type(data.get(k)) is int else 0
    if "targets" in shards[0][1]:
        joined["targets"] = shards[0][1]["targets"]
    if problem := result_problem(joined, pkg, BROKER / pkg, targets, sites):
        return None, f"the joined shards of {pkg} {problem}"
    return (joined, targets), None


def cmd_verify(args):
    """The gate on JSON that PR code wrote (#4106): every claimed package has a readable result, then gate."""
    diff = broker_diff(args.git, args.head)
    added, tests = changes(diff, args.git, args.head)
    pkgs = claimed(diff, base=args.git, head=args.head)
    if not pkgs:
        write_summary(args.summary, "### mutgate\n\nThis diff changes no .go line in a tier-A or tier-B package, and no "
                      f"{RECORD} record of one (a changed record claims its package too).\n")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        # The base's lister reads the PR's files as data (go/parser) and runs none of their code (#4602).
        if (lister := build_lister(tmp)) is None:
            return 1
        results, problems = read_results(pkgs, args.dir, added, tests, lister,
                                         bases_for(diff, args.git, args.head, tests, pkgs))
        records = record_waivers(pkgs, lister, args.git, args.head)
    for problem in problems:
        print(f"mutgate: {problem}", file=sys.stderr)
    if problems:
        return 1
    return decide(results, added, tests, args, records)


def decide(results, added, tests, args, records=({}, [])):
    """Gate the read results against the packages' records (record_waivers' pair; a stale entry fails),
    and write the summary table. The PR body waives nothing (#6379): a body can change after a review
    without changing the head, while a record is part of the head every accept names."""
    text = pathlib.Path(args.body).read_text(encoding="utf-8", errors="replace") if args.body else ""
    if waivers(text) or malformed_waivers(text):
        print(f"mutgate: the PR body's Mutant-equivalent and Mutant-uncovered lines waive nothing (#6379): write each into its package's "
              f"{RECORD} with `tools/mutgate.py waive FILE --accepted '#PR'` and commit it")
    kept, stale = records
    waived = {site: f"{reason} (record, {accepted}{', new in this PR' if new else ''})"
              for site, (reason, accepted, new) in kept.items()}
    targets = {pkg: t for pkg, (_, t) in results.items()}
    every = {pkg: mutants_of(d) for pkg, (d, _) in results.items()}
    found = violations(targets, {pkg: survivors_of(d) for pkg, (d, _) in results.items()}, waived, every)
    # Every target line must run (#5762, Security on #5770): a weakened test plus an edit to the lines
    # it ran (or a moved file) would otherwise leave them unrun unseen. In a package whose tests the diff
    # leaves alone too (L3 R1 and Security S2 on #5770, #5779): else new code with no test passed there
    # while the same code with a partial test failed, and code moved in with its test deleted passed.
    lost = violations(targets, {pkg: uncovered_of(d) for pkg, (d, _) in results.items()}, waived, every)
    # targets_for checked each record's tests against changed_tests, so the record names them.
    tested = {pkg: d["targets"]["tests"] for pkg, (d, _) in results.items() if tests_changed(tests, pkg)}
    fresh = sorted(((site, reason, accepted) for site, (reason, accepted, new) in kept.items() if new),
                   key=lambda f: (site_text(f[0]), f[1]))
    write_summary(args.summary, summary(results, tested, waived, {pkg for pkg in results if diff_targets(added, pkg)},
                                        stale, fresh))
    for problem in stale:
        print(f"mutgate: {problem}")
    for w, hit in covering(waived, every)[1]:
        print(f"mutgate: the waiver {site_text(w)} matches {len(hit)} mutants ("
              + ", ".join(site_text((p, n, k, c)) for p, n, k, c in hit) + "), so it waives none: name the one it "
              "proves: delete its entry from the package's " f"{RECORD} and run `tools/mutgate.py waive FILE --accepted '#PR'` again "
              "on a line `Mutant-equivalent: <path>:<line>:<col>:<KIND> <reason>`, then commit the record")
    return report_violations(found, lost) or (1 if stale else 0)


def write_summary(path, text):
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


CELL = 300


def cell(text):
    """Text from a result or the PR body as one Markdown table cell, never markup, cut at CELL characters."""
    text = re.sub(r"\s+", " ", str(text))[:CELL]
    return re.sub(r"([\\`*_\[\]<>|#!~&])", r"\\\1", text)


def record_of(path):
    """broker/<pkg>/MUTANTS-EQUIVALENT, the record holding an entry for a site in path."""
    return f"broker/{package_of(path)}/{RECORD}"


def proof_cell(reason, path):
    """cell(reason), ending with a mark naming the record when it is cut, since a new entry's proof is
    read in full (#5812): a clause past the cut would otherwise be accepted unseen."""
    cut = len(re.sub(r"\s+", " ", str(reason))) > CELL
    return cell(reason) + (f" … (cut; see {cell(record_of(path))})" if cut else "")


VERDICTS = {"TIMED OUT": "killed (timed out)", "NOT COVERED": "not covered", "NOT VIABLE": "not viable (does not build)"}
ROWS = 2000
# New record entries listed in full (#5812). Each line holds four cells of at most 300 characters
# (1200 bytes in UTF-8, or 600 escaped ASCII) plus the cut mark, so the list stays under 500 KiB,
# inside GitHub's 1 MiB step-summary limit, past which the whole summary is dropped.
FRESH = 100


def summary(results, tested, waived, own=(), stale=(), fresh=()):
    """One Markdown table of every mutant on a target line, survivors first, and its verdict.
    tested names the changed tests of each package whose tests changed (None: every test); own
    names the packages where the diff also adds non-test lines; fresh lists ((path, line, mutant),
    reason, accepted) of each record entry the base does not hold, whether or not a mutant uses it."""
    lines = ["### mutgate", ""]
    rows, used = [], set()
    cover, ambiguous = covering(waived, {pkg: mutants_of(d) for pkg, (d, _) in results.items()})
    for pkg, (data, targets) in sorted(results.items()):
        n = sum(len(v) for v in targets.values())
        lines.append(f"- {cell(pkg)}: {n} target lines, " + (
            "the lines the diff changes" if pkg not in tested
            else ("the lines the diff changes and " if pkg in own else "") + (
                "the lines every test covers (a change every test may run)" if tested[pkg] is None
                else "the lines " + cell(", ".join(tested[pkg])) + " cover")))
        for f in data["files"]:
            path = f"broker/{pkg}/{f['file_name']}"
            for m in f.get("mutations") or []:
                if m["line"] not in targets.get(path, ()):
                    continue
                col = m.get("column")
                site = f"{path}:{m['line']}" + (f":{col}" if type(col) is int else "")
                status = m["status"]
                w = cover.get((path, m["line"], m.get("type"), col if type(col) is int else None))
                reason = waived[w] if w else None
                if status == "LIVED" and reason:
                    used.add(w)
                    rank, verdict = 1, "equivalent: " + cell(reason)
                elif status == "LIVED":
                    rank, verdict = 0, "**LIVED**: no test fails"
                elif status == "NOT COVERED" and reason:
                    used.add(w)
                    rank, verdict = 1, "waived as uncovered (no test can run it): " + cell(reason)
                elif status == "NOT COVERED":
                    rank, verdict = 0, "**NOT COVERED**: no test of the package runs it"
                elif status == "KILLED":
                    by = m.get("killed_by")
                    rank, verdict = 2, (f"killed by {cell(by)}" if isinstance(by, str) and FAILED.fullmatch(
                        b"--- FAIL: " + by.encode()) else "killed" if m.get("type") == DELETION
                        else "killed (gremlins names no test)")
                else:
                    rank, verdict = 3, cell(VERDICTS.get(status, status))
                rows.append((rank, site, f"| {cell(site)} | {cell(m.get('type'))} | {verdict} |"))
    rows.sort(key=lambda r: r[:2])
    lines += ["", "| Site | Mutant | Verdict |", "| --- | --- | --- |", *(r[2] for r in rows[:ROWS])]
    if len(rows) > ROWS:
        lines.append(f"| {len(rows) - ROWS} more rows | | not shown |")
    if ambiguous:
        lines += ["", "Waivers matching more than one mutant, which waive none of them (#5792):",
                  *(f"- {cell(site_text(w))}: " + ", ".join(cell(site_text(m)) for m in hit) for w, hit in ambiguous)]
    if fresh:
        lines += ["", f"New {RECORD} entries in this PR (read each proof: it waives its mutant from the merge on):",
                  *(f"- {cell(site_text((p, n, None, col)))} {cell(kind)} ({cell(accepted)}): {proof_cell(reason, p)}"
                    for (p, n, kind, col), reason, accepted in fresh[:FRESH])]
        if len(fresh) > FRESH:
            lines.append(f"- {len(fresh) - FRESH} more new entries not shown: read them in "
                         + ", ".join(cell(r) for r in sorted({record_of(p) for (p, *_), *_ in fresh[FRESH:]})))
    if stale:
        lines += ["", f"Stale {RECORD} entries (each fails the gate):", *(f"- {cell(p)}" for p in stale)]
    return "\n".join(lines) + "\n"


def dry_run(data):
    """How many mutants gremlins left RUNNABLE, which it does only when it ran none of them."""
    return sum(m["status"] == "RUNNABLE" for f in data["files"] for m in f.get("mutations") or [])


def foreign_names(data, pkg_dir):
    """file_names carrying a LIVED mutant that are not a file directly in pkg_dir, sorted."""
    names = {f["file_name"] for f in data["files"]
             if any(m["status"] == "LIVED" for m in f.get("mutations") or [])}
    return sorted(n for n in names if "/" in n or "\\" in n or not (pkg_dir / n).is_file())


def shape_ok(data):
    """True when gremlins' JSON has the fields survivors() reads, for every mutation it counts."""
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        return False
    muts = [m for f in data["files"] for m in (f.get("mutations") or [])]
    if not all(isinstance(f.get("file_name"), str) for f in data["files"]):
        return False
    if not all(isinstance(m.get("status"), str) and isinstance(m.get("line"), int) for m in muts):
        return False
    # gremlins' own LIVED count must match what survivors() reads, so a renamed status fails too.
    return data.get("mutants_lived") == sum(m["status"] == "LIVED" for m in muts)


def cmd_report(args):
    if any(json.loads(f.read_text()).get("advisory") for f in pathlib.Path(args.dir).glob("*.json")):
        print("ADVISORY: local results without a delegated cgroup, not a verdict")
    live = survivors(args.dir)
    for pkg, items in live.items():
        print(f"{pkg}: {len(items)} surviving")
        for fname, line, kind, col in items:
            print(f"  {fname}:{line}" + (f":{col}" if col else "") + f" {kind}")
    return 0


def broker_diff(base, head):
    """`git diff BASE...HEAD` of broker/, and of each file outside it that a broker package names by
    path (read_index, #6436): an edit to SPEC.md changes the tests that read it."""
    names = subprocess.run(["git", "-c", "core.quotepath=off", "diff", "--name-only", "-z", "--no-renames", "--no-relative",
                            f"{base}...{head}"], cwd=ROOT, capture_output=True, check=True).stdout
    index = read_index(BROKER.resolve())
    read = sorted({n for n in names.decode("utf-8", "surrogateescape").split("\0")
                   if n and n.split("/")[0] != "broker" and n in index})
    return subprocess.run(
        # --text: a `-diff` .gitattributes line would otherwise hide a file's lines as binary.
        # The prefix, colour, external-diff, textconv and rename options pin the format: git config such as diff.noprefix,
        # color.ui=always, diff.external a diff.<driver>.textconv or diff.renames=copies would otherwise hide added lines (#4115).
        # Literal pathspecs: a read file's name is a path, never a pattern.
        ["git", "--literal-pathspecs", "-c", "core.quotepath=off", "diff", "-U0", "--text", "--src-prefix=a/", "--dst-prefix=b/",
         "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", f"{base}...{head}", "--", "broker", *read],
        # errors="replace" below: with --text a binary file's bytes are diff lines, and need not be UTF-8.
        cwd=ROOT, capture_output=True, check=True,
    # Bytes decoded here: text=True would turn a lone \r into \n and number the lines wrongly (#4028).
    ).stdout.decode("utf-8", errors="replace")


def cmd_plan(args):
    """The `mutants` matrix (#4961): [{pkg, shard, of}] for each package `claimed` names, K from its
    target lines and deletion sites. It runs the PR's tests (changed tests' coverage), so only in
    an untrusted job; K is a schedule, and `verify` checks the shards whatever K is."""
    try:
        advisory()
    except RuntimeError as e:
        print(e, file=sys.stderr)
        return 1
    diff = broker_diff(args.git, "HEAD")
    added, tests = changes(diff, args.git, "HEAD")
    counts, planned = [], {}
    pkgs = claimed(diff, base=args.git, head="HEAD")
    bases = bases_for(diff, args.git, "HEAD", tests, pkgs)
    with tempfile.TemporaryDirectory() as tmp:
        if (lister := build_lister(tmp)) is None:
            return 1
        for pkg in pkgs:
            targets, suite = diff_targets(added, pkg), None
            if tests_changed(tests, pkg):
                record, suite, problem = record_for(pkg, tests, bases, diff, args.git, tmp)
                if not problem:
                    targets, problem = targets_for(pkg, added, tests, {"targets": record}, bases)
                if problem:
                    print(f"mutgate: {problem}", file=sys.stderr)
                    return 1
                # The one coverage run every shard reads (#4970): a run of their own could differ.
                planned[pkg] = record
            sites, problem = deletion_sites(pkg, targets, lister)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                return 1
            # A test-changing package's whole suite already ran under coverage in record_for: its time
            # sizes the shards, so the slowest suite runs three times here, not four (#6155). Both times
            # are the test binary's run alone, so neither holds the build (#6162).
            if not (targets or sites):
                suite, problem = 0.0, None
            elif suite is None:
                suite, problem = suite_seconds(pkg, tmp)
            else:
                problem = None
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                return 1
            # `delete` runs each site with the tests that cover it (#6172), so its cost is theirs.
            costs, overhead = site_costs(pkg, sites, suite, tmp) if sites else (None, 0.0)
            # Any site may live and go to the lints that read its file, each shard copying broker/ (#6366).
            of = shard_count(targets, sites, suite, costs, overhead, lint_budget(pkg, sites))
            print(f"mutgate: {pkg}: {sum(map(len, targets.values()))} target lines, {len(sites)} deletion "
                  f"sites, a {suite:.0f} s suite, {of} shard(s)", file=sys.stderr)
            counts.append((pkg, of))
    include = pack(counts)
    if not counts:
        print("mutgate: 0 shards: no claimed package was planned; rerun the mutgate workflow", file=sys.stderr)
        return 1
    if not include:
        print(f"mutgate: {sum(of for _, of in counts)} shards do not fit {MATRIX_MAX} jobs (GitHub's matrix limit) "
              f"of at most {JOB_SHARDS_MAX} shards of one package each (its {JOB_MINUTES_MAX}-minute job limit): "
              "split the PR so each part changes fewer tier-A or tier-B packages", file=sys.stderr)
        return 1
    if len(include) < sum(of for _, of in counts):
        most = max(len(e["shards"].split(", ")) for e in include)
        print(f"mutgate: {sum(of for _, of in counts)} shards past {MATRIX_MAX} jobs: up to {most} shards a job, "
              "one after another", file=sys.stderr)
    if args.targets_out:
        pathlib.Path(args.targets_out).write_text(json.dumps(planned))
    print(json.dumps(include))
    return 0


def cmd_claimed(args):
    pkgs = claimed(broker_diff(args.git, args.head), base=args.git, head=args.head)
    print(json.dumps(pkgs) if args.json else "\n".join(pkgs))
    return 0


def cmd_gate(args):
    """`verify` without its checks, on DIR/<pkg>.json as `run` and `delete` write them (local use)."""
    diff = broker_diff(args.git, args.head)
    added, tests = changes(diff, args.git, args.head)
    # The claim verify makes, less its tier filter: a record-only package's record is read too (#5812).
    pkgs = touched(added, tests) | records_changed(diff)
    bases = bases_for(diff, args.git, args.head, tests, pkgs)
    results, bad = {}, 0
    for pkg in sorted(pkgs):
        try:
            data = json.loads((pathlib.Path(args.dir) / result_name(pkg)).read_text())
        except (OSError, ValueError):
            continue
        targets, problem = targets_for(pkg, added, tests, data, bases)
        if problem:
            print(f"mutgate: {pkg} {problem}", file=sys.stderr)
            bad += 1
            continue
        results[pkg] = (data, targets)
    if any(data.get("advisory") for data, _ in results.values()):
        print("mutgate: ADVISORY: local results without a delegated cgroup, not a verdict", file=sys.stderr)
    with tempfile.TemporaryDirectory() as tmp:
        records = ({}, [])
        if any((BROKER / pkg / RECORD).exists() or (BROKER / pkg / RECORD).is_symlink() for pkg in results):
            if (lister := build_lister(tmp)) is None:
                return 1
            records = record_waivers(results, lister, args.git, args.head)
    return decide(results, added, tests, args, records) or (1 if bad else 0)


def report_violations(found, lost=()):
    # Each line ends with the mutant's own waiver line, path:line:col:KIND, so two of one kind on a line
    # read apart, and the line pastes as printed with no backtick or bracket around it (#5828).
    for pkg, path, line, kind, col in found:
        # A deletion's line is the first added line of its statement, which may start earlier (#4603).
        what = f"deleting the whole statement holding line {line}" if kind == DELETION else kind
        print(f"mutgate: {path}:{line} {what} survives, on a line of package {pkg} that this PR changes or tests "
              f"; its waiver line: Mutant-equivalent: {site_text((path, line, kind, col))} <reason>")
    for pkg, path, line, kind, col in sorted(set(lost), key=lambda v: (v[:4], v[4] or 0)):
        print(f"mutgate: {path}:{line} is a target line no test of package {pkg} runs at the head ({kind} not "
              f"covered): cover it, or, if no test can reach it, name it in a Mutant-uncovered line "
              f"; its waiver line: Mutant-uncovered: {site_text((path, line, kind, col))} <reason>")
    found = [*found, *lost]
    if found:
        print("mutgate: add a test that fails when the line changes; if no test can tell, add a line "
              "`Mutant-equivalent: <path>:<line>[:<col>][:<KIND>] <reason>` (`Mutant-uncovered:` for one no test "
              "can reach) for that mutant to a file, record it with `tools/mutgate.py waive FILE --accepted '#PR'` "
              "(its column and kind as the summary's Site and Mutant cells give them, where its line holds another) "
              "and commit the record")
    return 1 if found else 0


def default_jobs():
    """The CPUs this process may run on (a container's cpuset), not the host's. macOS has no
    os.sched_getaffinity, so there the CPU count stands in (#4672)."""
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def mutant_kind(v):
    if not MUTANT_KIND.fullmatch(v):
        raise argparse.ArgumentTypeError("give a mutant type such as STATEMENT_DELETION or CONDITIONALS_NEGATION")
    return v


def commit_sha(v):
    if not re.fullmatch(r"[0-9a-f]{40}", v):
        raise argparse.ArgumentTypeError("give the full 40-character commit sha")
    return v


def dep_ref(v):
    """argparse type of --dep: (file, name), file a dep file (see RECORD) and name one its declaration declares."""
    f, _, name = v.rpartition(":")
    if not dep_file_ok(f) or not DEP_NAME.fullmatch(name):
        raise argparse.ArgumentTypeError(f"{v!r} is not broker/<pkg>/<file>.go:<name>, a non-test .go file and a "
                                         "name its top-level declaration declares (`Recv.Name` for a method)")
    return f, name


def pr_ref(v):
    if not re.fullmatch(r"#[1-9]\d*", v):
        raise argparse.ArgumentTypeError("give the PR as #<number>")
    return v


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["go-cover"] and len(argv) >= 4:  # go_shim's entries, not commands of their own
        return shim_entry(argv[2], go_cover, argv[1], argv[2], argv[4:], int(argv[3]) or None)
    if argv[:1] == ["go-capped"] and len(argv) >= 4:
        return shim_entry(argv[2], go_capped, argv[1], argv[2], int(argv[3]), argv[4:])
    if argv[:1] == ["cap-exec"] and len(argv) >= 5:
        return shim_entry(argv[1], cap_exec, int(argv[2]), argv[3], argv[4:])
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("packages")
    p = sub.add_parser("claimed")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("head", nargs="?", default="HEAD")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("plan")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("--targets-out", metavar="FILE", help="write the lines each package's changed tests cover here")
    p = sub.add_parser("run")
    p.add_argument("pkg", nargs="*")
    p.add_argument("--out", default="mutants")
    p.add_argument("--git", metavar="BASE")
    p.add_argument("--shard", type=int, default=0, metavar="I")
    p.add_argument("--of", type=int, default=1, metavar="K")
    p.add_argument("--targets", metavar="FILE", help="plan's --targets-out file: the lines changed tests cover")
    p = sub.add_parser("delete")
    p.add_argument("pkg", nargs="+")
    p.add_argument("--out", default="mutants")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("--jobs", type=int, default=default_jobs(), metavar="N")
    p = sub.add_parser("report")
    p.add_argument("dir")
    p = sub.add_parser("waive")
    p.add_argument("lines", metavar="FILE",
                   help="`Mutant-equivalent: <path>:<line>[:<col>][:<KIND>] <reason>` lines, one per line")
    p.add_argument("--accepted", required=True, metavar="#PR", type=pr_ref, help="the PR that adds these entries; its review reads each proof")
    p.add_argument("--mutant", type=mutant_kind,
                   help=f"the one mutant kind the proofs are for, where a line names none (default {DELETION}; "
                        "or a gremlins type)")
    p.add_argument("--dep", action="append", type=dep_ref, metavar="broker/PKG/FILE.go:NAME",
                   help="a top-level declaration every one of these proofs rests on, outside its own (repeatable): "
                        "the entries go stale when it changes (see RECORD's deps)")
    p = sub.add_parser("records")
    p.add_argument("pkg", nargs="*")
    for name in ("gate", "verify"):
        p = sub.add_parser(name)
        p.add_argument("dir")
        p.add_argument("--git", required=True, metavar="BASE")
        p.add_argument("head", nargs="?", default="HEAD")
        # Kept so an older workflow copy still runs; the body waives nothing (#6379).
        p.add_argument("--body", metavar="FILE", help="the PR body: its waiver lines are named, never applied")
        p.add_argument("--body-from", metavar="SHA", type=commit_sha, help="ignored (#6379)")
        p.add_argument("--summary", metavar="FILE", help="append the table of verdicts here")
    args = ap.parse_args(argv)
    # K is a package's shard count, which `plan` packs past MATRIX_MAX jobs up to SHARDS_MAX (#6170).
    if args.cmd == "run" and (not 0 <= args.shard < args.of <= SHARDS_MAX or (args.of > 1 and not args.git)):
        ap.error(f"--shard I --of K needs 0 <= I < K <= {SHARDS_MAX}, and --git when K > 1")
    if args.cmd == "packages":
        print("\n".join(gated_packages()))
        return 0
    cmd = {"claimed": cmd_claimed, "plan": cmd_plan, "run": cmd_run, "delete": cmd_delete, "report": cmd_report, "gate": cmd_gate,
           "verify": cmd_verify, "waive": cmd_waive, "records": cmd_records}[args.cmd]
    if args.cmd in ("plan", "delete") or (args.cmd == "run" and args.git):  # the gate's runs (#6456)
        with scratch():
            return cmd(args)
    return cmd(args)


if __name__ == "__main__":
    sys.exit(main())
