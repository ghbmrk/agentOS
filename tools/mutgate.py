#!/usr/bin/env python3
"""Mutation testing on the tier-A and tier-B broker packages (MUT-tierA, #1814; REV-PROOF-mut, #4908).

Runs gremlins (github.com/go-gremlins/gremlins, an existing Go mutation tool) per package,
reports the surviving mutants, and fails a PR where a mutant survives on a line it changes.

  tools/mutgate.py packages                  list the tier-A and tier-B broker packages
  tools/mutgate.py claimed --git BASE [HEAD] [--json]
                                             the listed packages where the diff BASE...HEAD adds or
                                             changes a line of a .go file: the only ones the gate
                                             can fail, so the only ones CI runs gremlins on
  tools/mutgate.py plan --git BASE [--targets-out FILE]
                                             the `mutants` matrix as JSON: K shards for each claimed
                                             package, K from its target lines, deletion sites and
                                             suite time (#4961, #5069); FILE gets each test-only
                                             package's target lines
  tools/mutgate.py run [PKG...] [--out DIR] [--git BASE [--shard I --of K] [--targets FILE]]
                                             run gremlins per package (default: all listed),
                                             one JSON file per package in DIR (default mutants/);
                                             with --git, only on the package's target lines (below),
                                             and with --shard, only on shard I of K of them; with
                                             --targets, a test-only package's lines are plan's FILE's
  tools/mutgate.py delete PKG... [--out DIR] --git BASE [--jobs N]
                                             delete each statement a target line belongs to, alone,
                                             on N parallel workers (default: one per usable CPU; a
                                             detected verdict is confirmed alone), run its tests, and
                                             add the verdicts to `run`'s JSON in DIR (#4573, #4603, #4633);
                                             only the sites of the result's own shard
  tools/mutgate.py report DIR                survivors per package, from the JSON in DIR
  tools/mutgate.py gate DIR --git BASE [HEAD] [--body FILE] [--summary FILE]
                                             exit 1 if a LIVED mutant sits on a target line that no
                                             `Mutant-equivalent:` line in FILE (the PR body) names
  tools/mutgate.py verify DIR --git BASE [HEAD] [--body FILE] [--summary FILE]
                                             `gate`, after checking that DIR/*/ holds exactly
                                             one readable result for each shard of every package
                                             `claimed` names, as `run` and `delete` check it, with
                                             one deletion verdict for each site it lists itself,
                                             then joining the shards: CI's trusted job (#4106,
                                             #4602, #4961)

Target lines. A package's target lines are the lines the diff adds or changes in its non-test .go
files (no `REQ:` marker is needed, #4908). When the diff changes only the package's _test.go files,
they are the lines of its non-test files that the changed test functions run: `run` names them
with one `go test -run '^(T1|T2)$' -coverprofile` run and records them in the result, and a change
no single test function holds (a helper, TestMain, an import, a deleted declaration or file) runs
every test, so the set is at most the package's covered lines. Coverage can differ from run to run
(a timing branch, a retry), so in CI `plan` measures it once and every shard reads that one record
(`--targets`), never a coverage run of its own: K shards of one package then name the same lines (#4970). Gremlins mutates a package's target
lines only: its `-D` reads `git diff --merge-base`, so for a test-only package `run` points HEAD for
that one call at a commit whose parent differs from the tree on exactly those lines.
A LIVED mutant on a target line is code the package's tests run (gremlins mutates only covered
code) but do not check, and fails the gate, unless the PR body holds the line
`Mutant-equivalent: broker/<pkg>/<file>.go:<line> <reason>` for its site: one site, one reason
the reviewer checks, never a range or pattern. The body is read as text by this file, never run.
Not covered mutants are not failures here; gremlins' coverage run is the only judge of "covered".
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
`mutants` job each. Gremlins tests every mutant alone with the whole package suite, and `delete`
deletes every statement alone and runs the whole suite, so a mutant's verdict does not depend on
which other mutants share its job: the joined shards give the verdicts one job would. K is only a
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
import collections
import concurrent.futures
import contextlib
import glob
import json
import math
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
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
# The PR body's waiver for one site: an exact repo path and line, then a reason.
EQUIVALENT = re.compile(r"^Mutant-equivalent: (broker/[^\s:*?\[\]]+\.go):([1-9]\d*) +(\S.*?)\s*$")


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
    """{package: [(file, line, type)]} of LIVED mutants in the per-package JSON files."""
    out = {}
    for f in sorted(pathlib.Path(results_dir).glob("*.json")):
        pkg = f.stem.replace("+", "/")
        out[pkg] = survivors_of(json.loads(f.read_text()))
    return out


def survivors_of(data):
    """[(file, line, type)] of LIVED mutants in one package's gremlins JSON, sorted."""
    return sorted(
        (m_file["file_name"], m["line"], m["type"])
        for m_file in data.get("files") or []
        for m in m_file.get("mutations") or []
        if m.get("status") == "LIVED"
    )


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


def added_lines(diff_text):
    """({path: set(line)} of the lines the diff adds, {path: set(line) or None} of the broker/
    _test.go files it changes). A test file's set holds the lines it adds and, for a hunk that only
    deletes, the line either side; it is None when the diff deletes the file or a line that starts
    a top-level declaration, so no test function left in it holds the change."""
    added, tests, path, old, line, in_hunk = {}, {}, None, None, 0, False

    def touch(p, lines):
        if tests.get(p, ()) is not None:
            tests.setdefault(p, set()).update(lines)

    # split("\n"), not splitlines(): that also breaks on \r, \x0b, \x0c, \x1c-\x1e, \x85, U+2028 and
    # U+2029, which a Go comment can carry, and every later added line would be numbered one low (#4028).
    for raw in diff_text.split("\n"):
        # Every line inside a hunk starts with space, + , - or \, so `diff ` can only be a file
        # header and a `+++ ` line is a header only before the first @@ (an added `++ x` is not one).
        if raw.startswith("diff "):
            in_hunk, path, old = False, None, None
            continue
        m = HUNK.match(raw)
        if m:
            in_hunk, line = True, int(m.group(1))
            if path is None and old is not None and is_test(old):
                tests[old] = None  # the file is deleted
            elif path is not None and is_test(path) and m.group(2) == "0":
                touch(path, {line, line + 1})  # git numbers a deletion after new line `line`
            continue
        if not in_hunk:
            if raw.startswith("--- "):
                old = _header_path(raw, "a/")
            elif raw.startswith("+++ "):
                path = _header_path(raw)
            continue
        if path is None or raw.startswith("\\"):  # "\ No newline at end of file" is no line (#4103)
            continue
        if raw.startswith("+"):
            added.setdefault(path, set()).add(line)
            if is_test(path):
                touch(path, {line})
            line += 1
        elif raw.startswith("-"):
            if is_test(path) and DECL.match(raw[1:]):
                tests[path] = None
        else:
            line += 1
    return added, tests


def package_of(path):
    """The broker/ package directory of a repo path, as survivors() names it, or None."""
    parts = path.split("/")
    if parts[0] != "broker" or len(parts) < 3:
        return None
    return "/".join(parts[1:-1])


def touched(added, tests):
    """The broker/ packages where the diff adds a line to a non-test .go file or changes a test file."""
    return ({package_of(p) for p in added if is_source(p)} | {package_of(p) for p in tests}) - {None}


def claimed(diff_text, packages=None):
    """Tier-A and tier-B packages where the diff adds or changes a .go line, sorted (#4908). A
    `REQ:` marker is no longer needed; violations() reads no other package."""
    return sorted(touched(*added_lines(diff_text)) & set(gated_packages() if packages is None else packages))


def diff_targets(added, pkg):
    """{path: lines} the diff adds to non-test .go files directly in broker/<pkg>/."""
    return {p: ls for p, ls in added.items() if is_source(p) and package_of(p) == pkg}


def test_functions(text, lines):
    """The names of the test functions holding lines (1-based) of a _test.go file's text, or None
    when one is outside every test function: a helper, TestMain, a method, a declaration or the
    file's header, which any test may run."""
    rows = text.split("\n")
    starts = [i + 1 for i, row in enumerate(rows) if DECL.match(row)]
    names = set()
    for line in lines:
        k = bisect.bisect_right(starts, line)
        if k == 0:
            return None
        m = TEST_FUNC.match(rows[starts[k - 1] - 1])
        if not m or m.group(1) == "TestMain":
            return None
        names.add(m.group(1))
    return names


def changed_tests(tests, pkg):
    """Sorted names of the test functions the diff changes in broker/<pkg>/, or None for every test.
    The files are read as text from the tree, never run; a link is not followed (L3 on #4643)."""
    names = set()
    for path, lines in sorted(tests.items()):
        if package_of(path) != pkg:
            continue
        f = BROKER / path.split("/", 1)[1]
        if lines is None or f.is_symlink() or not f.is_file():
            return None
        found = test_functions(f.read_bytes().decode("utf-8", "replace"), lines)
        if found is None:
            return None
        names |= found
    return sorted(names)


def targets_for(pkg, added, tests, data):
    """({path: lines}, None) of a claimed package's target lines, or (None, problem). From the diff
    when it changes a non-test file there; else the record `run` wrote in data of the lines the
    changed tests cover, which must name exactly the tests changed_tests names here."""
    own = diff_targets(added, pkg)
    if own:
        return own, None
    want = changed_tests(tests, pkg)
    rec = data.get("targets") if isinstance(data, dict) else None
    if not isinstance(rec, dict) or rec.get("tests") != want or not isinstance(rec.get("lines"), dict):
        return None, (f"holds no record of the lines that {'every test' if want is None else want} covers, "
                      f"the tests this test-only diff changes in broker/{pkg}/ (`mutgate.py run --git` writes it)")
    out = {}
    for name, lines in rec["lines"].items():
        f = BROKER / pkg / name if isinstance(name, str) else None
        if (f is None or "/" in name or "\\" in name or not is_source(name) or f.is_symlink() or not f.is_file()
                or not isinstance(lines, list) or not all(type(n) is int and n > 0 for n in lines)):
            return None, f"records covered lines {str(name)[:80]!r}: {str(lines)[:80]}, not lines of a non-test .go file in broker/{pkg}/"
        out[f"broker/{pkg}/{name}"] = set(lines)
    return out, None


def waivers(body):
    """{(path, line): reason} of the PR body's `Mutant-equivalent:` lines. The body is text only."""
    out = {}
    for row in (body or "").replace("\r\n", "\n").split("\n"):
        m = EQUIVALENT.match(row)
        if m and re.search(r"[A-Za-z]{2}", m.group(3)):
            out[(m.group(1), int(m.group(2)))] = m.group(3)
    return out


def violations(targets, live, waived=None):
    """(pkg, path, line, kind) of each LIVED mutant on a package's target line that waived (a
    {(path, line): reason}) does not name; targets is {pkg: {path: lines}}."""
    found = []
    for pkg in sorted(targets):
        for fname, line, kind in live.get(pkg, []):
            path = f"broker/{pkg}/{fname}"
            if line in targets[pkg].get(path, ()) and (path, line) not in (waived or {}):
                found.append((pkg, path, line, kind))
    return found


# Shards (#4961). The budgets size K so one shard's gremlins and deletion runs fit a job's 60 minutes:
# localui's 1048 target lines (about 0.35 deletion sites a line) ran gremlins in 10 minutes and
# deletion past 48 on #4945. GitHub runs at most 256 jobs from one matrix.
LINES_PER_SHARD = 250
SITES_PER_SHARD = 100
MATRIX_MAX = 256
# Every gremlins mutant and every deletion runs the package's whole suite, so a shard's time is its
# count times the suite's (#5069): kernel/sim's 48 s suite ran 6 shards of 89 sites past 60 minutes
# on #5006 (run 42368800375), where browser's 7 s suite ran 9 shards of 92 in 6 to 14. Seen there, a
# target line cost gremlins 0.1 to 0.2 suite runs and a site about 0.6 (its parallel run, then a
# detected one's run alone); the budget is half the job, as one package's shards took up to twice
# another's time.
LINE_RUNS = 0.25
SITE_RUNS = 1
SHARD_SECONDS = 1800


def shard_count(targets, sites, suite=0.0):
    """K for a package with these target lines ({path: lines}) and deletion sites, whose whole test
    suite takes suite seconds: at least one."""
    lines = sum(len(v) for v in targets.values())
    runs = LINE_RUNS * lines + SITE_RUNS * len(sites)
    return max(1, -(-lines // LINES_PER_SHARD), -(-len(sites) // SITES_PER_SHARD),
               math.ceil(suite * runs / SHARD_SECONDS))


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
    the record is not two ints with 0 <= index < of <= MATRIX_MAX."""
    rec = data.get("shard", {"index": 0, "of": 1}) if isinstance(data, dict) else None
    if not isinstance(rec, dict) or set(rec) != {"index", "of"}:
        return None
    i, k = rec["index"], rec["of"]
    if type(i) is not int or type(k) is not int or not 0 <= i < k <= MATRIX_MAX:
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


def covered_by(pkg, names, tmp):
    """({path: lines}, None) of the non-test .go files directly in broker/<pkg>/ that the named
    test functions (every test, for None) run, from one -coverprofile run of the PR's tests (so in
    the untrusted job only); or (None, problem). A block's lines from its start to its end count."""
    profile = pathlib.Path(tmp) / "tests.cover"
    profile.unlink(missing_ok=True)
    cmd = ["go", "test", "-count=1", "-covermode=set", f"-coverprofile={profile}"]
    if names is not None:
        cmd += ["-run", "^(" + "|".join(names) + ")$"]
    # Its output goes to stderr: `plan` prints the matrix on stdout (#4961).
    if subprocess.run([*cmd, "."], cwd=BROKER / pkg, stdout=sys.stderr).returncode or not profile.exists():
        return None, f"broker/{pkg}/'s tests {'(all)' if names is None else names} fail under -coverprofile"
    out = {}
    for name, blocks in covered_blocks(profile.read_text()).items():
        f = BROKER / pkg / name
        if is_source(name) and f.is_file() and not f.is_symlink():
            for (first, _), (last, _) in blocks:
                out.setdefault(f"broker/{pkg}/{name}", set()).update(range(first, last + 1))
    return out, None


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
    """The record of a test-only package's target lines that `run` writes and targets_for reads."""
    return {"tests": names, "lines": {p.rsplit("/", 1)[1]: sorted(ls) for p, ls in sorted(targets.items())}}


def planned_targets(planned, pkg, added, tests):
    """({path: lines}, None) of a test-only package's target lines from plan's --targets-out file, or
    (None, problem). The record is checked as verify checks the one a result carries (targets_for).
    A package the plan does not name is a problem, never a coverage run here: that run could name
    other lines than the other shards' (#4970)."""
    rec = planned.get(pkg) if isinstance(planned, dict) else None
    if rec is None:
        return None, f"the plan names no target lines for broker/{pkg}/; rerun the mutgate workflow"
    targets, problem = targets_for(pkg, added, tests, {"targets": rec})
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
    added, tests = added_lines(broker_diff(args.git, "HEAD")) if args.git else (None, None)
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
    for pkg in pkgs:
        dest = out / result_name(pkg)
        targets, record = (diff_targets(added, pkg) if args.git else None), None
        if args.git and not targets:
            # A test-only diff (#4908): the lines its changed test functions run are the targets,
            # from plan's one coverage run when given, so every shard names the same lines (#4970).
            names = changed_tests(tests, pkg)
            if planned is not None:
                targets, problem = planned_targets(planned, pkg, added, tests)
            else:
                targets, problem = covered_by(pkg, names, cfgdir.name)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                bad += 1
                continue
            record = coverage_record(names, targets)
        if args.git:
            # #4961: this job's share of the target lines; the record keeps them all.
            mine = shard_lines(targets, args.shard, args.of)
            extra = {"shard": {"index": args.shard, "of": args.of}, **({"targets": record} if record else {})}
            if not mine:
                # Gremlins' -D mutates every line when its diff is empty; none is a target here.
                dest.write_text(json.dumps({"files": [], "mutants_total": 0, "mutants_lived": 0, **extra}))
                continue
            # The base's own diff marks exactly the target lines, so one unsharded run of a
            # non-test diff keeps it; a share or a test-only diff marks its lines on a commit.
            marked = record or args.of > 1
            try:
                with marked_base(pkg, mine, cfgdir.name) if marked else contextlib.nullcontext(args.git) as base:
                    r = unleash(["gremlins", "unleash", str(BROKER / pkg), "-D", base, "--config", str(cfg),
                                 *SUBDIRS, "-o", str(dest)], cwd=BROKER / pkg, env={**env, **DIFF_GIT_CONFIG})
            except RuntimeError as e:
                print(f"mutgate: no marked base for broker/{pkg}/: {e}", file=sys.stderr)
                bad += 1
                continue
        else:
            r = unleash(["gremlins", "unleash", f"./{pkg}", "--config", str(cfg), *SUBDIRS, "-o", str(dest)],
                        cwd=BROKER, env=env)
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
    cfgdir.cleanup()
    return 1 if bad else 0


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


def covered_blocks(profile):
    """{file base name: [((line, col), (line, col))]} of the blocks a `-coverprofile` ran."""
    out = {}
    for row in profile.split("\n")[1:]:
        m = COVER.match(row)
        if m and int(m.group(6)) > 0:
            out.setdefault(m.group(1).rsplit("/", 1)[-1], []).append(
                ((int(m.group(2)), int(m.group(3))), (int(m.group(4)), int(m.group(5)))))
    return out


def is_covered(blocks, site):
    """Whether a block that ran holds the site's cover position: its own start, or for a case or
    select clause, whose block starts after its colon, its switch's or select's start."""
    pos = (site["cover_line"], site["cover_col"])
    return any(start <= pos < end for start, end in blocks.get(site["file"], ()))


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


def run_tests(binary, cwd, timeout, mem=None):
    """'KILLED', 'LIVED' or 'TIMED OUT' for one run of a compiled test binary; its process group
    is killed at the timeout, so a test's child cannot outlive the verdict. Its output goes to
    BINARY.out, where failed_test reads which test failed. With mem, the run is also killed, and
    KILLED by `memory_cap`, once its session's resident memory passes mem bytes, as the Go runtime's
    own out of memory crash would end it: a deletion that drops a bound can grow a test by gigabytes
    in seconds, and on a CI runner that takes the runner down with the job (egress on #5011). That
    counts as detection only because deletion_mutants first shows the unmutated tests stay well under it."""
    out = pathlib.Path(binary).with_suffix(".out")
    with open(out, "wb") as log:
        p = subprocess.Popen([str(binary), "-test.failfast", f"-test.timeout={timeout + 2}s"], cwd=cwd,
                             stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        end, _ = watch(p, timeout, mem)
        if end == "over":
            log.write(b"\n--- FAIL: memory_cap\n")  # failed_test's name for it, so the table says why
        return {"over": "KILLED", "timeout": "TIMED OUT"}.get(end) or ("LIVED" if end == 0 else "KILLED")


def watch(p, timeout=None, mem=None):
    """(end, peak) for Popen p started in its own session: end is its exit code, or "timeout" or
    "over" (resident memory past mem bytes), after which its session is killed; peak is the most
    resident memory read across the session, every MEM_POLL seconds."""
    deadline, peak = None if timeout is None else time.monotonic() + timeout, 0
    while True:
        wait = MEM_POLL if deadline is None else max(0, min(MEM_POLL, deadline - time.monotonic()))
        try:
            return p.wait(timeout=wait), peak
        except subprocess.TimeoutExpired:
            peak = max(peak, session_rss(p.pid))
            end = "over" if mem is not None and peak > mem else "timeout" if deadline and time.monotonic() >= deadline else None
            if end:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
                return end, peak


MEM_POLL = 0.25  # seconds between memory reads: about 50 MB of growth at the 200 MB/s seen on #5011


def session_rss(sid):
    """Resident bytes of every process in session sid (a test binary and its children), from
    /proc; 0 where there is no /proc (macOS), so the cap there is the timeout alone."""
    total = 0
    try:
        pids = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return 0
    for pid in pids:
        try:
            fields = pathlib.Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue  # gone between the listing and the read
        if len(fields) > 21 and fields[3] == str(sid):
            total += int(fields[21]) * PAGE
    return total


PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def available_memory():
    """MemAvailable in bytes, or None where /proc/meminfo does not say (macOS): no cap there."""
    try:
        m = re.search(r"^MemAvailable:\s+(\d+) kB$", pathlib.Path("/proc/meminfo").read_text(), re.M)
    except OSError:
        return None
    return int(m.group(1)) * 1024 if m else None


FAILED = re.compile(rb"^\s*--- FAIL: ([A-Za-z_]\w{0,199})", re.M)


def failed_test(binary):
    """The top-level test that failed first in run_tests' output for binary, or None."""
    try:
        m = FAILED.search(pathlib.Path(binary).with_suffix(".out").read_bytes())
    except OSError:
        return None
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
    began = time.monotonic()
    end, peak = watch(subprocess.Popen([str(base), "-test.failfast", f"-test.coverprofile={profile}"], cwd=pkg_dir,
                                       start_new_session=True), mem=alone_mem)
    if alone_mem and (end == "over" or 2 * peak > alone_mem):
        return None, (f"broker/{pkg}/'s tests hold {peak >> 20} MB before any statement is deleted, more than "
                      f"half the {alone_mem >> 20} MB memory cap of a run, so a cap kill would not show a test failed")
    if end != 0 or not profile.exists():
        return None, f"broker/{pkg}/'s tests fail before any statement is deleted"
    if alone_mem and peak:
        jobs = max(1, min(jobs, alone_mem // (2 * peak)))
    timeout = 3 * (time.monotonic() - began) + 10
    blocks = covered_blocks(profile.read_text())

    def cap(alone):
        return alone_mem if alone or not alone_mem else alone_mem // max(1, jobs)

    def verdict(i, alone):
        """The site's status, its binary when a detected verdict still needs confirming alone, and
        the test that failed."""
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
            status = run_tests(binary, pkg_dir, timeout, mem=cap(alone))
            keep = not alone and status in DETECTED
            return status, binary if keep else None, failed_test(binary)
        finally:
            if not keep:
                shutil.rmtree(work)  # a test binary per site would fill the runner's disk

    statuses = []
    with concurrent.futures.ThreadPoolExecutor(max(1, jobs)) as pool:
        while len(statuses) < len(sites):
            batch = range(len(statuses), min(len(sites), len(statuses) + 4 * jobs))
            results = [verdict(i, True) for i in batch] if jobs <= 1 else list(pool.map(lambda i: verdict(i, False), batch))
            for i, (status, binary, killer) in zip(batch, results):
                if binary is not None:
                    status, killer = run_tests(binary, pkg_dir, timeout, mem=alone_mem), failed_test(binary)
                    shutil.rmtree(binary.parent)
                statuses.append((status, killer))
            if sum(st == "TIMED OUT" for st, _, _ in results) * 2 > len(batch):
                jobs = 1  # each run needs the runner to itself: the rest runs alone, once
    return [mutation(s, *st) for s, st in zip(sites, statuses)], None


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
    added, tests = added_lines(broker_diff(args.git, "HEAD"))
    bad = 0
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
            targets, problem = targets_for(pkg, added, tests, data)
            if not problem and (shard := shard_of(data)) is None:
                problem = f"{dest} records a shard that is not 0 <= index < of <= {MATRIX_MAX}"
            mutants, problem = (None, problem) if problem else deletion_mutants(pkg, targets, tmp, lister, args.jobs, shard)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                bad += 1
                continue
            dest.write_text(json.dumps(add_mutants(data, mutants)))
    return 1 if bad else 0


def read_results(pkgs, root, added, tests, lister):
    """({pkg: (data, targets)}, problems) for each package's shards under root/*/, each rechecked as
    `run` and `delete` check it, with the deletion sites listed here (#4106, #4602), then joined (#4961)."""
    out, problems = {}, []
    for pkg in pkgs:
        # Each mutants job's artifact is its own directory, so a shard named twice (a job writing
        # another's) is refused rather than one copy picked.
        found = sorted(pathlib.Path(root).glob(f"*/{glob.escape(result_name(pkg))}"))
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
        joined, problem = (None, problem) if problem else join_shards(pkg, shards, added, tests, lister)
        if problem:
            problems.append(problem)
            continue
        out[pkg] = joined
    return out, problems


TOTALS = ("mutants_total", "mutants_killed", "mutants_lived", "mutants_not_viable", "mutants_not_covered",
          "statement_deletions")


def join_shards(pkg, shards, added, tests, lister):
    """((data, targets), None) of one package's shards [(file, data)] joined, or (None, problem).
    The shards must agree on K and on the target lines, number 0..K-1 once each, and each must pass
    `run`'s and `delete`'s checks on its own lines and sites with no mutant on another shard's line."""
    seen, targets, sites = {}, None, None
    for f, data in shards:
        if not shape_ok(data):
            return None, f"{f} is not gremlins' files[].mutations[] shape"
        if (shard := shard_of(data)) is None:
            return None, f"{f} records a shard that is not 0 <= index < of <= {MATRIX_MAX}"
        if shard in seen:
            if shard == (0, 1):
                return None, f"{f} and {seen[shard]} are both results for {pkg}: one run gives one result"
            return None, f"{f} and {seen[shard]} are both shard {shard[0]} of {shard[1]} for {pkg}: shards overlap"
        seen[shard] = f
        mine, problem = targets_for(pkg, added, tests, data)
        if problem:
            return None, f"{f} {problem}"
        if targets is None:
            targets = mine
            sites, problem = deletion_sites(pkg, targets, lister)
            if problem:
                return None, f"{f} {problem}"
        elif mine != targets:
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
    added, tests = added_lines(diff)
    pkgs = claimed(diff)
    if not pkgs:
        write_summary(args.summary, "### mutgate\n\nThis diff changes no .go line in a tier-A or tier-B package.\n")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        # The base's lister reads the PR's files as data (go/parser) and runs none of their code (#4602).
        if (lister := build_lister(tmp)) is None:
            return 1
        results, problems = read_results(pkgs, args.dir, added, tests, lister)
    for problem in problems:
        print(f"mutgate: {problem}", file=sys.stderr)
    if problems:
        return 1
    return decide(results, added, tests, args)


def decide(results, added, tests, args):
    """Gate the read results against the PR body's waivers, and write the summary table."""
    waived = waivers(pathlib.Path(args.body).read_text(encoding="utf-8", errors="replace") if args.body else "")
    targets = {pkg: t for pkg, (_, t) in results.items()}
    found = violations(targets, {pkg: survivors_of(d) for pkg, (d, _) in results.items()}, waived)
    tested = {pkg: changed_tests(tests, pkg) for pkg in results if not diff_targets(added, pkg)}
    write_summary(args.summary, summary(results, tested, waived))
    return report_violations(found)


def write_summary(path, text):
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def cell(text):
    """Text from a result or the PR body as one Markdown table cell, never markup."""
    text = re.sub(r"\s+", " ", str(text))[:300]
    return re.sub(r"([\\`*_\[\]<>|#!~&])", r"\\\1", text)


VERDICTS = {"TIMED OUT": "killed (timed out)", "NOT COVERED": "not covered", "NOT VIABLE": "not viable (does not build)"}
ROWS = 2000


def summary(results, tested, waived):
    """One Markdown table of every mutant on a target line, survivors first, and its verdict.
    tested names the changed tests of each test-only package (None: every test)."""
    lines = ["### mutgate", ""]
    rows, used = [], set()
    for pkg, (data, targets) in sorted(results.items()):
        n = sum(len(v) for v in targets.values())
        lines.append(f"- {cell(pkg)}: {n} target lines, " + (
            "the lines the diff changes" if pkg not in tested
            else "the lines every test covers (a change outside one test function)" if tested[pkg] is None
            else "the lines " + cell(", ".join(tested[pkg])) + " cover"))
        for f in data["files"]:
            path = f"broker/{pkg}/{f['file_name']}"
            for m in f.get("mutations") or []:
                if m["line"] not in targets.get(path, ()):
                    continue
                col = m.get("column")
                site = f"{path}:{m['line']}" + (f":{col}" if type(col) is int else "")
                status, reason = m["status"], waived.get((path, m["line"]))
                if status == "LIVED" and reason:
                    used.add((path, m["line"]))
                    rank, verdict = 1, "equivalent: " + cell(reason)
                elif status == "LIVED":
                    rank, verdict = 0, "**LIVED**: no test fails"
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
    if unused := sorted(set(waived) - used):
        lines += ["", "Mutant-equivalent lines naming no surviving mutant on a target line: "
                  + ", ".join(cell(f"{p}:{n}") for p, n in unused)]
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
    live = survivors(args.dir)
    for pkg, items in live.items():
        print(f"{pkg}: {len(items)} surviving")
        for fname, line, kind in items:
            print(f"  {fname}:{line} {kind}")
    return 0


def broker_diff(base, head):
    return subprocess.run(
        # --text: a `-diff` .gitattributes line would otherwise hide a file's lines as binary.
        # The prefix, colour, external-diff, textconv and rename options pin the format: git config such as diff.noprefix,
        # color.ui=always, diff.external a diff.<driver>.textconv or diff.renames=copies would otherwise hide added lines (#4115).
        ["git", "-c", "core.quotepath=off", "diff", "-U0", "--text", "--src-prefix=a/", "--dst-prefix=b/",
         "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", f"{base}...{head}", "--", "broker"],
        # errors="replace" below: with --text a binary file's bytes are diff lines, and need not be UTF-8.
        cwd=ROOT, capture_output=True, check=True,
    # Bytes decoded here: text=True would turn a lone \r into \n and number the lines wrongly (#4028).
    ).stdout.decode("utf-8", errors="replace")


def cmd_plan(args):
    """The `mutants` matrix (#4961): [{pkg, shard, of}] for each package `claimed` names, K from its
    target lines and deletion sites. It runs the PR's tests (a test-only diff's coverage), so only in
    an untrusted job; K is a schedule, and `verify` checks the shards whatever K is."""
    diff = broker_diff(args.git, "HEAD")
    added, tests = added_lines(diff)
    include, planned = [], {}
    with tempfile.TemporaryDirectory() as tmp:
        if (lister := build_lister(tmp)) is None:
            return 1
        for pkg in claimed(diff):
            targets = diff_targets(added, pkg)
            if not targets:
                names = changed_tests(tests, pkg)
                targets, problem = covered_by(pkg, names, tmp)
                if problem:
                    print(f"mutgate: {problem}", file=sys.stderr)
                    return 1
                # The one coverage run every shard reads (#4970): a run of their own could differ.
                planned[pkg] = coverage_record(names, targets)
            sites, problem = deletion_sites(pkg, targets, lister)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                return 1
            suite, problem = suite_seconds(pkg, tmp) if targets or sites else (0.0, None)
            if problem:
                print(f"mutgate: {problem}", file=sys.stderr)
                return 1
            of = shard_count(targets, sites, suite)
            print(f"mutgate: {pkg}: {sum(map(len, targets.values()))} target lines, {len(sites)} deletion "
                  f"sites, a {suite:.0f} s suite, {of} shard(s)", file=sys.stderr)
            include += [{"pkg": pkg, "shard": i, "of": of} for i in range(of)]
    if not include or len(include) > MATRIX_MAX:
        fix = ("split the PR so each part changes fewer tier-A or tier-B packages" if include
               else "rerun the mutgate workflow")
        print(f"mutgate: {len(include)} shards, not 1 to {MATRIX_MAX} (GitHub's matrix limit): {fix}",
              file=sys.stderr)
        return 1
    if args.targets_out:
        pathlib.Path(args.targets_out).write_text(json.dumps(planned))
    print(json.dumps(include))
    return 0


def cmd_claimed(args):
    pkgs = claimed(broker_diff(args.git, args.head))
    print(json.dumps(pkgs) if args.json else "\n".join(pkgs))
    return 0


def cmd_gate(args):
    """`verify` without its checks, on DIR/<pkg>.json as `run` and `delete` write them (local use)."""
    added, tests = added_lines(broker_diff(args.git, args.head))
    results, bad = {}, 0
    for pkg in sorted(touched(added, tests)):
        try:
            data = json.loads((pathlib.Path(args.dir) / result_name(pkg)).read_text())
        except (OSError, ValueError):
            continue
        targets, problem = targets_for(pkg, added, tests, data)
        if problem:
            print(f"mutgate: {pkg} {problem}", file=sys.stderr)
            bad += 1
            continue
        results[pkg] = (data, targets)
    return decide(results, added, tests, args) or (1 if bad else 0)


def report_violations(found):
    for pkg, path, line, kind in found:
        # A deletion's line is the first added line of its statement, which may start earlier (#4603).
        what = f"deleting the whole statement holding line {line}" if kind == DELETION else kind
        print(f"mutgate: {path}:{line} {what} survives, on a line of package {pkg} that this PR changes or tests")
    if found:
        print("mutgate: add a test that fails when the line changes; if no test can tell, add a line "
              "`Mutant-equivalent: <path>:<line> <reason>` to the PR body for that site")
    return 1 if found else 0


def default_jobs():
    """The CPUs this process may run on (a container's cpuset), not the host's. macOS has no
    os.sched_getaffinity, so there the CPU count stands in (#4672)."""
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("packages")
    p = sub.add_parser("claimed")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("head", nargs="?", default="HEAD")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("plan")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("--targets-out", metavar="FILE", help="write each test-only package's target lines here")
    p = sub.add_parser("run")
    p.add_argument("pkg", nargs="*")
    p.add_argument("--out", default="mutants")
    p.add_argument("--git", metavar="BASE")
    p.add_argument("--shard", type=int, default=0, metavar="I")
    p.add_argument("--of", type=int, default=1, metavar="K")
    p.add_argument("--targets", metavar="FILE", help="plan's --targets-out file: a test-only package's lines")
    p = sub.add_parser("delete")
    p.add_argument("pkg", nargs="+")
    p.add_argument("--out", default="mutants")
    p.add_argument("--git", required=True, metavar="BASE")
    p.add_argument("--jobs", type=int, default=default_jobs(), metavar="N")
    p = sub.add_parser("report")
    p.add_argument("dir")
    for name in ("gate", "verify"):
        p = sub.add_parser(name)
        p.add_argument("dir")
        p.add_argument("--git", required=True, metavar="BASE")
        p.add_argument("head", nargs="?", default="HEAD")
        p.add_argument("--body", metavar="FILE", help="the PR body, read as text for Mutant-equivalent lines")
        p.add_argument("--summary", metavar="FILE", help="append the table of verdicts here")
    args = ap.parse_args(argv)
    if args.cmd == "run" and (not 0 <= args.shard < args.of <= MATRIX_MAX or (args.of > 1 and not args.git)):
        ap.error(f"--shard I --of K needs 0 <= I < K <= {MATRIX_MAX}, and --git when K > 1")
    if args.cmd == "packages":
        print("\n".join(gated_packages()))
        return 0
    return {"claimed": cmd_claimed, "plan": cmd_plan, "run": cmd_run, "delete": cmd_delete, "report": cmd_report, "gate": cmd_gate,
            "verify": cmd_verify}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
