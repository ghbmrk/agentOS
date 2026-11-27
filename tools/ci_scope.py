#!/usr/bin/env python3
"""CI scope of a change: `records`, `race-blind` or `full` (CI-docs, CI-race-scope).

A records-only change (review records, BOARD and LATER lines, briefs, decisions, the
generated TRACE.md and METRICS.md) leaves every byte of code, tests, tools, workflows,
dependencies and the image as main has them, and main's strict ruleset makes the PR
branch carry main's tip, so main's CI already tested that code. ci.yml then runs only
the document checks (trace, doclint, board, the tests of those tools) and skips the Go,
machine and host jobs; assurance.yml skips its scans. Everything else runs full CI.

The set is deliberately narrow: Markdown files whose only readers are checks the records
run itself executes (D29, CI-PATHS), so CLAUDE.md and the other process documents are
records too. A path outside it, an empty change, or any doubt gives `full`: every
non-Markdown file, and any Markdown a Go test, a go:embed or the image reads (for
instance docs/owners-guide.md, and SPEC.md, which broker/browser's test reads).
tests/test_ci_scope.py fails if a Go file names a record path.

The workflows run the base commit's copy of this file (`git show BASE:tools/ci_scope.py`),
so a PR cannot widen the set for itself; a PR that edits this file is outside the set and
runs full CI anyway. Standard library only, so that copy runs on its own.

A change of records and modified files outside RACE_READ alone (and not records alone) is
`race-blind`: every job runs in full except broker-race, which skips its steps as on a
records-only change. RACE_READ is measured, not guessed: broker-race traces every file its tests
and their children reach and fails on a tracked file outside it (tools/race_reads.py, CI-race-scope).

Usage:
  tools/ci_scope.py PATH...            scope of the listed paths
  tools/ci_scope.py --git BASE [HEAD]  scope of `git diff --name-only BASE...HEAD`
Prints `records`, `race-blind` or `full` on stdout; on `full`, the first path that forced it on stderr.
"""
import argparse
import subprocess
import sys

# Record files, by exact path. The last line is CI-PATHS (D29): prose whose readers are
# the doc checks the records run executes (doclint, board, trace, metrics, risk_tier,
# specslice, product-name), plus two orphan notes.
RECORD_FILES = frozenset({
    "BOARD.md", "LATER.md", "LEDGER.md", "DECISIONS.md", "METRICS.md", "TRACE.md",
    "docs/MARK-QUEUE.md",
    "README.md", "PLAN.md", "CLAUDE.md", "AGENTS.md", "docs/OPERATING.md",
    "docs/LANES.md", "docs/BOARD-HISTORY.md", "docs/LATER-HISTORY.md",
    "docs/conv-3-triage.md", "docs/conv-5-uncovered.md",
})
# Record directories: any `*.md` at any depth below them. Other files there
# (scripts, JSON, HTML) are not records.
RECORD_DIRS = ("reviews/", "decisions/", "briefs/", "handoff/",
               "docs/development/", "docs/learning/", "docs/security/")


# CI-race-scope (#6692): the tracked files outside broker/ that broker-race's tests, or anything
# they run, read, as measured: each shard traces its `go test` and fails on a tracked file read
# outside this set (tools/race_reads.py). A trailing "/" is a directory and all below it. A change
# that only modifies files outside it and NEVER_BLIND (and records) is `race-blind`: broker-race
# skips its steps. NEVER_BLIND is never race-blind: the broker, the workflows and actions that run
# the job, and the tools the job runs outside its traced steps.
RACE_READ = (
    "assurance/", "evals/", "guest/", "image/", "spikes/",
    "SPEC.md", "docs/owners-guide.md", "tools/canary.py", "tools/canary_controls.py", "tools/depaudit.py",
    "tools/old_core.txt",
)
NEVER_BLIND = ("broker/", ".github/", ".git/", "tools/ci_scope.py", "tools/ci_split.py",
               "tools/race_reads.py")


def _plain(path):
    parts = path.split("/")
    return not ("" in parts or "." in parts or ".." in parts)


def race_read(path):
    """Whether broker-race's tests read the path, or the job runs it: RACE_READ or NEVER_BLIND."""
    return any(path == e.rstrip("/") or e.endswith("/") and path.startswith(e) for e in (*RACE_READ, *NEVER_BLIND))


def is_race_blind(path, status):
    """A change no broker test can see: a modification (git status M, mode unchanged) of a file
    outside RACE_READ and NEVER_BLIND. An addition, deletion, type or mode change alters a
    directory listing or what a stat shows, which the read audit does not trace, so it is never
    race-blind."""
    return status == "M" and _plain(path) and not race_read(path)


def is_record(path):
    if path in RECORD_FILES:
        return True
    parts = path.split("/")
    if "" in parts or "." in parts or ".." in parts:
        return False
    return path.endswith(".md") and path.startswith(RECORD_DIRS)


def scope_of(paths):
    """Return ("records" | "race-blind" | "full", first path outside the sets or None). Each
    entry is a path, or a (git status letter, path) pair; a bare path has no status, so it is
    never race-blind."""
    changes = [c if isinstance(c, tuple) else (None, c) for c in paths]
    changes = [(s, p) for s, p in changes if p]
    if not changes:
        return "full", None  # nothing changed, or nothing we can see: test everything
    for s, p in changes:
        # A record the read audit found a broker test reading goes into RACE_READ; it then runs
        # full, since a records-only change would skip broker-race, the test that reads it.
        if not (is_record(p) and not race_read(p)) and not is_race_blind(p, s):
            return "full", p
    if all(is_record(p) for _, p in changes):
        return "records", None
    return "race-blind", None


def changed_paths(base, head):
    """(status letter, path) for each change; a modification that also changes the file's mode
    is "X", never "M". --no-renames lists a moved file under its old path too, so moving
    broker/x.go to reviews/x.md is full. -z keeps git from quoting unusual names."""
    out = subprocess.run(
        ["git", "diff", "--raw", "-z", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    f = out.decode("utf-8", "surrogateescape").split("\0")
    if f and f[-1] == "":
        f.pop()
    if len(f) % 2:
        raise OSError(f"git diff --raw -z printed {len(f)} fields")
    got = []
    for i in range(0, len(f), 2):
        meta = f[i].split(" ")
        if len(meta) != 5 or not meta[0].startswith(":") or not meta[4]:
            raise OSError(f"git diff --raw -z printed {f[i]!r}")
        status = meta[4][:1]
        got.append(("X" if status == "M" and meta[0][1:] != meta[1] else status, f[i + 1]))
    return got


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--git", nargs="+", metavar="REF")
    a = ap.parse_args(argv)
    try:
        paths = changed_paths(a.git[0], a.git[1] if len(a.git) > 1 else "HEAD") if a.git else a.paths
    except (OSError, subprocess.CalledProcessError) as e:
        print("full")
        print(f"ci_scope: cannot list the change ({e}); full CI", file=sys.stderr)
        return 0
    scope, why = scope_of(paths)
    print(scope)
    if why:
        print(f"ci_scope: {why} is not a record document; full CI", file=sys.stderr)
    elif scope == "full":
        print("ci_scope: empty change; full CI", file=sys.stderr)
    elif scope == "race-blind":
        print("ci_scope: records and files no broker test reads; full CI but broker-race", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
