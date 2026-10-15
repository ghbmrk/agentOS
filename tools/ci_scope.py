#!/usr/bin/env python3
"""CI scope of a change: `records` if it touches only record documents, else `full` (CI-docs).

A records-only change (review records, BOARD and LATER lines, briefs, decisions, the
generated TRACE.md and METRICS.md) leaves every byte of code, tests, tools, workflows,
dependencies and the image as main has them, and main's strict ruleset makes the PR
branch carry main's tip, so main's CI already tested that code. ci.yml then runs only
the document checks (trace, doclint, board, the tests of those tools) and skips the Go,
machine and host jobs; assurance.yml skips its scans. Everything else runs full CI.

The set is deliberately narrow: Markdown files that no build, test or tool executes. A
path outside it, an empty change, or any doubt gives `full`. Contract documents (SPEC.md,
CLAUDE.md, README.md, docs/OPERATING.md) are not records: tests and tools read them.

The workflows run the base commit's copy of this file (`git show BASE:tools/ci_scope.py`),
so a PR cannot widen the set for itself; a PR that edits this file is outside the set and
runs full CI anyway. Standard library only, so that copy runs on its own.

Usage:
  tools/ci_scope.py PATH...            scope of the listed paths
  tools/ci_scope.py --git BASE [HEAD]  scope of `git diff --name-only BASE...HEAD`
Prints `records` or `full` on stdout; on `full`, the first path that forced it on stderr.
"""
import argparse
import subprocess
import sys

# Record files, by exact path.
RECORD_FILES = set({
    "BOARD.md", "LATER.md", "LEDGER.md", "DECISIONS.md", "METRICS.md", "TRACE.md",
    "docs/MARK-QUEUE.md",
})
# Record directories: any `*.md` at any depth below them. Other files there
# (scripts, JSON, HTML) are not records.
RECORD_DIRS = ("reviews/", "decisions/", "briefs/", "handoff/")
# Prose that no build, test or tool reads (CI-PATHS): the top-level guides the doc checks
# (doclint, trace, product-name) already cover in the records run, and `*.md` below these
# directories. Not here, because a test or tool reads them: SPEC.md, CLAUDE.md, AGENTS.md,
# docs/OPERATING.md, docs/LANES.md, docs/owners-guide.md (a Go test), the *-HISTORY files.
RECORD_FILES |= {"README.md", "PLAN.md", "docs/conv-3-triage.md", "docs/conv-5-uncovered.md"}
RECORD_DIRS += ("docs/development/", "docs/learning/", "docs/security/")


def is_record(path):
    if path in RECORD_FILES:
        return True
    parts = path.split("/")
    if "" in parts or "." in parts or ".." in parts:
        return False
    return path.endswith(".md") and path.startswith(RECORD_DIRS)


def scope_of(paths):
    """Return ("records" | "full", first path outside the set or None)."""
    paths = [p for p in paths if p]
    if not paths:
        return "full", None  # nothing changed, or nothing we can see: test everything
    for p in paths:
        if not is_record(p):
            return "full", p
    return "records", None


def changed_paths(base, head):
    # --no-renames lists a moved file under its old path too, so moving broker/x.go to
    # reviews/x.md is full. -z keeps git from quoting unusual names.
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    return out.decode("utf-8", "surrogateescape").split("\0")


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
    return 0


if __name__ == "__main__":
    sys.exit(main())
