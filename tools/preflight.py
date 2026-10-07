#!/usr/bin/env python3
"""Check a pull request's trace table against REQ markers.

An ID in the body's Trace table must be a real requirement ID, and must be
marked in a file this PR changes or already marked on the base revision.
A table left empty passes: tooling and docs claim nothing.
An added line that contains a PEM private-key header fails.

CI passes the event payload and the pull_request test-merge parents
(HEAD^1 is the base, HEAD^2 is the branch). Locally:

  python3 tools/preflight.py --body-file pr.md --diff-base origin/main --diff-head HEAD
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import trace as tr  # noqa: E402

ID = re.compile(r"[A-Z]{2,4}-\d+[a-z]?$")
PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
SKIP_SUFFIXES = {".png", ".jpg", ".img", ".iso", ".bin", ".pyc"}


def trace_ids(body):
    """Requirement IDs from the first column of the Trace table only."""
    if not body:
        return []
    body = body.replace("\r\n", "\n")
    # The section runs until the next heading.
    m = re.search(r"(?m)^## Trace\s*$", body)
    if not m:
        return []
    section = body[m.end():]
    nxt = re.search(r"(?m)^## ", section)
    if nxt:
        section = section[:nxt.start()]
    found = []
    for line in section.splitlines():
        if not line.startswith("|") or re.match(r"^\|\s*-+", line):
            continue
        cell = line.strip().strip("|").split("|", 1)[0]
        for part in cell.split(","):
            tok = part.strip().strip("`")
            if ID.match(tok) and tok not in found:
                found.append(tok)
    return found


def markers_in_text(text):
    ids = set()
    for m in tr.MARKER.finditer(text):
        for rid in re.split(r"\s*,\s*", m.group(1)):
            if rid:
                ids.add(rid)
    return ids


def check(claimed, known, marked_in_diff, marked_on_base, added):
    """Return error strings. Empty means pass."""
    errors = []
    for rid in claimed:
        if rid not in known:
            errors.append(f"{rid} is not a requirement ID in SPEC.md")
            continue
        if rid not in marked_in_diff and rid not in marked_on_base:
            errors.append(
                f"{rid} is in the trace table but no changed file marks it, and the base does not either"
            )
    for line in added:
        if PEM.search(line):
            errors.append("added line contains a PEM private key")
            break
    return errors


def _git(args):
    return subprocess.check_output(["git", *args], text=True, errors="replace")


def changed_files(base, head):
    out = _git(["diff", "--name-only", f"{base}...{head}"])
    return [l for l in out.splitlines() if l.strip()]


def added_lines(base, head):
    out = _git(["diff", "-U0", f"{base}...{head}"])
    lines = []
    for line in out.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
    return lines


def markers_at(rev):
    try:
        out = subprocess.check_output(
            ["git", "grep", "-h", "-e", "REQ:", rev, "--", "tests", "spikes", "broker", "src"],
            text=True, errors="replace", stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return set()
        raise
    return markers_in_text(out)


def markers_in_files(paths):
    ids = set()
    for rel in paths:
        path = pathlib.Path(rel)
        if not path.is_file() or path.suffix in SKIP_SUFFIXES:
            continue
        try:
            ids |= markers_in_text(path.read_text(errors="ignore"))
        except OSError:
            continue
    return ids


def body_from_event(path):
    ev = json.loads(pathlib.Path(path).read_text())
    pr = ev.get("pull_request") or {}
    return pr.get("body") or ""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--body", default="")
    ap.add_argument("--body-file", default="")
    ap.add_argument("--event", default="", help="path to a GitHub event payload")
    ap.add_argument("--diff-base", default="")
    ap.add_argument("--diff-head", default="")
    ap.add_argument("--root", default="")
    args = ap.parse_args(argv)

    if args.event:
        body = body_from_event(args.event)
    elif args.body_file:
        body = pathlib.Path(args.body_file).read_text()
    else:
        body = args.body

    root = pathlib.Path(args.root) if args.root else pathlib.Path.cwd()
    spec = root / "SPEC.md"
    if not spec.is_file():
        print("SPEC.md not found", file=sys.stderr)
        return 1
    known = set(tr.spec_ids(spec.read_text()))
    claimed = trace_ids(body)

    if args.diff_base and args.diff_head:
        files = changed_files(args.diff_base, args.diff_head)
        marked_diff = markers_in_files(files)
        marked_base = markers_at(args.diff_base)
        added = added_lines(args.diff_base, args.diff_head)
    else:
        marked_diff, marked_base, added = set(), set(), []

    errors = check(claimed, known, marked_diff, marked_base, added)
    for e in errors:
        print("::error::" + e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
