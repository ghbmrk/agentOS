#!/usr/bin/env python3
"""Every test module that reads a record file is on ci.yml's records-only step (CI-docs, CI-PATHS).

A records-only change can edit any record file (tools/ci_scope.is_record), and the records step
runs a fixed test list, so every test whose outcome rests on a record must be on that list. Full
CI's unit tests run each tests/test*.py module in its own process tree under `strace -f -y`,
which records every file opened anywhere in that tree, whatever the program (Python and its
children, sh, git, Go), and the file each open reached. `records_audit.py DIR` then fails unless
the records step lists whole each module whose tree opened a record file (by any name: a symlink
counts as its target), a directory of records, or anything in the git object store (`git diff`,
`show` and `cat-file` read records from there). The module is the unit: a read at import, in a
fixture, or cached by one test and used by another is covered alike. A module with no trace, or
whose trace does not show its own file opened and the top process exiting (tracing did not run
or was cut short), fails too; a module run in shards (tools/unit_tests.py SPLIT) is read from
every shard's trace, and each must show both.
Not seen: a stat or existence check that opens nothing; a hard link to a record; an io_uring
open or open_by_handle_at; a read by a process outside the tree that a test talks to (a daemon).
"""
import os
import re
import sys

import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir, "tools"))
import unit_tests  # noqa: E402  (which modules run as shards, each with its own trace)

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
TESTS = os.path.join(ROOT, "tests")
# An strace -f -y line for open/openat/openat2: pid, the directory fd's path, the path argument,
# the rest; a successful open ends `= N</file it reached>`, and a call split by another
# process's ends in `<unfinished ...>`, its result on a later `<... openat resumed>` line.
_OPEN = re.compile(r'^\d+\s+open(?:at2?)?\((?:[A-Z_\d]+<([^>]*)>, )?"((?:[^"\\]|\\.)*)"(.*)$')
_RESUMED = re.compile(r'^\d+\s+<\.\.\. open(?:at2?)? resumed>')
_REACHED = re.compile(r'\) = \d+<([^>]*)>$')


def records_run_tests(text=None):
    """The test names ci.yml's records-only step runs. Fails, rather than returning a partial
    list, unless exactly one records-only step runs `python -m unittest` on names, with no option
    but -v: any other option (-k, -p) could keep a listed test from running."""
    if text is None:
        with open(os.path.join(ROOT, ".github", "workflows", "ci.yml")) as f:
            text = f.read()
    lines = text.splitlines()
    steps = [i for i, l in enumerate(lines) if l.strip() == "if: env.RECORDS == 'true'"]
    runs = []
    for i in steps:
        indent = len(lines[i]) - len(lines[i].lstrip())
        end = next((j for j in range(i + 1, len(lines))
                    if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) < indent), len(lines))
        key = next((j for j in range(i + 1, end) if lines[j].startswith(" " * indent + "run:")), None)
        if key is None:
            continue
        # The run value: inline, a block scalar, or a plain scalar continued on deeper lines.
        value = [lines[key].split(":", 1)[1]] + [l for l in lines[key + 1:end]
                                                 if len(l) - len(l.lstrip()) > indent or not l.strip()]
        words = " ".join(value).replace("\\", " ").split()
        if words[:1] in (["|"], [">"], ["|-"], [">-"]):
            words = words[1:]
        if words[:3] == ["python", "-m", "unittest"]:
            runs.append(words[3:])
    assert len(runs) == 1, f"want one records-only unittest step in ci.yml, found {len(runs)}"
    names = [w for w in runs[0] if w != "-v"]
    assert names and all(re.fullmatch(r"tests(\.\w+)+", n) for n in names), runs[0]
    return names


def _is_record():
    spec = importlib.util.spec_from_file_location("_records_ci_scope", os.path.join(ROOT, "tools", "ci_scope.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    record_dirs = tuple(d.rstrip("/") for d in module.RECORD_DIRS)

    def read(rel, directory):
        if rel == ".git" or rel.startswith(".git/"):
            return True
        if directory and any(rel == d or rel.startswith(d + "/") for d in record_dirs):
            return True
        return module.is_record(rel)
    return read


def opened(trace, root=ROOT):
    """(repo-relative path, opened as a directory) for each open in a strace -f -y log: the file
    the open reached, else (failed or unfinished) the path it asked for. A relative path with no
    directory to resolve it against is returned as is."""
    out = set()

    def add(path, directory):
        rel = os.path.relpath(os.path.normpath(path), root).replace(os.sep, "/")
        if rel != ".." and not rel.startswith("../"):
            out.add((rel, directory))
    for line in trace.splitlines():
        if root not in line and 'open("' not in line:
            continue
        reached = _REACHED.search(line)
        m = _OPEN.match(line)
        if m:
            directory = "O_DIRECTORY" in m.group(3)
            if reached:
                add(reached.group(1), directory)
                continue
            base, path = m.group(1), m.group(2).replace('\\"', '"').replace("\\\\", "\\")
            if os.path.isabs(path):
                add(path, directory)
            elif base is None:
                out.add((path, directory))
            else:
                add(os.path.join(base, path), directory)
        elif reached and _RESUMED.match(line):
            add(reached.group(1), True)  # its flags were on the unfinished line
    return out


def finished(trace):
    """Whether the trace's first process, the module's test run, exited: a trace cut short (strace
    killed, a failed write) ends without it."""
    first = re.match(r"(\d+)\s", trace)
    return bool(first) and re.search(rf"(?m)^{first.group(1)}\s+\+\+\+ exited with \d+ \+\+\+$", trace) is not None


def problems(traces, listed, is_record=None):
    """traces: {module stem: strace text, or a list of them, one per shard}, one per tests/test*.py
    module. Each shard's trace must show the module opened and its run exiting; reads are pooled."""
    is_record = is_record or _is_record()
    out = []
    for stem, texts in sorted(traces.items()):
        texts = [texts] if isinstance(texts, str) else texts
        each = [opened(t) for t in texts]
        paths = set().union(*each)
        if not texts or not all(any(rel == f"tests/{stem}.py" or re.fullmatch(rf"tests/__pycache__/{stem}\.[\w.-]+\.pyc", rel)
                                    for rel, _ in p) for p in each):
            out.append(f"tests.{stem}\tno open of the module's own file: tracing did not run")
            continue
        if not all(finished(t) for t in texts):
            out.append(f"tests.{stem}\tthe trace ends before the module's run exits: it was cut short")
            continue
        if f"tests.{stem}" in listed:
            continue
        for rel, directory in sorted(paths):
            if is_record(rel, directory):
                out.append(f"tests.{stem}\t{rel}")
    return out


def read_trace(trace_dir, unit):
    try:
        with open(os.path.join(trace_dir, unit + ".trace"), errors="surrogateescape") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def main(argv):
    traces = {}
    for name in sorted(os.listdir(TESTS)):
        if name.startswith("test") and name.endswith(".py"):
            stem = name[:-3]
            traces[stem] = [read_trace(argv[1], u) for u in unit_tests.units([stem])]
    found = problems(traces, records_run_tests())
    for p in found:
        print(p)
    if found:
        print("Add these modules, whole, to ci.yml's records-only step (a test that reads a record "
              "must run there).", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
