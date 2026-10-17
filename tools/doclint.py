#!/usr/bin/env python3
"""Checks that the operating documents stay consistent (BOARD row DOC-2).

  README.md     the Documents table lists every top-level and docs/ markdown file, and every
                file it links exists
  rule files    no /mnt paths (local paths of one machine, unreadable by other agents)
  all *.md      `OPERATING §N` references name a section docs/OPERATING.md has
  reviews/      every file in a lens directory is a README or has a dated name; each record dated
                RECORD_FROM or later has a `Record:` line directly under its title (PR, package,
                head or main SHA)
  DECISIONS.md  a Decision cell over 300 characters links decisions/D-NNN.md (D-056); links resolve
  ASSUMPTIONS   no row ID appears twice in one ASSUMPTIONS.md; a new row's ID is package-scoped (tools/assumptions_ids.py)
  briefs/       each brief within the 20k-token cap (CLAUDE.md, Budget), as characters / 4, and
                none keeps its own `**State:**` line (state lives on the work-item issue), and each
                has an `**Acceptance tests:**` line unless listed in tools/brief_acceptance_baseline.txt
                (FIRST-PASS, #1818)

BOARD.md is generated from the work-item issues (tools/board.py), so its rows are checked there, not here.

Usage: python3 tools/doclint.py [repo root]. Prints one line per problem; exits 1 if any.
"""
import pathlib
import re
import subprocess
import sys

import assumptions_ids


RULE_FILES = ("CLAUDE.md", "AGENTS.md", "README.md", "docs/OPERATING.md", "docs/LANES.md")
BRIEF_TOKENS = 20_000
OPERATING_REF = re.compile(r"OPERATING(?:\.md)?\s*§\s*(\d+)(?:\s*[–-]\s*(\d+))?")
RECORD_FROM = "2026-10-09"
DECISION_CHARS = 300
LONG_DECISION_OK = ("D-062", "D-087", "D-088", "D-089")  # over 300 characters, no link yet (LATER DOC-7 f1)
STATE_LINE = re.compile(r"^\*\*State:\*\*")
RECORD_FILE = re.compile(r"(\d{4}-\d\d-\d\d)-.+\.md$")
RECORD_FIELDS = (re.compile(r"\bPRs? (?:#\d+|none)\b"), re.compile(r"\bpackages? \S"),
                 re.compile(r"\b(?:heads?|main) [0-9a-f]{7,40}\b"))
LINK = re.compile(r"\]\(([^)#\s]+)")


def readme(root):
    text = (root / "README.md").read_text()
    section = text.split("## Documents", 1)[-1].split("\n## ", 1)[0]
    listed = set(LINK.findall(section))
    docs = [p.name for p in root.glob("*.md")] + [f"docs/{p.name}" for p in (root / "docs").glob("*.md")]
    for doc in sorted(docs):
        if doc != "README.md" and doc not in listed:
            yield f"README.md: Documents table does not list {doc}"
    for link in sorted(listed):
        if "://" not in link and not (root / link).exists():
            yield f"README.md: Documents table links missing {link}"


def rule_files(root):
    for name in RULE_FILES:
        path = root / name
        if path.is_file():
            for n, line in enumerate(path.read_text().splitlines(), 1):
                if "/mnt/" in line:
                    yield f"{name}:{n}: /mnt path; cite a repository file instead"


def operating_refs(root, files):
    sections = {int(m) for m in re.findall(r"^## (\d+)\.", (root / "docs/OPERATING.md").read_text(), re.M)}
    for name in files:
        for n, line in enumerate((root / name).read_text().splitlines(), 1):
            for m in OPERATING_REF.finditer(line):
                for num in filter(None, m.groups()):
                    if int(num) not in sections:
                        yield f"{name}:{n}: OPERATING §{num} does not exist"


ACCEPTANCE_LINE = re.compile(r"^\s*(?:[-*]\s*)?\*\*Acceptance tests?:?\*\*(.*)$", re.M)
LIST_ITEM = re.compile(r"^(\s*)(?:[-*+]|\d+[.)])\s+\S")


def acceptance_named(text, line):
    """True when the marker line has text after it, or a list item follows it (OPERATING §5: a line or list)."""
    if line.group(1).strip().strip(":").strip():
        return True
    rest = [l for l in text[line.end():].splitlines() if l.strip()]
    item = LIST_ITEM.match(rest[0]) if rest else None
    if not item:
        return False
    own = line.group(0).splitlines()[-1]  # the match can start on blank lines before the marker
    marker = LIST_ITEM.match(own) or re.match(r"^(\s*)[-*]\s*\*\*", own)
    # A marker that is itself a list item needs a nested (more indented) list, not the next sibling.
    return not marker or len(item.group(1)) > len(marker.group(1))


def brief_baseline(root):
    f = root / "tools" / "brief_acceptance_baseline.txt"
    return set(f.read_text().split()) if f.is_file() else set()


def briefs(root):
    legacy = brief_baseline(root)
    for name in sorted(legacy):
        if not (root / "briefs" / name).is_file():
            yield f"tools/brief_acceptance_baseline.txt: {name} has no brief; delete the entry (the baseline only shrinks)"
    for path in sorted((root / "briefs").glob("*.md")):
        text = path.read_text()
        line = ACCEPTANCE_LINE.search(text)
        named = bool(line) and acceptance_named(text, line)
        if path.name in legacy and named:
            yield f"tools/brief_acceptance_baseline.txt: {path.name} now has its acceptance tests; delete the entry (the baseline only shrinks)"
        elif path.name not in legacy and not line:
            yield f"briefs/{path.name}: no `**Acceptance tests:**` line; name each ID's test up front, or `none: <why>`"
        elif line and not named:
            yield f"briefs/{path.name}: empty `**Acceptance tests:**` line; name each ID's test, or `none: <why>`"
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if STATE_LINE.match(line):
                yield f"briefs/{path.name}:{n}: `**State:**` line; state lives on the work-item issue"
        tokens = len(path.read_text()) // 4
        if tokens > BRIEF_TOKENS:
            yield f"briefs/{path.name}: ~{tokens} tokens, over the {BRIEF_TOKENS} cap; split the package"


def lens_files(root):
    """Markdown files in reviews/<lens>/, tracked ones when root is a git checkout."""
    try:
        out = subprocess.run(["git", "ls-files", "reviews/*/*.md"], cwd=root, capture_output=True, text=True,
                             check=True).stdout.split()
        return sorted(root / f for f in out if (root / f).is_file())
    except (OSError, subprocess.CalledProcessError):
        pass
    return sorted((root / "reviews").glob("*/*.md"))


def records(root):
    for path in lens_files(root):
        rel = f"reviews/{path.parent.name}/{path.name}"
        if path.name == "README.md":
            continue
        m = RECORD_FILE.match(path.name)
        if not m:
            yield f"{rel}: lens record names start `YYYY-MM-DD-`"
            continue
        if m.group(1) < RECORD_FROM:
            continue
        lines = [l for l in path.read_text().splitlines() if l.strip()]
        complete = [l for l in lines if l.startswith("Record:") and all(f.search(l) for f in RECORD_FIELDS)]
        title = next((i for i, l in enumerate(lines) if l.startswith("# ")), 0)  # a Verdict line may precede it
        if complete and lines[title + 1:title + 2] == complete[:1]:
            continue
        if complete:
            yield f"{rel}: put the `Record:` line directly under the title (OPERATING §4 step 3)"
        else:
            yield (f"{rel}: no complete `Record:` line; needs `PR #N` or `PR none`, `package <ID>`, "
                   "`head <7–40 lowercase hex>` (or `main <hex>`), e.g. `Record: PR #400 · package DOC-4 · head a74ee45`")


def decisions(root):
    path = root / "DECISIONS.md"
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
        if len(cells) < 4 or not re.fullmatch(r"D-\d+", cells[0]):
            continue
        for link in LINK.findall(cells[3]):
            if link.startswith("decisions/") and not (root / link).is_file():
                yield f"DECISIONS.md: {cells[0]}: links missing {link}"
        if len(cells[3]) > DECISION_CHARS and f"(decisions/{cells[0]}.md)" not in cells[3] \
                and cells[0] not in LONG_DECISION_OK:
            yield (f"DECISIONS.md: {cells[0]}: Decision cell is {len(cells[3])} characters; "
                   f"keep it to {DECISION_CHARS} or link decisions/{cells[0]}.md (D-056)")


def assumption_ids(root, files):
    for name in files:
        if name != "DECISIONS.md" and pathlib.PurePosixPath(name).name != "ASSUMPTIONS.md":
            continue
        seen, in_table = {}, False
        for n, line in enumerate((root / name).read_text().splitlines(), 1):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not line.startswith("|"):
                in_table = False
            elif cells[0] in ("ID", "#"):
                in_table = True
            elif in_table and not set(cells[0]) <= set("-: "):
                if cells[0] in seen:
                    yield f"{name}:{n}: duplicate ID {cells[0]} (first on line {seen[cells[0]]})"
                else:
                    seen[cells[0]] = n


def markdown_files(root):
    try:
        out = subprocess.run(["git", "ls-files", "*.md"], cwd=root, capture_output=True, text=True, check=True).stdout
        return [f for f in out.splitlines() if (root / f).is_file()]
    except (OSError, subprocess.CalledProcessError):
        return [str(p.relative_to(root)) for p in root.rglob("*.md")]


def lint(root):
    root = pathlib.Path(root)
    files = markdown_files(root)
    return [*readme(root), *rule_files(root), *operating_refs(root, files),
            *briefs(root), *records(root), *decisions(root), *assumption_ids(root, files),
            *assumptions_ids.check(root, files)]


def baseline_growth(root, base_file):
    """Baseline entries the PR added to the list in base_file (the base branch's copy)."""
    base = set(pathlib.Path(base_file).read_text().split()) if pathlib.Path(base_file).is_file() else set()
    for name in sorted(brief_baseline(pathlib.Path(root)) - base):
        yield f"tools/brief_acceptance_baseline.txt: {name} is new in the baseline; the baseline only shrinks, so name the brief's acceptance tests instead"


def main(argv):
    args = argv[1:]
    base = None
    if "--base-baseline" in args:
        i = args.index("--base-baseline")
        if i + 1 >= len(args):
            print("usage: doclint.py [ROOT] [--base-baseline FILE]", file=sys.stderr)
            return 2
        base = args[i + 1]
        del args[i:i + 2]
    root = args[0] if args else pathlib.Path(__file__).resolve().parent.parent
    problems = [*lint(root), *(baseline_growth(root, base) if base else [])]
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
