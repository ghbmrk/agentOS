#!/usr/bin/env python3
"""Checks that the operating documents stay consistent (BOARD row DOC-2).

  BOARD.md      every table row's last cell starts with a state metrics.py counts, and every
                brief it links exists
  README.md     the Documents table lists every top-level and docs/ markdown file, and every
                file it links exists
  rule files    no /mnt paths (local paths of one machine, unreadable by other agents)
  all *.md      `OPERATING §N` references name a section docs/OPERATING.md has
  reviews/      each record dated RECORD_FROM or later has a `Record:` line (PR, package, head SHA)
  ASSUMPTIONS   no row ID appears twice in one ASSUMPTIONS.md
  briefs/       each brief within the 20k-token cap (CLAUDE.md, Budget), as characters / 4

Usage: python3 tools/doclint.py [repo root]. Prints one line per problem; exits 1 if any.
"""
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from metrics import STATES, _rows  # noqa: E402

RULE_FILES = ("CLAUDE.md", "AGENTS.md", "README.md", "BOARD.md", "docs/OPERATING.md", "docs/LANES.md")
BRIEF_TOKENS = 20_000
OPERATING_REF = re.compile(r"OPERATING(?:\.md)?\s*§\s*(\d+)(?:\s*[–-]\s*(\d+))?")
RECORD_FROM = "2026-10-09"
RECORD_DIRS = ("ux", "potency", "security", "combined", "arbitration")
RECORD_FILE = re.compile(r"(\d{4}-\d\d-\d\d)-.+\.md$")
RECORD_FIELDS = (re.compile(r"\bPRs? (?:#\d+|none)\b"), re.compile(r"\bpackages? \S"),
                 re.compile(r"\bheads? [0-9a-f]{7,40}\b"))
LINK = re.compile(r"\]\(([^)#\s]+)")


def board(root):
    text = (root / "BOARD.md").read_text()
    for cells in _rows(text, "| ID |"):
        if not cells[-1].startswith(STATES):
            yield f"BOARD.md: {cells[0]}: state {cells[-1]!r} does not start with one of {', '.join(STATES)}"
        for link in LINK.findall(" ".join(cells)):
            if link.startswith("briefs/") and not (root / link).is_file():
                yield f"BOARD.md: {cells[0]}: links missing {link}"


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


def briefs(root):
    for path in sorted((root / "briefs").glob("*.md")):
        tokens = len(path.read_text()) // 4
        if tokens > BRIEF_TOKENS:
            yield f"briefs/{path.name}: ~{tokens} tokens, over the {BRIEF_TOKENS} cap; split the package"


def records(root):
    for lens in RECORD_DIRS:
        for path in sorted((root / "reviews" / lens).glob("*.md")):
            m = RECORD_FILE.match(path.name)
            if not m or m.group(1) < RECORD_FROM:
                continue
            lines = [l for l in path.read_text().splitlines() if l.startswith("Record:")]
            if not any(all(f.search(l) for f in RECORD_FIELDS) for l in lines):
                yield f"reviews/{lens}/{path.name}: no `Record: PR #N · package ID · head SHA` line"


def assumption_ids(root, files):
    for name in files:
        if pathlib.PurePosixPath(name).name != "ASSUMPTIONS.md":
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
    return [*board(root), *readme(root), *rule_files(root), *operating_refs(root, files),
            *briefs(root), *records(root), *assumption_ids(root, files)]


def main(argv):
    problems = lint(argv[1] if len(argv) > 1 else pathlib.Path(__file__).resolve().parent.parent)
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
