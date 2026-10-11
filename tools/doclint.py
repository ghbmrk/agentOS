#!/usr/bin/env python3
"""Checks that the operating documents stay consistent (BOARD row DOC-2).

  BOARD.md      every table row's last cell starts with a state metrics.py counts, and every
                brief it links exists
  README.md     the Documents table lists every top-level and docs/ markdown file, and every
                file it links exists
  rule files    no /mnt paths (local paths of one machine, unreadable by other agents)
  all *.md      `OPERATING §N` references name a section docs/OPERATING.md has
  reviews/      every file in a lens directory is a README or has a dated name; each record dated
                RECORD_FROM or later has a `Record:` line directly under its title (PR, package,
                head or main SHA)
  DECISIONS.md  a Decision cell over 300 characters links decisions/D-NNN.md (D-056); links resolve
  ASSUMPTIONS   no row ID appears twice in one ASSUMPTIONS.md
  BOARD.md      a row added on or after RELEASE_FROM whose state says `release` (or whose package
                says `(release`) names an acceptance test or invariant (D-085, CONV-0-5)
  BOARD.md      no two rows share an ID; no state says `blocked on <ID>` for a merged row
  LATER.md      a Release or Later row's ID is not a merged or dropped BOARD row (shared open IDs and
                finding suffixes such as `X-1 l1` are fine); no text says an ID "has no board row"
                while BOARD has one (DOC-5)
  briefs/       each brief within the 20k-token cap (CLAUDE.md, Budget), as characters / 4, and
                none keeps its own `**State:**` line (BOARD.md is authoritative)

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
DECISION_CHARS = 300
LONG_DECISION_OK = ("D-062", "D-087", "D-088", "D-089")  # over 300 characters, no link yet (LATER DOC-7 f1)
STATE_LINE = re.compile(r"^\*\*State:\*\*")
RECORD_FILE = re.compile(r"(\d{4}-\d\d-\d\d)-.+\.md$")
RECORD_FIELDS = (re.compile(r"\bPRs? (?:#\d+|none)\b"), re.compile(r"\bpackages? \S"),
                 re.compile(r"\b(?:heads?|main) [0-9a-f]{7,40}\b"))
RELEASE_FROM = "2026-10-10"
RELEASE_STATE = re.compile(r"\brelease\b")
RELEASE_CLASS = re.compile(r"\(release\b")
ACCEPTANCE = re.compile(r"\bInvariant\b|\bTest[A-Z]\w+")
SPEC_ID = re.compile(r"\b[A-Z][A-Z0-9]*-\d+[a-z]?\b")
NO_ROW = re.compile(r"(?<![\w-])([A-Z][A-Za-z0-9]*-[A-Za-z0-9]+)\b[^.|\n]{0,80}?\b(?:has|have) no (?:board row|row of its own)")
BLOCKED_ON = re.compile(r"\bblocked on ([A-Z][A-Za-z0-9]*-[A-Za-z0-9]+)(?![\w-])")
LINK = re.compile(r"\]\(([^)#\s]+)")


def board(root):
    text = (root / "BOARD.md").read_text()
    for cells in _rows(text, "| ID |"):
        if not cells[-1].startswith(STATES):
            yield f"BOARD.md: {cells[0]}: state {cells[-1]!r} does not start with one of {', '.join(STATES)}"
        for link in LINK.findall(" ".join(cells)):
            if link.startswith("briefs/") and not (root / link).is_file():
                yield f"BOARD.md: {cells[0]}: links missing {link}"


def contradictions(root):
    """BOARD and LATER claims that contradict each other (DOC-5); merge state from GitHub is DOC-6's."""
    text = (root / "BOARD.md").read_text()
    states, seen = {}, set()
    for cells in _rows(text, "| State |"):
        if cells[0] in seen:
            yield f"BOARD.md: duplicate row ID {cells[0]}"
        seen.add(cells[0])
        states.setdefault(cells[0], cells[-1])
    for cells in _rows(text, "| State |"):
        for target in BLOCKED_ON.findall(cells[-1]):
            if states.get(target, "").startswith("merged"):
                yield f"BOARD.md: {cells[0]}: blocked on {target}, which is merged"
    later = root / "LATER.md"
    for name, body in (("BOARD.md", text), ("LATER.md", later.read_text() if later.is_file() else "")):
        for target in dict.fromkeys(NO_ROW.findall(body)):
            if target in states:
                yield f"{name}: {target} has a BOARD row but the text says it has no board row"
    if later.is_file():
        for cells in _rows(later.read_text(), "| ID |"):
            state = states.get(cells[0], "")
            for done in ("merged", "dropped"):
                if state.startswith(done):
                    yield f"LATER.md: {cells[0]}: the BOARD row is {done}; remove the LATER row"


def board_added(root):
    """{row ID: date of the earliest commit that added it}; None without usable history.
    Every commit is walked and a merge is diffed against its first parent: main's rows first appear at their
    own earlier commit (a plain --first-parent log would date them by a merge of main), and a row born in a
    merge's conflict resolution is dated by the merge."""
    try:
        if _git(root, "rev-parse", "--is-shallow-repository").strip() != "false":
            return None  # a grafted tip would date every row as new
        log = _git(root, "log", "--diff-merges=first-parent", "--reverse", "-p", "--format=%x01%cI", "--", "BOARD.md")
    except (OSError, subprocess.CalledProcessError):
        return None
    added, date = {}, None
    for line in log.splitlines():
        if line.startswith("\x01"):
            date = line[1:]
        elif line.startswith("+| "):
            added.setdefault(line[1:].strip("| ").split(" |")[0].strip(), date)
    return added


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def release_rows(root):
    rows = [c for c in _rows((root / "BOARD.md").read_text(), "| ID |")
            if RELEASE_STATE.search(c[-1]) or RELEASE_CLASS.search(" ".join(c[1:-1]))]
    added = board_added(root) if rows else None
    if not added:
        return
    spec = root / "SPEC.md"
    spec_ids = set(SPEC_ID.findall(spec.read_text())) if spec.is_file() else set()
    for cells in rows:
        when = added.get(cells[0])
        if when is None or when[:10] < RELEASE_FROM:
            continue
        text = " ".join(cells[1:])
        if not (ACCEPTANCE.search(text) or spec_ids & set(SPEC_ID.findall(text))):
            yield (f"BOARD.md: {cells[0]}: a release row added {when[:10]} names no acceptance test or invariant "
                   "(a SPEC requirement ID, `Invariant`, or `TestName`; D-085)")


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
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if STATE_LINE.match(line):
                yield f"briefs/{path.name}:{n}: `**State:**` line; BOARD.md is the only record of state"
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
    return [*board(root), *contradictions(root), *release_rows(root), *readme(root), *rule_files(root), *operating_refs(root, files),
            *briefs(root), *records(root), *decisions(root), *assumption_ids(root, files)]


def main(argv):
    problems = lint(argv[1] if len(argv) > 1 else pathlib.Path(__file__).resolve().parent.parent)
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
