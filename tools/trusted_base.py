#!/usr/bin/env python3
"""Size of the trusted base on a PR: own lines, dependency lines, parsers (SPEC KRN-2, #2849).

The trusted processes are the binaries named by the `wiring cmd/<name>` lines of
broker/core/core.txt, read from each tree. Their linked packages come from `go list -deps`
under the image's build settings (CGO_ENABLED=0, linux/amd64, vendored modules); `go list`
only reads the tree, so a PR's code is listed, never built or run.

  own lines   compiled files (no _test.go) of linked packages in the broker module
  dep lines   the same over linked packages outside the broker module and the standard
              library (vendored modules and third_party/ replacements)
  parsers     linked packages that tools/trusted_base_parsers.txt classes `parser`

Every linked package outside the standard library must match a registry line, so no package
enters a trusted process unclassified. Own and dependency lines are reported, not gated: the
keeper domain's growth is gated by the trusted core below (D-157). A PR whose head adds a
parser package or reclassifies a parser as inert fails unless it adds a line
`<parsers|registry> #<PR> -- <reason>` to tools/trusted_base_reasons.txt. It is a measure, not a cap.
The reason is a committed line, not PR-body text (#6395): a body can change after the reviews without
changing the head, while the record is part of the head every accept names. A line counts only for
the PR it names and only when the base lacks it, so an old line never waives later growth. The
decision waivers below are record lines too (#6404), so `check` reads no PR body at all.

The trusted core (KRN-2cap, #2935) is the budgeted subset: the `root` packages of
tools/trusted_core.txt (kernel, key-check library, the clerk check path) and everything they
link. Its lines are every linked package's outside the standard library and the `allow` lines,
each one exact package from golang.org/x/crypto or golang.org/x/sys (a subtree would let a new
package or a vendored file under it in at +0). Every such package other than a root must have a
`known` line, so a new import fails whatever the record says, and a `known` line the core no longer
links must be deleted. Against the base tree's file, a head that adds a `known` or `allow` line,
drops a root or deletes the file fails unless the head adds a record line
`trusted-core #<PR> -- <decision ID>` naming an active DECISIONS.md row of the base tree whose text
names the PR (`#<number>`, from --pr), so neither a row added by the PR itself nor an unrelated
standing row can waive it; the
reviewer checks that the row records Mark approving it (#2945). Core lines are reported here and
capped by the ceilings below, not waived per PR (D-310 ends D-159's rule 2).

The ceilings (D-310) are tools/ceilings.txt: trusted lines (core lines plus the old core's Go
lines, tools/old_core.txt) and SPEC.md's words. A measure fails when it ends above the base's
ceiling and above the base's measure, and names the cut that passes; raising a ceiling or deleting
the file needs a record line `ceiling #<PR> -- <decision ID>` naming an active base-tree row that
names the PR.
In CI the base tree is the base branch's tip when the check runs (not the event's base.sha) and
the head tree is the PR head merged onto it, so the budget is what main holds now and the
measure is exactly what lands: a branch that cherry-picks main's cuts instead of merging main
gains nothing. It ratchets down on every merge with nothing to keep in step. A base tree with
no core file (one older than the file) is measured, with the head, by the file of the checkout
the tool runs from, which is the base branch tip in CI.

A check passed against an older main goes stale when main changes (CI-ceiling-fall): N PRs that
each fit the headroom would all stay green and land main up to (N-1) times it over. On every push
to main the trusted-base-rerun workflow reruns every open PR's newest trusted-base run, which then
measures that PR merged onto the new main. It reruns on every push, not only when main's measure
grows, because a push that shrinks main can still raise another PR's merged measure (an identical
cut both make, or a package one drops that the other links; L3 on #5179). PRs that merge within one
rerun's latency can still land together; main is then over the ceiling and may not grow.

A decision that records trusted-core growth under D-159 carries the measure as this tool prints
it (REV-PROOF-claims, #4909): `measure --sentence BASE HEAD --pr N` prints the one sentence, and
`claims` fails a PR that adds such a decision (a DECISIONS.md row or a decisions/D-*.md file whose
ID the base lacks, citing D-159 and saying "trusted-core growth") unless every sentence in it is
this tool's output for the PR it names, measured from that PR head's merge base with the base
tree's commit to the head. Every `PR #N` a decision names needs a sentence for #N, and a PR
already merged into the base fails (its measure would read +0). BASE is the merge base:
  git fetch origin pull/N/head && tools/trusted_base.py measure --sentence \\
      "$(git merge-base origin/main FETCH_HEAD)" FETCH_HEAD --pr N Rows #4862
hand-wrote "no new linked packages" over a measured +1; text the tool computes is not typed.

Usage:
  tools/trusted_base.py measure [--tree DIR]       print one tree's measure; exit 1 if a package is unclassified
  tools/trusted_base.py measure --sentence BASE HEAD --pr N [--tree REPO]
      print the canonical measure sentence for the commits BASE (the PR head's merge base with
      origin/main) and HEAD (the PR head) of the repository at REPO
  tools/trusted_base.py claims --base-tree DIR --head-tree DIR --repo REPO [--onto REV] [--fetch REMOTE] [--markdown FILE]
      check the measure sentences of the D-159 decisions the head adds; each named PR's head is
      refs/remotes/pr/<N> in REPO (fetched from REMOTE's refs/pull/<N>/head with --fetch). Exit 0
      pass, 1 a missing or wrong sentence, 2 a measurement or fetch error.
  tools/trusted_base.py check --base-tree DIR --head-tree DIR --pr N [--markdown FILE]
      the registry is the head tree's; the base tree's registry is read only to find
      reclassified parsers. Exit 0 pass, 1 growth without a reason or an unclassified
      package, 2 a measurement error.
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

REGISTRY = "tools/trusted_base_parsers.txt"
REASONS = "tools/trusted_base_reasons.txt"
CORE = "tools/trusted_core.txt"
FALLBACK = pathlib.Path(__file__).resolve().parent.parent  # the checkout this copy runs from
CORE_LIST = "broker/core/core.txt"
KEYS = ("parsers", "registry", "trusted-core", "ceiling")
# The keys whose reason is a decision: its first word names a base-tree DECISIONS.md row (#6404).
DECIDED = ("trusted-core", "ceiling")
GO_ENV = {
    "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "-mod=vendor",
    "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOENV": "off",
}
RECORD_LINE = re.compile(r"^(\S+)\s+#([1-9]\d*)\s+--\s+(.*?)\s*$")
CEILINGS = "tools/ceilings.txt"
OLD_CORE = "tools/old_core.txt"
SPEC = "SPEC.md"
CEILING_NAMES = ("trusted-lines", "spec-words")
PLACEHOLDER = re.compile(r"(?i)^(todo|tbd|n/?a|none|reason|-+|\.+)$")


class MeasureError(Exception):
    pass


SENTENCE = ("trusted-base measure of #{pr}: core lines {base} to {head} ({delta:+d}) from merge base {base_sha}"
            " to head {head_sha}, new linked packages: {new}")
SENTENCE_PR = re.compile(r"trusted-base measure of #(\d+):")
# A sentence ends at the end of the text, a closing bracket, `;`, a table bar, a line end, or a
# full stop before a space: so "packages: none" cannot pass inside "packages: none, broker/x".
SENTENCE_END = re.compile(r"$|[ \t]*[);|]|\n|\.(?:\s|$)")
CLAIM_ROW = re.compile(r"^\|\s*(D-\d+)\s*\|")
NAMED_PR = re.compile(r"\bPR #(\d+)(?!\d)")
GROWTH = re.compile(r"(?i)trusted-core growth")


def list_lines(text, where):
    """(number, line) for each "\n"-separated line of a list file, refusing any character outside
    printable ASCII: splitlines() also ends a line at "\r", U+2028 and others, so a break hidden in
    a comment would make a line mean other than it shows (REV-CHK-crlf, #3902)."""
    for n, line in enumerate(text.split("\n"), 1):
        bad = [c for c in line if not " " <= c <= "~"]
        if bad:
            raise MeasureError(f"{where}:{n}: character {bad[0]!r} outside printable ASCII")
        yield n, line


def tree_file(tree, rel):
    """tree/rel, or None when absent. A symlink at any step below tree, or a file that is not a
    regular file, is refused (#6406): CI checks the PR's tree out under pull_request_target, and a
    committed symlink would have this tool read and echo a runner file as one of the PR's own."""
    path = no_symlink_steps(tree, rel, "a committed regular file")
    if not path.exists():
        return None
    if not path.is_file():
        raise MeasureError(f"{path}: not a regular file")
    return path


def no_symlink_steps(tree, rel, what):
    """tree/rel, refusing a symlink at any step below tree."""
    path = pathlib.Path(tree)
    for part in pathlib.PurePosixPath(rel).parts:
        path = path / part
        if path.is_symlink():
            raise MeasureError(f"{path}: a symlink; {rel} is read only as {what}")
    return path


def no_symlinks_under(tree, rel):
    """tree/rel with no symlink at a step or anywhere below it, dangling or not (#6477 L3). `go list`
    and the line counts read every file there, and a parse error quotes a symlinked runner file's
    first token into the job summary, so the whole directory is refused before anything reads it."""
    root = no_symlink_steps(tree, rel, "committed regular files")
    for d, dirs, files in os.walk(root):  # does not follow a symlinked directory; lists it in dirs
        for name in sorted(dirs + files):
            if os.path.islink(os.path.join(d, name)):
                raise MeasureError(f"{os.path.join(d, name)}: a symlink; {rel}/ is read only as committed regular files")
    return root


def broker_dir(tree):
    """The tree's broker/, resolved, once no_symlinks_under has passed it."""
    no_symlinks_under(tree, "broker")
    return pathlib.Path(tree).resolve() / "broker"


def read_list(tree, rel):
    """A list file's text, line ends untranslated (read_text() turns "\r" into "\n"); None when absent."""
    path = tree_file(tree, rel)
    return None if path is None else path.read_bytes().decode("utf-8", "replace")


def trusted_mains(tree):
    """The `wiring cmd/<name>` lines of the tree's core list, as ./cmd/<name>."""
    path = pathlib.Path(tree) / CORE_LIST
    try:
        text = read_list(tree, CORE_LIST)
    except OSError as e:
        raise MeasureError(f"cannot read {path}: {e}")
    if text is None:
        raise MeasureError(f"cannot read {path}: missing")
    mains = []
    for _, line in list_lines(text, path):
        w = line.split("#", 1)[0].split()
        if len(w) == 2 and w[0] == "wiring" and w[1].startswith("cmd/"):
            mains.append("./" + w[1])
    if not mains:
        raise MeasureError(f"{path} names no `wiring cmd/...` binary")
    return sorted(set(mains))


def module_path(broker):
    for line in (broker / "go.mod").read_text().splitlines():
        w = line.split()
        if len(w) == 2 and w[0] == "module":
            return w[1]
    raise MeasureError(f"{broker / 'go.mod'} has no module line")


def go_list(broker, mains):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GO") and k != "CGO_ENABLED"}
    env.update(GO_ENV)
    cmd = ["go", "list", "-deps", "-json=ImportPath,Standard,Module,Dir,GoFiles,CgoFiles,SFiles,Error,DepsErrors"]
    r = subprocess.run(cmd + mains, cwd=broker, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise MeasureError(f"go list failed in {broker}: {r.stderr.strip()[-2000:]}")
    dec, text, i, pkgs = json.JSONDecoder(), r.stdout, 0, []
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            return pkgs
        obj, i = dec.raw_decode(text, i)
        if obj.get("Error") or obj.get("DepsErrors"):
            raise MeasureError(f"go list: {obj['ImportPath']}: {obj.get('Error') or obj.get('DepsErrors')}")
        pkgs.append(obj)


def count_lines(path):
    with open(path, "rb") as f:
        data = f.read()
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def packages(tree, targets=None):
    """{import path: (kind, lines)} with kind own, dep or std, for the tree's trusted processes
    (or for `targets`, ./<dir> paths under broker/)."""
    broker = broker_dir(tree)
    own_mod = module_path(broker)
    out = {}
    for p in go_list(broker, targets or trusted_mains(tree)):
        if p.get("Standard"):
            kind = "std"
        elif (p.get("Module") or {}).get("Path") == own_mod:
            kind = "own"
        else:
            kind = "dep"
        files = (p.get("GoFiles") or []) + (p.get("CgoFiles") or []) + (p.get("SFiles") or [])
        lines = 0 if kind == "std" else sum(count_lines(os.path.join(p["Dir"], f)) for f in files)
        out[p["ImportPath"]] = (kind, lines)
    return out


def parse_registry(text, where=REGISTRY):
    """[(pattern, kind)] from `parser|inert <pattern> -- <reason>` lines."""
    rules, seen = [], set()
    for n, line in list_lines(text, where):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.fullmatch(r"(parser|inert)\s+(\S+)\s+--\s+(\S.*)", s)
        if not m:
            raise MeasureError(f"{where}:{n}: want `parser|inert <pattern> -- <reason>`: {s}")
        if m.group(2) in seen:
            raise MeasureError(f"{where}:{n}: {m.group(2)} is listed twice")
        seen.add(m.group(2))
        rules.append((m.group(2), m.group(1)))
    return rules


def matches(pattern, path):
    if pattern.endswith("/..."):
        root = pattern[:-4]
        return path == root or path.startswith(root + "/")
    return path == pattern


def classify(path, rules):
    """The kind of the most specific matching pattern (longest path; exact beats `/...`), or None."""
    best = None
    for pat, kind in rules:
        if matches(pat, path):
            rank = (len(pat[:-4]) if pat.endswith("/...") else len(pat), not pat.endswith("/..."))
            if best is None or rank > best[0]:
                best = (rank, kind)
    return best and best[1]


def measure(pkgs, rules):
    m = {"lines": 0, "deps": 0, "parsers": set(), "unclassified": []}
    for path, (kind, lines) in pkgs.items():
        if kind == "own":
            m["lines"] += lines
        elif kind == "dep":
            m["deps"] += lines
        c = classify(path, rules)
        if c is None and kind != "std":
            m["unclassified"].append(path)
        if c == "parser":
            m["parsers"].add(path)
    m["unclassified"].sort()
    return m


def read_reasons(tree):
    """The lines of tree's reason record, comments and blanks dropped; none when it has no record."""
    text = read_list(tree, REASONS)
    if text is None:
        return []
    return [line.strip() for _, line in list_lines(text, pathlib.Path(tree) / REASONS)
            if line.strip() and not line.lstrip().startswith("#")]


def reasons(base_lines, head_lines, pr):
    """({key: reason}, [problem]) from the reason-record lines the head adds to the base's, for PR
    `pr`. A line the base already holds is history and waives nothing."""
    got, bad, old = {}, [], {" ".join(x.split()) for x in base_lines}
    for line in head_lines:
        if " ".join(line.split()) in old:
            continue
        r = RECORD_LINE.match(line)
        if not r:
            bad.append(f"{REASONS}: `{line.strip()}`: want `<{'|'.join(KEYS)}> #<PR> -- <reason>`")
            continue
        key, num, why = r.group(1).lower(), int(r.group(2)), r.group(3)
        if key not in KEYS:
            bad.append(f"{REASONS}: `{line.strip()}`: the key must be one of {', '.join(KEYS)}")
        elif num != int(pr):
            bad.append(f"{REASONS}: `{line.strip()}`: names #{num}, not this PR (#{int(pr)})")
        elif key in DECIDED and (not why or PLACEHOLDER.match(why.split()[0])):
            bad.append(f"{REASONS}: `{line.strip()}`: the reason must start with a decision ID")
        elif key not in DECIDED and (len(why.split()) < 2 or PLACEHOLDER.match(why)):
            bad.append(f"{REASONS}: `{line.strip()}`: the reason must be at least two words, not a placeholder")
        else:
            got[key] = why
    return got, bad


def compare(base, head, reclassified, record=({}, [])):
    """(problems, owed) for a base and head measure and reasons()' pair; owed maps each key that
    needs a reason to its detail. Own and dependency lines show in the table only."""
    owed = {}
    new = sorted(head["parsers"] - base["parsers"])
    if new:
        owed["parsers"] = "new parser packages: " + ", ".join(new)
    if reclassified:
        owed["registry"] = "reclassified from parser to inert: " + ", ".join(reclassified)
    got, bad = record
    problems = list(bad)
    for p in head["unclassified"]:
        problems.append(f"{p} is linked into a trusted process but no line of {REGISTRY} classes it")
    for key, detail in owed.items():
        if key not in got:
            problems.append(f"{detail}, and the PR adds no `{key} #<PR> -- <reason>` line to {REASONS}")
    return problems, owed


def table(base, head, owed, problems, mains):
    rows = [("Own lines", "lines"), ("Dependency lines", "deps"), ("Parsers", "parsers")]
    out = ["## Trusted base (KRN-2)", "",
           "Trusted processes: " + ", ".join(m[2:] for m in mains) + ".", "",
           "| Measure | Base | Head | Change |", "|---|---:|---:|---:|"]
    for label, key in rows:
        b = base[key] if key != "parsers" else len(base[key])
        h = head[key] if key != "parsers" else len(head[key])
        out.append(f"| {label} | {b} | {h} | {h - b:+d} |")
    gone = sorted(base["parsers"] - head["parsers"])
    new = sorted(head["parsers"] - base["parsers"])
    if new:
        out += ["", "New parsers: " + ", ".join(f"`{p}`" for p in new)]
    if gone:
        out += ["", "Parsers gone: " + ", ".join(f"`{p}`" for p in gone)]
    out += ["", "**Fail:**" if problems else "**Pass.**" + (" Growth has a stated reason." if owed else "")]
    out += [f"- {p}" for p in problems]
    return "\n".join(out) + "\n"


def read_rules(tree, required):
    path, text = pathlib.Path(tree) / REGISTRY, read_list(tree, REGISTRY)
    if text is None:
        if required:
            raise MeasureError(f"{path} is missing")
        return []
    return parse_registry(text, str(path))


def parse_core(text, where=CORE):
    """{"root": dirs, "allow": patterns, "known": import paths} from the core file's lines."""
    core = {"root": set(), "allow": set(), "known": set()}
    for n, line in list_lines(text, where):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.fullmatch(r"(root|allow)\s+(\S+)", s) or re.fullmatch(r"(known)\s+(\S+)\s+--\s+(\S.*)", s)
        if not m:
            raise MeasureError(f"{where}:{n}: want `root <dir>`, `allow <pattern>` or `known <path> -- <reason>`: {s}")
        kind, arg = m.group(1), m.group(2)
        if kind == "root" and (arg.startswith(("/", ".")) or ".." in arg.split("/")):
            raise MeasureError(f"{where}:{n}: a root is a directory under broker/, not {arg}")
        if kind == "allow" and arg.endswith("/..."):
            raise MeasureError(f"{where}:{n}: an allow line names one package, not a subtree: {arg}")
        if arg in core[kind]:
            raise MeasureError(f"{where}:{n}: {arg} is listed twice")
        core[kind].add(arg)
    if not core["root"]:
        raise MeasureError(f"{where} names no root")
    return core


def read_core(tree):
    text = read_list(tree, CORE)
    return None if text is None else parse_core(text, str(pathlib.Path(tree) / CORE))


def measure_core(tree, core):
    """Core lines, the linked packages a known line must cover, and the known lines unused."""
    roots = {f"{module_path(broker_dir(tree))}/{r}" for r in core["root"]}
    m = {"lines": 0, "imports": set()}
    for path, (kind, lines) in packages(tree, sorted("./" + r for r in core["root"])).items():
        if kind == "std" or path in core["allow"]:
            continue
        m["lines"] += lines
        if path not in roots:
            m["imports"].add(path)
    m["unlisted"] = sorted(m["imports"] - core["known"])
    m["unused"] = sorted(core["known"] - m["imports"])
    return m


def active_decision(decisions, ident, pr):
    """True if DECISIONS.md text has a row for `ident` whose status is active and whose text names
    PR `pr` as `#<pr>` (as tools/word_budget.py); never true without a PR number."""
    for line in decisions.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0] == ident:
            return cells[2] == "active" and pr is not None and bool(re.search(rf"#{int(pr)}(?!\d)", line))
    return False


def waiver(key, record, decisions, pr):
    """'' when the head's record line for `key` names an active base-tree decision row that names PR
    `pr`, else why not. Only a committed record line waives (#6404): the PR body can change after
    the accepts at the same head, so it is never read."""
    why = record[0].get(key)
    if why is None:
        return f"the PR adds no `{key} #<PR> -- <decision ID>` line to {REASONS}"
    ident = why.split()[0]
    if pr is None:
        return f"`{key} -- {ident}` cannot be checked without the PR number (--pr)"
    if not active_decision(decisions, ident, pr):
        return f"`{key} #{int(pr)} -- {ident}` names no active DECISIONS.md row on the base branch that names #{int(pr)}"
    return ""


def compare_core(base_core, head_core, base, head, record, decisions, pr=None):
    """(problems, owed) for the core; base_core and base are None when the base has no core file."""
    problems, owed = [], {}
    if head is not None:
        problems += [f"{p} is linked into the trusted core but is not the standard library or an allow or known line of {CORE}"
                     for p in head["unlisted"]]
        problems += [f"{p} is a known line of {CORE} that the core no longer links: delete the line" for p in head["unused"]]
    if base_core is not None:
        if head_core is None:
            owed["file"] = f"{CORE} is deleted"
        else:
            for kind, change, verb in (("root", base_core["root"] - head_core["root"], "dropped"),
                                       ("allow", head_core["allow"] - base_core["allow"], "added"),
                                       ("known", head_core["known"] - base_core["known"], "added")):
                if change:
                    owed[kind] = f"{kind} lines {verb}: " + ", ".join(sorted(change))
    why = waiver("trusted-core", record, decisions, pr) if owed else ""
    problems += [f"{detail}, and {why}" for detail in owed.values() if why]
    return problems, owed


def core_table(base, head, owed, problems):
    out = ["", "## Trusted core (KRN-2cap)", ""]
    if head is None:
        out.append(f"No {CORE} at the head.")
    else:
        out += ["| Measure | Base | Head | Change |", "|---|---:|---:|---:|"]
        for label, b, h in (("Core lines", base and base["lines"], head["lines"]),
                            ("Linked packages outside std and allow", base and len(base["imports"]), len(head["imports"]))):
            out.append(f"| {label} | {'-' if b is None else b} | {h} | {'-' if b is None else f'{h - b:+d}'} |")
    out += ["", "**Fail:**" if problems else "**Pass.**" + (" Growth names a decision that names this PR (reviewer: confirm Mark approved it)." if owed else "")]
    out += [f"- {p}" for p in problems]
    return "\n".join(out) + "\n"


def parse_ceilings(text, where=CEILINGS):
    """{name: int} from the ceilings file: `<name> <whole number>` lines, every name once."""
    out = {}
    for n, line in list_lines(text, where):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.fullmatch(r"(\S+)\s+(0|[1-9][0-9]*)", s)
        if not m or m.group(1) not in CEILING_NAMES:
            raise MeasureError(f"{where}:{n}: want `<{'|'.join(CEILING_NAMES)}> <whole number>`: {s}")
        if m.group(1) in out:
            raise MeasureError(f"{where}:{n}: {m.group(1)} is listed twice")
        out[m.group(1)] = int(m.group(2))
    missing = [k for k in CEILING_NAMES if k not in out]
    if missing:
        raise MeasureError(f"{where} names no {', '.join(missing)}")
    return out


def read_ceilings(tree):
    text = read_list(tree, CEILINGS)
    return None if text is None else parse_ceilings(text, str(pathlib.Path(tree) / CEILINGS))


def old_core_dirs(tree):
    text = read_list(tree, OLD_CORE)
    if text is None:
        return set()
    return {s.strip() for _, s in list_lines(text, str(pathlib.Path(tree) / OLD_CORE))
            if s.strip() and not s.lstrip().startswith("#")}


def old_core_lines(tree, dirs):
    """Lines of every Go file under the old-core directories that is not a test or under testdata.
    A file is counted whatever its build tags: the old core is measured as it sits, not as linked."""
    total = 0
    for d in sorted(dirs):
        if ".." in pathlib.PurePosixPath(d).parts or d.startswith("/"):
            raise MeasureError(f"{OLD_CORE}: {d} is not a directory of the repository")
        root = no_symlinks_under(tree, d)
        for f in sorted(root.rglob("*.go")) if root.is_dir() else ():
            rel = f.relative_to(root).parts
            if f.is_file() and not f.name.endswith("_test.go") and "testdata" not in rel:
                total += count_lines(f)
    return total


def spec_words(tree):
    """SPEC.md's words as tools/word_budget.py counts them: runs of non-whitespace."""
    path = tree_file(tree, SPEC)
    return len(path.read_text(encoding="utf-8").split()) if path else 0


UNITS = {"trusted-lines": "lines", "spec-words": "words"}
# The parts of trusted-lines, shown under it in the table: a PR that grows only the old core
# fails with core lines unchanged, and the table says where the lines went (#4946 UX).
PARTS = (("core", "core"), ("old-core", "old core"))


def ceiling_measures(tree, core_measure, dirs):
    core, old = (core_measure["lines"] if core_measure else 0), old_core_lines(tree, dirs)
    return {"trusted-lines": core + old, "core": core, "old-core": old, "spec-words": spec_words(tree)}


def compare_ceilings(base_c, head_c, base, head, record, decisions, pr=None):
    """(problems, caps) for the ceilings (D-310). A measure fails when it ends above its ceiling
    and above the base's measure: while main is over a ceiling a PR may not grow it, and no PR
    crosses one upward. The ceiling is the base's; a head that raises or deletes one needs a
    `ceiling #<PR> -- <decision ID>` record line naming an active base-tree DECISIONS.md row that names the PR,
    and then the head's number holds. A head that lowers one is held to the lower number."""
    if base_c is None:
        return [], {}
    problems, caps, raised = [], {}, []
    if head_c is None:
        raised.append(f"{CEILINGS} is deleted")
    else:
        raised += [f"{k} ceiling {base_c[k]} -> {head_c[k]}" for k in CEILING_NAMES if head_c[k] > base_c[k]]
    why = waiver("ceiling", record, decisions, pr) if raised else ""
    waived = bool(raised) and not why
    problems += [f"{r}: only Mark raises a ceiling (D-310), and {why}" for r in raised if why]
    for k in CEILING_NAMES:
        if head_c is None:
            caps[k] = None if waived else base_c[k]
        else:
            caps[k] = head_c[k] if waived else min(base_c[k], head_c[k])
        if caps[k] is not None and head[k] > caps[k] and head[k] > base[k]:
            # The PR passes once it ends at or under the higher of its ceiling and main's measure.
            cut = head[k] - max(caps[k], base[k])
            unit = UNITS[k] if cut != 1 else UNITS[k][:-1]  # "cut 1 line" (#4982 item 2)
            problems.append(f"{k} {base[k]} -> {head[k]} ends above its ceiling {caps[k]} ({CEILINGS}):"
                            f" cut {cut} {unit} elsewhere in this PR (D-310)")
    return problems, caps


def ceilings_table(base, head, caps, problems):
    out = ["", "## Ceilings (D-310)", ""]
    if not caps:
        out.append(f"No {CEILINGS} at the base.")
    else:
        out += ["| Measure | Base | Head | Change | Ceiling |", "|---|---:|---:|---:|---:|"]
        for k in CEILING_NAMES:
            out.append(f"| {k} | {base[k]} | {head[k]} | {head[k] - base[k]:+d} | {'-' if caps[k] is None else caps[k]} |")
            if k == "trusted-lines":
                out += [f"| &nbsp;&nbsp;{label} | {base[p]} | {head[p]} | {head[p] - base[p]:+d} | |" for p, label in PARTS]
        out += ["", "**Fail:**" if problems else "**Pass.**"]
        out += [f"- {p}" for p in problems]
    return "\n".join(out) + "\n"


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise MeasureError(f"git {' '.join(args)}: {r.stderr.strip()[-500:]}")
    return r.stdout.strip()


def commit_of(repo, rev):
    return git(repo, "rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}")


def core_at(repo, rev, tmp):
    """measure_core of commit `rev`, checked out as a detached worktree under `tmp`."""
    where = pathlib.Path(tmp, rev)
    git(repo, "worktree", "add", "-q", "--detach", str(where), rev)
    try:
        core = read_core(where) or read_core(FALLBACK)
        if core is None:
            raise MeasureError(f"no {CORE} at {rev[:7]} or in this checkout")
        own = module_path(where.resolve() / "broker")
        return measure_core(where, core), own
    finally:
        git(repo, "worktree", "remove", "--force", str(where))


def sentence(repo, base, head, pr):
    """The canonical measure sentence for PR `pr` from commit `base` to commit `head`."""
    import tempfile
    base, head = commit_of(repo, base), commit_of(repo, head)
    with tempfile.TemporaryDirectory() as tmp:
        b, _ = core_at(repo, base, tmp)
        h, own = core_at(repo, head, tmp)
    new = sorted(("broker/" + p[len(own) + 1:]) if p.startswith(own + "/") else p for p in h["imports"] - b["imports"])
    return SENTENCE.format(pr=int(pr), base=b["lines"], head=h["lines"], delta=h["lines"] - b["lines"],
                           base_sha=base[:7], head_sha=head[:7], new=", ".join(new) or "none")


def growth_claims(base_tree, head_tree):
    """[(where, ID, text)] for each decision the head tree adds that records trusted-core growth
    under D-159: a DECISIONS.md row or a decisions/D-*.md file whose ID the base tree lacks."""
    def rows(tree):
        p = tree_file(tree, "DECISIONS.md")
        return p.read_text().split("\n") if p else []
    base_ids = {m.group(1) for m in map(CLAIM_ROW.match, rows(base_tree)) if m}
    out = []
    for n, line in enumerate(rows(head_tree), 1):
        m = CLAIM_ROW.match(line)
        if m and m.group(1) not in base_ids | {"D-159"} and "D-159" in line and GROWTH.search(line):
            out.append((f"DECISIONS.md:{n}", m.group(1), line))
    for f in sorted(pathlib.Path(head_tree, "decisions").glob("D-*.md")):
        if f.stem == "D-159" or pathlib.Path(base_tree, "decisions", f.name).exists():
            continue
        text = tree_file(head_tree, f"decisions/{f.name}").read_text()
        if "D-159" in text and GROWTH.search(text):
            out.append((f"decisions/{f.name}", f.stem, text))
    return out


class Merged(Exception):
    """The PR a sentence names has already merged into the base, so it has no growth left to measure."""


COMMAND = "tools/trusted_base.py measure --sentence {base} {head} --pr {pr}"
FETCH_COMMAND = ('git fetch origin pull/{pr}/head && tools/trusted_base.py measure --sentence'
                 ' "$(git merge-base origin/main FETCH_HEAD)" FETCH_HEAD --pr {pr}')


def check_claims(claims, expected):
    """Problems with the claims' measure sentences. `expected(pr)` gives the tool's sentence and the
    command that prints it, or raises Merged. Every `PR #N` a decision names needs a sentence."""
    problems = []
    for where, ident, text in claims:
        prs = {int(m.group(1)) for m in SENTENCE_PR.finditer(text)}
        if not prs:
            problems.append(f"{where} ({ident}): records trusted-core growth under D-159 but has no measure sentence;"
                            " paste the output of `" + FETCH_COMMAND.format(pr="<N>") + "`")
        for named in sorted({int(m.group(1)) for m in NAMED_PR.finditer(text)} - prs):
            problems.append(f"{where} ({ident}): names PR #{named} but has no measure sentence for it;"
                            " paste the output of `" + FETCH_COMMAND.format(pr=named) + "`")
        for m in SENTENCE_PR.finditer(text):
            pr = int(m.group(1))
            try:
                want, command = expected(pr)
            except Merged as e:
                problems.append(f"{where} ({ident}): {e}")
                continue
            if not (text.startswith(want, m.start()) and SENTENCE_END.match(text, m.start() + len(want))):
                got = text[m.start():].split("\n", 1)[0][:len(want) + 40]
                problems.append(f"{where} ({ident}): the measure sentence is not the tool's output;"
                                f" want `{want}` (from `{command}`), got `{got}`")
    return problems


def run_claims(base_tree, head_tree, repo, onto="HEAD", fetch=None):
    claims = growth_claims(base_tree, head_tree)
    cache = {}

    def expected(pr):
        if pr not in cache:
            ref = f"refs/remotes/pr/{pr}"
            if fetch:
                git(repo, "fetch", "-q", "--no-tags", fetch, f"+refs/pull/{pr}/head:{ref}")
            head, base_tip = commit_of(repo, ref), commit_of(repo, onto)
            base = git(repo, "merge-base", base_tip, head)
            if base == head:
                # Merged (or never ahead): the measure would read +0 and "none", the #4862 claim.
                cache[pr] = Merged(f"PR #{pr}'s head {head[:7]} is already in the base; record its measure"
                                   " before it merges")
            else:
                cache[pr] = (sentence(repo, base, head, pr), COMMAND.format(base=base[:12], head=head[:12], pr=pr))
        if isinstance(cache[pr], Merged):
            raise cache[pr]
        return cache[pr]

    problems = check_claims(claims, expected)
    out = ["", "## Trusted-core growth decisions (REV-PROOF-claims)", ""]
    out += [f"- {where} ({ident})" for where, ident, _ in claims] or ["No decision added records trusted-core growth."]
    out += ["", "**Fail:**" if problems else "**Pass.**"] + [f"- {p}" for p in problems]
    return problems, "\n".join(out) + "\n"


def run_check(base_tree, head_tree, fallback_tree=None, pr=None):
    rules = read_rules(head_tree, True)
    base_rules = read_rules(base_tree, False)
    head_pkgs = packages(head_tree)
    base = measure(packages(base_tree), rules)
    head = measure(head_pkgs, rules)
    reclassified = sorted(p for p in head_pkgs
                          if classify(p, base_rules) == "parser" and classify(p, rules) == "inert")
    record = reasons(read_reasons(base_tree), read_reasons(head_tree), pr)
    problems, owed = compare(base, head, reclassified, record)
    text = table(base, head, owed, problems, trusted_mains(head_tree))
    base_core, head_core = read_core(base_tree), read_core(head_tree)
    if base_core is None:
        # A branch whose merge base predates the core file is measured with the file of the
        # checkout this tool runs from (the base branch tip), so it is not exempt (L3 on #2941).
        base_core = read_core(fallback_tree or FALLBACK)
        if head_core is None:
            head_core = base_core
    cbase = base_core and measure_core(base_tree, base_core)
    chead = head_core and measure_core(head_tree, head_core)
    # The base tree's decisions: a row the PR adds itself is not yet Mark's record (#2945).
    decisions = tree_file(base_tree, "DECISIONS.md")
    decisions = decisions.read_text() if decisions else ""
    cproblems, cowed = compare_core(base_core, head_core, cbase, chead, record, decisions, pr)
    # The ceilings (D-310): old-core directories listed on either side count on both, so dropping
    # a line of tools/old_core.txt cannot shed lines whose files stay.
    dirs = old_core_dirs(base_tree) | old_core_dirs(head_tree)
    # A head without the core file is measured by the base's, so deleting it sheds no lines.
    hcore = chead if head_core is not None else (base_core and measure_core(head_tree, base_core))
    ebase, ehead = ceiling_measures(base_tree, cbase, dirs), ceiling_measures(head_tree, hcore, dirs)
    eproblems, caps = compare_ceilings(read_ceilings(base_tree), read_ceilings(head_tree), ebase, ehead,
                                       record, decisions, pr)
    return (problems + cproblems + eproblems,
            text + core_table(cbase, chead, cowed, cproblems) + ceilings_table(ebase, ehead, caps, eproblems))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--tree", default=str(pathlib.Path(__file__).resolve().parent.parent))
    m.add_argument("--sentence", nargs=2, metavar=("BASE", "HEAD"), help="print the measure sentence for two commits")
    m.add_argument("--pr", type=int, help="the growth PR the sentence names (with --sentence)")
    k = sub.add_parser("claims")
    k.add_argument("--base-tree", required=True)
    k.add_argument("--head-tree", required=True)
    k.add_argument("--repo", required=True, help="the repository holding the named PRs' heads")
    k.add_argument("--onto", default="HEAD", help="the base commit a named PR's merge base is taken with")
    k.add_argument("--fetch", help="remote to fetch refs/pull/<N>/head from")
    k.add_argument("--markdown", help="also write the result to this file")
    c = sub.add_parser("check")
    c.add_argument("--base-tree", required=True)
    c.add_argument("--head-tree", required=True)
    # Required (#6406): without it a reason line naming any PR would pass, weaker than CI.
    c.add_argument("--pr", type=int, required=True, help="the PR number a reason line or waiving decision row must name")
    c.add_argument("--markdown", help="also write the table to this file")
    a = ap.parse_args(argv)
    if a.cmd == "measure" and a.sentence and a.pr is None:
        ap.error("--sentence needs --pr")
    try:
        if a.cmd == "measure" and a.sentence:
            problems, text = [], sentence(a.tree, *a.sentence, a.pr) + "\n"
        elif a.cmd == "claims":
            problems, text = run_claims(a.base_tree, a.head_tree, a.repo, a.onto, a.fetch)
        elif a.cmd == "measure":
            rules = read_rules(a.tree, True)
            m = measure(packages(a.tree), rules)
            problems = [f"{p} is linked into a trusted process but no line of {REGISTRY} classes it"
                        for p in m["unclassified"]]
            text = (f"own lines {m['lines']}, dependency lines {m['deps']}, parsers {len(m['parsers'])}"
                    f" ({', '.join(x[2:] for x in trusted_mains(a.tree))})\n")
            core = read_core(a.tree)
            if core:
                c = measure_core(a.tree, core)
                text += f"core lines {c['lines']}, linked packages outside std and allow {len(c['imports'])}\n"
                problems += compare_core(None, core, None, c, ({}, []), "")[0]
                e = ceiling_measures(a.tree, c, old_core_dirs(a.tree))
                caps = read_ceilings(a.tree) or {}
                text += "".join(f"{k} {e[k]}" + (f" (ceiling {caps[k]})" if k in caps else "") + "\n" for k in CEILING_NAMES)
            text += "".join(f"- {p}\n" for p in problems)
        else:
            problems, text = run_check(a.base_tree, a.head_tree, pr=a.pr)
    except (MeasureError, OSError, ValueError) as e:
        print(f"trusted_base: {e}", file=sys.stderr)
        if a.cmd in ("check", "claims") and a.markdown:
            with open(a.markdown, "a") as f:
                f.write(f"\n**Error ({a.cmd}):** {e}\n")
        return 2
    print(text, end="")
    if a.cmd in ("check", "claims") and a.markdown:
        with open(a.markdown, "a") as f:
            f.write(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
