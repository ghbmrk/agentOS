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
parser package or reclassifies a parser as inert fails unless its body has a line
`Trusted-base: <parsers|registry> -- <reason>`. It is a measure, not a cap.

The trusted core (KRN-2cap, #2935) is the budgeted subset: the `root` packages of
tools/trusted_core.txt (kernel, key-check library, the clerk check path) and everything they
link. Its lines are every linked package's outside the standard library and the `allow` lines,
each one exact package from golang.org/x/crypto or golang.org/x/sys (a subtree would let a new
package or a vendored file under it in at +0). Every such package other than a root must have a
`known` line, so a new import fails whatever the body, and a `known` line the core no longer
links must be deleted. Against the base tree's file and measure, a head that grows core lines,
adds a `known` or `allow` line, drops a root or deletes the file fails unless the body has a
line `Trusted-core: <decision ID>` naming an active DECISIONS.md row of the base tree whose
text names the PR (`#<number>`, from --pr), so neither a row added by the PR itself nor an
unrelated standing row can waive it; the reviewer checks that the row records Mark approving
the growth (the D-152 word budget, for code; #2945). In CI the base tree is the base branch tip
and the head tree is the PR head merged onto it, so the budget is what main holds now and the
measure is exactly what lands: a branch that cherry-picks main's cuts instead of merging main
gains nothing. It ratchets down on every merge with nothing to keep in step. A base tree with
no core file (one older than the file) is measured, with the head, by the file of the checkout
the tool runs from, which is the base branch tip in CI.

Usage:
  tools/trusted_base.py measure [--tree DIR]       print one tree's measure; exit 1 if a package is unclassified
  tools/trusted_base.py check --base-tree DIR --head-tree DIR --body FILE [--pr N] [--markdown FILE]
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
CORE = "tools/trusted_core.txt"
FALLBACK = pathlib.Path(__file__).resolve().parent.parent  # the checkout this copy runs from
CORE_LIST = "broker/core/core.txt"
KEYS = ("parsers", "registry")
RETIRED = ("lines", "deps")  # keys that no longer gate (D-157); a body that still has one passes
GO_ENV = {
    "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "-mod=vendor",
    "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOENV": "off",
}
REASON = re.compile(r"^\s*Trusted-base:\s*(\S+)\s+--\s+(.*?)\s*$")
WAIVER = re.compile(r"^\s*Trusted-core:\s*(\S+)\s*$", re.M)
PLACEHOLDER = re.compile(r"(?i)^(todo|tbd|n/?a|none|reason|-+|\.+)$")


class MeasureError(Exception):
    pass


def trusted_mains(tree):
    """The `wiring cmd/<name>` lines of the tree's core list, as ./cmd/<name>."""
    path = pathlib.Path(tree) / CORE_LIST
    try:
        text = path.read_text()
    except OSError as e:
        raise MeasureError(f"cannot read {path}: {e}")
    mains = []
    for line in text.splitlines():
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
    broker = pathlib.Path(tree).resolve() / "broker"
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
    for n, line in enumerate(text.splitlines(), 1):
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


def reasons(body):
    """{key: reason} from the PR body's `Trusted-base: <key> -- <reason>` lines; bad keys listed."""
    got, bad = {}, []
    for line in (body or "").splitlines():
        r = REASON.match(line)
        if not r:
            continue
        key, why = r.group(1).lower(), r.group(2)
        if key in RETIRED:
            continue
        if key not in KEYS:
            bad.append(f"`{line.strip()}`: the key must be one of {', '.join(KEYS)}")
        elif len(why.split()) < 2 or PLACEHOLDER.match(why):
            bad.append(f"`{line.strip()}`: the reason must be at least two words, not a placeholder")
        else:
            got[key] = why
    return got, bad


def compare(base, head, reclassified, body):
    """(problems, owed) for a base and head measure; owed maps each key that needs a reason to its
    detail. Own and dependency lines show in the table only."""
    owed = {}
    new = sorted(head["parsers"] - base["parsers"])
    if new:
        owed["parsers"] = "new parser packages: " + ", ".join(new)
    if reclassified:
        owed["registry"] = "reclassified from parser to inert: " + ", ".join(reclassified)
    got, bad = reasons(body)
    problems = list(bad)
    for p in head["unclassified"]:
        problems.append(f"{p} is linked into a trusted process but no line of {REGISTRY} classes it")
    for key, detail in owed.items():
        if key not in got:
            problems.append(f"{detail}, and the PR body has no `Trusted-base: {key} -- <reason>` line")
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
    path = pathlib.Path(tree) / REGISTRY
    if not path.exists():
        if required:
            raise MeasureError(f"{path} is missing")
        return []
    return parse_registry(path.read_text(), str(path))


def parse_core(text, where=CORE):
    """{"root": dirs, "allow": patterns, "known": import paths} from the core file's lines."""
    core = {"root": set(), "allow": set(), "known": set()}
    for n, line in enumerate(text.splitlines(), 1):
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
    path = pathlib.Path(tree) / CORE
    return parse_core(path.read_text(), str(path)) if path.exists() else None


def measure_core(tree, core):
    """Core lines, the linked packages a known line must cover, and the known lines unused."""
    roots = {f"{module_path(pathlib.Path(tree).resolve() / 'broker')}/{r}" for r in core["root"]}
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


def compare_core(base_core, head_core, base, head, body, decisions, pr=None):
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
            if head["lines"] > base["lines"]:
                owed["lines"] = f"core lines {base['lines']} -> {head['lines']}"
            for kind, change, verb in (("root", base_core["root"] - head_core["root"], "dropped"),
                                       ("allow", head_core["allow"] - base_core["allow"], "added"),
                                       ("known", head_core["known"] - base_core["known"], "added")):
                if change:
                    owed[kind] = f"{kind} lines {verb}: " + ", ".join(sorted(change))
    if owed:
        w = WAIVER.search(body or "")
        if not (w and active_decision(decisions, w.group(1), pr)):
            why = (f"`Trusted-core: {w.group(1)}` names no active DECISIONS.md row on the base branch that names #{pr}"
                   if w else "no `Trusted-core: <decision ID>` line")
            problems += [f"{detail}, and the PR body has {why}" for detail in owed.values()]
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


def run_check(base_tree, head_tree, body, fallback_tree=None, pr=None):
    rules = read_rules(head_tree, True)
    base_rules = read_rules(base_tree, False)
    head_pkgs = packages(head_tree)
    base = measure(packages(base_tree), rules)
    head = measure(head_pkgs, rules)
    reclassified = sorted(p for p in head_pkgs
                          if classify(p, base_rules) == "parser" and classify(p, rules) == "inert")
    problems, owed = compare(base, head, reclassified, body)
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
    decisions = pathlib.Path(base_tree, "DECISIONS.md")
    cproblems, cowed = compare_core(base_core, head_core, cbase, chead, body,
                                    decisions.read_text() if decisions.exists() else "", pr)
    return problems + cproblems, text + core_table(cbase, chead, cowed, cproblems)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--tree", default=str(pathlib.Path(__file__).resolve().parent.parent))
    c = sub.add_parser("check")
    c.add_argument("--base-tree", required=True)
    c.add_argument("--head-tree", required=True)
    c.add_argument("--body", required=True, help="file holding the PR body")
    c.add_argument("--pr", type=int, help="the PR number a waiving decision row must name")
    c.add_argument("--markdown", help="also write the table to this file")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "measure":
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
                problems += compare_core(None, core, None, c, "", "")[0]
            text += "".join(f"- {p}\n" for p in problems)
        else:
            body = pathlib.Path(a.body).read_text()
            problems, text = run_check(a.base_tree, a.head_tree, body, pr=a.pr)
    except (MeasureError, OSError, ValueError) as e:
        print(f"trusted_base: {e}", file=sys.stderr)
        return 2
    print(text, end="")
    if a.cmd == "check" and a.markdown:
        with open(a.markdown, "a") as f:
            f.write(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
