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
enters a trusted process unclassified. Growth is allowed with a reason: a PR whose head grows
own or dependency lines, adds a parser package, or reclassifies a parser as inert fails
unless its body has a line `Trusted-base: <lines|deps|parsers|registry> -- <reason>`.
It is a measure, not a cap.

Usage:
  tools/trusted_base.py measure [--tree DIR]       print one tree's measure; exit 1 if a package is unclassified
  tools/trusted_base.py check --base-tree DIR --head-tree DIR --body FILE [--markdown FILE]
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
CORE_LIST = "broker/core/core.txt"
METRICS = ("lines", "deps", "parsers")
KEYS = METRICS + ("registry",)
GO_ENV = {
    "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOFLAGS": "-mod=vendor",
    "GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOENV": "off",
}
REASON = re.compile(r"^\s*Trusted-base:\s*(\S+)\s+--\s+(.*?)\s*$")
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


def packages(tree):
    """{import path: (kind, lines)} with kind own, dep or std, for the tree's trusted processes."""
    broker = pathlib.Path(tree).resolve() / "broker"
    own_mod = module_path(broker)
    out = {}
    for p in go_list(broker, trusted_mains(tree)):
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
        if key not in KEYS:
            bad.append(f"`{line.strip()}`: the key must be one of {', '.join(KEYS)}")
        elif len(why.split()) < 2 or PLACEHOLDER.match(why):
            bad.append(f"`{line.strip()}`: the reason must be at least two words, not a placeholder")
        else:
            got[key] = why
    return got, bad


def compare(base, head, reclassified, body):
    """(problems, owed) for a base and head measure; owed maps each grown key to its detail."""
    owed = {}
    if head["lines"] > base["lines"]:
        owed["lines"] = f"own lines {base['lines']} -> {head['lines']}"
    if head["deps"] > base["deps"]:
        owed["deps"] = f"dependency lines {base['deps']} -> {head['deps']}"
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


def run_check(base_tree, head_tree, body):
    rules = read_rules(head_tree, True)
    base_rules = read_rules(base_tree, False)
    head_pkgs = packages(head_tree)
    base = measure(packages(base_tree), rules)
    head = measure(head_pkgs, rules)
    reclassified = sorted(p for p in head_pkgs
                          if classify(p, base_rules) == "parser" and classify(p, rules) == "inert")
    problems, owed = compare(base, head, reclassified, body)
    return problems, table(base, head, owed, problems, trusted_mains(head_tree))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--tree", default=str(pathlib.Path(__file__).resolve().parent.parent))
    c = sub.add_parser("check")
    c.add_argument("--base-tree", required=True)
    c.add_argument("--head-tree", required=True)
    c.add_argument("--body", required=True, help="file holding the PR body")
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
            text += "".join(f"- {p}\n" for p in problems)
        else:
            body = pathlib.Path(a.body).read_text()
            problems, text = run_check(a.base_tree, a.head_tree, body)
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
