#!/usr/bin/env python3
"""The Go tests that skip unless root, and which of them no root CI step runs (CI-root-go, #3539).

A test that skips off root (`os.Geteuid() != 0`, directly or through a helper such as needRoot)
goes green in every non-root job, so unless a root step runs it, CI never checks it: renaming
EdgeEnroll's `cosign` tag passed CI while the only test of it skipped (#3536). This finds every
such test by reading the broker's `_test.go` files, and the root steps by reading ci.yml.

A test is root-gated when its body, or a function of its package it calls (to any depth), holds
an `if` on `Geteuid()` or `Getuid()` compared with 0 that either skips or returns off root (`!= 0`)
or branches, so that some of its checks run only as root (#3541: agentos-unlock's capability
check). A test that skips as root (`== 0` with `.Skip`) is never root-gated: it runs only in the
non-root jobs. A root step covers a test only when CI fails if the test skips or fails there: a
ci.yml line runs `go test` under sudo with its output in a file (`> FILE`), the test's package and
`-run` pattern match, and the next line of the step that reads or rewrites FILE is
`python3 ... require_ran.py ... < FILE || exit 1`, naming the test (or its package after
`--gated`); the step has no `if:`, `continue-on-error:` or `shell:` key and no line that opens
control flow, sets a trap, defines a function or exits or returns 0.

  root_tests.py           exit 1, naming each root-gated test that no root step and no EXEMPT
                          line covers, and each EXEMPT line that matches no root-gated test
  root_tests.py --plan    print `<package> <-run pattern> <test>...` per package of the gated tests
                          only ci.yml's generated step (\"Root-gated Go tests\") runs, for that step

The generated step runs every package --plan prints as root and fails unless each listed test
ran and passed, with no skip (tools/require_ran.py), so a new root-gated test is run as root by
default and a test that cannot run on the runner has to be listed in EXEMPT with its reason.
"""
import os
import re
import shlex
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROKER = os.path.join(ROOT, "broker")
MODULE = "github.com/ghbmrk/agentos/broker"
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")
GENERATED = "Root-gated Go tests"

# Root-gated tests the runner cannot run, as {"<package>.<Test>": reason}. Keep each reason to
# what the runner lacks; a test that can run belongs in a root step, not here.
EXEMPT = {
}

GATE = re.compile(r"^(\s*)(?:\}\s*else\s+)?if\s(.*\bGete?uid\(\)\s*[!=]=\s*0\b.*)\{\s*(?://.*)?$", re.M)
SKIP = re.compile(r"\.Skip(?:f|Now)?\(|^\s*return\b", re.M)
SKIPCALL = re.compile(r"\.Skip(?:f|Now)?\(")
FUNC = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\(", re.M)
TEST = re.compile(r"^Test(?!Main$)[A-Z0-9_]")
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def funcs(src):
    """{name: body} for the top-level functions of gofmt'd Go source; a body ends at a line `}`."""
    out = {}
    for m in FUNC.finditer(src):
        end = src.find("\n}", m.end())
        body = src[m.end(): end if end >= 0 else len(src)]
        out[m.group(1)] = out.get(m.group(1), "") + body
    return out


def uid_gates(body):
    """(gates, skips as root) for body: whether an `if` on the uid against 0 skips or returns off
    root or branches, and whether one skips as root."""
    gates = as_root = False
    for m in GATE.finditer(body):
        end = body.find("\n" + m.group(1) + "}", m.end())
        block = body[m.end(): end if end >= 0 else len(body)]
        if re.search(r"Gete?uid\(\)\s*==\s*0", m.group(2)) and SKIPCALL.search(block):
            as_root = True
        else:
            gates = True  # skips or returns off root, or branches: some checks run only as root
    return gates, as_root


def _closure(bodies, seed):
    """seed and every function of bodies that calls one of them, to any depth."""
    out, grew = set(seed), True
    while grew:
        more = {n for n, b in bodies.items() if n not in out and any(c in out for c in CALL.findall(b))}
        out |= more
        grew = bool(more)
    return out


def gated(broker=BROKER):
    """{package import path: sorted root-gated test names}."""
    found = {}
    for d, subdirs, files in os.walk(broker):
        subdirs[:] = sorted(s for s in subdirs if s not in ("vendor", "testdata") and not s.startswith((".", "_")))
        bodies = {}
        for f in sorted(files):
            if f.endswith("_test.go"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    for name, body in funcs(fh.read()).items():
                        bodies[name] = bodies.get(name, "") + body
        marks = {n: uid_gates(b) for n, b in bodies.items()}
        gate = _closure(bodies, {n for n, (g, _) in marks.items() if g})
        root_skip = _closure(bodies, {n for n, (_, r) in marks.items() if r})
        tests = sorted(n for n in gate - root_skip if TEST.match(n))
        if tests:
            rel = os.path.relpath(d, broker).replace(os.sep, "/")
            found[MODULE if rel == "." else f"{MODULE}/{rel}"] = tests
    return found


def _steps(ci_text):
    """[(name, keys, run lines)] for each step in ci.yml; run lines are joined across `\\` and
    stripped of comments, since a comment never runs (#3540 Security review)."""
    out, lines, i = [], ci_text.split("\n"), 0
    while i < len(lines):
        m = re.match(r"^(\s*)- ([A-Za-z][\w-]*):(.*)$", lines[i])
        if not m:
            i += 1
            continue
        ind, body = len(m.group(1)), [lines[i][: len(m.group(1))] + "  " + lines[i][len(m.group(1)) + 2:]]
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > ind):
            body.append(lines[i])
            i += 1
        keys, name, run, j = {}, "", [], 0
        while j < len(body):
            k = re.match(r"^ {%d}([A-Za-z][\w-]*):\s*(.*)$" % (ind + 2), body[j])
            j += 1
            if not k:
                continue
            keys[k.group(1)] = k.group(2)
            if k.group(1) == "name":
                name = k.group(2).strip()
            if k.group(1) != "run":
                continue
            raw = [] if k.group(2).strip() in ("|", ">", "|-", ">-") else [k.group(2)]
            while j < len(body) and (not body[j].strip() or len(body[j]) - len(body[j].lstrip()) > ind + 2):
                raw.append(body[j])
                j += 1
            n = 0
            while n < len(raw):
                cmd = raw[n]
                while cmd.rstrip().endswith("\\") and n + 1 < len(raw):
                    n += 1
                    cmd = cmd.rstrip()[:-1] + " " + raw[n].strip()
                n += 1
                cmd = "" if cmd.lstrip().startswith("#") else re.split(r"(?:^|\s)#", cmd, maxsplit=1)[0]
                if cmd.strip():
                    run.append(cmd.strip())
        out.append((name, keys, run))
    return out


PUNCT = {"<", ">", "|", "||", "&", "&&", ";", ";;", ">>", "2>", "(", ")"}


def _words(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None


def _root_run(cmd):
    """(package patterns, -run regex or None, output file) for a `sudo ... go test ... > FILE`, else None."""
    before, sep, after = cmd.partition("go test")
    if not sep or "sudo" not in before.split():
        return None
    words = _words(after)
    if words is None or ">" not in words:
        return None
    out = words[words.index(">") + 1] if words.index(">") + 1 < len(words) else None
    words = words[: words.index(">")]
    pat, pkgs, j = None, [], 0
    while j < len(words):
        w = words[j]
        if w in PUNCT:
            return None
        if w == "-run" and j + 1 < len(words):
            pat, j = words[j + 1], j + 2
            continue
        if w.startswith("-run="):
            pat = w[5:]
        elif w.startswith("./"):
            pkgs.append(w)
        elif w in ("-timeout", "-parallel", "-p", "-tags", "-count", "-skip"):
            j += 1
        j += 1
    return (pkgs, pat, out) if pkgs and out else None


def _require(cmd):
    """(input file, names, --gated patterns) for `python3 ... require_ran.py ... < FILE || exit 1`,
    whose failure ends the step whatever errexit's state (#3546 L3), else None."""
    words = _words(cmd)
    if not words or words[0] != "python3" or not any(w.endswith("require_ran.py") for w in words):
        return None
    words = words[[i for i, w in enumerate(words) if w.endswith("require_ran.py")][0] + 1:]
    if words[-3:] != ["||", "exit", "1"]:
        return None
    words = words[:-3]
    if words.count("<") != 1 or words.index("<") + 1 >= len(words) or any(w in PUNCT - {"<"} for w in words):
        return None
    i = words.index("<")
    src, args = words[i + 1], words[:i] + words[i + 2:]
    names, pats, gated_mode = set(), [], False
    for w in args:
        if w == "--named-skips-only":
            continue
        if w == "--gated":
            gated_mode = True
        elif gated_mode and w.startswith("./"):
            pats.append(w)
        else:
            names.add(w)
    return src, names, pats


# A step with one of these keys may skip or not fail the job; a line opening shell control flow
# may run a root line conditionally, and a trap, a function or a zero exit or return may turn a
# failure green. Either way the step covers nothing.
UNSAFE_KEYS = ("if", "continue-on-error", "shell")
UNSAFE_LINE = re.compile(r"^(?:if|while|until|for|case|select|trap|function)\b|\(\)\s*\{|\b(?:exit|return)\s+0+\b|&\s*$")


def root_runs(ci_text):
    """[(package patterns, -run regex or None, names, --gated patterns)] for each sudo `go test` in
    ci.yml whose skips and failures fail CI: require_ran.py reads its output next (see module doc).
    The generated step is left out."""
    runs = []
    for name, keys, run in _steps(ci_text):
        if name.startswith(GENERATED) or any(k in keys for k in UNSAFE_KEYS) or any(UNSAFE_LINE.search(c) for c in run):
            continue
        for i, cmd in enumerate(run):
            r = _root_run(cmd)
            if not r:
                continue
            pkgs, pat, out = r
            nxt = next((c for c in run[i + 1:] if out in (_words(c) or [])), None)
            req = _require(nxt) if nxt else None
            if req and req[0] == out:
                runs.append((pkgs, pat, frozenset(req[1]), tuple(req[2])))
    return runs


def _in(pkg, pattern):
    rel = pkg[len(MODULE):].lstrip("/") or "."
    pattern = pattern[2:] if pattern.startswith("./") else pattern
    if pattern.endswith("/..."):
        base = pattern[:-4]
        return rel == base or rel.startswith(base + "/")
    return rel == pattern.rstrip("/")


def covered(pkg, test, runs):
    """True when a root run executes the test and require_ran.py names it there, by name or package."""
    return any(any(_in(pkg, p) for p in pkgs) and (pat is None or re.search(pat, test))
               and (f"{pkg}.{test}" in names or any(_in(pkg, g) for g in gpats))
               for pkgs, pat, names, gpats in runs)


def gated_names(patterns, found=None, exempt=EXEMPT):
    """The `<package>.<Test>` names of the root-gated, non-exempt tests in packages the patterns match."""
    found = gated() if found is None else found
    return [f"{p}.{t}" for p, ts in sorted(found.items()) if any(_in(p, g) for g in patterns)
            for t in ts if f"{p}.{t}" not in exempt]


def plan(found, runs, exempt=EXEMPT):
    """[(package, -run regex, tests)] for the gated tests the generated step must run."""
    out = []
    for pkg, tests in sorted(found.items()):
        left = [t for t in tests if not covered(pkg, t, runs) and f"{pkg}.{t}" not in exempt]
        if left:
            out.append((pkg, "^(" + "|".join(left) + ")$", left))
    return out


def problems(found, runs, generated, exempt=EXEMPT):
    """Why a root-gated test could go unrun as root; empty when each is covered or exempt."""
    out = []
    if not generated:
        for pkg, tests in sorted(found.items()):
            for t in tests:
                if not covered(pkg, t, runs) and f"{pkg}.{t}" not in exempt:
                    out.append(f"{pkg}.{t}: root-gated, and no root step in ci.yml runs it")
    names = {f"{p}.{t}" for p, ts in found.items() for t in ts}
    for name, why in sorted(exempt.items()):
        if name not in names:
            out.append(f"{name}: EXEMPT names no root-gated test")
        if not why.strip():
            out.append(f"{name}: EXEMPT gives no reason")
    return out


def generated_step(ci_text):
    """True when ci.yml has the generated step and it runs --plan's packages through require_ran."""
    i = ci_text.find(f"- name: {GENERATED}")
    if i < 0:
        return False
    nxt = ci_text.find("\n      - ", i + 1)
    body = ci_text[i: nxt if nxt >= 0 else len(ci_text)]
    return "root_tests.py --plan" in body and "require_ran.py" in body and "sudo" in body


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    with open(CI, encoding="utf-8") as f:
        ci = f.read()
    found, runs = gated(), root_runs(ci)
    if argv == ["--plan"]:
        for pkg, pat, tests in plan(found, runs):
            print(pkg, pat, *(f"{pkg}.{t}" for t in tests))
        return 0
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    probs = problems(found, runs, generated_step(ci))
    for p in probs:
        print(f"::error::{p}", file=sys.stderr)
    if not probs:
        n = sum(map(len, found.values()))
        print(f"{n} root-gated tests in {len(found)} packages; each runs in a root step or is exempt")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
