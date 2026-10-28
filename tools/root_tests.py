#!/usr/bin/env python3
"""The Go tests that skip unless root, and which of them no root CI step runs (CI-root-go, #3539).

A test that skips off root (`os.Geteuid() != 0`, directly or through a helper such as needRoot)
goes green in every non-root job, so unless a root step runs it, CI never checks it: renaming
EdgeEnroll's `cosign` tag passed CI while the only test of it skipped (#3536). This finds every
such test by reading the broker's `_test.go` files, and the root steps by reading ci.yml.

A test is root-gated when its body, or a function of its package it calls (to any depth), holds
an `if` on `Geteuid() != 0` whose block skips (`.Skip`, `.Skipf`, `.SkipNow`) or returns, since a
test that returns early off root leaves its root half as unchecked as one that skips. A root step is a ci.yml line that runs `go test` under sudo; it covers a test
when it names the test's package (or a `/...` above it) and its `-run` pattern, if any, matches.

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

GATE = re.compile(r"^(\s*)(?:\}\s*else\s+)?if\s.*Geteuid\(\)\s*!=\s*0.*\{\s*(?://.*)?$", re.M)
SKIP = re.compile(r"\.Skip(?:f|Now)?\(|^\s*return\b", re.M)
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


def skips_off_root(body):
    """True when an `if` on Geteuid() != 0 in body skips or returns inside its block."""
    for m in GATE.finditer(body):
        end = body.find("\n" + m.group(1) + "}", m.end())
        if SKIP.search(body[m.end(): end if end >= 0 else len(body)]):
            return True
    return False


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
        gate = {n for n, b in bodies.items() if skips_off_root(b)}
        grew = True
        while grew:
            more = {n for n, b in bodies.items() if n not in gate and any(c in gate for c in CALL.findall(b))}
            gate |= more
            grew = bool(more)
        tests = sorted(n for n in gate if TEST.match(n))
        if tests:
            rel = os.path.relpath(d, broker).replace(os.sep, "/")
            found[MODULE if rel == "." else f"{MODULE}/{rel}"] = tests
    return found


def root_runs(ci_text):
    """[(package patterns, -run regex or None)] for each `go test` ci.yml runs under sudo, generated step left out."""
    runs, lines, i, step = [], ci_text.split("\n"), 0, ""
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("- name:"):
            step = line.split("- name:", 1)[1].strip()
        cmd = line
        while cmd.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            cmd = cmd.rstrip()[:-1] + " " + lines[i].strip()
        i += 1
        if step.startswith(GENERATED) or "go test" not in cmd:
            continue
        before, _, after = cmd.partition("go test")
        if "sudo" not in before:
            continue
        after = re.split(r"\s(?:>|\|\||&&|\|)\s", after, maxsplit=1)[0]
        try:
            words = shlex.split(after)
        except ValueError:
            continue
        pat, pkgs, j = None, [], 0
        while j < len(words):
            w = words[j]
            if w == "-run" and j + 1 < len(words):
                pat, j = words[j + 1], j + 2
                continue
            if w.startswith("-run="):
                pat = w[5:]
            elif w.startswith("./"):
                pkgs.append(w)
            elif w.startswith("-") and w in ("-timeout", "-parallel", "-p", "-tags", "-count"):
                j += 1
            j += 1
        if pkgs:
            runs.append((pkgs, pat))
    return runs


def _in(pkg, pattern):
    rel = pkg[len(MODULE):].lstrip("/") or "."
    pattern = pattern[2:] if pattern.startswith("./") else pattern
    if pattern.endswith("/..."):
        base = pattern[:-4]
        return rel == base or rel.startswith(base + "/")
    return rel == pattern.rstrip("/")


def covered(pkg, test, runs):
    return any(any(_in(pkg, p) for p in pkgs) and (pat is None or re.search(pat, test)) for pkgs, pat in runs)


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
