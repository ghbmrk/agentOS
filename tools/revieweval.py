#!/usr/bin/env python3
"""Reviewer eval (REVIEW-eval, #2166; cases live in evals/review/cases, added with the first corpus): score a reviewer prompt against bugs the reviews missed.

A case is a merged PR that a later `Defect: <ID>` PR fixed. It holds the introducing PR's diff
at its reviewed head and, as the expected finding, the lines the fix PR changed. A clean case is
a merged PR with no later defect. A reviewer change is kept only when `keep` says the score rose.

  revieweval.py build --pulls pulls.json --out evals/review/cases   (from saved PR data)
  revieweval.py score --cases evals/review/cases --cmd "<reviewer>" --out score.json
  revieweval.py compare old.json new.json                            (exit 0 = keep the change)

The reviewer command reads the case diff on stdin and prints a JSON list of findings,
`[{"file": "a.go", "line": 12, "class": "blocker"}]`. It is the caller's command: a prompt, tool
or model change is a different --cmd. Cases are data files, so scoring needs no network.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFECT = re.compile(r"^Defect:\s*(\S.*?)\s*$", re.M)
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def expected_ranges(fix_diff):
    """{file: [(first, last)]} on the old side of each hunk of a unified diff: the lines of the
    introducing code the fix changed. A pure addition points at the line it was added after."""
    out, path, old, run = {}, None, 0, None

    def close():
        nonlocal run
        if run and path:
            out.setdefault(path, []).append(run)
        run = None

    for line in fix_diff.splitlines():
        if line.startswith("--- "):
            close()
            path = None
        elif line.startswith("+++ "):
            path = None if line[4:] == "/dev/null" else re.sub(r"^b/", "", line[4:])
        elif (m := HUNK.match(line)):
            close()
            old = int(m.group(1))
        elif path and line.startswith("-") and not line.startswith("---"):
            run = (run[0], old) if run else (old, old)
            old += 1
        elif path and line.startswith("+"):
            if run is None:
                run = (max(old - 1, 1), max(old - 1, 1))
        elif path and line.startswith(" "):
            close()
            old += 1
    close()
    return out


def hit(finding, expected):
    return any(a <= finding.get("line", -1) <= b for a, b in expected.get(finding.get("file"), []))


def score_case(case, findings):
    """A defect case is caught when a finding lands inside the fix's hunks. Any finding
    classed blocker on a clean case, or outside the hunks on a defect case, is a false blocker."""
    blockers = [f for f in findings if f.get("class", "blocker") == "blocker"]
    if case["kind"] == "clean":
        return {"caught": None, "false_blockers": len(blockers)}
    exp = {f: [tuple(r) for r in rs] for f, rs in case["expected"].items()}
    return {"caught": any(hit(f, exp) for f in findings),
            "false_blockers": sum(not hit(f, exp) for f in blockers)}


def summarize(results):
    defects = [r for r in results if r["caught"] is not None]
    return {"defect_cases": len(defects), "caught": sum(r["caught"] for r in defects),
            "clean_cases": len(results) - len(defects),
            "false_blockers": sum(r["false_blockers"] for r in results)}


def keep(old, new):
    """Keep a reviewer change only when the score rose: more defects caught without more false
    blockers, or fewer false blockers without fewer caught. Equal scores keep the old reviewer."""
    if new["caught"] < old["caught"] or new["false_blockers"] > old["false_blockers"]:
        return False
    return new["caught"] > old["caught"] or new["false_blockers"] < old["false_blockers"]


def build_cases(pulls, diffs):
    """Cases from saved PR data. `pulls`: [{number, title, body, merged, reviewed_head}]; `diffs`:
    {key: unified diff} with keys `intro:<n>` (the PR at its reviewed head) and `fix:<n>`. A fix PR
    names its defective PR on a `Defect: <ID>` line; the defective PR is the merged one whose title
    starts with that ID. PRs with no diff on hand are skipped."""
    by_id = {}
    for p in pulls:
        if p.get("merged"):
            by_id.setdefault(p["title"].split()[0].rstrip(":"), p)
    cases, defective = [], set()
    for fix in pulls:
        for m in DEFECT.finditer(fix.get("body") or ""):
            for pid in (x.strip() for x in m.group(1).split(",")):
                intro = by_id.get(pid)
                if not (fix.get("merged") and intro and intro["number"] != fix["number"]
                        and f"intro:{intro['number']}" in diffs and f"fix:{fix['number']}" in diffs):
                    continue
                defective.add(intro["number"])
                exp = expected_ranges(diffs[f"fix:{fix['number']}"])
                if exp:
                    cases.append({"id": f"pr{intro['number']}-fix{fix['number']}", "kind": "defect",
                                  "intro_pr": intro["number"], "fix_pr": fix["number"],
                                  "head": intro.get("reviewed_head"), "expected": exp,
                                  "diff": diffs[f"intro:{intro['number']}"]})
    return cases, sorted(defective)


def add_clean(pulls, diffs, numbers, defective):
    """Known-clean merged PRs named by hand; one that has a Defect: fix is refused."""
    out = []
    for n in numbers:
        if n in defective:
            raise SystemExit(f"PR #{n} has a Defect: fix and cannot be a clean case")
        if f"intro:{n}" in diffs:
            out.append({"id": f"pr{n}-clean", "kind": "clean", "intro_pr": n, "diff": diffs[f"intro:{n}"]})
    return out


def run_reviewer(cmd, case, timeout=600):
    r = subprocess.run(cmd, shell=True, input=case["diff"], capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise SystemExit(f"reviewer failed on {case['id']}: {r.stderr[-300:]}")
    return json.loads(r.stdout or "[]")


def load_cases(directory):
    return [json.loads(p.read_text()) for p in sorted(pathlib.Path(directory).glob("*.json"))]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="action", required=True)
    b = sub.add_parser("build")
    b.add_argument("--pulls", required=True, help="JSON: PR list, with a `diffs` map next to it")
    b.add_argument("--out", default=str(ROOT / "evals/review/cases"))
    b.add_argument("--clean", default="", help="comma-separated merged PR numbers known to be clean")
    s = sub.add_parser("score")
    s.add_argument("--cases", default=str(ROOT / "evals/review/cases"))
    s.add_argument("--cmd", dest="reviewer", required=True)
    s.add_argument("--out")
    c = sub.add_parser("compare")
    c.add_argument("old")
    c.add_argument("new")
    a = ap.parse_args(argv)
    if a.action == "build":
        data = json.loads(pathlib.Path(a.pulls).read_text())
        cases, defective = build_cases(data["pulls"], data["diffs"])
        cases += add_clean(data["pulls"], data["diffs"], [int(x) for x in a.clean.split(",") if x], defective)
        out = pathlib.Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        for case in cases:
            (out / f"{case['id']}.json").write_text(json.dumps(case, indent=1, sort_keys=True) + "\n")
        print(f"{len(cases)} cases")
        return 0
    if a.action == "score":
        cases = load_cases(a.cases)
        results = [score_case(k, run_reviewer(a.reviewer, k)) for k in cases]
        summary = summarize(results)
        text = json.dumps(summary, sort_keys=True)
        if a.out:
            pathlib.Path(a.out).write_text(text + "\n")
        print(text)
        return 0
    old, new = (json.loads(pathlib.Path(x).read_text()) for x in (a.old, a.new))
    ok = keep(old, new)
    print("keep" if ok else "discard")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
