#!/usr/bin/env python3
"""Reviewer eval (REVIEW-eval, #2166; cases live in evals/review/cases, added with the first corpus): score a reviewer prompt against bugs the reviews missed.

A case is a merged PR that a later `Defect: <ID>` PR fixed. It holds the introducing PR's diff
and, as the expected finding, the lines the fix PR changed. The introducing PR is the latest
merged PR of that ID merged before the fix. A clean case is a merged PR of an ID no `Defect:`
line names. Score = caught blockers - false blockers; a change is kept only when `keep` says the
score rose on the same case set.

  revieweval.py build --repo owner/name [--out evals/review/cases]   (reads GITHUB_TOKEN)
  revieweval.py build --pulls pulls.json                             (saved PR data, no network)
  revieweval.py score --cases evals/review/cases --cmd "<reviewer>" --out score.json
  revieweval.py compare old.json new.json                            (exit 0 = keep the change)

The reviewer command reads the case diff on stdin and prints a JSON list of findings,
`[{"file": "a.go", "line": 12, "class": "blocker"}]`. Only a `blocker` can catch a defect. It is the caller's command: a prompt, tool
or model change is a different --cmd. Cases are data files, so scoring needs no network.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFECT = re.compile(r"^Defect:\s*(\S.*?)\s*$", re.M)
MAX_DIFF = 150_000  # bytes; a larger PR is not a case a reviewer reads whole
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
    """A defect case is caught when a finding classed blocker lands inside the fix's hunks; a
    `later` or `release` finding never catches. A blocker outside the hunks of a defect case, or
    any blocker on a clean case, is a false blocker."""
    blockers = [f for f in findings if f.get("class", "blocker") == "blocker"]
    if case["kind"] == "clean":
        return {"caught": None, "false_blockers": len(blockers)}
    exp = {f: [tuple(r) for r in rs] for f, rs in case["expected"].items()}
    return {"caught": any(hit(f, exp) for f in blockers),
            "false_blockers": sum(not hit(f, exp) for f in blockers)}


def case_set(cases):
    """Digest of the case ids and contents: scores are comparable only on equal digests."""
    h = hashlib.sha256()
    for c in sorted(cases, key=lambda c: c["id"]):
        h.update(json.dumps(c, sort_keys=True).encode())
    return h.hexdigest()[:16]


def summarize(results, cases=()):
    defects = [r for r in results if r["caught"] is not None]
    caught, false = sum(r["caught"] for r in defects), sum(r["false_blockers"] for r in results)
    return {"defect_cases": len(defects), "caught": caught,
            "clean_cases": len(results) - len(defects), "false_blockers": false,
            "score": caught - false, "case_set": case_set(cases)}


def keep(old, new):
    """Keep a reviewer change only when the score (caught - false blockers) rose without fewer
    catches, so neither silence nor noise wins. Equal scores keep the old reviewer. Scores from
    different case sets are not comparable and raise."""
    if old.get("case_set") != new.get("case_set"):
        raise SystemExit("scores come from different case sets; re-score both on the same cases")
    return new["caught"] >= old["caught"] and new["score"] > old["score"]


def _pid(p):
    return p["title"].split()[0].rstrip(":") if p.get("title", "").split() else ""


def _refs(pull):
    return [x.strip() for m in DEFECT.finditer(pull.get("body") or "") for x in m.group(1).split(",")]


def wanted(pulls):
    """PR numbers whose diffs build_cases may use: every merged PR carrying a `Defect:` line and
    the PRs it can point at."""
    ids = {i for p in pulls if p.get("merged_at") for i in _refs(p)}
    return sorted({p["number"] for p in pulls if p.get("merged_at") and (_refs(p) or _pid(p) in ids)})


def build_cases(pulls, diffs):
    """Defect cases from PR data. `pulls`: [{number, title, body, merged_at, reviewed_head}];
    `diffs`: {key: unified diff} with keys `intro:<n>` and `fix:<n>`. A fix PR names its defective
    ID on a `Defect: <ID>` line; the defective PR is the latest merged PR whose title starts with
    that ID and that merged before the fix. PRs with no diff on hand are skipped. Returns
    (cases, defective PR numbers)."""
    by_id = {}
    for p in sorted((p for p in pulls if p.get("merged_at")), key=lambda p: p["merged_at"]):
        by_id.setdefault(_pid(p), []).append(p)
    cases, defective = [], set()
    for fix in pulls:
        if not fix.get("merged_at"):
            continue
        for pid in _refs(fix):
            intros = [p for p in by_id.get(pid, []) if p["merged_at"] < fix["merged_at"] and p["number"] != fix["number"]]
            if not intros:
                continue
            intro = intros[-1]
            if f"intro:{intro['number']}" not in diffs or f"fix:{fix['number']}" not in diffs:
                continue
            exp = expected_ranges(diffs[f"fix:{fix['number']}"])
            if exp:
                defective.add(intro["number"])
                cases.append({"id": f"pr{intro['number']}-fix{fix['number']}", "kind": "defect",
                              "intro_pr": intro["number"], "fix_pr": fix["number"],
                              "head": intro.get("reviewed_head"), "expected": exp,
                              "diff": diffs[f"intro:{intro['number']}"]})
    return cases, sorted(defective)


def pick_clean(pulls, diffs, count):
    """`count` known-clean cases, evenly spaced over merged PRs that carry a diff, name no defect
    and whose ID no `Defect:` line names."""
    named = {i for p in pulls if p.get("merged_at") for i in _refs(p)}
    pool = sorted((p for p in pulls if p.get("merged_at") and not _refs(p) and _pid(p) not in named
                   and f"intro:{p['number']}" in diffs), key=lambda p: p["number"])
    step = max(len(pool) // count, 1) if count else 1
    return [{"id": f"pr{p['number']}-clean", "kind": "clean", "intro_pr": p["number"],
             "diff": diffs[f"intro:{p['number']}"]} for p in pool[::step][:count]]


def _get(url, token, accept):
    req = urllib.request.Request(url, headers={"Accept": accept, "X-GitHub-Api-Version": "2022-11-28",
                                               **({"Authorization": f"Bearer {token}"} if token else {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def fetch(repo, token, count_clean=10):
    """(pulls, diffs) from GitHub: all closed PRs, then the diffs build_cases and pick_clean need."""
    pulls, page = [], 1
    while True:
        batch = json.loads(_get(f"https://api.github.com/repos/{repo}/pulls?state=closed&per_page=100&page={page}",
                                token, "application/vnd.github+json"))
        pulls += [{"number": p["number"], "title": p["title"], "body": p.get("body") or "",
                   "merged_at": p.get("merged_at"), "reviewed_head": p["head"]["sha"]} for p in batch]
        if len(batch) < 100:
            break
        page += 1
    diffs = {}
    need = set(wanted(pulls))
    named = {i for p in pulls if p.get("merged_at") for i in _refs(p)}
    clean = [p for p in pulls if p.get("merged_at") and not _refs(p) and _pid(p) not in named]
    need |= {p["number"] for p in clean[::max(len(clean) // max(count_clean, 1), 1)][:count_clean]}
    for n in sorted(need):
        try:
            d = _get(f"https://api.github.com/repos/{repo}/pulls/{n}", token, "application/vnd.github.diff")
        except OSError:
            continue
        if len(d) <= MAX_DIFF:
            diffs[f"intro:{n}"] = diffs[f"fix:{n}"] = d
    return pulls, diffs


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
    src = b.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo", help="owner/name; fetch merged PRs from GitHub (GITHUB_TOKEN)")
    src.add_argument("--pulls", help="JSON {pulls, diffs} saved earlier; no network")
    b.add_argument("--out", default=str(ROOT / "evals/review/cases"))
    b.add_argument("--clean", type=int, default=10, help="number of known-clean cases")
    s = sub.add_parser("score")
    s.add_argument("--cases", default=str(ROOT / "evals/review/cases"))
    s.add_argument("--cmd", dest="reviewer", required=True)
    s.add_argument("--out")
    c = sub.add_parser("compare")
    c.add_argument("old")
    c.add_argument("new")
    a = ap.parse_args(argv)
    if a.action == "build":
        if a.repo:
            pulls, diffs = fetch(a.repo, os.environ.get("GITHUB_TOKEN"), a.clean)
        else:
            data = json.loads(pathlib.Path(a.pulls).read_text())
            pulls, diffs = data["pulls"], data["diffs"]
        cases, _ = build_cases(pulls, diffs)
        cases += pick_clean(pulls, diffs, a.clean)
        out = pathlib.Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        for old in out.glob("*.json"):
            old.unlink()
        for case in cases:
            (out / f"{case['id']}.json").write_text(json.dumps(case, indent=1, sort_keys=True) + "\n")
        print(f"{len(cases)} cases")
        return 0
    if a.action == "score":
        cases = load_cases(a.cases)
        summary = summarize([score_case(k, run_reviewer(a.reviewer, k)) for k in cases], cases)
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
