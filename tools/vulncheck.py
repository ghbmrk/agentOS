#!/usr/bin/env python3
"""Known-vulnerability gate (SPEC EVL-5, A22 "Known vulnerabilities"; TN-vulncheck, #2855).

run      govulncheck on each Go target of assurance/vulncheck.json and an OSV scan of every
         lockfile in the tree. A finding fails unless a record in that file accepts it:
           - Go: a vulnerable symbol reachable from the target's code, or any finding in a
             module the target vendors (vendor/modules.txt). An unreachable finding in the
             standard library or a module the target does not vendor is reported, not failed.
           - OSV: any vulnerability in a non-Go package (Go is govulncheck's). Every lockfile
             in the tree ships in the image or is vendored, so presence alone fails.
         A record names the vulnerability (its ID or any alias), the issue that records why it
         is accepted, and the reason. With --check-issues each cited issue must be an open
         issue (not a PR) on GITHUB_REPOSITORY, read with GITHUB_TOKEN; closing the issue
         withdraws the acceptance.
control  The same scan against tests/fixtures/vulncheck with planted synthetic databases,
         offline: every planted vulnerability must fail, the unreachable standard-library one
         must not, and the fixture's acceptance records must clear the rest. The workflow runs
         it first, so a clean `run` counts only because the same scanners, in the same job,
         caught every plant.

A scan that reads nothing fails: a govulncheck stream with no config or no modules, an
expected lockfile the OSV scan did not report, or a scanner exit code other than its
clean/found codes.

Usage:
  vulncheck.py run [--config F] [--root DIR] [--report F] [--check-issues]
  vulncheck.py control
Exit 0 pass, 1 unaccepted findings or a failed check, 2 a scanner or usage error.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "assurance" / "vulncheck.json"
FIXTURE = ROOT / "tests" / "fixtures" / "vulncheck"
STDLIB = "stdlib"
# osv-scanner: 0 nothing found, 1 vulnerabilities found; anything else is an error.
OSV_OK = (0, 1)
RECORD_KEYS = {"id", "issue", "why", "where"}

# What the control must see with no records: the reachable symbol, the vendored module's
# unreachable package, and the npm plant. GO-0000-0003 (stdlib fmt, symbol not called) passes.
CONTROL_FAILS = {"GO-0000-0001", "GO-0000-0002", "AGENTOS-VULNCHECK-CONTROL-1"}
CONTROL_INFO = {"GO-0000-0003"}
CONTROL_CONFIG = {
    "go_targets": ["gomod"],
    "osv_sources": ["npm/package-lock.json"],
    "skip_paths": [],
    "accepted": [
        {"id": "CVE-0000-0001", "issue": 1, "why": "control: accepted by alias"},
        {"id": "GO-0000-0002", "issue": 1, "why": "control: accepted by ID", "where": "gomod"},
        {"id": "GHSA-0000-0000-0001", "issue": 1, "why": "control: accepted by alias",
         "where": "npm/package-lock.json"},
    ],
}


class ScanError(Exception):
    """A scanner did not run, or its output cannot be read."""


def json_stream(text):
    """The JSON values in a stream of concatenated values (govulncheck -format json)."""
    dec, out, i = json.JSONDecoder(), [], 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i == len(text):
            return out
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError as e:
            raise ScanError(f"govulncheck output is not a JSON stream at offset {i}: {e}")
        out.append(obj)


def vendored(target_dir):
    """Module paths the target vendors: each `# path version` line of vendor/modules.txt."""
    f = pathlib.Path(target_dir) / "vendor" / "modules.txt"
    if not f.exists():
        return set()
    return {m.group(1) for m in re.finditer(r"^# (\S+) \S+", f.read_text(), re.M)}


def level(trace):
    """symbol, package or module: how precisely govulncheck placed one finding."""
    top = trace[0] if trace else {}
    return "symbol" if top.get("function") else "package" if top.get("package") else "module"


RANK = {"module": 0, "package": 1, "symbol": 2}


def go_findings(where, objs, vendored_mods):
    """One finding per OSV ID from a govulncheck stream, at its most precise level."""
    if not any("config" in o for o in objs):
        raise ScanError(f"{where}: govulncheck wrote no config message, so it did not scan")
    sbom = next((o["SBOM"] for o in objs if "SBOM" in o), None)
    if not sbom or not sbom.get("modules"):
        raise ScanError(f"{where}: govulncheck listed no modules, so it scanned nothing")
    aliases = {o["osv"]["id"]: o["osv"].get("aliases") or [] for o in objs if "osv" in o}
    best = {}
    for o in objs:
        f = o.get("finding")
        if not f:
            continue
        trace = f.get("trace") or []
        lv = level(trace)
        if f["osv"] in best and RANK[best[f["osv"]]["level"]] >= RANK[lv]:
            continue
        top = trace[0] if trace else {}
        mod = top.get("module", "")
        best[f["osv"]] = {
            "where": where, "id": f["osv"], "aliases": aliases.get(f["osv"], []),
            "level": lv, "module": mod, "version": top.get("version", ""),
            "package": top.get("package", ""), "function": top.get("function", ""),
            "fixed": f.get("fixed_version", ""),
            "fails": lv == "symbol" or (mod != STDLIB and mod in vendored_mods),
        }
    return sorted(best.values(), key=lambda x: x["id"])


def osv_findings(doc, root, skip, expected):
    """Findings from an osv-scanner JSON report, and the problems with what it scanned."""
    root = pathlib.Path(root).resolve()
    found, scanned, problems = [], set(), []
    for res in doc.get("results") or []:
        p = pathlib.Path(res["source"]["path"])
        rel = (p.resolve().relative_to(root) if p.is_absolute() else p).as_posix()
        if any(rel == s.rstrip("/") or rel.startswith(s.rstrip("/") + "/") for s in skip):
            continue
        if res.get("packages"):
            scanned.add(rel)
        for pkg in res.get("packages") or []:
            meta = pkg["package"]
            if meta.get("ecosystem") == "Go":
                continue  # govulncheck's, with reachability
            for g in pkg.get("groups") or [{"ids": [v["id"]], "aliases": v.get("aliases") or []}
                                          for v in pkg.get("vulnerabilities") or []]:
                ids = list(dict.fromkeys(g["ids"] + (g.get("aliases") or [])))
                found.append({
                    "where": rel, "id": ids[0], "aliases": ids[1:], "level": "package",
                    "module": meta.get("name", ""), "version": meta.get("version", ""),
                    "package": f"{meta.get('ecosystem', '')}:{meta.get('name', '')}",
                    "function": "", "fixed": "", "fails": True,
                })
    for want in expected:
        if want not in scanned:
            problems.append(f"{want}: the OSV scan reported no packages for this lockfile")
    return sorted(found, key=lambda x: (x["where"], x["id"])), problems


def record_problems(records):
    """Shape problems in the acceptance records."""
    problems = []
    for n, r in enumerate(records):
        tag = f"accepted[{n}]"
        if not isinstance(r, dict):
            problems.append(f"{tag}: not an object")
            continue
        if set(r) - RECORD_KEYS:
            problems.append(f"{tag}: unknown keys {sorted(set(r) - RECORD_KEYS)}")
        if not isinstance(r.get("id"), str) or not r["id"].strip():
            problems.append(f"{tag}: no vulnerability id")
        if not isinstance(r.get("issue"), int) or isinstance(r.get("issue"), bool) or r["issue"] < 1:
            problems.append(f"{tag}: issue must be an issue number")
        if not isinstance(r.get("why"), str) or not r["why"].strip():
            problems.append(f"{tag}: no reason")
        if "where" in r and (not isinstance(r["where"], str) or not r["where"].strip()):
            problems.append(f"{tag}: where must name a Go target or lockfile")
    return problems


def apply_records(findings, records):
    """Mark each failing finding a record accepts; return the records nothing used."""
    used = set()
    for f in findings:
        names = {f["id"], *f["aliases"]}
        for n, r in enumerate(records):
            if r["id"] in names and r.get("where", f["where"]) == f["where"]:
                f["accepted_by"] = r["issue"]
                used.add(n)
                break
    return [r for n, r in enumerate(records) if n not in used]


def issue_problems(records, repo, token, opener=urllib.request.urlopen):
    """Each cited issue must exist on repo, be an issue rather than a PR, and be open."""
    problems = []
    for num in sorted({r["issue"] for r in records}):
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/issues/{num}",
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"})
        try:
            with opener(req, timeout=30) as resp:
                issue = json.load(resp)
        except urllib.error.HTTPError as e:
            problems.append(f"issue #{num}: GitHub answered {e.code}")
            continue
        except (urllib.error.URLError, OSError, ValueError) as e:
            problems.append(f"issue #{num}: could not read it ({e})")
            continue
        if "pull_request" in issue:
            problems.append(f"issue #{num} is a pull request; an acceptance names an issue")
        elif issue.get("state") != "open":
            problems.append(f"issue #{num} is {issue.get('state')}; a closed issue withdraws the acceptance")
    return problems


def run_govulncheck(target_dir, db=None):
    exe = shutil.which("govulncheck")
    if not exe:
        raise ScanError("govulncheck is not on PATH")
    cmd = [exe, "-format", "json"] + (["-db", db] if db else []) + ["./..."]
    p = subprocess.run(cmd, cwd=target_dir, capture_output=True, text=True)
    if p.returncode != 0:
        raise ScanError(f"{target_dir}: govulncheck exited {p.returncode}: {p.stderr.strip()[-2000:]}")
    return json_stream(p.stdout)


def run_osv(root, env=None, offline=False):
    exe = shutil.which("osv-scanner")
    if not exe:
        raise ScanError("osv-scanner is not on PATH")
    cmd = [exe, "scan", "source", "-r", "--format", "json", "--all-packages", "--all-vulns",
           "--no-call-analysis=all"]  # Go reachability is govulncheck's, run above
    if offline:
        cmd += ["--offline", "--offline-vulnerabilities"]
    p = subprocess.run(cmd + ["."], cwd=root, capture_output=True, text=True,
                       env={**os.environ, **(env or {})})
    if p.returncode not in OSV_OK:
        raise ScanError(f"osv-scanner exited {p.returncode}: {p.stderr.strip()[-2000:]}")
    try:
        return json.loads(p.stdout)
    except ValueError as e:
        raise ScanError(f"osv-scanner output is not JSON: {e}")


def scan(config, root, go_db=None, osv_env=None, offline=False):
    """Findings and problems for one tree; records applied, issues not checked."""
    records = config.get("accepted", [])
    problems = record_problems(records)
    if problems:
        return [], problems, []
    findings = []
    for t in config["go_targets"]:
        d = pathlib.Path(root) / t
        findings += go_findings(t, run_govulncheck(d, go_db), vendored(d))
    osv, osv_problems = osv_findings(run_osv(root, osv_env, offline), root,
                                     config.get("skip_paths", []), config.get("osv_sources", []))
    findings += osv
    problems += osv_problems
    unused = apply_records([f for f in findings if f["fails"]], records)
    return findings, problems, unused


def verdict(f):
    if not f["fails"]:
        return "info"
    return f"accepted #{f['accepted_by']}" if "accepted_by" in f else "FAIL"


def summary(findings, problems, unused, out=None):
    out = out or sys.stdout
    for f in findings:
        alias = f" ({', '.join(f['aliases'])})" if f["aliases"] else ""
        at = f"{f['package']}.{f['function']}" if f["function"] else f["package"] or f["module"]
        fix = f", fixed in {f['fixed']}" if f["fixed"] else ""
        print(f"{verdict(f):12} {f['where']}: {f['id']}{alias} {f['level']} {at} "
              f"{f['version']}{fix}", file=out)
    for r in unused:
        print(f"unused record: {r['id']} (issue #{r['issue']}) matches no finding; remove it", file=out)
    for p in problems:
        print(f"problem: {p}", file=out)
    failing = [f for f in findings if verdict(f) == "FAIL"]
    print(f"{len(findings)} findings, {len(failing)} failing, {len(problems)} problems", file=out)
    return not failing and not problems


def control():
    """Run the scan on the fixture with planted databases; return problems with the result."""
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        # osv-scanner 2.5's offline layout; Go is empty here, since govulncheck owns Go.
        for name in ("npm", "Go"):
            eco = pathlib.Path(tmp) / "osv-scalibr" / name
            eco.mkdir(parents=True)
            with zipfile.ZipFile(eco / "all.zip", "w") as z:
                for f in sorted((FIXTURE / "osvdb" / name).glob("*.json")):
                    z.write(f, f.name)
        kw = dict(go_db=(FIXTURE / "godb").as_uri(), offline=True,
                  osv_env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": tmp})
        bare = {**CONTROL_CONFIG, "accepted": []}
        findings, probs, _ = scan(bare, FIXTURE, **kw)
        summary(findings, probs, [])
        problems += [f"no records: {p}" for p in probs]
        fails = {f["id"] for f in findings if f["fails"]}
        info = {f["id"] for f in findings if not f["fails"]}
        if fails != CONTROL_FAILS:
            problems.append(f"planted failures: want {sorted(CONTROL_FAILS)}, got {sorted(fails)}")
        if info != CONTROL_INFO:
            problems.append(f"unreachable non-vendored: want {sorted(CONTROL_INFO)}, got {sorted(info)}")
        findings, probs, unused = scan(CONTROL_CONFIG, FIXTURE, **kw)
        problems += [f"with records: {p}" for p in probs]
        if not summary(findings, probs, unused) or unused:
            problems.append("the fixture's records did not clear every planted failure")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--config", default=str(CONFIG))
    r.add_argument("--root", default=str(ROOT))
    r.add_argument("--report")
    r.add_argument("--check-issues", action="store_true")
    sub.add_parser("control")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "control":
            problems = control()
            for p in problems:
                print(f"control failed: {p}", file=sys.stderr)
            print("control: every plant caught" if not problems else "control: FAILED")
            return 1 if problems else 0
        config = json.loads(pathlib.Path(a.config).read_text())
        findings, problems, unused = scan(config, a.root)
    except ScanError as e:
        print(f"vulncheck: {e}", file=sys.stderr)
        return 2
    if a.check_issues and not record_problems(config.get("accepted", [])):
        repo, token = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_TOKEN")
        if not repo or not token:
            problems.append("--check-issues needs GITHUB_REPOSITORY and GITHUB_TOKEN")
        else:
            problems += issue_problems(config.get("accepted", []), repo, token)
    ok = summary(findings, problems, unused)
    if a.report:
        pathlib.Path(a.report).write_text(json.dumps(
            {"findings": [{**f, "verdict": verdict(f)} for f in findings],
             "problems": problems, "unused_records": unused}, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
