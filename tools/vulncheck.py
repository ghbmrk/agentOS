#!/usr/bin/env python3
"""Known-vulnerability gate (SPEC EVL-5, A22 "Known vulnerabilities"; TN-vulncheck, #2855).

run      govulncheck on each Go target of assurance/vulncheck.json, an OSV scan of every
         lockfile in the tree, and an OSV scan of each module a target replaces with a
         directory (TN-vulncheck-2, #2886). A finding fails unless a record in that file
         accepts it:
           - Go: a vulnerable symbol reachable from the target's code, or any finding in a
             module the target vendors (vendor/modules.txt). An unreachable finding in the
             standard library or a module the target does not vendor is reported, not failed.
           - OSV: any vulnerability in a non-Go package (Go is govulncheck's). Every lockfile
             in the tree ships in the image or is vendored, so presence alone fails.
           - Fork: any vulnerability in the release a directory-replaced module's require
             line names (broker/third_party/go-imap is upstream go-imap v1.2.1). govulncheck
             sees no version for such a module and matches nothing, and the fork is vendored
             code, so presence alone fails; a record accepts one the fork has fixed.
         A record names the vulnerability (its ID or any alias), the issue that records why it
         is accepted, and the reason. With --check-issues each cited issue must be an open
         issue (not a PR) on GITHUB_REPOSITORY that names the record's id in its title or
         body, read with GITHUB_TOKEN; closing the issue withdraws the acceptance.
image    An OSV scan of the Debian packages in a built image: DIR holds the dpkg status
         file and os-release that image/mkosi/mkosi.postinst copies out of the build tree
         (agentos.dpkg-status, agentos.os-release). osv-scanner reads them as a one-layer
         container image, so each installed package is queried by its source package in
         Debian:<VERSION_ID>. Any vulnerability fails; only records whose where is "image"
         apply here, and `run` ignores those records.
control  The same scans against tests/fixtures/vulncheck with planted synthetic databases,
         offline: every planted vulnerability must fail, the unreachable standard-library one
         must not, and the fixture's acceptance records must clear the rest. The workflows run
         it first, so a clean `run` or `image` counts only because the same scanners, in the
         same job, caught every plant.

A scan that reads nothing fails: an empty go_targets or osv_sources, a govulncheck stream
with no config or no modules, an expected lockfile the OSV scan did not report, a go.mod
outside every Go target (neither scanner would check it), a directory-replaced module the
fork scan did not report, an image scan with no packages or with packages outside a
versioned Debian ecosystem, or a scanner exit code other than its clean/found codes. The OSV scan ignores .gitignore, so a tracked lockfile cannot
be hidden by one.

Usage:
  vulncheck.py run [--config F] [--root DIR] [--report F] [--check-issues]
  vulncheck.py image DIR [--config F] [--report F] [--check-issues]
  vulncheck.py control
Exit 0 pass, 1 unaccepted findings or a failed check, 2 a scanner or usage error.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
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
# The `where` of every image finding, and of every record that accepts one.
IMAGE = "image"
# What mkosi.postinst writes to the image build's output directory.
DPKG_STATUS, OS_RELEASE = "agentos.dpkg-status", "agentos.os-release"

# What the control must see with no records, as (where, ID): the reachable symbol, the
# vendored module's unreachable package, the npm plant, and the same plant in a tracked
# lockfile that a .gitignore beside it names (osv-scanner skips those without --no-ignore),
# and the directory-replaced example.com/fork's required release.
# GO-0000-0003 (stdlib fmt, symbol not called) passes.
CONTROL_FAILS = {("gomod", "GO-0000-0001"), ("gomod", "GO-0000-0002"),
                 ("gomod", "AGENTOS-VULNCHECK-FORK-1"),
                 ("npm/package-lock.json", "AGENTOS-VULNCHECK-CONTROL-1"),
                 ("ignored/package-lock.json", "AGENTOS-VULNCHECK-CONTROL-1")}
CONTROL_INFO = {("gomod", "GO-0000-0003")}
# The image plants: binary libplant1 of source agentos-plant 1.0-1, queried by its source, whose
# advisory Debian has fixed (in 1.0-2), so no record can accept it; and agentos-nofix, whose
# advisory has no fix, which the fixture's record accepts. agentos-fixed is at its advisory's fixed version, and agentos-removed (source agentos-gone,
# which has its own advisory) is not installed, so none of them may be reported.
CONTROL_IMAGE_FAILS = {(IMAGE, "AGENTOS-VULNCHECK-DEB-1"), (IMAGE, "AGENTOS-VULNCHECK-DEB-4")}
# With the fixture's records: the fixed advisory still fails and its record goes unused.
CONTROL_IMAGE_VERDICTS = {("AGENTOS-VULNCHECK-DEB-1", "FAIL"), ("AGENTOS-VULNCHECK-DEB-4", "accepted #1")}
CONTROL_CONFIG = {
    "go_targets": ["gomod"],
    "osv_sources": ["npm/package-lock.json"],
    "skip_paths": [],
    "accepted": [
        {"id": "CVE-0000-0001", "issue": 1, "why": "control: accepted by alias"},
        {"id": "GO-0000-0002", "issue": 1, "why": "control: accepted by ID", "where": "gomod"},
        {"id": "GHSA-0000-0000-0001", "issue": 1, "why": "control: accepted by alias",
         "where": "npm/package-lock.json"},
        {"id": "AGENTOS-VULNCHECK-CONTROL-1", "issue": 1, "why": "control: accepted by ID",
         "where": "ignored/package-lock.json"},
        {"id": "CVE-0000-0102", "issue": 1, "why": "control: fork accepted by alias", "where": "gomod"},
        {"id": "AGENTOS-VULNCHECK-DEB-1", "issue": 1, "why": "control: Debian has fixed it, so this "
         "cannot accept it", "where": IMAGE},
        {"id": "CVE-0000-0105", "issue": 1, "why": "control: no Debian fix; accepted by alias",
         "where": IMAGE},
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


def under(rel, dirs):
    return any(rel == d.rstrip("/") or rel.startswith(d.rstrip("/") + "/") for d in dirs)


def _vulns(pkg, where, package, version):
    """One failing finding per vulnerability group of one package in an osv-scanner report."""
    out = []
    for g in pkg.get("groups") or [{"ids": [v["id"]], "aliases": v.get("aliases") or []}
                                  for v in pkg.get("vulnerabilities") or []]:
        ids = list(dict.fromkeys(g["ids"] + (g.get("aliases") or [])))
        out.append({
            "where": where, "id": ids[0], "aliases": ids[1:], "level": "package",
            "module": pkg["package"].get("name", ""), "version": version,
            "package": package, "function": "", "fixed": "", "fails": True,
        })
    return out


def osv_findings(doc, root, skip, expected, go_targets=()):
    """Findings from an osv-scanner JSON report, and the problems with what it scanned.

    Go packages are left to govulncheck, so a go.mod outside every Go target (and outside
    skip_paths) is a problem: neither scanner would check its dependencies."""
    root = pathlib.Path(root).resolve()
    found, scanned, problems = [], set(), []
    for res in doc.get("results") or []:
        p = pathlib.Path(res["source"]["path"])
        rel = (p.resolve().relative_to(root) if p.is_absolute() else p).as_posix()
        if under(rel, skip):
            continue
        if pathlib.PurePosixPath(rel).name == "go.mod" and not under(rel, go_targets):
            problems.append(f"{rel}: a Go module outside go_targets; add it there or to skip_paths")
        if res.get("packages"):
            scanned.add(rel)
        for pkg in res.get("packages") or []:
            meta = pkg["package"]
            if meta.get("ecosystem") == "Go":
                continue  # govulncheck's, with reachability
            found += _vulns(pkg, rel, f"{meta.get('ecosystem', '')}:{meta.get('name', '')}",
                            meta.get("version", ""))
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
    """Each cited issue must exist on repo, be an issue rather than a PR, be open, and name
    the vulnerability (the record's id) in its title or body."""
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
        else:
            text = f"{issue.get('title') or ''}\n{issue.get('body') or ''}"
            for r in records:
                if r["issue"] == num and r["id"] not in text:
                    problems.append(f"issue #{num} does not name {r['id']}, which a record accepts with it")
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


def osv_scan(args, cwd, env=None, offline=False):
    """osv-scanner's JSON report for `scan ARGS` (ARGS[0] is the subcommand)."""
    exe = shutil.which("osv-scanner")
    if not exe:
        raise ScanError("osv-scanner is not on PATH")
    cmd = [exe, "scan", args[0], "--format", "json", "--all-packages", "--all-vulns"]
    if offline:
        cmd += ["--offline", "--offline-vulnerabilities"]
    p = subprocess.run(cmd + args[1:], cwd=cwd, capture_output=True, text=True,
                       env={**os.environ, **(env or {})})
    if p.returncode not in OSV_OK:
        raise ScanError(f"osv-scanner exited {p.returncode}: {p.stderr.strip()[-2000:]}")
    try:
        return json.loads(p.stdout)
    except ValueError as e:
        raise ScanError(f"osv-scanner output is not JSON: {e}")


def run_osv(root, env=None, offline=False):
    # --no-ignore: a .gitignore the PR adds must not hide a tracked lockfile from the scan.
    # Go reachability is govulncheck's, run above.
    return osv_scan(["source", "-r", "--no-ignore", "--no-call-analysis=all", "."], root, env, offline)


def dir_replaced(target_dir):
    """(module, version, directory) for each required module the target's go.mod replaces
    with a directory. The version is the one its require line (or the replace's left side)
    names: the upstream release the fork was taken from."""
    p = subprocess.run(["go", "mod", "edit", "-json"], cwd=target_dir, capture_output=True, text=True)
    if p.returncode != 0:
        raise ScanError(f"{target_dir}: go mod edit -json exited {p.returncode}: {p.stderr.strip()[-2000:]}")
    try:
        mod = json.loads(p.stdout)
    except ValueError as e:
        raise ScanError(f"{target_dir}: go mod edit -json is not JSON: {e}")
    req = {r["Path"]: r["Version"] for r in mod.get("Require") or []}
    out = []
    for r in mod.get("Replace") or []:
        if r["New"].get("Version"):
            continue  # a module replacement has a version, which govulncheck matches
        path = r["Old"]["Path"]
        version = r["Old"].get("Version") or req.get(path)
        if version:
            out.append((path, version, r["New"]["Path"]))
    return sorted(out)


def fork_findings(where, doc, forks):
    """Findings for a target's directory-replaced modules from an osv-scanner report of the
    custom lockfile fork_lockfile wrote, and the forks it did not report."""
    by_name = {path: (version, new) for path, version, new in forks}
    found, scanned = [], set()
    for res in doc.get("results") or []:
        for pkg in res.get("packages") or []:
            meta = pkg["package"]
            if meta.get("ecosystem") != "Go" or meta.get("name") not in by_name:
                continue
            scanned.add(meta["name"])
            version, new = by_name[meta["name"]]
            found += _vulns(pkg, where, f"Go:{meta['name']} => {new}", version)
    problems = [f"{where}: the fork scan reported nothing for {p} (replaced by {by_name[p][1]})"
                for p in sorted(set(by_name) - scanned)]
    return sorted(found, key=lambda x: x["id"]), problems


def fork_lockfile(forks, path):
    """osv-scanner's custom lockfile format, listing each fork at its upstream release."""
    pkgs = [{"package": {"name": p, "version": v.removeprefix("v"), "ecosystem": "Go"}}
            for p, v, _ in forks]
    pathlib.Path(path).write_text(json.dumps({"results": [{"source": {"path": "forks", "type": "lockfile"},
                                                           "packages": pkgs}]}))


def run_forks(where, target_dir, env=None, offline=False):
    forks = dir_replaced(target_dir)
    if not forks:
        return [], []
    with tempfile.TemporaryDirectory() as tmp:
        lock = pathlib.Path(tmp) / "osv-scanner.json"
        fork_lockfile(forks, lock)
        doc = osv_scan(["source", "-L", f"osv-scanner:{lock}"], tmp, env, offline)
    return fork_findings(where, doc, forks)


def image_archive(src, dest):
    """A one-layer docker-archive holding SRC's dpkg status and os-release where a Debian
    tree keeps them, the input osv-scanner's image scan reads: its dpkg extractor takes the
    ecosystem from os-release and queries each installed package by its source package."""
    files = {"etc/os-release": pathlib.Path(src) / OS_RELEASE,
             "var/lib/dpkg/status": pathlib.Path(src) / DPKG_STATUS}
    for f in files.values():
        if not f.is_file() or not f.stat().st_size:
            raise ScanError(f"{f}: missing or empty; the image build writes it (image/mkosi/mkosi.postinst)")
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w", format=tarfile.PAX_FORMAT) as t:
        for d in ("etc", "var", "var/lib", "var/lib/dpkg"):
            ti = tarfile.TarInfo(d)
            ti.type, ti.mode = tarfile.DIRTYPE, 0o755
            t.addfile(ti)
        for name, f in files.items():
            data = f.read_bytes()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o644
            t.addfile(ti, io.BytesIO(data))
    layer = layer.getvalue()
    diff = hashlib.sha256(layer).hexdigest()
    cfg = json.dumps({"architecture": "amd64", "os": "linux", "config": {},
                      "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff}"]},
                      "history": [{"created_by": "tools/vulncheck.py image"}]}).encode()
    cfg_name = hashlib.sha256(cfg).hexdigest() + ".json"
    manifest = json.dumps([{"Config": cfg_name, "RepoTags": ["agentos:packages"],
                            "Layers": [f"{diff}/layer.tar"]}]).encode()
    with tarfile.open(dest, "w") as t:
        for name, data in ((f"{diff}/layer.tar", layer), (cfg_name, cfg), ("manifest.json", manifest)):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))


def image_findings(doc):
    """Findings from an osv-scanner image report, and the problems with what it scanned."""
    found, problems, n = [], [], 0
    for res in doc.get("results") or []:
        for pkg in res.get("packages") or []:
            meta = pkg["package"]
            n += 1
            eco = meta.get("ecosystem", "")
            if not re.fullmatch(r"Debian:\d+", eco):
                problems.append(f"{meta.get('name')}: ecosystem {eco!r} is not a versioned Debian "
                                "release, so its advisories would not match; check agentos.os-release")
            binary = meta.get("os_package_name") or meta.get("name", "")
            vulns = _vulns(pkg, IMAGE, f"{eco}:{meta.get('name', '')} ({binary})", meta.get("version", ""))
            for f in vulns:
                f["fixed"] = debian_fix(pkg, {f["id"], *f["aliases"]}, meta.get("name"), eco)
            found += vulns
    if not n:
        problems.append("the image scan reported no packages")
    return sorted(found, key=lambda x: (x["id"], x["package"])), problems


def debian_fix(pkg, ids, name, eco):
    """The version that fixes one of IDS in source package NAME in ECO, from the advisory
    entries in one package of an osv-scanner report; "" when Debian has no fix there."""
    for v in pkg.get("vulnerabilities") or []:
        if v.get("id") not in ids:
            continue
        for a in v.get("affected") or []:
            pk = a.get("package") or {}
            if pk.get("ecosystem") == eco and pk.get("name") == name:
                for r in a.get("ranges") or []:
                    for e in r.get("events") or []:
                        if e.get("fixed"):
                            return e["fixed"]
    return ""


def run_image(src, env=None, offline=False):
    with tempfile.TemporaryDirectory() as tmp:
        tar = pathlib.Path(tmp) / "packages.tar"
        image_archive(src, tar)
        doc = osv_scan(["image", "--archive", str(tar)], tmp, env, offline)
    return image_findings(doc)


def scan(config, root, go_db=None, osv_env=None, offline=False):
    """Findings and problems for one tree; records applied, issues not checked."""
    problems = record_problems(config.get("accepted", []))
    records = [r for r in config.get("accepted", []) if r.get("where") != IMAGE]
    for key in ("go_targets", "osv_sources"):
        if not config.get(key):
            problems.append(f"{key} is empty, so that side of the scan would read nothing")
    if problems:
        return [], problems, []
    findings = []
    for t in config["go_targets"]:
        d = pathlib.Path(root) / t
        findings += go_findings(t, run_govulncheck(d, go_db), vendored(d))
        forks, fork_problems = run_forks(t, d, osv_env, offline)
        findings += forks
        problems += fork_problems
    osv, osv_problems = osv_findings(run_osv(root, osv_env, offline), root,
                                     config.get("skip_paths", []), config["osv_sources"],
                                     config["go_targets"])
    findings += osv
    problems += osv_problems
    unused = apply_records([f for f in findings if f["fails"]], records)
    return findings, problems, unused


def scan_image(config, src, osv_env=None, offline=False):
    """Findings and problems for one image's packages; image records applied.

    A record accepts only an advisory Debian has not fixed in the image's release: once a fix
    ships, the finding fails until the image is rebuilt with it, and the record goes unused."""
    problems = record_problems(config.get("accepted", []))
    if problems:
        return [], problems, []
    records = [r for r in config.get("accepted", []) if r.get("where") == IMAGE]
    findings, problems = run_image(src, osv_env, offline)
    return findings, problems, apply_records([f for f in findings if not f["fixed"]], records)


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
    if failing:
        print("fix: upgrade to the fixed version, or add a record to assurance/vulncheck.json "
              "naming an open issue that names the vulnerability and says why it is accepted", file=out)
    return not failing and not problems


def control():
    """Run the scan on the fixture with planted databases; return problems with the result."""
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        # osv-scanner 2.5's offline layout. Go holds only the fork plant: govulncheck owns
        # the rest of Go. Debian holds the image plants.
        for name in ("npm", "Go", "Debian"):
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
        fails = {(f["where"], f["id"]) for f in findings if f["fails"]}
        info = {(f["where"], f["id"]) for f in findings if not f["fails"]}
        if fails != CONTROL_FAILS:
            problems.append(f"planted failures: want {sorted(CONTROL_FAILS)}, got {sorted(fails)}")
        if info != CONTROL_INFO:
            problems.append(f"unreachable non-vendored: want {sorted(CONTROL_INFO)}, got {sorted(info)}")
        findings, probs, unused = scan(CONTROL_CONFIG, FIXTURE, **kw)
        problems += [f"with records: {p}" for p in probs]
        if not summary(findings, probs, unused) or unused:
            problems.append("the fixture's records did not clear every planted failure")

        img = dict(osv_env=kw["osv_env"], offline=True)
        findings, probs, _ = scan_image(bare, FIXTURE / IMAGE, **img)
        summary(findings, probs, [])
        problems += [f"image, no records: {p}" for p in probs]
        fails = {(f["where"], f["id"]) for f in findings}
        if fails != CONTROL_IMAGE_FAILS:
            problems.append(f"planted image failures: want {sorted(CONTROL_IMAGE_FAILS)}, got {sorted(fails)}")
        findings, probs, unused = scan_image(CONTROL_CONFIG, FIXTURE / IMAGE, **img)
        summary(findings, probs, unused)
        problems += [f"image, with records: {p}" for p in probs]
        got = {(f["id"], verdict(f)) for f in findings}
        if got != CONTROL_IMAGE_VERDICTS or [r["id"] for r in unused] != ["AGENTOS-VULNCHECK-DEB-1"]:
            problems.append(f"image records: want {sorted(CONTROL_IMAGE_VERDICTS)} with the DEB-1 record "
                            f"unused, got {sorted(got)}, unused {[r['id'] for r in unused]}")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--config", default=str(CONFIG))
    r.add_argument("--root", default=str(ROOT))
    r.add_argument("--report")
    r.add_argument("--check-issues", action="store_true")
    i = sub.add_parser("image")
    i.add_argument("dir")
    i.add_argument("--config", default=str(CONFIG))
    i.add_argument("--report")
    i.add_argument("--check-issues", action="store_true")
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
        if a.cmd == "image":
            findings, problems, unused = scan_image(config, a.dir)
        else:
            findings, problems, unused = scan(config, a.root)
    except ScanError as e:
        print(f"vulncheck: {e}", file=sys.stderr)
        return 2
    if a.check_issues and not record_problems(config.get("accepted", [])):
        repo, token = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_TOKEN")
        if not repo or not token:
            problems.append("--check-issues needs GITHUB_REPOSITORY and GITHUB_TOKEN")
        else:
            mine = [r for r in config.get("accepted", []) if (r.get("where") == IMAGE) == (a.cmd == "image")]
            problems += issue_problems(mine, repo, token)
    ok = summary(findings, problems, unused)
    if a.report:
        pathlib.Path(a.report).write_text(json.dumps(
            {"findings": [{**f, "verdict": verdict(f)} for f in findings],
             "problems": problems, "unused_records": unused}, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
