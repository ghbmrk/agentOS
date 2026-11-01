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
           - Inlined: any vulnerability in a package a bundler copied into another package's
             files, which no lockfile lists (#4153). Each tarball an npm lockfile installs is
             fetched, checked against the lockfile's sha512 integrity, and read for the marks
             that name such a copy and its version: a pnpm store path in a module marker or
             require key, and a license sidecar or notice listing a bundle's packages. A bundler
             mark that names a package but no version (an esbuild module key or path comment,
             a rolldown region, outside a pnpm store) fails unless a sidecar or notice for that
             file, or an "inlined" entry, gives that package's version there (#4197). A copy
             with no mark (a minified bundle) is found by its string literals (#4234): a script
             holding FP_MIN or more literals that only one package's own unminified, unmarked
             scripts hold, where that package has an OSV advisory at any version, fails unless a
             mark, sidecar, notice or "inlined" entry names it there. Fingerprints come from the
             lockfile's tarballs, the packages they ship whole under node_modules/, and the
             registry's tarball of each package a mark or entry names with a version no lockfile
             installs. The config's "inlined" names such a copy's version, a file that copies
             another installed package's bundle (taking that bundle's versions, and failing on
             any mark the bundle lacks), or a lookalike: a file whose matching literals are
             another package's code (failing once they match nothing); an entry fails once no
             lockfile installs its holder at the version it names.
         A record names the vulnerability (its ID or any alias), the package and version it
         accepts (a Debian image record names only its source package), the issue that records
         why it is accepted, and the reason; a record accepts no other package or version. With --check-issues each cited issue must be an open
         issue (not a PR) on GITHUB_REPOSITORY that names the record's id in its title or
         body, read with GITHUB_TOKEN; closing the issue withdraws the acceptance.
image    An OSV scan of the Debian packages in a built image: DIR holds the dpkg status
         file and os-release that image/mkosi/mkosi.postinst copies out of the build tree
         (agentos.dpkg-status, agentos.os-release). osv-scanner reads them as a one-layer
         container image, so each installed package is queried by its source package in
         Debian:<VERSION_ID>, with a canary (source curl at version 0) that must match an
         advisory, since osv-scanner reports a failed image query as no vulnerabilities. The
         status file must list exactly the packages of the mkosi manifest in DIR. Any
         vulnerability fails. Only records whose where is "image" apply here (`run` ignores
         them); each names its source package, and accepts only an advisory with no Debian fix.
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
import base64
import concurrent.futures
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
import urllib.parse
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONFIG = ROOT / "assurance" / "vulncheck.json"
FIXTURE = ROOT / "tests" / "fixtures" / "vulncheck"
STDLIB = "stdlib"
# osv-scanner: 0 nothing found, 1 vulnerabilities found; anything else is an error.
OSV_OK = (0, 1)
RECORD_KEYS = {"id", "issue", "why", "where", "package", "version"}
INLINED_KEYS = {"holder", "copy", "files", "why"}
INLINED_BUNDLE_KEYS = {"holder", "bundle", "files", "why"}
# The `where` of every image finding, and of every record that accepts one.
IMAGE = "image"
# What mkosi.postinst writes to the image build's output directory.
DPKG_STATUS, OS_RELEASE = "agentos.dpkg-status", "agentos.os-release"
# A package the image scan adds to every query: source curl at version 0, which every Debian
# advisory against curl affects. osv-scanner's image scan reports packages with no
# vulnerabilities when its OSV query fails, and exits 0; a canary with no advisory is that.
CANARY, CANARY_SOURCE = "agentos-vulncheck-canary", "curl"
CANARY_STANZA = (f"Package: {CANARY}\nStatus: install ok installed\nArchitecture: all\n"
                 f"Source: {CANARY_SOURCE} (0)\nVersion: 0\n"
                 "Description: tools/vulncheck.py canary; not in the image\n")

# What the control must see with no records, as (where, ID): the reachable symbol, the
# vendored module's unreachable package, the npm plant, and the same plant in a tracked
# lockfile that a .gitignore beside it names (osv-scanner skips those without --no-ignore),
# and the directory-replaced example.com/fork's required release.
# GO-0000-0003 (stdlib fmt, symbol not called) passes.
CONTROL_FAILS = {("gomod", "GO-0000-0001"), ("gomod", "GO-0000-0002"),
                 ("gomod", "AGENTOS-VULNCHECK-FORK-1"),
                 ("npm/package-lock.json", "AGENTOS-VULNCHECK-CONTROL-1"),
                 ("ignored/package-lock.json", "AGENTOS-VULNCHECK-CONTROL-1")}
CONTROL_FAILS |= {("npm/package-lock.json", f"AGENTOS-VULNCHECK-INLINED-{n}") for n in (1, 2, 3, 4)}
CONTROL_INFO = {("gomod", "GO-0000-0003")}
# The inlined plants in agentos-bundle's tarball (#4153), as (ID, package, version): a copy a pnpm
# store path marks, one its license sidecar lists, one the config's inlined entry names, one an
# unversioned module key marks and its sidecar gives the version of (#4197), and left-pad 0.9.0,
# which the record accepting left-pad 1.0.0 must not accept: it is the one failure left once the
# records apply.
CONTROL_INLINED = {("AGENTOS-VULNCHECK-INLINED-1", "agentos-inlined", "1.0.0"),
                   ("AGENTOS-VULNCHECK-INLINED-2", "agentos-listed", "2.0.0"),
                   ("AGENTOS-VULNCHECK-INLINED-3", "agentos-unmarked", "3.0.0"),
                   ("AGENTOS-VULNCHECK-INLINED-4", "agentos-bare", "4.0.0"),
                   ("AGENTOS-VULNCHECK-CONTROL-1", "left-pad", "0.9.0")}
CONTROL_STILL_FAILS = {("AGENTOS-VULNCHECK-CONTROL-1", "left-pad", "0.9.0")}
# The unversioned marks (#4197) no sidecar, notice or entry resolves, as (holder:file, package),
# which fail in both runs: a module key into another package's pnpm store directory, one for a
# package nested under a store package's root, and an esbuild path comment. dist/bare.js's key takes its sidecar's version, dist/region/region.mjs's rolldown
# region its directory's NOTICE, and dist/again.js's key the bundle entry's (dist/bare.js's).
CONTROL_UNVERSIONED = {("agentos-bundle@1.0.0:dist/marked.mjs", "agentos-decoy"),
                       ("agentos-bundle@1.0.0:dist/nested.js", "agentos-nested"),
                       ("agentos-bundle@1.0.0:dist/orphan.js", "agentos-orphan")}
# The unmarked copies (#4234), as (holder:file, package), which fail in both runs: minified files
# with no mark holding the literals of left-pad, which the lockfile installs, and of agentos-inlined,
# which only a mark names, so its fingerprint comes from the registry (the mirror's registry.json).
CONTROL_UNMARKED = {("agentos-bundle@1.0.0:dist/packed.js", "left-pad"),
                    ("agentos-bundle@1.0.0:dist/fetched.js", "agentos-inlined")}
# The files each plant's finding names (#4197): the bundle entry adds dist/again.js to the sidecar's.
CONTROL_BARE_FILES = ("AGENTOS-VULNCHECK-INLINED-4", "npm:agentos-bare inlined in agentos-bundle@1.0.0:dist/again.js (+1)")
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
    "inlined": [{"holder": "agentos-bundle@1.0.0", "copy": "agentos-unmarked@3.0.0", "files": ["dist/min.js"],
                 "why": "control: a minified copy with no mark"},
                {"holder": "agentos-bundle@1.0.0", "bundle": "agentos-bundle@1.0.0:dist/bare.js",
                 "files": ["dist/again.js"], "why": "control: a file that copies another file's bundle"}],
    "accepted": [
        {"id": "CVE-0000-0001", "issue": 1, "why": "control: accepted by alias",
         "package": "example.com/dep", "version": "v1.0.0"},
        {"id": "GO-0000-0002", "issue": 1, "why": "control: accepted by ID", "where": "gomod",
         "package": "example.com/quiet", "version": "v1.0.0"},
        {"id": "GHSA-0000-0000-0001", "issue": 1, "why": "control: accepted by alias for 1.0.0 only",
         "where": "npm/package-lock.json", "package": "left-pad", "version": "1.0.0"},
        {"id": "AGENTOS-VULNCHECK-CONTROL-1", "issue": 1, "why": "control: accepted by ID",
         "where": "ignored/package-lock.json", "package": "left-pad", "version": "1.0.0"},
        {"id": "CVE-0000-0102", "issue": 1, "why": "control: fork accepted by alias", "where": "gomod",
         "package": "example.com/fork", "version": "v1.2.1"},
        {"id": "AGENTOS-VULNCHECK-INLINED-1", "issue": 1, "why": "control: a marked copy",
         "where": "npm/package-lock.json", "package": "agentos-inlined", "version": "1.0.0"},
        {"id": "GHSA-0000-0000-0102", "issue": 1, "why": "control: a listed copy, by alias",
         "where": "npm/package-lock.json", "package": "agentos-listed", "version": "2.0.0"},
        {"id": "AGENTOS-VULNCHECK-INLINED-3", "issue": 1, "why": "control: an unmarked copy",
         "where": "npm/package-lock.json", "package": "agentos-unmarked", "version": "3.0.0"},
        {"id": "GHSA-0000-0000-0104", "issue": 1, "why": "control: a copy an unversioned key marks, by alias",
         "where": "npm/package-lock.json", "package": "agentos-bare", "version": "4.0.0"},
        {"id": "AGENTOS-VULNCHECK-DEB-1", "issue": 1, "why": "control: Debian has fixed it, so this "
         "cannot accept it", "where": IMAGE, "package": "agentos-plant"},
        {"id": "CVE-0000-0105", "issue": 1, "why": "control: no Debian fix; accepted by alias",
         "where": IMAGE, "package": "agentos-nofix"},
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


def source(res, root):
    """The path of one osv-scanner result's source, relative to ROOT."""
    p = pathlib.Path(res["source"]["path"])
    return (p.resolve().relative_to(pathlib.Path(root).resolve()) if p.is_absolute() else p).as_posix()


def npm_lockfiles(doc, root, skip):
    """The npm lockfiles an osv-scanner report read packages from, outside skip_paths: the
    inlined scan reads the tarballs of each."""
    return sorted({source(r, root) for r in doc.get("results") or [] if r.get("packages")
                   and pathlib.PurePosixPath(source(r, root)).name == NPM_LOCK
                   and not under(source(r, root), skip)})


def osv_findings(doc, root, skip, expected, go_targets=()):
    """Findings from an osv-scanner JSON report, and the problems with what it scanned.

    Go packages are left to govulncheck, so a go.mod outside every Go target (and outside
    skip_paths) is a problem: neither scanner would check its dependencies."""
    found, scanned, problems = [], set(), []
    for res in doc.get("results") or []:
        rel = source(res, root)
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
        if not isinstance(r.get("package"), str) or not r["package"].strip():
            problems.append(f"{tag}: package must name the package it accepts (a Debian source "
                            "package for an image record)")
        if r.get("where") == IMAGE:
            if "version" in r:
                problems.append(f"{tag}: an image record names no version; it accepts only an "
                                "advisory Debian has not fixed")
        elif not isinstance(r.get("version"), str) or not r["version"].strip():
            problems.append(f"{tag}: version must name the exact version it accepts (#4153)")
    return problems


def apply_records(findings, records):
    """Mark each failing finding a record accepts; return the records nothing used. A record
    accepts only its package, and outside the image only its exact version (#4153)."""
    used = set()
    for f in findings:
        names = {f["id"], *f["aliases"]}
        for n, r in enumerate(records):
            if (r["id"] in names and r.get("where", f["where"]) == f["where"]
                    and r["package"] == f["module"] and r.get("version", f["version"]) == f["version"]):
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


# Inlined copies (#4153): a package a bundler copied into another package's files. No lockfile
# lists it, so the OSV lockfile scan cannot see it and an override cannot reach it. These marks
# name one with its version:
#   - a pnpm store path in a bundle's module marker or require key,
#     node_modules/.pnpm/<name, "/" as "+">@<version>[_<peers>]/node_modules/<name>/;
#   - in a license sidecar or notice, a "- <name>@<version>" or "%% <name>@<version>" line
#     listing what a bundle holds, or a "Name: <name>" block with its "Version: <version>".
PNPM_MARK = re.compile(rb"node_modules/\.pnpm/((?:@[\w.-]+\+)?[\w.-]+)@(\d[^_/\s\"'`]*)"
                       rb"(?:_[^/\s\"'`]*)?/node_modules/((?:@[\w.-]+/)?[\w.-]+)/")
LIST_MARK = re.compile(r"^(?:- |%% )((?:@[\w.-]+/)?[\w.-]+)@(\d[\w.+-]*)", re.M)
NOTICE_MARK = re.compile(r"^Name: ((?:@[\w.-]+/)?[\w.-]+)[ \t]*\n(?:(?!Name:).*\n){0,8}?"
                         r"Version: (\d[\w.+-]*)", re.M)
SCRIPTS = (".js", ".mjs", ".cjs")
NOTICE = re.compile(r"licen[cs]e|notice", re.I)
NPM_LOCK = "package-lock.json"
# Bundler marks that name an inlined module by its path and so its package, but not always its
# version (#4197): a line comment holding only the path (esbuild's "// node_modules/ws/lib/x.js",
# rolldown's "//#region node_modules/ws/lib/x.js"), and a quoted path used as a module key
# (esbuild's __commonJS({"node_modules/ws/lib/x.js"(exports, module) {...}}), webpack's
# "./node_modules/ws/lib/x.js": ...). The package is the path's last node_modules/<name>. A
# path a PNPM_MARK names a version for is versioned; any other is an unversioned mark, which
# fails unless a sidecar or notice for that file, or an "inlined" entry, gives that package's
# version there.
# Also esbuild's namespaced paths ("ns:node_modules/..."), webpack's "// CONCATENATED MODULE:
# ./node_modules/..." comments, and Turbopack's "[project]/node_modules/... [ssr] (ecmascript)" ids.
_MARK_PATH = rb"(?:[\w-]+:)?((?:[\w.@+-]+/)*?node_modules/[^\s\"'`()]+?\.\w+)"
COMMENT_MARK = re.compile(rb"^[ \t]*//(?:#region| CONCATENATED MODULE:)? +" + _MARK_PATH + rb"[ \t]*\r?$", re.M)
KEY_MARK = re.compile(rb"[\"'`]" + _MARK_PATH + rb"[\"'`][(:]")
TURBOPACK_MARK = re.compile(rb"[\"'`]\[project\]/" + _MARK_PATH + rb"(?: [^\"'`\n]*)?[\"'`]")
MODULE_SEG = re.compile(rb"node_modules/((?:@[\w.-]+/)?[\w.-]+)/")
# Unmarked copies (#4234): a minified bundle can drop every mark, but it keeps the string literals
# of the code it copied. A package's fingerprint is the literals of FP_LEN characters in its own
# scripts that no other package's own scripts hold. Its own scripts are the unminified ones in its
# tarball that no mark, sidecar or notice says hold a copy (a bundle's literals are its copies' as
# much as its own), whether the package is installed, shipped whole under another package's
# node_modules/, or only named with a version by a mark elsewhere (then read from the registry).
# Only a package with an OSV advisory, at any version, has a fingerprint: a copy of any other
# cannot fail. A script holding FP_MIN or more of one package's fingerprint holds a copy of it,
# unless its marks, sidecar, notices or an entry name that package.
FP_LEN = (24, 200)
FP_MIN = 5
# A minified script: half its bytes or more sit in lines longer than MINIFIED_LINE bytes.
MINIFIED_LINE = 1000
REGISTRY = "https://registry.npmjs.org"
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
# A package with advisories that will not be withdrawn: each batch asks for it, and a batch that
# finds none for it answered nothing, which fails the scan (as the image scan's curl canary).
ADVISORY_CANARY = "lodash"
LITERAL = re.compile(rb'"((?:[^"\\\n]|\\.){%d,%d})"|\'((?:[^\'\\\n]|\\.){%d,%d})\'|`((?:[^`\\$\n]|\\.){%d,%d})`'
                     % (FP_LEN * 3))
INLINED_LOOKALIKE_KEYS = {"holder", "lookalike", "files", "why"}


# Text between two literals that a scan misaligned on a quote inside another literal: code, which a
# minifier rewrites, not a literal it keeps.
CODE = re.compile(rb"[;{}]|&&|\|\||===?|!==?|=>|\$\{|\b(?:return|typeof|function|var|const|let|this)\b")


def literals(body):
    """The quoted string literals of FP_LEN characters in one script that read as text, not code."""
    return {lit for a, b, c in LITERAL.findall(body) if not CODE.search(lit := a or b or c)}


def minified(body):
    """Whether one script is minified: built output, which can hold copies no mark names."""
    return 2 * sum(len(line) for line in body.split(b"\n") if len(line) > MINIFIED_LINE) >= len(body) > 0


def at(spec):
    """(name, version) of "name@version"; a scoped name keeps its leading @."""
    name, _, version = spec.rpartition("@")
    return name, version


def bundle_ref(spec):
    """(name, version, path) of "name@version:path", the bundle an "inlined" entry's files copy."""
    pkg, _, path = spec.partition(":")
    return (*at(pkg), path)


def mark_owner(path):
    """(package, versioned, unreadable) for one bundler mark path, or None if it names no package.
    The path belongs to the last package of its chain of node_modules/<name>/ steps that each
    follow a package root directly: a pnpm store step (.pnpm/<name>@<version>/node_modules/<name>/)
    names its version, any other step does not (pnpm's hoisted .pnpm/node_modules/ among them), and
    a node_modules/ deeper inside a package (its own src/node_modules/) is that package's own
    source. A step MODULE_SEG cannot read (a legacy name, a store directory with no node_modules/
    after it) fails closed: it names its own text, unversioned, and the walk goes on from there
    (#4281); the mark stays unreadable, so it is never taken for the bundling package's own path. A step
    with no "/" after it is a file, not a package (#4278)."""
    store = [m for m in PNPM_MARK.finditer(path) if m.group(1).replace(b"+", b"/") == m.group(3)]
    if store:
        pos, name, versioned = store[-1].end(), store[-1].group(3), True
    else:
        pos, name, versioned = path.find(b"node_modules/"), None, False
        if pos < 0:
            return None
    unreadable = False
    while path.startswith(b"node_modules/", pos):
        m = MODULE_SEG.match(path, pos)
        if m and m.group(1) == b".pnpm":
            pos = m.end()
            if path.startswith(b"node_modules/", pos):
                continue  # pnpm's hoisted .pnpm/node_modules/
            end = path.find(b"/", pos)
            if end < 0:
                break  # a file in the store directory itself
            step, pos = path[pos:end], end + 1  # the store directory, which node_modules/ must follow
            if not path.startswith(b"node_modules/", pos):
                name, versioned, unreadable = step, False, True
            continue
        if m:
            name, versioned, pos = m.group(1), False, m.end()  # after an unreadable step, still unreadable
            continue
        start = pos + len(b"node_modules/")
        end = path.find(b"/", start)
        if end >= 0 and path.startswith(b"@", start):
            end = path.find(b"/", end + 1)
        if end < 0:
            break  # a file directly in node_modules/
        name, versioned, unreadable, pos = path[start:end], False, True, end + 1
    return None if name is None else (name.decode(), versioned, unreadable)


def unversioned_marks(body, own):
    """{package: the mark paths naming it} for the unversioned bundler marks in one script. A mark
    of OWN is the script's own source, unless a step of it was unreadable."""
    out = {}
    for path in COMMENT_MARK.findall(body) + KEY_MARK.findall(body) + TURBOPACK_MARK.findall(body):
        o = mark_owner(path)
        if o and not o[1] and (o[0] != own or o[2]):
            out.setdefault(o[0], set()).add(path.decode())
    return out


def notice_scope(notice, scripts, files):
    """The scripts a license or notice file gives versions for. A sidecar (another file's name,
    or its name without the extension, and a suffix: utilsBundle.js.LICENSE, webp_codec.LICENSE
    beside webp_codec.wasm) gives them for that file only, and a script's sidecar (X.js.LICENSE)
    gives them to no other file even when X.js is missing; any other notice for the scripts in
    its directory and below, within its package (no node_modules/ between)."""
    d, _, base = notice.rpartition("/")
    if (named := re.match(r"(.+\.[cm]?js)\.", base)):
        return {f"{d}/{named.group(1)}" if d else named.group(1)} & scripts  # a script's sidecar, even with no script
    side = {f for f in files if f.rpartition("/")[0] == d and not NOTICE.search(f.rpartition("/")[2])
            and any(base.startswith(n + ".") for n in (f.rpartition("/")[2], f.rpartition("/")[2].rpartition(".")[0]) if n)}
    if side:
        return side & scripts
    pre = d + "/" if d else ""
    return {s for s in scripts if s.startswith(pre) and "node_modules/" not in s[len(pre):].rpartition("/")[0] + "/"}


def lock_tarballs(lock, where):
    """(name, version, resolved, integrity) of each tarball an npm lockfile installs, and the
    entries it names none for. A bundled entry (inBundle) ships inside its parent's tarball,
    and a link is a directory in the tree, so neither has a tarball of its own."""
    packages = lock.get("packages")
    if not packages:
        return [], [f"{where}: no packages map (lockfileVersion 2 or 3), so the inlined scan reads nothing"]
    out, problems = [], []
    for key, e in packages.items():
        if not key or e.get("inBundle") or e.get("link"):
            continue
        r, i = e.get("resolved", ""), e.get("integrity", "")
        if not (r.startswith("https://") and i.startswith("sha512-")):
            problems.append(f"{where}: {key} names no https tarball with a sha512 integrity, so "
                            "the inlined scan cannot read it")
            continue
        out.append((e.get("name") or key.rpartition("node_modules/")[2], e.get("version", ""), r, i))
    return out, problems


def fetch_tarball(resolved, integrity, mirror=None):
    """The tarball's bytes, which must match the lockfile's sha512 integrity. With a mirror
    (the control's offline copies), it is read from the file of the URL's last name there."""
    if mirror:
        data = (pathlib.Path(mirror) / resolved.rpartition("/")[2]).read_bytes()
    else:
        try:
            with urllib.request.urlopen(resolved, timeout=120) as resp:
                data = resp.read()
        except (urllib.error.URLError, OSError) as e:
            raise ScanError(f"{resolved}: could not fetch it ({e})")
    if hashlib.sha512(data).digest() != base64.b64decode(integrity.removeprefix("sha512-")):
        raise ScanError(f"{resolved}: does not match the lockfile's integrity")
    return data


def tarball_marks(data, own, prints=None):
    """What a package tarball's marks say about its inlined copies: its files (without the
    leading package/); (name, version) -> the files whose marks name that copy; and for each
    script with unversioned marks (#4197), {package: (its mark paths, the versions its sidecar
    or notices give)}. OWN, (name, version) of the package itself, is not a copy. PRINTS, when
    given, gets for each script (its string literals, the packages its marks, sidecar or notices
    name, whether it is minified), for the unmarked-copy check (#4234)."""
    files, marks, by_file, bare, lits = set(), {}, {}, {}, {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t:
            if not m.isfile():
                continue
            rel = m.name.partition("/")[2]
            files.add(rel)
            base = rel.rpartition("/")[2]
            script, notice = base.endswith(SCRIPTS), bool(NOTICE.search(base))
            if not (script or notice):
                continue
            body = t.extractfile(m).read()
            found = []
            if script:
                found += [(n.decode(), v.decode()) for d, v, n in PNPM_MARK.findall(body)
                          if d.decode().replace("+", "/") == n.decode()]
                if u := unversioned_marks(body, own[0]):
                    bare[rel] = u
                if prints is not None:
                    lits[rel] = (literals(body), minified(body))
            if notice:
                text = body.decode("utf-8", "replace")
                found += LIST_MARK.findall(text) + NOTICE_MARK.findall(text)
            found = [k for k in found if k != own]
            by_file[rel] = (script, found)
            for k in found:
                marks.setdefault(k, set()).add(rel)
    scripts = {rel for rel, (script, _) in by_file.items() if script}
    # Only a sidecar or notice gives a bundle's versions: a pnpm mark for the same package in the
    # same file names another copy (OpenClaw's worker.mjs holds its own debug and playwright-core's).
    known = {rel: set() for rel in bare}
    for n, (script, found) in by_file.items():
        if not script and found:
            for rel in notice_scope(n, scripts, files) & set(bare):
                known[rel].update(found)
    unversioned = {rel: {name: (paths, {v for k, v in known[rel] if k == name}) for name, paths in names.items()}
                   for rel, names in bare.items()}
    if prints is not None:
        named = {rel: {n for n, _ in found} | set(bare.get(rel, ())) for rel, (_, found) in by_file.items()}
        for n, (script, found) in by_file.items():
            if not script and found:
                for rel in notice_scope(n, scripts, files):
                    named[rel].update(k for k, _ in found)
        prints.update({rel: (ls, named[rel], mini) for rel, (ls, mini) in lits.items()})
    return files, marks, unversioned


def inlined_problems(entries):
    """Shape problems in the config's "inlined" list: copies whose marks give no version, each
    as {holder: name@version, copy: name@version, files: [the holder's files holding it], why},
    files that copy another installed package's bundle, as {holder, bundle:
    name@version:path, files, why}, whose marks and versions the bundle's give (#4197), or files
    that match a package's fingerprint without holding a copy of it, as {holder, lookalike: name,
    files, why}, the why saying whose code the matching literals are (#4234)."""
    problems = []
    for n, e in enumerate(entries):
        tag = f"inlined[{n}]"
        if not isinstance(e, dict):
            problems.append(f"{tag}: not an object")
            continue
        if set(e) not in (INLINED_KEYS, INLINED_BUNDLE_KEYS, INLINED_LOOKALIKE_KEYS):
            problems.append(f"{tag}: needs exactly the keys {sorted(INLINED_KEYS)}, {sorted(INLINED_BUNDLE_KEYS)} "
                            f"or {sorted(INLINED_LOOKALIKE_KEYS)}")
            continue
        if "lookalike" in e and (not isinstance(e["lookalike"], str) or not e["lookalike"].strip()):
            problems.append(f"{tag}: lookalike must name the package whose fingerprint the files match")
        if "bundle" in e and (not isinstance(e["bundle"], str) or not all(bundle_ref(e["bundle"]))):
            problems.append(f"{tag}: bundle must be name@version:path")
        for k in ("holder", "copy"):
            if k in e and (not isinstance(e[k], str) or not all(at(e[k]))):
                problems.append(f"{tag}: {k} must be name@version")
        if not isinstance(e["files"], list) or not e["files"] or not all(isinstance(f, str) and f for f in e["files"]):
            problems.append(f"{tag}: files must list the holder's files that hold the copy")
        if not isinstance(e["why"], str) or not e["why"].strip():
            problems.append(f"{tag}: no reason (how the copy and its version were identified)")
    return problems


def inlined_copies(where, tarballs, entries, mirror, advised):
    """(name, version) -> the holders' files that hold it, for one lockfile's tarballs, with
    the entries of the config's "inlined" that one of them holds; and the problems. ADVISED maps
    a set of package names to those with an OSV advisory (advised_names): only those have a
    fingerprint (#4234)."""
    copies, problems, held, bare, prints = {}, [], {}, {}, {}

    def read(t):
        name, version, resolved, integrity = t
        p = {}
        return f"{name}@{version}", tarball_marks(fetch_tarball(resolved, integrity, mirror), (name, version), p), p

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for holder, (files, marks, unversioned), p in pool.map(read, tarballs):
            held[holder] = files
            bare[holder] = unversioned
            prints[holder] = p
            for k, fs in marks.items():
                copies.setdefault(k, set()).update(f"{holder}:{f}" for f in fs)
    # Entries naming a copy first: a bundle entry takes the versions its bundle ends up with.
    named = {}  # (holder, file) -> the packages an entry names there
    for e in sorted(entries, key=lambda e: "bundle" in e):
        if e["holder"] not in held:
            continue
        what = e.get("copy") or e.get("bundle") or e["lookalike"]
        missing = sorted(set(e["files"]) - held[e["holder"]])
        if missing:
            problems.append(f"{where}: {e['holder']} has no {missing[0]}, which the inlined entry for "
                            f"{what} names; requalify it")
        marked = bare[e["holder"]]
        if "lookalike" in e:
            for f in e["files"]:
                named.setdefault((e["holder"], f), set()).add(e["lookalike"])
            continue
        if "copy" in e:
            name, version = at(e["copy"])
            copies.setdefault((name, version), set()).update(f"{e['holder']}:{f}" for f in e["files"])
            for f in e["files"]:
                named.setdefault((e["holder"], f), set()).add(name)
                if name in marked.get(f, {}):
                    marked[f][name][1].add(version)
            continue
        name, version, path = bundle_ref(e["bundle"])
        src = bare.get(f"{name}@{version}", {}).get(path)
        if src is None:
            problems.append(f"{where}: {e['bundle']} is not a file with unversioned marks in a tarball this "
                            f"lockfile installs, so the inlined entry for {e['holder']} checks nothing; requalify it")
            continue
        for f in e["files"]:
            if f not in marked:
                problems.append(f"{where}: {e['holder']}:{f} has no unversioned marks, so the inlined entry "
                                f"for {e['bundle']} checks nothing there; requalify it")
                continue
            extra = sorted(p for n, (paths, _) in marked[f].items()
                           for p in paths - src.get(n, (set(), set()))[0])
            if extra:
                problems.append(f"{where}: {e['holder']}:{f} marks {extra[0]}, which {e['bundle']} does not; "
                                "its files are not that bundle's copy, so requalify the entry")
                continue
            for n, (_, versions) in marked[f].items():
                for v in src[n][1]:
                    versions.add(v)
                    copies.setdefault((n, v), set()).add(f"{e['holder']}:{f}")
            named.setdefault((e["holder"], f), set()).update(prints.get(f"{name}@{version}", {}).get(path, ((), (), False))[1])
    installed = {at(h) for h in held}
    shipped = {n for scripts in prints.values() for rel in scripts if (n := shipped_owner(rel))}
    names = {n for n, _ in installed} | {n for n, _ in copies} | shipped
    has = advised(names)
    # The copies marks or entries name with a version, at versions no tarball here installs: the
    # registry's tarball of each gives its fingerprint.
    wanted = sorted(k for k in copies if k[0] in has and k not in installed)

    def source(k):
        p = {}
        data, problem = registry_tarball(*k, mirror)
        if data:
            tarball_marks(data, k, p)
        return f"{k[0]}@{k[1]}", p, problem

    sources = dict(prints)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for spec, p, problem in pool.map(source, wanted):
            sources[spec] = p
            if problem:
                problems.append(f"{where}: {problem}")
    problems += unmarked_problems(where, prints, fingerprints(sources, has), named, entries)
    for holder in sorted(bare):
        for f, names in sorted(bare[holder].items()):
            for n, (paths, versions) in sorted(names.items()):
                if not versions:
                    problems.append(unversioned_problem(where, holder, f, n, paths))
    return copies, problems, set(held)


def fingerprints(sources, has):
    """{literal: package} for each literal that only one package's own scripts hold, where that
    package is in HAS. SOURCES maps name@version to tarball_marks' PRINTS for its tarball. A
    script under node_modules/<name>/ in a tarball is <name>'s, shipped whole; any other is the
    tarball's own package's. A minified script, or one that a mark, sidecar or notice says holds
    a copy, is no package's own: a bundle's literals are its copies' as much as its own."""
    own = {}
    for spec, scripts in sources.items():
        for rel, (ls, marked, mini) in scripts.items():
            if marked or mini:
                continue
            if "node_modules/" in rel:
                name = shipped_owner(rel)
                if not name:
                    continue  # an unreadable step, or a node_modules/ inside the package: a copy
            else:
                name = at(spec)[0]
            own.setdefault(name, set()).update(ls)
    owners = {}
    for name, ls in own.items():
        for lit in ls:
            owners[lit] = None if lit in owners else name
    return {lit: name for lit, name in owners.items() if name in has}


def shipped_owner(rel):
    """The package a tarball ships whole at REL, a path under its root node_modules/<name>/ that
    the walk reads, or None. A node_modules/ deeper in the package (dist/vendor/node_modules/x/)
    is no package npm installs or a lockfile versions, so a file there is a copy like any other."""
    o = mark_owner(rel.encode()) if rel.startswith("node_modules/") else None
    return o[0] if o and not o[2] else None


def unmarked_problems(where, prints, owner_of, named, entries):
    """The scripts that hold FP_MIN or more literals of one package's fingerprint (OWNER_OF, from
    fingerprints) while nothing names that package there (#4234): no mark, sidecar or notice, and
    no entry (NAMED: (holder, file) -> the packages entries name there). The holder, and a
    package its tarball ships whole under node_modules/<name>/, hold their own literals. A
    lookalike entry whose files match no fingerprint of its package is a problem."""
    problems, matched = [], set()
    for holder, scripts in sorted(prints.items()):
        for rel, (ls, marked, _) in sorted(scripts.items()):
            own = {at(holder)[0], shipped_owner(rel)} - {None}
            hits = {}
            for lit in ls:
                if (n := owner_of.get(lit)) and n not in own:
                    hits.setdefault(n, []).append(lit)
            for n, lits in sorted(hits.items()):
                if len(lits) < FP_MIN:
                    continue
                matched.add((holder, rel, n))
                if n in marked or n in named.get((holder, rel), ()):
                    continue
                problems.append(f"{where}: {holder}:{rel} holds {len(lits)} string literals only {n}'s own files "
                                f"hold (e.g. {min(lits).decode('utf-8', 'replace')!r}), but no mark, sidecar, "
                                f"notice or entry names {n} there: an unmarked copy. Add an \"inlined\" entry naming "
                                "its version, or a lookalike entry saying whose code they are (#4234)")
    for e in entries:
        if "lookalike" in e and e["holder"] in prints:
            for f in e["files"]:
                if (e["holder"], f, e["lookalike"]) not in matched:
                    problems.append(f"{where}: {e['holder']}:{f} matches no fingerprint of {e['lookalike']}, so the "
                                    "lookalike entry checks nothing there; requalify it")
    return problems


def registry_tarball(name, version, mirror=None):
    """(the registry's tarball of name@version, checked against the registry's sha512 integrity,
    or None; a problem when it cannot be read). With a mirror (the control's offline copies),
    its registry.json stands in for the registry's version documents."""
    spec = f"{name}@{version}"
    try:
        if mirror:
            dist = json.loads((pathlib.Path(mirror) / "registry.json").read_text()).get(spec)
        else:
            url = f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}"
            with urllib.request.urlopen(url, timeout=120) as resp:
                dist = json.load(resp).get("dist")
    except (urllib.error.URLError, OSError, ValueError) as e:
        dist = None
        why = f"could not read it ({e})"
    else:
        why = "the registry has no such version"
    integrity = (dist or {}).get("integrity", "")
    if not dist:
        return None, f"{spec}, which a mark or entry names: {why}, so no fingerprint finds its unmarked copies (#4234)"
    if not integrity.startswith("sha512-") or not str(dist.get("tarball", "")).startswith("https://"):
        return None, (f"{spec}, which a mark or entry names: the registry gives no https tarball with a sha512 "
                      "integrity, so no fingerprint finds its unmarked copies (#4234)")
    return fetch_tarball(dist["tarball"], integrity, mirror), None


def advised_names(names, env=None, offline=False, opener=urllib.request.urlopen):
    """The NAMES (npm packages) with an OSV advisory at any version, withdrawn ones included: from
    the offline database osv-scanner reads when OFFLINE, else from OSV's batch query, which with
    no version returns every advisory for the package."""
    names = sorted(names)
    if offline:
        path = pathlib.Path((env or {}).get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "")) / "osv-scalibr" / "npm" / "all.zip"
        found = set()
        try:
            with zipfile.ZipFile(path) as z:
                for f in z.namelist():
                    for a in json.loads(z.read(f)).get("affected") or []:
                        if (a.get("package") or {}).get("ecosystem") == "npm":
                            found.add(a["package"].get("name"))
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            raise ScanError(f"{path}: unreadable OSV database ({e})")
        return found & set(names)
    out = set()
    for i in range(0, len(names), 999):
        chunk = names[i:i + 999] + [ADVISORY_CANARY]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "npm"}} for n in chunk]}).encode()
        req = urllib.request.Request(OSV_QUERYBATCH, data=body, headers={"Content-Type": "application/json"})
        try:
            with opener(req, timeout=120) as resp:
                results = json.load(resp).get("results")
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ScanError(f"{OSV_QUERYBATCH}: the advisory query failed ({e})")
        if not isinstance(results, list) or len(results) != len(chunk) or not all(isinstance(r, dict) for r in results):
            raise ScanError(f"{OSV_QUERYBATCH}: the advisory query answered {len(results or [])} of {len(chunk)} packages")
        # A next_page_token means more advisories remain, so the package has one (osv-scanner reads it so).
        found = {n for n, r in zip(chunk, results) if r.get("vulns") or r.get("next_page_token")}
        if ADVISORY_CANARY not in found:
            raise ScanError(f"{OSV_QUERYBATCH}: the advisory query found nothing for {ADVISORY_CANARY}, so its answers are not read")
        out |= found
    return out & set(names)


def unversioned_problem(where, holder, f, name, paths):
    return (f"{where}: {holder}:{f} inlines {name} (marked {sorted(paths)[0]}) with no version: no "
            "sidecar or notice for that file names one; add an \"inlined\" entry naming its "
            "version, or the installed bundle the file copies (#4197)")


def inlined_findings(where, doc, copies):
    """Findings for one lockfile's inlined copies from an osv-scanner report of the custom
    lockfile inlined_lockfile wrote, and the copies it did not report."""
    found, scanned = [], set()
    for res in doc.get("results") or []:
        for pkg in res.get("packages") or []:
            meta = pkg["package"]
            k = (meta.get("name"), meta.get("version"))
            if meta.get("ecosystem") != "npm" or k not in copies:
                continue
            scanned.add(k)
            files = sorted(copies[k])
            more = f" (+{len(files) - 1})" if len(files) > 1 else ""
            for f in _vulns(pkg, where, f"npm:{k[0]} inlined in {files[0]}{more}", k[1]):
                f["level"] = "inlined"
                found.append(f)
    problems = [f"{where}: the inlined scan reported nothing for {n}@{v}"
                for n, v in sorted(set(copies) - scanned)]
    return sorted(found, key=lambda x: (x["id"], x["module"], x["version"])), problems


def inlined_lockfile(copies, path):
    """osv-scanner's custom lockfile format, listing each inlined copy."""
    pkgs = [{"package": {"name": n, "version": v, "ecosystem": "npm"}} for n, v in sorted(copies)]
    pathlib.Path(path).write_text(json.dumps({"results": [{"source": {"path": "inlined", "type": "lockfile"},
                                                           "packages": pkgs}]}))


def run_inlined(root, lockfiles, entries, env=None, offline=False, mirror=None):
    """Findings and problems for the inlined copies in the tarballs of each npm lockfile, and
    an entry of the config's "inlined" whose holder no lockfile installs."""
    findings, problems, holders = [], [], set()
    for where in lockfiles:
        try:
            lock = json.loads((pathlib.Path(root) / where).read_text())
        except (OSError, ValueError) as e:
            raise ScanError(f"{where}: unreadable lockfile: {e}")
        tarballs, probs = lock_tarballs(lock, where)
        problems += probs
        if not tarballs:
            continue
        copies, probs, held = inlined_copies(where, tarballs, entries, mirror,
                                             lambda names: advised_names(names, env, offline))
        problems += probs
        holders |= held
        if not copies:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = pathlib.Path(tmp) / "osv-scanner.json"
            inlined_lockfile(copies, lock_path)
            doc = osv_scan(["source", "-L", f"osv-scanner:{lock_path}"], tmp, env, offline)
        found, probs = inlined_findings(where, doc, copies)
        findings += found
        problems += probs
    problems += [f"inlined: no lockfile installs {e['holder']}, so the entry for {e.get('copy') or e.get('bundle') or e['lookalike']} checks "
                 "nothing; requalify the holder's unmarked copies and update it" for e in entries
                 if e["holder"] not in holders]
    return findings, problems


def image_archive(src, dest):
    """A one-layer docker-archive holding SRC's dpkg status and os-release where a Debian
    tree keeps them, the input osv-scanner's image scan reads: its dpkg extractor takes the
    ecosystem from os-release and queries each installed package by its source package. The
    status file gains the canary (CANARY_STANZA)."""
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
            if name == "var/lib/dpkg/status":
                data = data.rstrip(b"\n") + b"\n\n" + CANARY_STANZA.encode()
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
    found, problems, n, canary = [], [], 0, None
    for res in doc.get("results") or []:
        for pkg in res.get("packages") or []:
            meta = pkg["package"]
            if meta.get("os_package_name") == CANARY:
                canary = len(_vulns(pkg, IMAGE, "", ""))
                continue
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
    if not canary:
        problems.append(f"the canary ({CANARY_SOURCE} at version 0) matched no advisory, so the OSV "
                        "query did not run or returned nothing; the scan proves nothing")
    return sorted(found, key=lambda x: (x["id"], x["package"])), problems


def dpkg_installed(text):
    """(Package, Version) of each installed package in a dpkg status file."""
    out = set()
    for stanza in re.split(r"\n\s*\n", text):
        fields = dict(m.groups() for m in re.finditer(r"(?m)^([A-Za-z-]+):[ \t]*(.*)$", stanza))
        if fields.get("Status", "").endswith(" installed") and fields.get("Package"):
            out.add((fields["Package"], fields.get("Version", "")))
    return out


def manifest_problems(src):
    """The status file must list exactly the packages of the build's mkosi manifest, which
    image.yml's reproduce job compares across two runners."""
    found = sorted(pathlib.Path(src).glob("*.manifest"))
    if len(found) != 1:
        return [f"{src}: expected one mkosi *.manifest beside {DPKG_STATUS}, found {len(found)}"]
    try:
        pkgs = json.loads(found[0].read_text())["packages"]
        manifest = {(p["name"], p["version"]) for p in pkgs}
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [f"{found[0]}: unreadable manifest: {e}"]
    status = dpkg_installed((pathlib.Path(src) / DPKG_STATUS).read_text())
    if status == manifest:
        return []
    extra, missing = sorted(status - manifest), sorted(manifest - status)
    return [f"{DPKG_STATUS} does not list the manifest's packages: only in the status file "
            f"{extra[:5]}{'...' if len(extra) > 5 else ''}, only in the manifest "
            f"{missing[:5]}{'...' if len(missing) > 5 else ''}"]


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


def scan(config, root, go_db=None, osv_env=None, offline=False, mirror=None):
    """Findings and problems for one tree; records applied, issues not checked. MIRROR holds
    the control's offline copies of the tarballs its lockfiles name."""
    problems = record_problems(config.get("accepted", [])) + inlined_problems(config.get("inlined", []))
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
    doc = run_osv(root, osv_env, offline)
    skip = config.get("skip_paths", [])
    osv, osv_problems = osv_findings(doc, root, skip, config["osv_sources"], config["go_targets"])
    findings += osv
    problems += osv_problems
    inlined, inlined_probs = run_inlined(root, npm_lockfiles(doc, root, skip), config.get("inlined", []),
                                         osv_env, offline, mirror)
    findings += inlined
    problems += inlined_probs
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
    problems += manifest_problems(src)
    return findings, problems, apply_records([f for f in findings if not f["fixed"]], records)


def issue_records(config, cmd):
    """The records whose issues `cmd --check-issues` checks: the image's for `image`, the
    rest for `run`."""
    return [r for r in config.get("accepted", []) if (r.get("where") == IMAGE) == (cmd == "image")]


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
    if any(f["where"] == IMAGE and f["fixed"] for f in failing):
        print("fix: rebuild the image; Debian has fixed each image finding that names a fixed "
              "version, and no record can accept those", file=out)
    if any(not (f["where"] == IMAGE and f["fixed"]) for f in failing):
        print("fix: upgrade to the fixed version, or add a record to assurance/vulncheck.json "
              "naming an open issue that names the vulnerability and says why it is accepted", file=out)
    return not failing and not problems


UNVERSIONED = re.compile(r"^npm/package-lock\.json: (\S+) inlines (\S+) \(marked ")
UNMARKED = re.compile(r"^npm/package-lock\.json: (\S+) holds \d+ string literals only (\S+)'s own files hold ")


def control_unversioned(probs):
    """The problems but the unversioned marks CONTROL_UNVERSIONED and the unmarked copies
    CONTROL_UNMARKED plant, and a problem if those are not exactly the ones reported."""
    rest = probs
    for pattern, want, what in ((UNVERSIONED, CONTROL_UNVERSIONED, "unversioned marks"),
                                (UNMARKED, CONTROL_UNMARKED, "unmarked copies")):
        got = {m.groups() for m in map(pattern.match, rest) if m}
        rest = [p for p in rest if not pattern.match(p)]
        if got != want:
            rest.append(f"{what}: want {sorted(want)}, got {sorted(got)}")
    return rest


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
        kw = dict(go_db=(FIXTURE / "godb").as_uri(), offline=True, mirror=FIXTURE / "tarballs",
                  osv_env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": tmp})
        bare = {**CONTROL_CONFIG, "accepted": []}
        findings, probs, _ = scan(bare, FIXTURE, **kw)
        summary(findings, probs, [])
        problems += [f"no records: {p}" for p in control_unversioned(probs)]
        fails = {(f["where"], f["id"]) for f in findings if f["fails"]}
        info = {(f["where"], f["id"]) for f in findings if not f["fails"]}
        if fails != CONTROL_FAILS:
            problems.append(f"planted failures: want {sorted(CONTROL_FAILS)}, got {sorted(fails)}")
        if info != CONTROL_INFO:
            problems.append(f"unreachable non-vendored: want {sorted(CONTROL_INFO)}, got {sorted(info)}")
        inlined = {(f["id"], f["module"], f["version"]) for f in findings if f["level"] == "inlined"}
        if inlined != CONTROL_INLINED:
            problems.append(f"inlined plants: want {sorted(CONTROL_INLINED)}, got {sorted(inlined)}")
        if CONTROL_BARE_FILES not in {(f["id"], f["package"]) for f in findings}:
            problems.append(f"the bundle entry's file: want the finding {CONTROL_BARE_FILES}")
        findings, probs, unused = scan(CONTROL_CONFIG, FIXTURE, **kw)
        summary(findings, probs, unused)
        problems += [f"with records: {p}" for p in control_unversioned(probs)]
        failing = {(f["id"], f["module"], f["version"]) for f in findings if verdict(f) == "FAIL"}
        if failing != CONTROL_STILL_FAILS or unused:
            problems.append(f"the fixture's records must clear every planted failure but "
                            f"{sorted(CONTROL_STILL_FAILS)}: still failing {sorted(failing)}, "
                            f"unused {[r['id'] for r in unused]}")

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
            problems += issue_problems(issue_records(config, a.cmd), repo, token)
    ok = summary(findings, problems, unused)
    if a.report:
        pathlib.Path(a.report).write_text(json.dumps(
            {"findings": [{**f, "verdict": verdict(f)} for f in findings],
             "problems": problems, "unused_records": unused}, indent=1) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
