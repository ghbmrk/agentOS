"""tools/vulncheck.py: the known-vulnerability gate (SPEC EVL-5, TN-vulncheck #2855, #2886).

REQ: EVL-5

Unit tests read synthetic scanner output. TestControl runs the real scanners against the
planted fixture when both are on PATH (the vulncheck workflow installs them and also runs
`vulncheck.py control` as its own step).
"""
import base64
import contextlib
import hashlib
import io
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import vulncheck  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "vulncheck.yml"
IMAGE_WORKFLOW = ROOT / ".github" / "workflows" / "image.yml"
POSTINST = ROOT / "image" / "mkosi" / "mkosi.postinst"


def stream(*findings, modules=("example.com/m",), config=True, osv=()):
    """A govulncheck -format json stream, as concatenated indented objects."""
    objs = []
    if config:
        objs.append({"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}})
    objs.append({"SBOM": {"modules": [{"path": m} for m in modules]}})
    objs += [{"osv": o} for o in osv]
    objs += [{"finding": f} for f in findings]
    return "\n".join(json.dumps(o, indent=2) for o in objs)


def finding(osv, module, package=None, function=None, version="v1.0.0"):
    top = {"module": module, "version": version}
    if package:
        top["package"] = package
    if function:
        top["function"] = function
    return {"osv": osv, "fixed_version": "v1.0.1", "trace": [top]}


def go(text, vendored=()):
    return vulncheck.go_findings("t", vulncheck.json_stream(text), set(vendored))


class GoFindingsTest(unittest.TestCase):
    def test_reachable_symbol_fails(self):
        # TN-vulncheck-a: a symbol-level finding fails, whatever module it is in.
        for mod in ("example.com/m", vulncheck.STDLIB):
            fs = go(stream(finding("GO-1", mod), finding("GO-1", mod, "p"),
                           finding("GO-1", mod, "p", "F")))
            self.assertEqual([(f["id"], f["level"], f["fails"]) for f in fs], [("GO-1", "symbol", True)], mod)

    def test_vendored_module_fails_unreachable(self):
        # TN-vulncheck-b: any finding in a vendored module fails, at package or module level.
        fs = go(stream(finding("GO-2", "example.com/v", "example.com/v"),
                       finding("GO-3", "example.com/v")), vendored={"example.com/v"})
        self.assertEqual([(f["id"], f["level"], f["fails"]) for f in fs],
                         [("GO-2", "package", True), ("GO-3", "module", True)])

    def test_unreachable_stdlib_and_unvendored_are_info(self):
        # TN-vulncheck-b: unreachable stdlib and unvendored findings are reported, not failed.
        fs = go(stream(finding("GO-4", vulncheck.STDLIB, "fmt"), finding("GO-5", "example.com/u")),
                vendored={vulncheck.STDLIB})
        self.assertEqual([(f["id"], f["fails"]) for f in fs], [("GO-4", False), ("GO-5", False)])

    def test_aliases_come_from_osv_messages(self):
        fs = go(stream(finding("GO-6", "m", "m", "F"), osv=[{"id": "GO-6", "aliases": ["CVE-1", "GHSA-x"]}]))
        self.assertEqual(fs[0]["aliases"], ["CVE-1", "GHSA-x"])

    def test_a_scan_that_read_nothing_is_an_error(self):
        # TN-vulncheck-f
        with self.assertRaisesRegex(vulncheck.ScanError, "no config"):
            go(stream(config=False))
        with self.assertRaisesRegex(vulncheck.ScanError, "no modules"):
            go(stream(modules=()))
        with self.assertRaises(vulncheck.ScanError):
            vulncheck.json_stream('{"config": {}} {broken')

    def test_vendored_reads_modules_txt(self):
        got = vulncheck.vendored(ROOT / "tests" / "fixtures" / "vulncheck" / "gomod")
        self.assertEqual(got, {"example.com/dep", "example.com/fork", "example.com/quiet"})
        self.assertEqual(vulncheck.vendored(ROOT / "docs"), set())
        broker = vulncheck.vendored(ROOT / "broker")
        self.assertIn("github.com/emersion/go-imap", broker)  # a replaced module still counts


def osv_doc(*results):
    return {"results": [{"source": {"path": p, "type": "lockfile"}, "packages": pk} for p, pk in results]}


def pkg(name, eco, *vulns):
    return {"package": {"name": name, "version": "1.0.0", "ecosystem": eco},
            "vulnerabilities": [{"id": v} for v in vulns],
            "groups": [{"ids": [v], "aliases": [v, f"CVE-{v}"]} for v in vulns]}


class OsvFindingsTest(unittest.TestCase):
    def test_any_non_go_vulnerability_fails_and_go_is_left_to_govulncheck(self):
        # TN-vulncheck-c
        doc = osv_doc(("/r/a/package-lock.json", [pkg("x", "npm", "GHSA-1"), pkg("y", "npm")]),
                      ("/r/broker/go.mod", [pkg("golang.org/x/net", "Go", "GO-9")]))
        fs, probs = vulncheck.osv_findings(doc, "/r", [], ["a/package-lock.json"], ["broker"])
        self.assertEqual(probs, [])
        self.assertEqual([(f["where"], f["id"], f["aliases"], f["fails"]) for f in fs],
                         [("a/package-lock.json", "GHSA-1", ["CVE-GHSA-1"], True)])

    def test_expected_lockfile_missing_is_a_problem(self):
        # TN-vulncheck-f: a lockfile the scan skipped (or found empty) cannot read as clean.
        doc = osv_doc(("/r/a/package-lock.json", []))
        _, probs = vulncheck.osv_findings(doc, "/r", [], ["a/package-lock.json", "b/x.lock"])
        self.assertEqual(len(probs), 2)

    def test_go_module_outside_targets_is_a_problem(self):
        # Potency finding 1: OSV leaves Go to govulncheck, so an unlisted go.mod is unscanned.
        doc = osv_doc(("/r/broker/go.mod", [pkg("x", "Go")]),
                      ("/r/broker/third_party/m/go.mod", [pkg("y", "Go")]),
                      ("/r/spikes/s/go.mod", [pkg("z", "Go")]),
                      ("/r/guest/new/go.mod", [pkg("w", "Go")]))
        _, probs = vulncheck.osv_findings(doc, "/r", ["spikes"], [], ["broker"])
        self.assertEqual(probs, ["guest/new/go.mod: a Go module outside go_targets; add it there or to skip_paths"])

    def test_scan_ignores_gitignore(self):
        # Security finding 1: a tracked lockfile a .gitignore names is still scanned; the
        # control's ignored/ plant proves the flag works with the real scanner.
        src = (ROOT / "tools" / "vulncheck.py").read_text()
        self.assertIn('"--no-ignore"', src)
        x = ROOT / "tests" / "fixtures" / "vulncheck" / "ignored"
        self.assertIn("package-lock.json", (x / ".gitignore").read_text().splitlines())
        self.assertIn(("ignored/package-lock.json", "AGENTOS-VULNCHECK-CONTROL-1"), vulncheck.CONTROL_FAILS)

    def test_skip_paths_drop_the_fixture(self):
        doc = osv_doc(("/r/tests/fixtures/vulncheck/npm/package-lock.json", [pkg("left-pad", "npm", "P")]),
                      ("/r/tests/fixtures/vulncheckx/package-lock.json", [pkg("z", "npm", "Q")]))
        fs, _ = vulncheck.osv_findings(doc, "/r", ["tests/fixtures/vulncheck"], [])
        self.assertEqual([f["id"] for f in fs], ["Q"])


# The package and version every fail() finding names, for a record that accepts it.
M = {"package": "m", "version": "v1.0.0"}


def fail(fid, where="t", aliases=()):
    return {"id": fid, "aliases": list(aliases), "where": where, "fails": True, "level": "symbol",
            "module": "m", "version": "v1.0.0", "package": "p", "function": "F", "fixed": ""}


class RecordsTest(unittest.TestCase):
    def test_a_record_accepts_by_id_or_alias_and_where(self):
        # TN-vulncheck-d
        fs = [fail("GO-1", aliases=["CVE-1"]), fail("GO-2"), fail("GO-3", where="other")]
        recs = [{"id": "CVE-1", "issue": 10, "why": "x", **M},
                {"id": "GO-3", "issue": 11, "why": "x", "where": "t", **M},
                {"id": "GO-7", "issue": 12, "why": "x", **M}]
        unused = vulncheck.apply_records(fs, recs)
        self.assertEqual([f.get("accepted_by") for f in fs], [10, None, None])
        self.assertEqual([r["id"] for r in unused], ["GO-3", "GO-7"])
        out = io.StringIO()
        self.assertFalse(vulncheck.summary(fs, [], unused, out))
        self.assertIn("unused record: GO-7", out.getvalue())
        self.assertTrue(vulncheck.summary(fs[:1], [], [], io.StringIO()))

    def test_a_record_accepts_only_its_package_and_version(self):
        # #4153 (Security finding 2 on #4152): a record for minimatch 10.2.5 must not accept
        # an upgraded or other copy that the same advisory is later widened to cover.
        fs = [{**fail("GHSA-1"), "module": "minimatch", "version": v} for v in ("10.2.5", "11.0.3")]
        fs.append({**fail("GHSA-1"), "module": "glob", "version": "10.2.5"})
        rec = {"id": "GHSA-1", "issue": 4, "why": "x", "package": "minimatch", "version": "10.2.5"}
        self.assertEqual(vulncheck.apply_records(fs, [rec]), [])
        self.assertEqual([vulncheck.verdict(f) for f in fs], ["accepted #4", "FAIL", "FAIL"])

    def test_record_shape(self):
        good = {"id": "GO-1", "issue": 5, "why": "unreachable in our build, see issue", **M}
        self.assertEqual(vulncheck.record_problems([good, {**good, "where": "broker"}]), [])
        for bad in ({**good, "issue": "5"}, {**good, "issue": 0}, {**good, "issue": True},
                    {**good, "why": " "}, {k: v for k, v in good.items() if k != "id"},
                    {**good, "extra": 1}, {**good, "where": ""}, "GO-1",
                    {k: v for k, v in good.items() if k != "package"}, {**good, "package": " "},
                    {k: v for k, v in good.items() if k != "version"}, {**good, "version": ""}):
            self.assertEqual(len(vulncheck.record_problems([bad])), 1, bad)

    def test_bad_records_stop_the_scan(self):
        fs, probs, _ = vulncheck.scan({"go_targets": ["broker"], "osv_sources": ["a"],
                                       "accepted": [{"id": "x"}]}, ROOT)
        self.assertEqual(fs, [])
        self.assertTrue(probs)

    def test_empty_config_sides_stop_the_scan(self):
        # Security finding 3: an empty side would pass with nothing scanned.
        for cfg in ({"go_targets": [], "osv_sources": ["a"]}, {"go_targets": ["broker"]}):
            fs, probs, _ = vulncheck.scan(cfg, ROOT)
            self.assertEqual((fs, len(probs)), ([], 1), cfg)

    def test_cited_issue_must_be_an_open_issue(self):
        # TN-vulncheck-d: closing the issue withdraws the acceptance.
        answers = {1: {"state": "open", "title": "Accept V1", "body": None},
                   2: {"state": "closed", "title": "V2"},
                   3: {"state": "open", "pull_request": {}, "body": "V3"}, 4: 404,
                   5: {"state": "open", "title": "unrelated", "body": "names V9 only"}}
        seen = []

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(req, timeout):
            seen.append((req.full_url, req.get_header("Authorization")))
            n = int(req.full_url.rsplit("/", 1)[1])
            if answers[n] == 404:
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return Resp(json.dumps(answers[n]).encode())

        recs = [{"id": f"V{n}", "issue": n, "why": "x"} for n in (1, 2, 3, 4, 1, 5)]
        probs = vulncheck.issue_problems(recs, "o/r", "tok", opener)
        self.assertEqual(len(seen), 5)
        self.assertEqual(seen[0], ("https://api.github.com/repos/o/r/issues/1", "Bearer tok"))
        self.assertEqual(len(probs), 4, probs)
        self.assertTrue(any("closed" in p for p in probs) and any("pull request" in p for p in probs))
        # Security finding 2: an open issue that does not name the vulnerability accepts nothing.
        self.assertIn("issue #5 does not name V5, which a record accepts with it", probs)

    def test_check_issues_without_a_token_fails(self):
        # TN-vulncheck-d: in CI an acceptance that cannot be checked is a failure, not a pass.
        rec = {"id": "GO-1", "issue": 1, "why": "x", **M}
        saved, env = vulncheck.scan, dict(vulncheck.os.environ)
        vulncheck.scan = lambda config, root: ([{**fail("GO-1"), "accepted_by": 1}], [], [])
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cfg = pathlib.Path(tmp.name) / "vulncheck.json"
        try:
            vulncheck.os.environ.pop("GITHUB_TOKEN", None)
            cfg.write_text(json.dumps({"go_targets": [], "accepted": [rec]}))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(vulncheck.main(["run", "--config", str(cfg)]), 0)
                self.assertEqual(vulncheck.main(["run", "--config", str(cfg), "--check-issues"]), 1)
            self.assertIn("needs GITHUB_REPOSITORY and GITHUB_TOKEN", out.getvalue())
        finally:
            vulncheck.scan = saved
            vulncheck.os.environ.clear()
            vulncheck.os.environ.update(env)


def osv_pkg(name, version, eco, *vulns, binary=None):
    meta = {"name": name, "version": version, "ecosystem": eco}
    if binary:
        meta["os_package_name"] = binary
    return {"package": meta, "groups": [{"ids": [v], "aliases": [v, f"CVE-{v}"]} for v in vulns]}


class ForkTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("go"), "go not installed")
    def test_dir_replaced_reads_the_required_release(self):
        # TN-vulncheck-5: the fork's version is the upstream release its require line names.
        self.assertEqual(vulncheck.dir_replaced(vulncheck.FIXTURE / "gomod"),
                         [("example.com/fork", "v1.2.1", "./fork")])
        self.assertIn(("github.com/emersion/go-imap", "v1.2.1", "./third_party/go-imap"),
                      vulncheck.dir_replaced(ROOT / "broker"))

    @unittest.skipUnless(shutil.which("go"), "go not installed")
    def test_module_replacements_and_unrequired_replaces_are_not_forks(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        (pathlib.Path(tmp.name) / "go.mod").write_text(
            "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n\n"
            "replace example.com/a => example.com/a2 v1.0.1\n"
            "replace example.com/b v1.0.0 => ../b\n"
            "replace example.com/unused => ./unused\n")
        self.assertEqual(vulncheck.dir_replaced(tmp.name), [("example.com/b", "v1.0.0", "../b")])

    def test_every_vulnerability_in_a_fork_fails(self):
        forks = [("example.com/f", "v1.2.1", "./f"), ("example.com/g", "v2.0.0", "./g")]
        doc = {"results": [{"source": {"path": "/tmp/x/osv-scanner.json"}, "packages": [
            osv_pkg("example.com/f", "1.2.1", "Go", "GO-9"), osv_pkg("example.com/g", "2.0.0", "Go"),
            osv_pkg("example.com/other", "1.0.0", "Go", "GO-8")]}]}
        fs, probs = vulncheck.fork_findings("broker", doc, forks)
        self.assertEqual(probs, [])
        self.assertEqual([(f["where"], f["id"], f["aliases"], f["version"], f["fails"]) for f in fs],
                         [("broker", "GO-9", ["CVE-GO-9"], "v1.2.1", True)])
        self.assertIn("example.com/f => ./f", fs[0]["package"])

    def test_a_fork_the_scan_did_not_report_is_a_problem(self):
        fs, probs = vulncheck.fork_findings("broker", {"results": []}, [("example.com/f", "v1.0.0", "./f")])
        self.assertEqual(fs, [])
        self.assertEqual(len(probs), 1)
        self.assertIn("example.com/f", probs[0])

    def test_lockfile_lists_each_fork_without_the_v(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        f = pathlib.Path(tmp.name) / "osv-scanner.json"
        vulncheck.fork_lockfile([("example.com/f", "v1.2.1", "./f")], f)
        pkgs = json.loads(f.read_text())["results"][0]["packages"]
        self.assertEqual(pkgs, [{"package": {"name": "example.com/f", "version": "1.2.1", "ecosystem": "Go"}}])


class ImageTest(unittest.TestCase):
    CANARY = {**osv_pkg("curl", "0", "Debian:13", "DEBIAN-CVE-0", binary=vulncheck.CANARY)}

    def image(self, *pkgs, canary=True):
        return {"results": [{"source": {"path": "/var/lib/dpkg/status"},
                             "packages": list(pkgs) + ([self.CANARY] if canary else [])}]}

    def scan(self, records, found, src="x"):
        saved = vulncheck.run_image, vulncheck.manifest_problems
        vulncheck.run_image = lambda src, env=None, offline=False: ([dict(f) for f in found], [])
        vulncheck.manifest_problems = lambda src: []
        try:
            return vulncheck.scan_image({"accepted": records}, src)
        finally:
            vulncheck.run_image, vulncheck.manifest_problems = saved

    def test_every_vulnerability_in_an_image_package_fails(self):
        # TN-vulncheck-6: queried by source package; the binary is shown beside it; the
        # canary's own findings are dropped.
        fs, probs = vulncheck.image_findings(self.image(
            osv_pkg("openssl", "3.5.1-1", "Debian:13", "DSA-1", binary="libssl3t64"),
            osv_pkg("zlib", "1.3-1", "Debian:13", binary="zlib1g")))
        self.assertEqual(probs, [])
        self.assertEqual([(f["where"], f["id"], f["package"], f["module"], f["fails"]) for f in fs],
                         [("image", "DSA-1", "Debian:13:openssl (libssl3t64)", "openssl", True)])

    def test_a_failed_query_is_a_problem_not_a_clean_scan(self):
        # L3 blocker on #2917: osv-scanner's image scan reports a failed OSV query as packages
        # with no vulnerabilities and exits 0; the canary must then match nothing.
        pkg = osv_pkg("openssl", "3.5.1-1", "Debian:13", binary="libssl3t64")
        for doc in (self.image(pkg, canary=False),
                    {"results": [{"packages": [pkg, osv_pkg("curl", "0", "Debian:13", binary=vulncheck.CANARY)]}]}):
            probs = vulncheck.image_findings(doc)[1]
            self.assertEqual(len(probs), 1, probs)
            self.assertIn("canary", probs[0])

    def test_a_scan_that_read_nothing_or_the_wrong_release_is_a_problem(self):
        self.assertEqual(vulncheck.image_findings(self.image())[1], ["the image scan reported no packages"])
        for eco in ("Ubuntu:24.04", "Debian", ""):
            doc = self.image(osv_pkg("openssl", "3.5.1-1", eco))
            self.assertEqual(len(vulncheck.image_findings(doc)[1]), 1, eco)

    def test_archive_holds_the_two_files_and_the_canary_where_debian_keeps_them(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = pathlib.Path(tmp.name) / "a.tar"
        vulncheck.image_archive(vulncheck.FIXTURE / "image", out)
        with tarfile.open(out) as t:
            manifest = json.load(t.extractfile("manifest.json"))
            layer = tarfile.open(fileobj=t.extractfile(manifest[0]["Layers"][0]))
            status = layer.extractfile("var/lib/dpkg/status").read()
            self.assertTrue(status.startswith((vulncheck.FIXTURE / "image" / vulncheck.DPKG_STATUS).read_bytes().rstrip(b"\n")))
            self.assertIn((vulncheck.CANARY, "0"), vulncheck.dpkg_installed(status.decode()))
            self.assertIn(b"ID=debian", layer.extractfile("etc/os-release").read())

    def test_a_missing_or_empty_list_fails(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = pathlib.Path(tmp.name)
        with self.assertRaises(vulncheck.ScanError):
            vulncheck.image_archive(d, d / "a.tar")
        (d / vulncheck.DPKG_STATUS).write_text("")
        (d / vulncheck.OS_RELEASE).write_text("ID=debian\n")
        with self.assertRaises(vulncheck.ScanError):
            vulncheck.image_archive(d, d / "a.tar")

    def manifest_dir(self, edit):
        """A copy of the fixture's status file beside its manifest after EDIT(packages)."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = pathlib.Path(tmp.name)
        shutil.copy(vulncheck.FIXTURE / "image" / vulncheck.DPKG_STATUS, d)
        m = json.loads((vulncheck.FIXTURE / "image" / "agentos_control.manifest").read_text())
        edit(m["packages"])
        (d / "a.manifest").write_text(json.dumps(m))
        return d

    def test_status_must_list_the_manifests_packages(self):
        # Security release finding on #2917: the scanned list is tied to the manifest the
        # reproduce job compares across runners. Combined review 6376479024 (#2930): equality is
        # pinned in both directions and by version, not only one subset.
        self.assertEqual(vulncheck.manifest_problems(vulncheck.FIXTURE / "image"), [])
        status = (vulncheck.FIXTURE / "image" / vulncheck.DPKG_STATUS).read_text()
        self.assertEqual(vulncheck.dpkg_installed(status),
                         {("libplant1", "1.0-1+b1"), ("agentos-fixed", "1.0-2"), ("agentos-nofix", "2.0-1")})
        d = self.manifest_dir(lambda pkgs: None)
        (d / "a.manifest").unlink()
        self.assertEqual(len(vulncheck.manifest_problems(d)), 1)  # no manifest
        extra = {"type": "deb", "name": "agentos-unscanned", "version": "1.0-1", "architecture": "all"}
        cases = {
            # shipped but not scanned: the status file under-reports
            "agentos-unscanned": lambda pkgs: pkgs.append(extra),
            # scanned but not in the reproduced manifest: the status file over-reports
            "agentos-fixed": lambda pkgs: pkgs.pop(0),
            # same package, another version
            "9.9-9": lambda pkgs: pkgs[1].update(version="9.9-9"),
        }
        for want, edit in cases.items():
            with self.subTest(want):
                probs = vulncheck.manifest_problems(self.manifest_dir(edit))
                self.assertEqual(len(probs), 1, probs)
                self.assertIn(want, probs[0])

    def test_the_image_scan_reports_a_manifest_mismatch(self):
        # Combined review 6376479024: scan_image must apply manifest_problems, not only have it.
        d = self.manifest_dir(lambda pkgs: pkgs.pop(0))
        saved = vulncheck.run_image
        vulncheck.run_image = lambda src, env=None, offline=False: ([], [])
        try:
            _, probs, _ = vulncheck.scan_image({"accepted": []}, d)
            self.assertEqual(probs, vulncheck.manifest_problems(d))
            self.assertEqual(len(probs), 1)
            _, probs, _ = vulncheck.scan_image({"accepted": []}, vulncheck.FIXTURE / "image")
            self.assertEqual(probs, [])
        finally:
            vulncheck.run_image = saved

    def test_image_records_apply_only_to_the_image_scan_and_their_package(self):
        recs = [{"id": "DSA-1", "issue": 1, "why": "x", "where": "image", "package": "m"},
                {"id": "DSA-2", "issue": 1, "why": "x", **M},
                {"id": "DSA-3", "issue": 1, "why": "x", "where": "image", "package": "other"}]
        found = [{**fail(i), "where": "image"} for i in ("DSA-1", "DSA-2", "DSA-3")]
        fs, probs, unused = self.scan(recs, found)
        self.assertEqual(([vulncheck.verdict(f) for f in fs], probs), (["accepted #1", "FAIL", "FAIL"], []))
        self.assertEqual([r["id"] for r in unused], ["DSA-3"])

    def test_an_image_record_names_its_source_package_and_no_version(self):
        # Debian's fix decides an image record, so it names no version; every other record does.
        good = {"id": "DSA-1", "issue": 1, "why": "x"}
        self.assertEqual(vulncheck.record_problems([{**good, "where": "image", "package": "curl"}]), [])
        for bad in ({**good, "where": "image"}, {**good, "package": "curl"},
                    {**good, "where": "broker", "package": "curl"}, {**good, "where": "image", "package": " "},
                    {**good, "where": "image", "package": "curl", "version": "1.0-1"}):
            self.assertEqual(len(vulncheck.record_problems([bad])), 1, bad)

    def test_check_issues_partitions_the_records(self):
        # Potency finding on #2917: closing #2919 must withdraw the image acceptances.
        cfg = {"accepted": [{"id": "A", "where": "image"}, {"id": "B"}, {"id": "C", "where": "broker"}]}
        self.assertEqual([r["id"] for r in vulncheck.issue_records(cfg, "image")], ["A"])
        self.assertEqual([r["id"] for r in vulncheck.issue_records(cfg, "run")], ["B", "C"])

    def test_a_record_cannot_accept_an_advisory_debian_has_fixed(self):
        # TN-vulncheck-6: once Debian ships a fix, the finding fails until the image is rebuilt.
        def pkg(name, *events):
            return {**osv_pkg(name, "1.0-1", "Debian:13", "DEBIAN-CVE-1"),
                    "vulnerabilities": [{"id": "DEBIAN-CVE-1", "affected": [
                        {"package": {"ecosystem": "Debian:12", "name": name}, "ranges": [{"events": [{"fixed": "0.9"}]}]},
                        {"package": {"ecosystem": "Debian:13", "name": name},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, *events]}]}]}]}
        fs, probs = vulncheck.image_findings(self.image(pkg("a", {"fixed": "1.0-2"}), pkg("b")))
        self.assertEqual(probs, [])
        self.assertEqual([(f["package"], f["fixed"]) for f in fs], [("Debian:13:a (a)", "1.0-2"), ("Debian:13:b (b)", "")])
        recs = [{"id": "DEBIAN-CVE-1", "issue": 1, "why": "x", "where": "image", "package": p} for p in "ab"]
        fs, probs, unused = self.scan(recs, fs)
        self.assertEqual([vulncheck.verdict(f) for f in fs], ["FAIL", "accepted #1"])
        out = io.StringIO()
        vulncheck.summary(fs, [], unused, out)
        self.assertIn("fix: rebuild the image", out.getvalue())
        self.assertNotIn("or add a record", out.getvalue())

def tgz(files):
    """A gzipped npm tarball holding FILES (path -> text) under package/."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as t:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(f"package/{name}")
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return raw.getvalue()


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class InlinedTest(unittest.TestCase):
    # #4153 (Security finding 1 on #4152): copies a bundler put in a package's files.
    def test_marks_name_each_copy_and_its_version(self):
        files, marks, _ = vulncheck.tarball_marks(tgz({
            "dist/a.mjs": "//#region node_modules/.pnpm/minimatch@10.2.6/node_modules/minimatch/dist/esm/index.js\n"
                          'x(__commonJS({"node_modules/.pnpm/@scope+pkg@1.2.3-beta.1_peer@2.0.0/node_modules/@scope/pkg/i.js"(){}}))\n'
                          # the store directory and the package differ: a link, not a copy
                          '"node_modules/.pnpm/minimatch@10.2.6/node_modules/brace-expansion/i.js"\n'
                          # the package's own path is not a copy
                          '"node_modules/.pnpm/holder@1.0.0/node_modules/holder/x.js"\n'
                          # a list line outside a license or notice file is not a mark
                          "- listed@9.9.9\n",
            "lib/bundle.js.LICENSE": "- ajv@8.20.0 (https://example.invalid)\n%% ws@8.21.3 NOTICES AND INFORMATION BEGIN HERE\n",
            "third_party/THIRD_PARTY_NOTICES": "Name: core-js\nURL: https://example.invalid\nVersion: 3.50.0\n"
                                               "License: MIT\n\nName: no-version\nLicense: MIT\n\nName: tslib\nVersion: 2.8.1\n",
            "README.md": "node_modules/.pnpm/readme@1.0.0/node_modules/readme/\n",
        }), ("holder", "1.0.0"))
        self.assertEqual(files, {"dist/a.mjs", "lib/bundle.js.LICENSE", "third_party/THIRD_PARTY_NOTICES", "README.md"})
        self.assertEqual(marks, {("minimatch", "10.2.6"): {"dist/a.mjs"}, ("@scope/pkg", "1.2.3-beta.1"): {"dist/a.mjs"},
                                 ("ajv", "8.20.0"): {"lib/bundle.js.LICENSE"}, ("ws", "8.21.3"): {"lib/bundle.js.LICENSE"},
                                 ("core-js", "3.50.0"): {"third_party/THIRD_PARTY_NOTICES"},
                                 ("tslib", "2.8.1"): {"third_party/THIRD_PARTY_NOTICES"}})

    # REQ: EVL-5. #4197: bundler marks that name a package but no version.
    def test_unversioned_marks_name_the_package_and_not_a_version(self):
        body = "\n".join([
            "// node_modules/colors/lib/styles.js",                        # esbuild path comment
            "//#region node_modules/@scope/pkg/dist/index.js",             # rolldown region
            'var a = __commonJS({"node_modules/ws/lib/buffer-util.js"(exports, module) {',
            '/***/ "./node_modules/left-pad/index.js":',                   # webpack module key
            'x(__commonJS({"node_modules/ajv-formats/node_modules/ajv/dist/ajv.js"(e){}}))',  # nested: ajv
            "  // ../../node_modules/yaml/dist/index.js",                  # a path above the cwd
            # a pnpm store path names its version: a versioned mark, and its src/node_modules is its own
            '"node_modules/.pnpm/debug@4.4.0_x@1.0.0/node_modules/debug/src/node.js"(e){}',
            '"node_modules/.pnpm/b@1.0.0/node_modules/b/src/node_modules/internal/x.js"(e){}',
            # a key into another package's store directory gives no version for the one it names
            '"node_modules/.pnpm/minimatch@10.2.6/node_modules/brace-expansion/index.js"(e){}',
            '"node_modules/holder/x.js"(e){}',                             # the package itself
            # not marks: a runtime path, a call argument, prose in a comment, a directory
            'path.join(store, "node_modules/openclaw/package.json")',
            'require("node_modules/fs-extra/lib/index.js")',
            "// node_modules/npm/node_modules/node-gyp/lib depending on the",
            '"node_modules/dir/"(e){}',
        ]).encode()
        self.assertEqual(vulncheck.unversioned_marks(body, "holder"), {
            "colors": {"node_modules/colors/lib/styles.js"},
            "@scope/pkg": {"node_modules/@scope/pkg/dist/index.js"},
            "ws": {"node_modules/ws/lib/buffer-util.js"},
            "left-pad": {"./node_modules/left-pad/index.js"},
            "ajv": {"node_modules/ajv-formats/node_modules/ajv/dist/ajv.js"},
            "yaml": {"../../node_modules/yaml/dist/index.js"},
            "brace-expansion": {"node_modules/.pnpm/minimatch@10.2.6/node_modules/brace-expansion/index.js"}})

    def test_only_a_sidecar_or_notice_for_the_file_gives_its_versions(self):
        key = lambda n: f'__commonJS({{"node_modules/{n}/index.js"(e){{}}}})\n'
        _, marks, bare = vulncheck.tarball_marks(tgz({
            "lib/utilsBundle.js": key("ws") + key("ip-address"),
            "lib/utilsBundle.js.LICENSE": "- ws@8.0.0 (https://example.invalid)\n",
            # a sidecar gives versions for its own file only
            "lib/other.js": key("ws"),
            # a sidecar of a non-script file is not a notice for the directory
            "lib/webp_codec.wasm": "", "lib/webp_codec.LICENSE": "- ws@7.0.0\n",
            # a notice that is no file's sidecar covers its directory and below, within its package
            "third_party/NOTICES": "Name: lodash-es\nVersion: 4.17.21\n",
            "third_party/x/bundle.js": "// node_modules/lodash-es/a.js\n",
            "third_party/node_modules/dep/bundle.js": "// node_modules/lodash-es/a.js\n",
            # a pnpm mark for the same package in the same file names another copy, not this one
            "dist/worker.mjs": key("debug") + '"node_modules/.pnpm/debug@4.4.0/node_modules/debug/src/node.js"(e){}\n',
        }), ("holder", "1.0.0"))
        self.assertEqual({f: {n: v for n, (_, v) in d.items()} for f, d in bare.items()}, {
            "lib/utilsBundle.js": {"ws": {"8.0.0"}, "ip-address": set()},
            "lib/other.js": {"ws": set()},
            "third_party/x/bundle.js": {"lodash-es": {"4.17.21"}},
            "third_party/node_modules/dep/bundle.js": {"lodash-es": set()},
            "dist/worker.mjs": {"debug": set()}})
        # Every version a notice lists is still a copy the scan checks.
        self.assertIn(("ws", "7.0.0"), marks)

    def bundle_tarballs(self):
        key = lambda n: f'__commonJS({{"node_modules/{n}/index.js"(e){{}}}})\n'
        return self.mirror(
            pw_1={"lib/utilsBundle.js": key("ws") + key("ip-address"),
                  "lib/utilsBundle.js.LICENSE": "- ws@8.0.0\n- ip-address@10.2.0\n"},
            oc_1={"dist/worker.mjs": key("ws") + key("ip-address"), "dist/extra.mjs": key("ws") + key("yaml"),
                  "dist/lone.mjs": key("socks")})

    def test_an_unversioned_mark_fails_unless_an_entry_gives_its_version(self):
        tbs, mirror = self.bundle_tarballs()
        copies, probs, _ = vulncheck.inlined_copies("l", tbs, [], mirror)
        self.assertEqual(sorted(p.split(" (marked")[0] for p in probs), [
            "l: oc@1:dist/extra.mjs inlines ws", "l: oc@1:dist/extra.mjs inlines yaml",
            "l: oc@1:dist/lone.mjs inlines socks",
            "l: oc@1:dist/worker.mjs inlines ip-address", "l: oc@1:dist/worker.mjs inlines ws"])
        self.assertEqual(set(copies), {("ws", "8.0.0"), ("ip-address", "10.2.0")})
        entries = [{"holder": "oc@1", "copy": "socks@2.8.0", "files": ["dist/lone.mjs"], "why": "x"},
                   {"holder": "oc@1", "bundle": "pw@1:lib/utilsBundle.js", "files": ["dist/worker.mjs"], "why": "x"}]
        copies, probs, _ = vulncheck.inlined_copies("l", tbs, entries, mirror)
        self.assertEqual(sorted(p.split(" (marked")[0] for p in probs),
                         ["l: oc@1:dist/extra.mjs inlines ws", "l: oc@1:dist/extra.mjs inlines yaml"])
        self.assertEqual(copies, {("ws", "8.0.0"): {"pw@1:lib/utilsBundle.js.LICENSE", "oc@1:dist/worker.mjs"},
                                  ("ip-address", "10.2.0"): {"pw@1:lib/utilsBundle.js.LICENSE", "oc@1:dist/worker.mjs"},
                                  ("socks", "2.8.0"): {"oc@1:dist/lone.mjs"}})

    def test_a_bundle_entry_fails_when_its_files_are_not_that_bundles_copy(self):
        tbs, mirror = self.bundle_tarballs()
        # dist/extra.mjs marks yaml, which the bundle does not: it is not the bundle's copy.
        entry = {"holder": "oc@1", "bundle": "pw@1:lib/utilsBundle.js", "files": ["dist/extra.mjs"], "why": "x"}
        copies, probs, _ = vulncheck.inlined_copies("l", tbs, [entry], mirror)
        self.assertIn("l: oc@1:dist/extra.mjs marks node_modules/yaml/index.js, which pw@1:lib/utilsBundle.js "
                      "does not; its files are not that bundle's copy, so requalify the entry", probs)
        self.assertNotIn("oc@1:dist/extra.mjs", set().union(*copies.values()))
        # A bundle this lockfile does not install, or a file of it with no unversioned marks.
        for bundle in ("pw@2:lib/utilsBundle.js", "pw@1:lib/utilsBundle.js.LICENSE"):
            _, probs, _ = vulncheck.inlined_copies("l", tbs, [{**entry, "bundle": bundle, "files": ["dist/worker.mjs"]}], mirror)
            self.assertEqual(sum("checks nothing; requalify it" in p for p in probs), 1, probs)
        # A file of the holder with no unversioned marks: the entry checks nothing there.
        tbs, mirror = self.mirror(pw_1={"lib/u.js": '"node_modules/ws/i.js"(e){}', "lib/u.js.LICENSE": "- ws@8.0.0\n"},
                                  oc_1={"dist/min.mjs": "minified"})
        _, probs, _ = vulncheck.inlined_copies("l", tbs, [{**entry, "bundle": "pw@1:lib/u.js", "files": ["dist/min.mjs"]}], mirror)
        self.assertEqual(probs, ["l: oc@1:dist/min.mjs has no unversioned marks, so the inlined entry for pw@1:lib/u.js "
                                 "checks nothing there; requalify it"])

    def test_lockfile_tarballs_and_the_entries_with_none(self):
        lock = {"packages": {
            "": {"name": "root"},
            "node_modules/a": {"version": "1.0.0", "resolved": "https://r/a-1.0.0.tgz", "integrity": "sha512-A"},
            "node_modules/a/node_modules/b": {"version": "2.0.0", "inBundle": True},
            "node_modules/c": {"resolved": "packages/c", "link": True},
            "node_modules/d": {"version": "1.0.0", "resolved": "http://r/d.tgz", "integrity": "sha512-D"},
            "node_modules/e": {"version": "1.0.0", "resolved": "https://r/e.tgz", "integrity": "sha1-E"},
            "node_modules/x/node_modules/@s/f": {"version": "3.0.0", "resolved": "https://r/f.tgz", "integrity": "sha512-F"}}}
        tbs, probs = vulncheck.lock_tarballs(lock, "l")
        self.assertEqual(tbs, [("a", "1.0.0", "https://r/a-1.0.0.tgz", "sha512-A"),
                               ("@s/f", "3.0.0", "https://r/f.tgz", "sha512-F")])
        self.assertEqual(len(probs), 2, probs)
        self.assertEqual(len(vulncheck.lock_tarballs({"lockfileVersion": 1}, "l")[1]), 1)

    def test_a_tarball_must_match_its_integrity(self):
        data = tgz({"index.js": ""})
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        (pathlib.Path(tmp.name) / "a-1.0.0.tgz").write_bytes(data)
        self.assertEqual(vulncheck.fetch_tarball("https://r/a/-/a-1.0.0.tgz", sri(data), tmp.name), data)
        with self.assertRaisesRegex(vulncheck.ScanError, "integrity"):
            vulncheck.fetch_tarball("https://r/a/-/a-1.0.0.tgz", sri(b"other"), tmp.name)

    def mirror(self, **tarballs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = []
        for spec, files in tarballs.items():
            name, version = spec.split("_")
            data = tgz(files)
            (pathlib.Path(tmp.name) / f"{name}-{version}.tgz").write_bytes(data)
            out.append((name, version, f"https://r/{name}/-/{name}-{version}.tgz", sri(data)))
        return out, tmp.name

    def test_an_unmarked_copy_comes_from_its_entry_while_its_holder_holds_its_files(self):
        tbs, mirror = self.mirror(oc_1={"dist/w.mjs": "minified", "dist/x.mjs": ""})
        entry = {"holder": "oc@1", "copy": "minimatch@10.2.6", "files": ["dist/w.mjs"], "why": "x"}
        copies, probs, held = vulncheck.inlined_copies("l", tbs, [entry], mirror)
        self.assertEqual((copies, probs, held), ({("minimatch", "10.2.6"): {"oc@1:dist/w.mjs"}}, [], {"oc@1"}))
        _, probs, _ = vulncheck.inlined_copies("l", tbs, [{**entry, "files": ["dist/gone.mjs"]}], mirror)
        self.assertEqual(len(probs), 1, probs)
        self.assertIn("requalify", probs[0])
        # Another holder version: the entry names nothing this lockfile installs.
        copies, probs, _ = vulncheck.inlined_copies("l", tbs, [{**entry, "holder": "oc@2"}], mirror)
        self.assertEqual((copies, probs), ({}, []))

    def test_an_entry_whose_holder_no_lockfile_installs_is_a_problem(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        (pathlib.Path(tmp.name) / "package-lock.json").write_text(json.dumps({"packages": {"": {}}}))
        entry = {"holder": "oc@1", "copy": "minimatch@10.2.6", "files": ["dist/w.mjs"], "why": "x"}
        fs, probs = vulncheck.run_inlined(tmp.name, ["package-lock.json"], [entry])
        self.assertEqual(fs, [])
        self.assertEqual(len(probs), 1, probs)
        self.assertIn("no lockfile installs oc@1", probs[0])

    def test_every_vulnerability_in_an_inlined_copy_fails(self):
        copies = {("minimatch", "10.2.6"): {"oc@1:dist/a.mjs", "oc@1:dist/b.mjs"}, ("ws", "8.0.0"): {"oc@1:dist/a.mjs"},
                  ("ajv", "8.0.0"): {"pw@1:lib/u.js.LICENSE"}}
        doc = osv_doc(("inlined", [osv_pkg("minimatch", "10.2.6", "npm", "GHSA-1"), osv_pkg("ws", "8.0.0", "npm")]))
        fs, probs = vulncheck.inlined_findings("l", doc, copies)
        self.assertEqual([(f["id"], f["module"], f["version"], f["level"], f["fails"]) for f in fs],
                         [("GHSA-1", "minimatch", "10.2.6", "inlined", True)])
        self.assertEqual(fs[0]["package"], "npm:minimatch inlined in oc@1:dist/a.mjs (+1)")
        self.assertEqual(probs, ["l: the inlined scan reported nothing for ajv@8.0.0"])

    def test_the_inlined_scan_reads_each_npm_lockfile_the_osv_scan_read(self):
        doc = osv_doc(("/r/guest/a/package-lock.json", [pkg("x", "npm", "P")]),
                      ("/r/guest/b/package-lock.json", []),
                      ("/r/tests/fixtures/vulncheck/npm/package-lock.json", [pkg("x", "npm", "P")]),
                      ("/r/guest/c/requirements.txt", [pkg("y", "PyPI", "Q")]))
        self.assertEqual(vulncheck.npm_lockfiles(doc, "/r", ["tests/fixtures/vulncheck"]),
                         ["guest/a/package-lock.json"])

    def test_inlined_entry_shape(self):
        good = {"holder": "oc@1", "copy": "@s/m@2", "files": ["dist/w.mjs"], "why": "minified"}
        bundle = {"holder": "oc@1", "bundle": "@s/pw@1:lib/u.js", "files": ["dist/w.mjs"], "why": "same keys"}
        self.assertEqual(vulncheck.inlined_problems([good, bundle]), [])
        for bad in ({**good, "holder": "oc"}, {**good, "copy": "@s/m"}, {**good, "files": []},
                    {**good, "files": "dist/w.mjs"}, {**good, "why": ""}, {**good, "extra": 1},
                    {k: v for k, v in good.items() if k != "why"}, "oc@1",
                    {**good, "bundle": "pw@1:lib/u.js"}, {**bundle, "bundle": "pw@1"}, {**bundle, "bundle": "pw:lib/u.js"},
                    {**bundle, "bundle": 1}):
            self.assertEqual(len(vulncheck.inlined_problems([bad])), 1, bad)

    def test_bad_inlined_entries_stop_the_scan(self):
        fs, probs, _ = vulncheck.scan({"go_targets": ["broker"], "osv_sources": ["a"], "inlined": [{}]}, ROOT)
        self.assertEqual((fs, len(probs)), ([], 1))


class ConfigTest(unittest.TestCase):
    def test_config_is_valid_and_targets_exist(self):
        cfg = json.loads(vulncheck.CONFIG.read_text())
        self.assertEqual(vulncheck.record_problems(cfg["accepted"]), [])
        self.assertEqual(vulncheck.inlined_problems(cfg["inlined"]), [])
        self.assertIn("broker", cfg["go_targets"])
        for t in cfg["go_targets"]:
            self.assertTrue((ROOT / t / "go.mod").exists(), t)
        for s in cfg["osv_sources"]:
            self.assertTrue((ROOT / s).exists(), s)
        self.assertIn("tests/fixtures/vulncheck", cfg["skip_paths"])
        self.assertEqual(set(cfg["skip_paths"]), {"tests/fixtures/vulncheck", "spikes"})

    def test_every_shipped_lockfile_is_expected(self):
        # A lockfile under guest/ or image/ is an image dependency; list it so a scan
        # that misses it fails rather than passing clean.
        cfg = json.loads(vulncheck.CONFIG.read_text())
        names = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
                 "poetry.lock", "Cargo.lock", "Gemfile.lock")
        found = {p.relative_to(ROOT).as_posix() for d in ("guest", "image")
                 for n in names for p in (ROOT / d).rglob(n)}
        self.assertEqual(found - set(cfg["osv_sources"]), set())


class WorkflowTest(unittest.TestCase):
    def test_control_runs_before_the_scan_on_every_pr(self):
        # TN-vulncheck-e
        wf = WORKFLOW.read_text()
        self.assertRegex(wf, r"(?m)^  pull_request:\s*$")
        self.assertRegex(wf, r"(?m)^  schedule:")
        c = wf.index("python3 tools/vulncheck.py control")
        r = wf.index("python3 tools/vulncheck.py run --check-issues")
        self.assertLess(c, r)
        self.assertNotIn("continue-on-error", wf)
        self.assertNotIn("|| true", wf)

    def test_scanners_are_pinned(self):
        wf = WORKFLOW.read_text()
        self.assertRegex(wf, r"go install golang\.org/x/vuln/cmd/govulncheck@v\d+\.\d+\.\d+\n")
        self.assertRegex(wf, r"go install github\.com/google/osv-scanner/v2/cmd/osv-scanner@v\d+\.\d+\.\d+\n")
        self.assertNotIn("@latest", wf)
        self.assertIn("GOTOOLCHAIN: local", wf)

    def test_token_is_read_only(self):
        for wf in (WORKFLOW.read_text(), IMAGE_WORKFLOW.read_text()):
            grants = re.findall(r"(?m)^\s+(contents|issues|pull-requests|actions|checks|statuses):\s*(\w+)", wf)
            self.assertTrue(grants)
            self.assertEqual({g for _, g in grants}, {"read"})

    def test_image_build_is_scanned_after_the_control(self):
        # TN-vulncheck-6: every image build scans its own package list, with the same pins.
        wf = IMAGE_WORKFLOW.read_text()
        job = wf[wf.index("\n  image-vulncheck:"):]
        self.assertIn("needs: build", job)
        self.assertLess(job.index("python3 tools/vulncheck.py control"),
                        job.index("python3 tools/vulncheck.py image rec --check-issues"))
        self.assertNotIn("continue-on-error", job)
        pins = r"go install (\S+@v\d+\.\d+\.\d+)\n"
        self.assertEqual(re.findall(pins, job), re.findall(pins, WORKFLOW.read_text()))
        self.assertEqual(len(re.findall(pins, job)), 2)
        for name in (vulncheck.DPKG_STATUS, vulncheck.OS_RELEASE):
            self.assertIn(f'"$RUNNER_TEMP"/out/{name}', wf)
            self.assertIn(f'"$OUTPUTDIR/{name}"', POSTINST.read_text())
        self.assertTrue(POSTINST.stat().st_mode & 0o111)

    def test_main_image_is_rescanned_daily(self):
        wf = WORKFLOW.read_text()
        step = wf[wf.index("Known vulnerabilities in main's latest image"):]
        self.assertIn("github.event_name == 'schedule'", step)
        self.assertIn('python3 tools/vulncheck.py image "$d" --check-issues', step)

    def test_install_is_retried_three_times_then_fails(self):
        # #3768: a Go proxy stream error on either install retries; its third failure fails the step.
        gov = "install golang.org/x/vuln/cmd/govulncheck@v1.8.0"
        osv = "install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.5.1"
        for wf in (WORKFLOW, IMAGE_WORKFLOW):
            text = wf.read_text()
            lines = text[text.index("- name: Install govulncheck and osv-scanner"):].splitlines()[2:]
            script = "\n".join(l[10:] for l in lines[:lines.index(next(l for l in lines if not l.startswith(" " * 10)))])
            for flaky in (gov, osv):
                for fails in (0, 2, 3):
                    with self.subTest(workflow=wf.name, flaky=flaky, fails=fails), \
                            tempfile.TemporaryDirectory() as tmp:
                        d = pathlib.Path(tmp)
                        # The stub fails its first `fails` installs of `flaky` only.
                        (d / "go").write_text(
                            "#!/bin/sh\n[ \"$1\" = env ] && { echo /gopath; exit; }\n"
                            f"echo \"$*\" >> {d}/calls\n"
                            f"[ \"$*\" = \"{flaky}\" ] && [ $(grep -cxF \"$*\" {d}/calls) -le {fails} ] && "
                            "{ echo 'stream error: INTERNAL_ERROR' >&2; exit 1; }\nexit 0\n")
                        (d / "sleep").write_text(f"#!/bin/sh\necho $1 >> {d}/slept\n")
                        for stub in ("go", "sleep"):
                            (d / stub).chmod(0o755)
                        (d / "step.sh").write_text(script + "\n")
                        r = subprocess.run(["bash", "--noprofile", "--norc", "-e", str(d / "step.sh")],
                                           env={"PATH": f"{d}:/usr/bin:/bin", "GITHUB_PATH": str(d / "path")},
                                           capture_output=True, text=True)
                        calls = (d / "calls").read_text().splitlines()
                        slept = (d / "slept").read_text().split() if (d / "slept").exists() else []
                        tries = min(fails + 1, 3)
                        if fails < 3:
                            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                            self.assertEqual(calls, [gov] * (tries if flaky == gov else 1)
                                             + [osv] * (tries if flaky == osv else 1))
                            self.assertEqual((d / "path").read_text(), "/gopath/bin\n")
                        else:
                            self.assertNotEqual(r.returncode, 0)
                            self.assertEqual(calls, ([] if flaky == gov else [gov]) + [flaky] * 3)
                            self.assertFalse((d / "path").exists())
                            self.assertIn(f"go {flaky} failed 3 times", r.stdout)
                        self.assertEqual(slept, ["15", "30"][:min(fails, 2)])
                        for t in range(1, min(fails, 3) + 1):
                            self.assertIn(f"try {t} of 3 failed: go {flaky}", r.stderr)


@unittest.skipUnless(shutil.which("govulncheck") and shutil.which("osv-scanner"),
                     "scanners not installed; the vulncheck workflow runs the control")
class TestControl(unittest.TestCase):
    def test_every_plant_is_caught(self):
        # TN-vulncheck-e: real scanners, planted databases, offline.
        out = io.StringIO()
        sys.stdout, saved = out, sys.stdout
        try:
            problems = vulncheck.control()
        finally:
            sys.stdout = saved
        self.assertEqual(problems, [], out.getvalue())


if __name__ == "__main__":
    unittest.main()
