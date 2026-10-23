"""tools/vulncheck.py: the known-vulnerability gate (SPEC EVL-5, TN-vulncheck #2855).

REQ: EVL-5

Unit tests read synthetic scanner output. TestControl runs the real scanners against the
planted fixture when both are on PATH (the vulncheck workflow installs them and also runs
`vulncheck.py control` as its own step).
"""
import contextlib
import io
import json
import pathlib
import re
import shutil
import sys
import tempfile
import unittest
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import vulncheck  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "vulncheck.yml"


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
        self.assertEqual(got, {"example.com/dep", "example.com/quiet"})
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
        fs, probs = vulncheck.osv_findings(doc, "/r", [], ["a/package-lock.json"])
        self.assertEqual(probs, [])
        self.assertEqual([(f["where"], f["id"], f["aliases"], f["fails"]) for f in fs],
                         [("a/package-lock.json", "GHSA-1", ["CVE-GHSA-1"], True)])

    def test_expected_lockfile_missing_is_a_problem(self):
        # TN-vulncheck-f: a lockfile the scan skipped (or found empty) cannot read as clean.
        doc = osv_doc(("/r/a/package-lock.json", []))
        _, probs = vulncheck.osv_findings(doc, "/r", [], ["a/package-lock.json", "b/x.lock"])
        self.assertEqual(len(probs), 2)

    def test_skip_paths_drop_the_fixture(self):
        doc = osv_doc(("/r/tests/fixtures/vulncheck/npm/package-lock.json", [pkg("left-pad", "npm", "P")]),
                      ("/r/tests/fixtures/vulncheckx/package-lock.json", [pkg("z", "npm", "Q")]))
        fs, _ = vulncheck.osv_findings(doc, "/r", ["tests/fixtures/vulncheck"], [])
        self.assertEqual([f["id"] for f in fs], ["Q"])


def fail(fid, where="t", aliases=()):
    return {"id": fid, "aliases": list(aliases), "where": where, "fails": True, "level": "symbol",
            "module": "m", "version": "v1.0.0", "package": "p", "function": "F", "fixed": ""}


class RecordsTest(unittest.TestCase):
    def test_a_record_accepts_by_id_or_alias_and_where(self):
        # TN-vulncheck-d
        fs = [fail("GO-1", aliases=["CVE-1"]), fail("GO-2"), fail("GO-3", where="other")]
        recs = [{"id": "CVE-1", "issue": 10, "why": "x"},
                {"id": "GO-3", "issue": 11, "why": "x", "where": "t"},
                {"id": "GO-7", "issue": 12, "why": "x"}]
        unused = vulncheck.apply_records(fs, recs)
        self.assertEqual([f.get("accepted_by") for f in fs], [10, None, None])
        self.assertEqual([r["id"] for r in unused], ["GO-3", "GO-7"])
        out = io.StringIO()
        self.assertFalse(vulncheck.summary(fs, [], unused, out))
        self.assertIn("unused record: GO-7", out.getvalue())
        self.assertTrue(vulncheck.summary(fs[:1], [], [], io.StringIO()))

    def test_record_shape(self):
        good = {"id": "GO-1", "issue": 5, "why": "unreachable in our build, see issue"}
        self.assertEqual(vulncheck.record_problems([good, {**good, "where": "broker"}]), [])
        for bad in ({**good, "issue": "5"}, {**good, "issue": 0}, {**good, "issue": True},
                    {**good, "why": " "}, {k: v for k, v in good.items() if k != "id"},
                    {**good, "extra": 1}, {**good, "where": ""}, "GO-1"):
            self.assertEqual(len(vulncheck.record_problems([bad])), 1, bad)

    def test_bad_records_stop_the_scan(self):
        fs, probs, _ = vulncheck.scan({"go_targets": [], "accepted": [{"id": "x"}]}, ROOT)
        self.assertEqual(fs, [])
        self.assertTrue(probs)

    def test_cited_issue_must_be_an_open_issue(self):
        # TN-vulncheck-d: closing the issue withdraws the acceptance.
        answers = {1: {"state": "open"}, 2: {"state": "closed"},
                   3: {"state": "open", "pull_request": {}}, 4: 404}
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

        recs = [{"id": f"V{n}", "issue": n, "why": "x"} for n in (1, 2, 3, 4, 1)]
        probs = vulncheck.issue_problems(recs, "o/r", "tok", opener)
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen[0], ("https://api.github.com/repos/o/r/issues/1", "Bearer tok"))
        self.assertEqual(len(probs), 3)
        self.assertTrue(any("closed" in p for p in probs) and any("pull request" in p for p in probs))

    def test_check_issues_without_a_token_fails(self):
        # TN-vulncheck-d: in CI an acceptance that cannot be checked is a failure, not a pass.
        rec = {"id": "GO-1", "issue": 1, "why": "x"}
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


class ConfigTest(unittest.TestCase):
    def test_config_is_valid_and_targets_exist(self):
        cfg = json.loads(vulncheck.CONFIG.read_text())
        self.assertEqual(vulncheck.record_problems(cfg["accepted"]), [])
        self.assertIn("broker", cfg["go_targets"])
        for t in cfg["go_targets"]:
            self.assertTrue((ROOT / t / "go.mod").exists(), t)
        for s in cfg["osv_sources"]:
            self.assertTrue((ROOT / s).exists(), s)
        self.assertIn("tests/fixtures/vulncheck", cfg["skip_paths"])

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
        wf = WORKFLOW.read_text()
        grants = re.findall(r"(?m)^\s+(contents|issues|pull-requests|actions|checks|statuses):\s*(\w+)", wf)
        self.assertTrue(grants)
        self.assertEqual({g for _, g in grants}, {"read"})


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
