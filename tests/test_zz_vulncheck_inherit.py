"""Inherited mode of the image scan (#6631): a PR that changes no image input applies main's live records.

REQ: EVL-5

A new no-fix Debian advisory failed image-vulncheck on every open PR, and each PR then needed a main merge
(and a mutgate restart) to pick up the record main had gained. These tests hold the mode to fail closed:
every finding still needs a record, a PR that touches an image input or the records gets the full check,
and anything unreadable falls back to the full check.
"""
import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import vulncheck  # noqa: E402

IMAGE_WORKFLOW = ROOT / ".github" / "workflows" / "image.yml"


def fail(fid, where="image", module="m", fixed=""):
    return {"where": where, "id": fid, "aliases": [], "level": "package", "module": module, "version": "1",
            "package": f"Debian:13:{module} ({module})", "function": "", "fixed": fixed, "fails": True}


def rec(fid, issue, where="image", package="m"):
    return {"id": fid, "issue": issue, "why": "no fix", "where": where, "package": package}


class ScanTest(unittest.TestCase):
    def scan(self, records, found, main_records=()):
        names = ("run_image", "manifest_problems", "initrd_status", "guest_problems", "linked_problems",
                 "exclusion_problems", "excluded_packages")
        saved = {n: getattr(vulncheck, n) for n in names}
        vulncheck.run_image = lambda src, env=None, offline=False, where="image", status=None, excluded=frozenset(): (
            [] if pathlib.Path(src).name == vulncheck.LINKED else [dict(f) for f in found if f["where"] == where], [])
        vulncheck.manifest_problems = vulncheck.guest_problems = vulncheck.linked_problems = lambda src: []
        vulncheck.initrd_status = lambda src: (b"Package: x\n", [])
        vulncheck.exclusion_problems = lambda src, excluded: []
        vulncheck.excluded_packages = lambda *a: {}
        self.addCleanup(lambda: [setattr(vulncheck, n, f) for n, f in saved.items()])
        return vulncheck.scan_image({"accepted": records}, "x", main_records=main_records)

    def test_main_records_accept_only_what_own_records_leave_and_are_never_unused(self):
        found = [fail("DSA-1"), fail("DSA-2"), fail("DSA-3")]
        fs, probs, unused = self.scan([rec("DSA-1", 1), rec("DSA-9", 9)], found,
                                      [rec("DSA-1", 11), rec("DSA-2", 12), rec("DSA-8", 18)])
        self.assertEqual(probs, [])
        self.assertEqual([vulncheck.verdict(f) for f in fs], ["accepted #1", "accepted #12", "FAIL"])
        # Only the PR's own unused records come back; main's DSA-8 is main's scans' to fail.
        self.assertEqual([r["id"] for r in unused], ["DSA-9"])

    def test_a_main_record_keeps_every_bound_of_a_record(self):
        # Its own tree and source package only, no fixed advisory, and no record outside the image trees.
        found = [fail("DSA-1", where="image/initrd"), fail("DSA-2", module="other"), fail("DSA-3", fixed="2"),
                 fail("DSA-4")]
        fs, _, _ = self.scan([], found, [rec("DSA-1", 1), rec("DSA-2", 2), rec("DSA-3", 3),
                                         rec("DSA-4", 4, where="broker")])
        self.assertEqual([vulncheck.verdict(f) for f in fs], ["FAIL"] * 4)

    def test_without_main_records_the_scan_is_unchanged(self):
        fs, _, unused = self.scan([rec("DSA-9", 9)], [fail("DSA-1")])
        self.assertEqual(([vulncheck.verdict(f) for f in fs], [r["id"] for r in unused]), (["FAIL"], ["DSA-9"]))


class InheritsTest(unittest.TestCase):
    def test_only_a_readable_nonempty_diff_off_every_input_inherits(self):
        self.assertTrue(vulncheck.inherits(None))
        self.assertTrue(vulncheck.inherits([]))
        for path in ("image/mkosi/mkosi.conf", "guest/openclaw/package-lock.json", "assurance/vulncheck.json",
                     "assurance/README.md", "tools/vulncheck.py", "tests/fixtures/vulncheck/x",
                     ".github/workflows/image.yml", ".github/workflows/vulncheck.yml", ".github/actions/scope/a.yml",
                     "broker/cmd/agentos-infer/llama.pins"):
            with self.subTest(path=path):
                self.assertIn(path, vulncheck.inherits(["broker/kernel/a.go", path]))
        self.assertEqual(vulncheck.inherits(["broker/kernel/a.go", "imagery/x", "docs/image/x.md"]), "")

    def git(self, d, *args):
        subprocess.run(["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                       check=True, capture_output=True)

    def repo(self, path):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = pathlib.Path(tmp.name)
        self.git(d, "init", "-q")
        (d / "base").write_text("x")
        self.git(d, "add", "-A")
        self.git(d, "commit", "-qm", "base")
        (d / path).parent.mkdir(parents=True, exist_ok=True)
        (d / path).write_text("y")
        self.git(d, "add", "-A")
        self.git(d, "commit", "-qm", "pr")
        main = d / "main.json"
        main.write_text(json.dumps({"accepted": [rec("DSA-1", 1)]}))
        return d, main

    def test_main_records_are_read_only_when_the_pr_inherits(self):
        d, main = self.repo("broker/kernel/a.go")
        self.assertEqual(vulncheck.inherited_records(main, "HEAD^1", d), ([rec("DSA-1", 1)], ""))
        d, main = self.repo("image/x")
        records, why = vulncheck.inherited_records(main, "HEAD^1", d)
        self.assertIsNone(records)
        self.assertIn("image/x", why)

    def test_anything_unreadable_falls_back_to_the_full_check(self):
        d, main = self.repo("broker/kernel/a.go")
        self.assertIsNone(vulncheck.inherited_records(main, "no-such-rev", d)[0])
        self.assertIsNone(vulncheck.inherited_records(d / "missing.json", "HEAD^1", d)[0])
        main.write_text("{")
        self.assertIsNone(vulncheck.inherited_records(main, "HEAD^1", d)[0])
        main.write_text(json.dumps({"accepted": [{"id": "DSA-1"}]}))
        self.assertIn("problems", vulncheck.inherited_records(main, "HEAD^1", d)[1])


class MainTest(unittest.TestCase):
    def run_main(self, changed):
        saved = (vulncheck.scan_image, vulncheck.changed_paths)
        self.addCleanup(lambda: (setattr(vulncheck, "scan_image", saved[0]),
                                 setattr(vulncheck, "changed_paths", saved[1])))
        seen = {}

        def scan(config, src, main_records=()):
            seen["main"] = list(main_records)
            return [], [], [rec("DSA-9", 9)]
        vulncheck.scan_image, vulncheck.changed_paths = scan, lambda base, root=vulncheck.ROOT: changed
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = pathlib.Path(tmp.name)
        (d / "c.json").write_text(json.dumps({"accepted": [rec("DSA-9", 9)]}))
        (d / "m.json").write_text(json.dumps({"accepted": [rec("DSA-1", 1)]}))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = vulncheck.main(["image", "x", "--config", str(d / "c.json"), "--report", str(d / "r.json"),
                                   "--inherit", str(d / "m.json"), "--base", "HEAD^1"])
        return code, out.getvalue(), seen["main"], json.loads((d / "r.json").read_text())

    def test_an_inheriting_pr_notes_unused_records_and_passes(self):
        code, out, main, report = self.run_main(["broker/kernel/a.go"])
        self.assertEqual((code, main, report["unused_records"]), (0, [rec("DSA-1", 1)], []))
        self.assertEqual([r["id"] for r in report["deferred_unused"]], ["DSA-9"])
        self.assertIn("inherited mode:", out)

    def test_a_pr_touching_an_input_gets_the_full_check(self):
        code, out, main, report = self.run_main(["broker/kernel/a.go", "assurance/vulncheck.json"])
        self.assertEqual((code, main, [r["id"] for r in report["unused_records"]]), (1, [], ["DSA-9"]))
        self.assertNotIn("deferred_unused", report)
        self.assertIn("inherited mode off", out)


class WorkflowTest(unittest.TestCase):
    def step(self):
        wf = IMAGE_WORKFLOW.read_text()
        job = wf[wf.index("\n  image-vulncheck:"):]
        return job, job[job.index("- name: Known vulnerabilities in the image's"):]

    def test_inherited_mode_runs_only_on_a_prs_merge_commit_with_main_read(self):
        job, step = self.step()
        self.assertIn("fetch-depth: 2", job[:job.index("download-artifact")])
        guard = step[step.index("if [ "):step.index("then")]
        for want in ('[ "$EVENT" = pull_request ]', "git rev-parse -q --verify 'HEAD^2'", "curl -fsS",
                     "contents/assurance/vulncheck.json?ref=main"):
            self.assertIn(want, guard)
        self.assertIn("inherit=(--inherit \"$main\" --base 'HEAD^1')", step)
        self.assertIn('python3 tools/vulncheck.py image rec --check-issues --report image-vulncheck-report.json '
                      '"${inherit[@]}"', step)
        self.assertIn("EVENT: ${{ github.event_name }}", step)


if __name__ == "__main__":
    unittest.main()
