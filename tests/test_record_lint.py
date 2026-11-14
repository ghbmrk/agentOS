"""tools/record_lint.py: a verdict draft passes only when premerge reads it with the verdict and head it states.

REQ: RECORD-lint (#5679)
"""
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import record_lint  # noqa: E402
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _nogit_bg  # noqa: E402

PR = 5661
# A repository of its own with two commits, so no test reads this checkout's object store (records_audit, CI-PATHS).
_tmp = REPO = PARENT = HEAD = SHORT = None


def setUpModule():
    global _tmp, REPO, PARENT, HEAD, SHORT
    _nogit_bg.setUpModule()
    _tmp = tempfile.TemporaryDirectory()
    REPO = _tmp.name
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

    def git(*args):
        return subprocess.run(["git", *args], cwd=REPO, env=env, capture_output=True, text=True, check=True).stdout.strip()
    git("init", "-q")
    git("commit", "-q", "--allow-empty", "-m", "one")
    PARENT = git("rev-parse", "HEAD")
    git("commit", "-q", "--allow-empty", "-m", "two")
    HEAD = git("rev-parse", "HEAD")
    SHORT = HEAD[:10]


def tearDownModule():
    _tmp.cleanup()
    _nogit_bg.tearDownModule()


def draft(record, *markers, verdict="accept"):
    lines = [f"Verdict: {verdict}"] + ([] if verdict == "accept" else ["Cause: defect"])
    return "\n".join(lines + [record, *markers, "", "1. note", "", "Next: arm; owed: none", ""])


def rec(package="VULN-debian-r8", head=None, pr=PR):
    return f"Record: PR #{pr} · package {package} · head {head or SHORT}"


class Lint(unittest.TestCase):
    def problems(self, body, head=None):
        return record_lint.lint(body, PR, head, REPO)[0]

    def test_well_formed_passes(self):
        self.assertEqual(record_lint.lint(draft(rec(), "<!-- record: l3 -->"), PR, cwd=REPO), ([], f"accept {SHORT} l3"))
        self.assertEqual(self.problems(draft(rec(head=HEAD), "<!-- record: ux -->", "<!-- record: potency -->")), [])
        self.assertEqual(self.problems(draft(rec(), "<!-- record: combined -->", verdict="fix-list")), [])
        self.assertEqual(self.problems(draft(rec(), "<!-- record: security -->"), head=HEAD), [])

    def test_package_with_issue_number(self):  # #5661
        out = self.problems(draft(rec(package="VULN-debian-r8 (#5660)"), "<!-- record: l3 -->"))
        self.assertEqual(len(out), 1)
        self.assertIn("no spaces", out[0])
        self.assertIn("`VULN-debian-r8`", out[0])

    def test_head_that_names_no_commit(self):  # #5652
        out = self.problems(draft(rec(head="6d78023c9e"), "<!-- record: l3 -->"))
        self.assertEqual(len(out), 1)
        self.assertIn("names no single commit", out[0])

    def test_missing_head(self):  # #5669
        out = self.problems(draft(f"Record: PR #{PR} · package X", "<!-- record: l3 -->"))
        self.assertEqual(out, ["Record line has no `· head <sha>` part"])

    def test_bad_head_text(self):
        out = self.problems(draft(rec(head=SHORT.upper()), "<!-- record: l3 -->"))
        self.assertTrue(any("lowercase hex" in p for p in out), out)

    def test_wrong_pr(self):
        out = self.problems(draft(rec(pr=PR + 1), "<!-- record: l3 -->"))
        self.assertEqual(out, [f"Record line names PR #{PR + 1}, not #{PR}"])

    def test_no_record_line(self):
        out = self.problems("Verdict: accept\n<!-- record: l3 -->\n")
        self.assertTrue(any(p.startswith("no Record line") for p in out), out)

    def test_head_other_than_reviewed(self):
        out = self.problems(draft(rec(), "<!-- record: l3 -->"), head=PARENT)
        self.assertEqual(len(out), 1)
        self.assertIn("not the --head", out[0])
        out = self.problems(draft(rec(), "<!-- record: l3 -->"), head="0000000")
        self.assertEqual(out, ["--head 0000000 names no single commit in this checkout"])

    def test_marker_above_record(self):  # #5541: premerge's own cause is named
        body = f"Verdict: accept\n<!-- record: l3 -->\n{rec()}\n"
        out = self.problems(body)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith("misplaced-marker l3"), out)

    def test_marker_shape_and_lens(self):
        out = self.problems(draft(rec(), "<!-- record:l3 -->"))
        self.assertTrue(any("must be exactly" in p for p in out), out)
        self.assertTrue(any(p.startswith("no `<!-- record") for p in out), out)
        out = self.problems(draft(rec(), "<!-- record: L3 -->"))
        self.assertTrue(any("must be exactly" in p for p in out), out)

    def test_security_beside_l3(self):  # D-137: one comment cannot be both
        out = self.problems(draft(rec(), "<!-- record: l3 -->", "<!-- record: security -->"))
        self.assertEqual(len(out), 1)
        self.assertIn("Security in its own comment", out[0])

    def test_first_line(self):
        out = self.problems("LGTM\n" + rec() + "\n<!-- record: l3 -->\n")
        self.assertTrue(any("must be `Verdict:" in p for p in out), out)
        out = self.problems(draft(rec(), "<!-- record: l3 -->", verdict="approve"))
        self.assertTrue(any("verdict 'approve'" in p for p in out), out)

    def test_fenced_record_is_not_the_record(self):  # #4261: a quoted example does not count
        body = f"Verdict: accept\n```text\n{rec()}\n<!-- record: l3 -->\n```\n"
        out = self.problems(body)
        self.assertTrue(out, out)


class Main(unittest.TestCase):
    def run_main(self, argv, body):
        buf = io.StringIO()
        stdin, sys.stdin = sys.stdin, io.StringIO(body)
        cwd = os.getcwd()
        os.chdir(REPO)
        try:
            with redirect_stdout(buf):
                code = record_lint.main(["record_lint.py", *argv])
        finally:
            sys.stdin = stdin
            os.chdir(cwd)
        return code, buf.getvalue()

    def test_exit_codes(self):
        code, out = self.run_main([str(PR)], draft(rec(), "<!-- record: l3 -->"))
        self.assertEqual((code, out), (0, f"ok accept {SHORT} l3\n"))
        code, out = self.run_main([str(PR), "--head", HEAD], draft(rec(head="6d78023c9e"), "<!-- record: l3 -->"))
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("record-lint: head 6d78023c9e"), out)
        self.assertEqual(self.run_main(["nope"], "")[0], 2)
        self.assertEqual(self.run_main([str(PR), "--head"], "")[0], 2)

    def test_crlf_draft(self):
        code, _ = self.run_main([str(PR)], draft(rec(), "<!-- record: l3 -->").replace("\n", "\r\n"))
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
