"""REV-PROOF-claims (#4909): tools/claims.py checks claims in a PR body that a tool can compute.

`closes`: a body that closes #N and defers part of #N names a follow-up issue for that part.
The failing case is #2623's, which said `Closes #2619` while deferring items of #2619.
"""
# REQ: REV-PROOF-claims
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import claims  # noqa: E402

INCIDENT = """\
## Summary
Retries the send step.

Closes #2619

Deferred to a later PR: the #2619 backoff ceiling.
"""


class Closes(unittest.TestCase):
    def test_incident_fails_naming_the_line(self):
        problems = claims.closes(INCIDENT)
        self.assertEqual(len(problems), 1, problems)
        self.assertTrue(problems[0].startswith("body line 6: the body closes #2619"), problems)

    def test_follow_up_issue_passes(self):
        self.assertEqual(claims.closes(INCIDENT.replace("ceiling.", "ceiling, follow-up #2650.")), [])

    def test_clean_body_passes(self):
        self.assertEqual(claims.closes("Closes #2619\n\nAll of #2619 is done here.\n"), [])

    def test_deferral_without_a_close_passes(self):
        self.assertEqual(claims.closes("Part of #2619.\n\nThe #2619 backoff ceiling is deferred.\n"), [])

    def test_every_keyword_form(self):
        for kw in ("Closes #", "closed #", "close #", "Fixes #", "fix #", "fixed #", "Resolves #", "resolve #",
                   "resolved #", "Closes: #", "closes ghbmrk/agentOS#"):
            body = f"{kw}12\n\n- #12 retry half: later\n"
            self.assertEqual(len(claims.closes(body)), 1, kw)

    def test_every_deferral_word(self):
        for word in ("deferred", "defers", "later", "follow-up", "followup", "follow up", "remaining",
                     "out of scope", "left for", "postponed", "not in this PR", "TODO"):
            self.assertEqual(len(claims.closes(f"Closes #12\n\n#12's cap is {word}.\n")), 1, word)

    def test_same_line_close_and_deferral(self):
        self.assertEqual(len(claims.closes("Closes #12 (its cap is deferred)\n")), 1)
        self.assertEqual(claims.closes("Closes #12 (its cap is deferred to #13)\n"), [])

    def test_negated_deferral_passes(self):
        for text in ("nothing deferred", "no follow-up", "none remaining", "not later"):
            self.assertEqual(claims.closes(f"Closes #12; {text} for #12.\n"), [], text)

    def test_another_closed_issue_is_not_a_follow_up_for_itself(self):
        problems = claims.closes("Closes #12\nCloses #13\n\nDeferred: the #12 cap and the #13 cap.\n")
        self.assertEqual(len(problems), 2, problems)  # a follow-up is an issue the body leaves open
        self.assertEqual(claims.closes("Closes #12\nCloses #13\n\nDeferred: the #12 and #13 caps, to #14.\n"), [])

    def test_number_prefix_is_not_the_issue(self):
        self.assertEqual(len(claims.closes("Closes #12\n\nThe #123 and #12 caps are deferred.\n")), 0)
        self.assertEqual(len(claims.closes("Closes #12\n\nThe #123 cap is deferred.\n")), 0)
        self.assertEqual(len(claims.closes("Closes #123\n\nThe #12 cap is deferred.\n")), 0)

    def test_code_and_comments_are_not_read(self):
        self.assertEqual(claims.closes("Closes #12\n\n```\n#12 deferred\n```\n<!-- #12 later -->\n"), [])
        self.assertEqual(claims.closes("<!-- Closes #12 -->\n#12 deferred\n"), [])

    def test_line_numbers_survive_comments(self):
        problems = claims.closes("<!--\nx\n-->\nCloses #12\n#12 deferred\n")
        self.assertTrue(problems and problems[0].startswith("body line 5:"), problems)

    def test_entities_and_paths_are_not_issues(self):
        self.assertEqual(claims.closes("Closes #12\n\nlater: &#12; and a/b/#12\n"), [])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            body = pathlib.Path(tmp, "body.txt")
            for text, rc in ((INCIDENT, 1), ("Closes #1\n", 0), ("", 0)):
                body.write_text(text)
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(claims.main(["closes", "--body", str(body)]), rc, out.getvalue())
                self.assertIn("claims: ", out.getvalue())


if __name__ == "__main__":
    unittest.main()
