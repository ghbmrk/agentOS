"""Tests for tools/premerge.py, the reviewed-diff equals merged-diff check (parallel-merge design, section 4 item 9).

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import premerge  # noqa: E402


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


EDITED = lambda kind: ["edited-verdict", kind + ":", *"a verdict edited after posting never counts, post a new comment".split()]
UNPARSED = lambda kind, pr=7: ["unparsed-record", kind + ":",
    *f'Record line must be "Record: PR #{pr} · package <ID-without-spaces> · head <sha>"'.split()]


class PremergeTest(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.r = pathlib.Path(self._d.name)
        git(self.r, "init", "-q", "-b", "main")
        self.write("a.txt", "".join(f"line {i}\n" for i in range(30)))
        self.write("b.txt", "b\n")
        git(self.r, "add", "."), git(self.r, "commit", "-qm", "base")

    def write(self, name, text):
        (self.r / name).write_text(text)

    def commit(self, msg):
        git(self.r, "add", "."), git(self.r, "commit", "-qm", msg)
        return git(self.r, "rev-parse", "HEAD")

    def pr(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("a.txt", self.read("a.txt").replace("line 2\n", "line two\n"))
        return self.commit("pr")

    def read(self, name):
        return (self.r / name).read_text()

    def check(self, reviewed, head="HEAD"):
        return premerge.compare(self.r, reviewed, head, "main")

    def test_same_head_is_same(self):
        reviewed = self.pr()
        self.assertEqual(self.check(reviewed), [])

    def test_main_merged_in_far_from_the_hunks_is_same(self):
        reviewed = self.pr()
        git(self.r, "checkout", "-q", "main")
        self.write("a.txt", self.read("a.txt").replace("line 25\n", "line 25 main\n"))
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")
        self.assertEqual(self.check(reviewed), [])

    def merge_main_after(self, edit):
        git(self.r, "checkout", "-q", "main")
        edit()
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")

    def test_main_merged_in_next_to_a_hunk_is_same(self):
        # #1580, #1592: a base change in the PR hunk's context lines read as `changed`.
        reviewed = self.pr()
        self.merge_main_after(lambda: self.write("a.txt", self.read("a.txt").replace("line 4\n", "line 4 main\n")))
        self.assertEqual(self.check(reviewed), [])

    def test_assumptions_renumbering_only_is_same_but_text_edit_is_changed(self):
        rows = "| N1 | first | basis |\n| N2 | second | basis |\n"
        git(self.r, "checkout", "-q", "main")
        self.write("ASSUMPTIONS.md", "| # | A |\n|---|---|\n" + rows)
        self.commit("assumptions")
        reviewed = self.pr()
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md") + "| N3 | mine | basis |\n")
        reviewed = self.commit("pr row")
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("| N3 |", "| N4 |"))
        self.commit("renumbered")
        self.assertEqual(self.check(reviewed), [])
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("mine", "changed"))
        self.commit("text edit")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def decisions_conflict(self, name="DECISIONS.md", main="| D-1 | base |\n| D-2 | main |\n",
                           pr="| D-1 | base |\n| D-3 | mine |\n"):
        """main and the PR each rewrite the row block of `name`; returns the reviewed head, with main's merge conflicted."""
        git(self.r, "checkout", "-q", "main")
        self.resolve(name, "", base=True)
        git(self.r, "checkout", "-q", "-b", "pr")
        reviewed = self.resolve(name, pr, base=False)
        git(self.r, "checkout", "-q", "main")
        self.resolve(name, main, base=False)
        git(self.r, "checkout", "-q", "pr")
        merge = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                               cwd=self.r, capture_output=True, text=True)
        self.assertNotEqual(merge.returncode, 0, "the merge was meant to conflict")
        return reviewed

    def resolve(self, name, rows, base=True):
        """Writes `name` with `rows` after D-1 (or, without `base`, as the whole row block) and commits."""
        self.write(name, "| ID | Decision |\n|---|---|\n" + ("| D-1 | base |\n" if base else "") + rows + "\nPer-team section.\n")
        return self.commit("rows")

    def test_decisions_rows_both_appended_and_kept_verbatim_is_same(self):
        # #3224, #3233: two PRs appending a DECISIONS row at one spot forced a delta review on every main-merge.
        for rows in ("| D-2 | main |\n| D-3 | mine |\n", "| D-3 | mine |\n| D-2 | main |\n"):
            with self.subTest(rows=rows):
                self.setUp()
                reviewed = self.decisions_conflict()
                self.resolve("DECISIONS.md", rows)
                self.assertEqual(self.check(reviewed), [])

    def test_decisions_resolution_that_edits_drops_or_adds_a_row_is_changed(self):
        for rows in ("| D-2 | main |\n| D-4 | mine |\n", "| D-2 | main |\n", "| D-3 | mine |\n",
                     "| D-2 | main |\n| D-3 | mine |\n| D-5 | extra |\n", "| D-2 | main |\n| D-3 | mine |\n| D-2 | main |\n"):
            with self.subTest(rows=rows):
                self.setUp()
                reviewed = self.decisions_conflict()
                self.resolve("DECISIONS.md", rows)
                self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    def test_decisions_conflict_on_an_edited_row_is_changed_even_if_both_kept(self):
        # A non-empty base section: both sides changed D-1, so keeping both is not two appends.
        reviewed = self.decisions_conflict(main="| D-1 | main edit |\n", pr="| D-1 | pr edit |\n")
        self.resolve("DECISIONS.md", "| D-1 | pr edit |\n| D-1 | main edit |\n", base=False)
        self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    def chmod_commit(self, name):
        (self.r / name).chmod(0o755)
        return self.commit("chmod")

    def test_assumptions_renumbering_with_a_mode_flip_is_changed(self):
        # #3266: the exemption compared blob text only, so a chmod rode along as `same`.
        git(self.r, "checkout", "-q", "main")
        self.write("ASSUMPTIONS.md", "| # | A |\n|---|---|\n| N1 | first | basis |\n")
        self.commit("assumptions")
        reviewed = self.pr()
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("| N1 |", "| N2 |"))
        self.chmod_commit("ASSUMPTIONS.md")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_assumptions_mode_is_read_from_the_literal_path(self):
        # #3275 review: pathspec magic in a name made the mode check read X/ASSUMPTIONS.md instead.
        table = "| # | A |\n|---|---|\n| N1 | first | basis |\n"
        git(self.r, "checkout", "-q", "main")
        for name in ("X/ASSUMPTIONS.md", ":(literal)X/ASSUMPTIONS.md"):
            (self.r / name).parent.mkdir(exist_ok=True)
            self.write(name, table)
        self.commit("assumptions")
        reviewed = self.pr()
        name = ":(literal)X/ASSUMPTIONS.md"
        self.write(name, self.read(name).replace("| N1 |", "| N2 |"))
        self.chmod_commit(name)
        self.assertEqual(self.check(reviewed), [name])

    def test_decisions_rows_kept_verbatim_with_a_mode_flip_is_changed(self):
        # #3266: as above, for the appended-rows exemption.
        reviewed = self.decisions_conflict()
        self.resolve("DECISIONS.md", "| D-2 | main |\n| D-3 | mine |\n")
        self.chmod_commit("DECISIONS.md")
        self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    UNION = "| ID | A |\n|---|---|\n| E-1 | one |\n| E-2 | two |\n"

    def union_merge(self, main_rows, pr_rows, base_rows="| L-1 | edge old |\n"):
        """#3369's shape: ASSUMPTIONS.md under merge=union, main and the PR each rewrite the rows after E-2; returns
        the reviewed head, with main merged into the PR cleanly by the union driver."""
        git(self.r, "checkout", "-q", "main")
        self.write(".gitattributes", "ASSUMPTIONS.md merge=union\n")
        self.write("ASSUMPTIONS.md", self.UNION + base_rows)
        self.commit("assumptions")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("ASSUMPTIONS.md", self.UNION + pr_rows)
        reviewed = self.commit("pr edits a row")
        self.merge_main_after(lambda: self.write("ASSUMPTIONS.md", self.UNION + main_rows))
        return reviewed

    def test_a_union_merge_that_keeps_an_edited_row_twice_is_changed(self):
        # #3369: the replay kept both rows too, so the broken merge read `same` and the fix read `changed`.
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", "| L-1 | edge new |\n")
        self.assertEqual(self.read("ASSUMPTIONS.md").count("| L-1 |"), 2, "the union driver was meant to keep both")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        for rows in ("| B-1 | bak |\n| L-1 | edge new |\n", "| L-1 | edge new |\n| B-1 | bak |\n"):
            with self.subTest(fixed=rows):  # e842a58 kept the PR's row after main's; dropping the old row in place is the same merge
                self.write("ASSUMPTIONS.md", self.UNION + rows)
                self.commit("drop the stale row")
                self.assertEqual(self.check(reviewed), [])
        for rows in ("| B-1 | bak |\n| L-1 | edge old |\n", "| L-1 | edge new |\n| B-1 | bak |\n| L-2 | edge old |\n",
                     "| L-1 | edge new |\n", "| B-1 | bak |\n| L-1 | edge newer |\n"):
            with self.subTest(wrong=rows):  # main's row kept, the stale row renumbered, main's row dropped, the PR row edited
                self.write("ASSUMPTIONS.md", self.UNION + rows)
                self.commit("another resolution")
                self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_head_that_undoes_a_pr_move_to_another_table_is_changed(self):
        # #3401 L3: the PR moves L-1 to the Retired table; putting it back at main's spot is not the union's hunk.
        retired = "\n## Retired\n\n| ID | A |\n|---|---|\n| R-1 | old |\n"
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n" + retired,
                                    retired + "| L-1 | edge new |\n", base_rows="| L-1 | edge old |\n" + retired)
        self.write("ASSUMPTIONS.md", self.UNION + "| B-1 | bak |\n| L-1 | edge new |\n" + retired)
        self.commit("move it back")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_head_that_drops_main_copy_of_a_stale_row_elsewhere_is_changed(self):
        # #3401 Security P3: the stale row's text was matched file-wide, so main's copy in another table went too.
        other = "\n## Other\n\n| Name | x |\n|---|---|\n| L-1 | edge old |\n"
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n" + other, "| L-1 | edge new |\n")
        self.write("ASSUMPTIONS.md", self.UNION + "| L-1 | edge new |\n| B-1 | bak |\n" + other.replace("| L-1 | edge old |\n", ""))
        self.commit("drop both")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    SHARED = "\n## Other\n\n| ID | B |\n|---|---|\n| F-1 | f |\n| S-1 | shared |\n| F-2 | g |\n"

    def test_a_copy_of_a_repeated_row_both_sides_delete_is_same_but_an_edit_is_changed(self):
        # #3534: copies were counted file-wide, so the copy both sides deleted read as one the union brought back.
        far = "".join(f"| P-{i} | p |\n" for i in range(8))
        gone = self.SHARED.replace("| S-1 | shared |\n", "")
        reviewed = self.union_merge("| S-1 | shared |\n" + far + "| M-1 | main |\n" + gone, "| S-1 | shared |\n| L-2 | pr |\n" + far + gone,
                                    base_rows="| S-1 | shared |\n" + far + self.SHARED)
        self.assertEqual(self.read("ASSUMPTIONS.md").count("| S-1 |"), 1, "both sides were meant to delete one copy cleanly")
        self.assertEqual(self.check(reviewed), [])
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("| S-1 | shared |", "| S-1 | edited |"))
        self.commit("edit the repeated row")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_row_the_union_kept_where_merge_file_aligns_unlike_the_replay_is_changed(self):
        # #3534: where merge-file's conflicts do not rebuild the replay, the stale rows are counted file-wide as before.
        base = "\n| C |\nx\n| C |\n| A |\n| A |\n| D |\n\n"
        reviewed = self.union_merge(base + "| B |\n", "\n| C |\nx\n| A |\n", base_rows=base)
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        self.setUp()  # #3587 L3: here merge-file's conflicts alone count no row, so only the replay check reads it
        reviewed = self.union_merge("\n| A |\n| B |\n| A |\n", "\n| B |\n| A |\n", base_rows="\n| B |\n| C |\n| A |\n")
        onto = git(self.r, "merge-base", "main", "HEAD")
        # Which alignment each git picks varies by version (git 2.55 replays this merge without the extra row), so
        # merge-file's clean merge and the replay that kept a second `| B |` are fixed here rather than taken from git.
        clean = (self.UNION + "\n| A |\n| B |\n| A |\n").encode()
        replay = (self.UNION + "\n| B |\n| A |\n| B |\n| A |\n").encode()
        with mock.patch.object(premerge, "_merge_file", return_value=(clean, "unused")):
            self.assertEqual(premerge._stale(self.r, replay, "ASSUMPTIONS.md", reviewed, onto), {b"| B |": 1})
            self.assertEqual(premerge._stale(self.r, clean, "ASSUMPTIONS.md", reviewed, onto), {})

    def test_a_head_that_moves_a_pr_row_out_of_a_comment_is_changed(self):
        # #3401 Security P6: a row the reviewer read as inert, inside an HTML comment, moved into the live table.
        draft = "\n<!-- draft:\n| X | y |\n| L-1 | edge new |\n-->\n"
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", draft)
        self.write("ASSUMPTIONS.md", self.UNION + draft.replace("| L-1 | edge new |\n", "") + "| B-1 | bak |\n| L-1 | edge new |\n")
        self.commit("make it live")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_stale_row_dropped_is_changed_with_another_duplicate_id_or_a_mode_flip(self):
        # #3401 potency: each guard of the exemption is pinned, so reverting one fails here.
        far = "".join(f"| F-{i} | f |\n" for i in range(6))
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n" + far + "| X-1 | main |\n",
                                    "| X-1 | mine |\n| L-1 | edge new |\n" + far, base_rows="| L-1 | edge old |\n" + far)
        self.assertEqual(self.read("ASSUMPTIONS.md").count("| X-1 |"), 2, "both sides were meant to add X-1 cleanly")
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("| L-1 | edge old |\n", ""))
        self.commit("drop the stale row, keep both X-1")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        self.setUp()
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", "| L-1 | edge new |\n")
        self.write("ASSUMPTIONS.md", self.UNION + "| B-1 | bak |\n| L-1 | edge new |\n")
        self.commit("drop the stale row")
        self.assertEqual(self.check(reviewed), [])
        self.chmod_commit("ASSUMPTIONS.md")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_row_main_deleted_in_the_union_hunk_stays_deleted(self):
        # #3401 L3 delta: main deleted L-2 next to the PR's edit; the union kept it, and so did the exemption.
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", "| L-1 | edge new |\n| L-2 | b |\n",
                                    base_rows="| L-1 | edge old |\n| L-2 | b |\n")
        for rows, want in (("| L-1 | edge new |\n| B-1 | bak |\n", []), ("| B-1 | bak |\n| L-1 | edge new |\n", []),
                           ("| L-1 | edge new |\n| L-2 | b |\n| B-1 | bak |\n", ["ASSUMPTIONS.md"]),
                           ("| B-1 | bak |\n| L-1 | edge new |\n| L-2 | b |\n", ["ASSUMPTIONS.md"])):  # both forms
            with self.subTest(rows=rows):
                self.write("ASSUMPTIONS.md", self.UNION + rows)
                self.commit("resolve")
                self.assertEqual(self.check(reviewed), want)

    def test_a_row_the_pr_doubled_and_main_deleted_keeps_one_copy(self):
        # #3441: gone and cut were sets, so main's delete of R dropped the PR's added copy too.
        table = "\n| Name | x |\n|---|---|\n"
        reviewed = self.union_merge(table + "| S | s |\n", table + "| R | r |\n| R | r |\n", base_rows=table + "| R | r |\n")
        self.assertEqual(self.read("ASSUMPTIONS.md").count("| R |"), 2, "the union driver was meant to keep both")
        for rows, want in (("| R | r |\n| S | s |\n", []), ("| S | s |\n| R | r |\n", []),
                           ("| S | s |\n", ["ASSUMPTIONS.md"]), ("| R | r |\n| R | r |\n| S | s |\n", ["ASSUMPTIONS.md"])):
            with self.subTest(rows=rows):
                self.write("ASSUMPTIONS.md", self.UNION + table + rows)
                self.commit("resolve")
                self.assertEqual(self.check(reviewed), want)

    def test_a_union_replay_that_keeps_a_copy_of_a_deleted_duplicate_is_changed(self):
        # #3502: _stale read rows as a set, so the replay's second R, a copy the PR deleted, read same.
        table = "\n| Name | x |\n|---|---|\n"
        reviewed = self.union_merge(table + "| R | r |\n| R | r |\n| Q | qm |\n", table + "| R | r |\n| Q | qp |\n",
                                    base_rows=table + "| R | r |\n| R | r |\n| Q | q |\n")
        self.assertEqual(self.read("ASSUMPTIONS.md").count("| R |"), 2, "the union driver was meant to keep both")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        for rows, want in (("| R | r |\n| Q | qp |\n| Q | qm |\n", []),
                           ("| R | r |\n| R | r |\n| Q | qp |\n| Q | qm |\n", ["ASSUMPTIONS.md"])):
            with self.subTest(rows=rows):
                self.write("ASSUMPTIONS.md", self.UNION + table + rows)
                self.commit("resolve")
                self.assertEqual(self.check(reviewed), want)

    def test_a_union_replay_that_keeps_a_row_only_main_deleted_is_changed(self):
        # #3441: _stale read only the rows the PR dropped, so a replay keeping L-2, which main deleted, read same.
        reviewed = self.union_merge("| B-1 | bak |\n", "| L-1 | edge new |\n| L-2 | b |\n",
                                    base_rows="| L-1 | edge old |\n| L-2 | b |\n")
        self.assertIn("| L-2 | b |", self.read("ASSUMPTIONS.md"), "the union driver was meant to keep L-2")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        self.write("ASSUMPTIONS.md", self.UNION + "| L-1 | edge new |\n| B-1 | bak |\n")
        self.commit("drop the row main deleted")
        self.assertEqual(self.check(reviewed), [])

    def test_a_stale_row_kept_after_main_rows_or_a_prose_line_dropped_is_changed(self):
        # #3401 lens delta: pins the moved form's drop of a stale row with no PR edit, and the all-rows hunk guard.
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", "| N-1 | new |\n")
        self.write("ASSUMPTIONS.md", self.UNION + "| B-1 | bak |\n| L-1 | edge old |\n| N-1 | new |\n")
        self.commit("keep the deleted row")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        self.setUp()
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", "| L-1 | edge new |\nL-1 only holds on x86.\n")
        self.write("ASSUMPTIONS.md", self.UNION + "| L-1 | edge new |\n| B-1 | bak |\n")
        self.commit("drop the PR's prose line")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_head_built_from_another_diff_alignment_is_changed(self):
        # #3401 Security P7: merge-file (Myers) and merge-tree (histogram) merge this file differently outside the
        # union hunk; a head copying merge-file's merge read `same` though it differs from the replay there.
        top = "\n\n## Notes\n\n"
        b = "| B |\n\n| C |\n| D |\n| A |\nx\nx\nx\n"
        p = "| B |\n\n| D |\n| A |\n\nx\nx\nx\n"
        m = "| C |\n| B |\n\n| C |\n| D |\n| D |\n| A |\nx\n| A |\nx\nx\n"
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |" + top + m, "| L-1 | edge new |" + top + p,
                                    base_rows="| L-1 | edge old |" + top + b)
        merge_file = "| C |\n| B |\n\n| D |\n| D |\n| A |\n\nx\n| A |\nx\nx\n"
        self.write("ASSUMPTIONS.md", self.UNION + "| L-1 | edge new |\n| B-1 | bak |" + top + merge_file)
        self.commit("merge-file's merge, stale dropped")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_decisions_rows_both_appended_under_one_id_are_changed(self):
        # #3401 L3: the appended-rows exemption kept two D-9 rows as `same`; doclint fails that head.
        reviewed = self.decisions_conflict(main="| D-1 | base |\n| D-9 | main |\n", pr="| D-1 | base |\n| D-9 | mine |\n")
        self.resolve("DECISIONS.md", "| D-9 | mine |\n| D-9 | main |\n")
        self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    def test_a_union_merge_that_brings_back_a_deleted_row_is_changed(self):
        # #1912: the PR deleted a row main left alone; the union keeps it without any duplicate ID.
        reviewed = self.union_merge("| B-1 | bak |\n| L-1 | edge old |\n", "", base_rows="| L-1 | edge old |\n")
        self.assertIn("| L-1 | edge old |", self.read("ASSUMPTIONS.md"))
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        self.write("ASSUMPTIONS.md", self.UNION + "| B-1 | bak |\n")
        self.commit("drop the stale row")
        self.assertEqual(self.check(reviewed), [])

    def test_a_union_merge_of_two_edits_to_one_row_is_changed_however_resolved(self):
        # Both sides edited L-1: no stale row, a real conflict, so every resolution owes a delta review.
        reviewed = self.union_merge("| L-1 | main edit |\n", "| L-1 | pr edit |\n")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])
        for rows in ("| L-1 | pr edit |\n", "| L-1 | main edit |\n"):
            with self.subTest(rows=rows):
                self.write("ASSUMPTIONS.md", self.UNION + rows)
                self.commit("pick one")
                self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

    def test_a_clean_merge_that_repeats_a_decision_id_is_changed(self):
        # No union driver: both sides add D-9 far apart, git merges cleanly, doclint would fail the head.
        rows = "".join(f"| D-{i} | d{i} |\n" for i in range(1, 8))
        git(self.r, "checkout", "-q", "main")
        self.write("DECISIONS.md", "| ID | Decision |\n|---|---|\n" + rows)
        self.commit("decisions")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("DECISIONS.md", self.read("DECISIONS.md") + "| D-9 | mine |\n")
        reviewed = self.commit("pr row")
        self.merge_main_after(lambda: self.write("DECISIONS.md", self.read("DECISIONS.md").replace(
            "| D-1 | d1 |\n", "| D-1 | d1 |\n| D-9 | main |\n")))
        self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    def test_two_appended_rows_kept_in_another_file_are_changed(self):
        reviewed = self.decisions_conflict(name="NOTES.md")
        self.resolve("NOTES.md", "| D-2 | main |\n| D-3 | mine |\n")
        self.assertEqual(self.check(reviewed), ["NOTES.md"])

    def test_main_merged_in_then_a_pr_line_changed_is_changed(self):
        reviewed = self.pr()
        self.merge_main_after(lambda: self.write("a.txt", self.read("a.txt").replace("line 4\n", "line 4 main\n")))
        self.write("a.txt", self.read("a.txt").replace("line two\n", "line 2 again\n"))
        self.commit("after the accept")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_main_merged_in_then_a_pr_hunk_moved_is_changed(self):
        # Same added lines at another place: equal +/- lines, different merged file.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("a.txt", self.read("a.txt").replace("line 3\n", "line 3\ndeny()\n"))
        reviewed = self.commit("pr")
        self.merge_main_after(lambda: self.write("b.txt", "b main\n"))
        self.write("a.txt", self.read("a.txt").replace("line 3\ndeny()\n", "line 3\n").replace("line 20\n", "line 20\ndeny()\n"))
        self.commit("move the call")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_a_merge_resolution_that_edits_a_pr_line_is_changed(self):
        reviewed = self.pr()
        git(self.r, "checkout", "-q", "main")
        self.write("a.txt", self.read("a.txt").replace("line 2\n", "line 2 main\n"))
        self.commit("main conflicts")
        git(self.r, "checkout", "-q", "pr")
        pr_text = git(self.r, "show", "pr:a.txt") + "\n"
        merge = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                               cwd=self.r, capture_output=True, text=True)
        self.assertNotEqual(merge.returncode, 0, "the merge was meant to conflict")
        git(self.r, "rev-parse", "-q", "--verify", "MERGE_HEAD")
        self.write("a.txt", pr_text.replace("line two\n", "line 2 main\n"))
        self.commit("resolve to main's line")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_a_side_branch_merged_in_is_changed(self):
        reviewed = self.pr()
        git(self.r, "checkout", "-q", "-b", "side", "main")
        self.write("c.txt", "side\n")
        self.commit("side")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "side")
        self.assertEqual(self.check(reviewed), ["c.txt"])

    def test_main_moving_on_unmerged_is_same(self):
        reviewed = self.pr()
        self.merge_main_after(lambda: self.write("a.txt", self.read("a.txt").replace("line 4\n", "line 4 main\n")))
        git(self.r, "checkout", "-q", "main")
        self.write("a.txt", self.read("a.txt").replace("line 1\n", "line 1 later\n"))
        self.commit("main moves again")
        git(self.r, "checkout", "-q", "pr")
        self.assertEqual(self.check(reviewed), [])

    def test_a_later_push_names_the_changed_file(self):
        reviewed = self.pr()
        self.write("b.txt", "b changed\n")
        self.commit("after the accept")
        self.assertEqual(self.check(reviewed), ["b.txt"])

    def test_an_indentation_only_push_that_flips_a_decision_is_changed(self):
        # Reported 2026-10-10: patch-id ignores whitespace, so this read as `same`.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("auth.py", "def allowed(user):\n    ok = False\n    if user.admin:\n        log(user)\n        ok = True\n    return ok\n")
        reviewed = self.commit("pr: only admins")
        self.write("auth.py", self.read("auth.py").replace("        ok = True\n", "    ok = True\n"))
        self.commit("dedent: everyone allowed")
        self.assertEqual(self.check(reviewed), ["auth.py"])

    def test_a_whitespace_only_change_is_changed(self):
        reviewed = self.pr()
        self.write("a.txt", self.read("a.txt").replace("line two\n", "line  two\n"))
        self.commit("spacing")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_a_binary_change_is_changed(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "blob.bin").write_bytes(b"\x00\x01deny")
        reviewed = self.commit("pr")
        (self.r / "blob.bin").write_bytes(b"\x00\x01allow")
        self.commit("later")
        self.assertEqual(self.check(reviewed), ["blob.bin"])

    def test_cli_exit_codes(self):
        reviewed = self.pr()
        run = lambda: subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--base", "main", reviewed],
                                     cwd=self.r, capture_output=True, text=True)
        ok = run()
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "same"))
        self.write("b.txt", "x\n")
        self.commit("later")
        bad = run()
        self.assertEqual((bad.returncode, bad.stdout.split()), (1, ["changed", "b.txt"]))

    def test_mark_press_merge_paths(self):
        for f in ("CLAUDE.md", "docs/OPERATING.md", ".claude/settings.json", ".github/workflows/ci.yml",
                  "tools/risk_tier.py", "tools/premerge.py", "tools/ci_scope.py", "tools/ci_scope_x.py",
                  "tools/g1_scope.py", "tools/g1_scope_g2.txt", "docs/LANES.md", "tools/trace.py", "tools/old_core.txt",
                  # KRN-2cap (#2935): the trusted core's budget and the tool that enforces it.
                  "tools/trusted_base.py", "tools/trusted_core.txt",
                  # #2438: this gate's own tests and the lens rules need the Security accept too.
                  "tests/test_premerge.py", "tests/test_premerge_lens.py", "reviews/l3/README.md",
                  "reviews/security/README.md", "reviews/ux/README.txt"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        # The other gate tests stay as narrowed on Mark's "Narrow only" (2026-10-16).
        for f in ("tools/records.py", "reviews/l3/2026-10-15-pr1.md", "README.md", "docs/OTHER.md", "src/claude/x.go",
                  "reviews/README.md", "reviews/a/b/README.md", "tests/x/test_premerge.py", "tests/test_risk_tier.py",
                  "tests/test_ci_scope.py", "tests/test_g1_scope.py", "tests/test_workflows.py", "tests/test_merge_queue.py",
                  "tests/test_lane.py", "tools/trusted_base_parsers.txt", "tests/test_trusted_base.py"):
            self.assertEqual(premerge.mark_paths([f]), [], f)

    def test_mark_paths_cover_agent_config_and_tier_inputs(self):
        # Security R3 on #1824: MCP config, other teams' rules, nested CLAUDE files, and the
        # core list tools/risk_tier.py reads to set tiers.
        self.assertTrue((ROOT / "broker/core/core.txt").is_file())
        self.assertIn("core.txt", (ROOT / "tools/risk_tier.py").read_text())
        for f in (".mcp.json", "AGENTS.md", "CLAUDE.local.md", "broker/CLAUDE.md", "a/b/CLAUDE.local.md",
                  "broker/core/core.txt"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        # PREMERGE-paths (#1835): nested config and newline-bearing paths.
        for f in ("sub/AGENTS.md", "sub/.mcp.json", "sub/.claude/settings.json", "a/b/.claude/x",
                  "x\n/.claude/y", ".github/a\nb", "tools/premerge.py"):
            self.assertEqual(premerge.mark_paths([f]), [f], repr(f))
        for f in ("CLAUDE.md\n", "tools/premerge.py\n", "tests/test_records.py", "x/.claudex/y"):
            self.assertEqual(premerge.mark_paths([f]), [], repr(f))
        for f in ("broker/core/core.go", "docs/AGENTS.md.bak", "XCLAUDE.md", "a/CLAUDE.md/x.go", "x.mcp.json"):
            self.assertEqual(premerge.mark_paths([f]), [], f)

    def test_cli_needs_mark(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        run = lambda: subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "--base", "main"],
                                     cwd=self.r, capture_output=True, text=True)
        self.write("b.txt", "x\n")
        self.commit("code")
        ok = run()
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "agent"))
        (self.r / "CLAUDE.md").write_text("rules\n")
        self.commit("rules")
        bad = run()
        self.assertEqual((bad.returncode, bad.stdout.split()), (1, ["mark", "CLAUDE.md"]))

    def test_cli_needs_mark_in_any_position(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "sub").mkdir()
        self.write("sub/CLAUDE.md", "rules\n")
        self.commit("nested rules")
        for argv in (["--needs-mark", "--base", "main"], ["--base", "main", "--needs-mark"],
                     ["--base", "main", "HEAD", "--needs-mark"]):
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), *argv],
                               cwd=self.r, capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout.split()), (1, ["mark", "sub/CLAUDE.md"]), argv)

    def test_cli_needs_mark_rejects_a_second_positional(self):
        # `--needs-mark origin/main pr` read origin/main as the head and printed `agent` for any PR.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("CLAUDE.md", "rules\n")
        self.commit("rules")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "main", "pr"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("agent", r.stdout.split())

    def test_cli_needs_mark_rejects_an_empty_range(self):
        # `--needs-mark origin/main` read origin/main as the head: base..base is empty and printed `agent`.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("CLAUDE.md", "rules\n")
        self.commit("rules")
        git(self.r, "update-ref", "refs/remotes/origin/main", "main")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "origin/main"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("agent", r.stdout.split())

    def needs_mark(self, head="pr"):
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "--base", "main", head],
                           cwd=self.r, capture_output=True, text=True)
        return r.returncode, r.stdout.split()

    def test_cli_needs_mark_sees_a_revert_made_by_a_criss_cross_merge(self):
        # #2138: with two merge bases, `git merge-base` picked the one where the head's CLAUDE.md was
        # unchanged, so a PR whose merge reverts main's CLAUDE.md printed `agent`.
        self.write("CLAUDE.md", "v0\n")
        m0 = self.commit("m0")
        git(self.r, "checkout", "-q", "-b", "side")
        self.write("CLAUDE.md", "v1\n")
        m2 = self.commit("m2")
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "m1\n")
        m1 = self.commit("m1")
        git(self.r, "checkout", "-q", "-b", "pr", m1)
        git(self.r, "merge", "-q", "--no-edit", m2)
        self.write("CLAUDE.md", "v0\n")
        self.write("a.txt", "pr\n")
        git(self.r, "add", "."), git(self.r, "commit", "-q", "--amend", "--no-edit")
        git(self.r, "checkout", "-q", "main")
        git(self.r, "merge", "-q", "--no-edit", m2)
        self.assertEqual(len(git(self.r, "merge-base", "--all", "main", "pr").split()), 2, m0)
        merged = git(self.r, "merge-tree", "--write-tree", "main", "pr")
        self.assertEqual(git(self.r, "show", f"{merged}:CLAUDE.md"), "v0")  # the merge reverts main's v1
        self.assertEqual(self.needs_mark(), (1, ["mark", "CLAUDE.md"]))

    def test_cli_needs_mark_sees_a_mark_file_the_merge_resolves_in_conflict(self):
        # #2138: a conflicted merge-tree keeps its markers, so the conflicted file still reads as changed.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("CLAUDE.md", "pr\n")
        self.commit("pr rules")
        git(self.r, "checkout", "-q", "main")
        self.write("CLAUDE.md", "main\n")
        self.commit("main rules")
        self.assertEqual(self.needs_mark(), (1, ["mark", "CLAUDE.md"]))

    def test_cli_needs_mark_sees_a_claude_symlink(self):
        # #2138: `.claude/` needed a slash, so `broker/.claude -> ../cfg` plus cfg/settings.json printed `agent`.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "cfg").mkdir()
        (self.r / "broker").mkdir()
        self.write("cfg/settings.json", "{}\n")
        (self.r / "broker/.claude").symlink_to("../cfg")
        self.commit("linked settings")
        self.assertEqual(self.needs_mark(), (1, ["mark", "broker/.claude"]))
        for f in (".claude", "a/.claude", "a/.claude/x"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        for f in (".claudex", "a/.claude.bak", "a/x.claude", ".claude\n"):
            self.assertEqual(premerge.mark_paths([f]), [], repr(f))

    def test_check_gate(self):
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("b.md", "x\n")  # top-level *.md: tier C, so no lens screen is owed
        sha = self.commit("code")
        c = lambda verdict, sha, at, who="OWNER", pr=7, mark="<!-- record: l3 -->": {
            "author_association": who, "created_at": at, "updated_at": at,
            "body": f"Verdict: {verdict}\n# t\nRecord: PR #{pr} · package X-1 · head {sha[:7]}\n{mark}\n"}
        def run(comments, head="HEAD"):
            f = pathlib.Path(self._d.name + ".comments.json")
            self.addCleanup(lambda: f.unlink(missing_ok=True))
            f.write_text(json.dumps(comments))
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main", head],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run([c("accept", sha, "1")]), (0, ["same"]))
        self.assertEqual(run([]), (1, ["no-verdict"]))
        # untrusted author, other PR, no L3 marker: none counts
        for bad in (c("accept", sha, "1", who="NONE"), c("accept", sha, "1", pr=8), c("accept", sha, "1", mark="")):
            self.assertEqual(run([bad]), (1, ["no-verdict"]))
        # an edited verdict is never an accept and still supersedes the earlier one; only a fresh comment replaces it
        edited = lambda x: {**x, "updated_at": "9"}
        # #3105: the edit is named, not reported as a bare not-accepted
        self.assertEqual(run([edited(c("accept", sha, "1"))]), (1, EDITED("l3")))
        self.assertEqual(run([c("accept", sha, "1"), edited(c("fix-list", sha, "2"))]), (1, EDITED("l3")))
        self.assertEqual(run([edited(c("accept", sha, "1")), c("accept", sha, "2")]), (0, ["same"]))
        missing = {k: v for k, v in c("accept", sha, "1").items() if k != "updated_at"}
        self.assertEqual(run([missing]), (1, EDITED("l3")))
        self.assertEqual(run([{**c("accept", sha, "1"), "updated_at": "1"}]), (0, ["same"]))
        # #3611: a Record line that does not parse is named, not read as no-verdict; like an edit it supersedes
        spaced = lambda x: {**x, "body": x["body"].replace("package X-1", "package house keeping")}
        self.assertEqual(run([spaced(c("accept", sha, "1"))]), (1, UNPARSED("l3")))
        self.assertEqual(run([c("accept", sha, "1"), spaced(c("accept", sha, "2"))]), (1, UNPARSED("l3")))
        self.assertEqual(run([spaced(c("accept", sha, "1")), c("accept", sha, "2")]), (0, ["same"]))
        unrecorded = {**c("accept", sha, "1"), "body": "Verdict: accept\n# t\n<!-- record: l3 -->\n"}
        self.assertEqual(run([unrecorded]), (1, UNPARSED("l3")))
        # a later fix-list supersedes the accept
        self.assertEqual(run([c("accept", sha, "1"), c("fix-list", sha, "2")]), (1, ["not-accepted"]))
        # a push after the accept reads as changed; a delta accept at the new head clears it
        self.write("b.md", "y\n")
        new = self.commit("later")
        self.assertEqual(run([c("accept", sha, "1")]), (1, ["changed", "b.md"]))
        self.assertEqual(run([c("accept", sha, "1"), c("accept", new, "2")]), (0, ["same"]))

    def test_check_gate_spec_needs_nothing_extra(self):
        # D-137 supersedes D-130: a SPEC.md change merges on its accepts alone, with no Transcribes: line.
        # SPEC.md is tier B, so those are L3 plus the combined pass (#2644), which one comment may carry.
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("SPEC.md", "spec\n")
        sha = self.commit("spec")
        f = pathlib.Path(self._d.name + ".comments.json")
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        def run(mark):
            f.write_text(json.dumps([{"author_association": "OWNER", "created_at": "1", "updated_at": "1",
                "body": f"Verdict: accept\n# t\nRecord: PR #7 · package X-1 · head {sha[:7]}\n{mark}\n"}]))
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run("<!-- record: l3 -->"), (1, ["needs-lens", "combined"]))
        self.assertEqual(run("<!-- record: combined -->"), (0, ["same"]))

    def test_check_gate_files_need_a_separate_security_accept(self):
        # D-137: a PR touching a --needs-mark path also needs the newest trusted Security verdict, in a comment
        # without an l3/combined marker, to accept a head whose diff equals this one.
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "docs").mkdir()
        self.write("docs/OPERATING.md", "rules\n")
        sha = self.commit("gate")
        rec = lambda v, head, marks, who="OWNER", at="1", pr=7: {"author_association": who, "created_at": at, "updated_at": at,
            "body": f"Verdict: {v}\n# t\nRecord: PR #{pr} · package X-1 · head {head[:7]}\n{marks}"}
        l3 = rec("accept", sha, "<!-- record: combined -->\n", at="0")
        sec = lambda v="accept", head=sha, **k: rec(v, head, "<!-- record: security -->\n", **k)
        def run(comments):
            f = pathlib.Path(self._d.name + ".comments.json")
            self.addCleanup(lambda: f.unlink(missing_ok=True))
            f.write_text(json.dumps(comments))
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        need = (1, ["needs-security", "docs/OPERATING.md"])
        self.assertEqual(run([l3]), need)
        self.assertEqual(run([l3, sec()]), (0, ["same"]))
        # untrusted author, other PR, fix-list, unknown head: none counts
        self.assertEqual(run([l3, sec(who="NONE")]), need)
        self.assertEqual(run([l3, sec(pr=8)]), need)
        self.assertEqual(run([l3, sec("fix-list")]), need)
        self.assertEqual(run([l3, sec(head="0" * 40)]), need)
        # an edited Security accept is not an accept, and an edited Security fix-list still supersedes an earlier accept
        self.assertEqual(run([l3, {**sec(), "updated_at": "9"}]), (1, EDITED("security")))
        self.assertEqual(run([l3, sec(at="1"), {**sec("fix-list", at="2"), "updated_at": "9"}]), (1, EDITED("security")))
        self.assertEqual(run([l3, {**sec(at="1"), "updated_at": "9"}, sec(at="2")]), (0, ["same"]))
        # #3611 (seen on #3603): a package with spaces never parsed, so the accept read as needs-security
        spaced = lambda x: {**x, "body": x["body"].replace("package X-1", "package housekeeping (G2 freeze exempt-pr cleanup)")}
        self.assertEqual(run([l3, spaced(sec())]), (1, UNPARSED("security")))
        self.assertEqual(run([l3, spaced(sec(at="1")), sec(at="2")]), (0, ["same"]))
        # one comment carrying both markers is one review: it counts as the L3 accept, not the Security one
        both = rec("accept", sha, "<!-- record: security -->\n<!-- record: combined -->\n")
        self.assertEqual(run([both]), need)
        # a later Security fix-list supersedes the accept; a later accept clears it
        self.assertEqual(run([l3, sec(at="1"), sec("fix-list", at="2")]), need)
        self.assertEqual(run([l3, sec("fix-list", at="1"), sec(at="2")]), (0, ["same"]))
        # main merged in after the accept: the Security accept carries
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "main\n")
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")
        self.assertEqual(run([l3, sec()]), (0, ["same"]))
        # a push after the Security accept: the L3 delta accept alone is not enough
        self.write("docs/OPERATING.md", "looser rules\n")
        new = self.commit("later")
        self.assertEqual(run([l3, sec(), rec("accept", new, "<!-- record: combined -->\n", at="2")]), need)
        self.assertEqual(run([l3, sec(), rec("accept", new, "<!-- record: combined -->\n", at="2"),
                              sec(head=new, at="3")]), (0, ["same"]))

    def test_bot_gate(self):
        # PREMERGE-wire (#1860): the generated-file bot PRs carry no L3 verdict, so `--bot` passes
        # them only when the branch is a known bot branch and the diff is that bot's file alone.
        git(self.r, "checkout", "-q", "-b", "pr")
        def run(ref):
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", ref, "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run("bot/trace"), (1, ["not-bot"]))  # empty change
        self.write("TRACE.md", "t\n")
        self.commit("trace")
        self.assertEqual(run("bot/trace"), (0, ["bot"]))
        for ref in ("bot/metrics", "bot/board"):  # another bot's file
            self.assertEqual(run(ref), (1, ["not-bot", "TRACE.md"]), ref)
        # not a bot branch; bot/records went with records.yml (#2235)
        for ref in ("pkg/x", "bot/trace2", "xbot/trace", "bot/trace/x", "bot/records"):
            self.assertEqual(run(ref), (1, ["not-bot"]), ref)
        self.write("b.txt", "x\n")
        self.commit("smuggled code")
        self.assertEqual(run("bot/trace"), (1, ["not-bot", "b.txt"]))

    def test_bot_gate_records_is_gone(self):
        # #2235: records.yml was its only writer, so a bot/records branch of new review files is hand-made and needs a verdict.
        self.assertNotIn("bot/records", premerge.BOT)
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "reviews/security").mkdir(parents=True)
        self.write("reviews/security/2026-10-15-pr2.md", "fabricated\n")
        self.commit("records")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", "bot/records", "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.split()), (1, ["not-bot"]))

    def lens_run(self, comments):
        import json
        f = pathlib.Path(self._d.name + ".comments.json")
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        f.write_text(json.dumps(comments))
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        return r.returncode, r.stdout.split()

    @staticmethod
    def rec(v, head, marks, who="OWNER", at="1", pr=7):
        return {"author_association": who, "created_at": at, "updated_at": at,
                "body": f"Verdict: {v}\n# t\nRecord: PR #{pr} · package X-1 · head {head[:7]}\n{marks}"}

    def test_check_gate_tier_a_needs_ux_and_potency(self):
        # PREMERGE-lens (#2644): #2628 and #2632 were tier A and merged on L3 and Security alone.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "image").mkdir()
        self.write("image/build.sh", "true\n")
        sha = self.commit("tier A")
        self.assertEqual(premerge.lenses_owed(["image/build.sh"]), ["ux", "potency"])
        l3 = self.rec("accept", sha, "<!-- record: l3 -->\n", at="0")
        ux = lambda v="accept", head=sha, **k: self.rec(v, head, "<!-- record: ux -->\n", **k)
        pot = lambda v="accept", head=sha, **k: self.rec(v, head, "<!-- record: potency -->\n", **k)
        sec = lambda head=sha, at="4": self.rec("accept", head, "<!-- record: security -->\n", at=at)
        run = lambda comments: self.lens_run(comments + [sec()])  # #3817: tier A owes Security too
        self.assertEqual(run([l3]), (1, ["needs-lens", "ux,potency"]))
        self.assertEqual(run([l3, ux()]), (1, ["needs-lens", "potency"]))
        self.assertEqual(run([l3, pot()]), (1, ["needs-lens", "ux"]))
        self.assertEqual(run([l3, ux(), pot()]), (0, ["same"]))
        # one comment carrying both markers covers both lenses
        both = self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n")
        self.assertEqual(run([l3, both]), (0, ["same"]))
        # untrusted, other PR, fix-list, edited, unknown head, superseded: none counts
        for bad in (ux(who="NONE"), ux(pr=8), ux("fix-list"), ux(head="0" * 40)):
            self.assertEqual(run([l3, bad, pot()]), (1, ["needs-lens", "ux"]), bad)
        self.assertEqual(run([l3, {**ux(), "updated_at": "9"}, pot()]), (1, EDITED("ux")))
        self.assertEqual(run([l3, {**ux(), "updated_at": "9"}]), (1, EDITED("ux")))
        spaced = lambda x: {**x, "body": x["body"].replace("package X-1", "package two words")}
        self.assertEqual(run([l3, spaced(ux()), pot()]), (1, UNPARSED("ux")))
        self.assertEqual(run([l3, spaced(ux()), spaced(pot())]), (1, UNPARSED("ux,potency")))
        self.assertEqual(run([l3, ux(at="1"), ux("fix-list", at="2"), pot()]), (1, ["needs-lens", "ux"]))
        # a marker that is not on its own line is not a marker
        inline = self.rec("accept", sha, "see <!-- record: ux --> above\n")
        self.assertEqual(run([l3, inline, pot()]), (1, ["needs-lens", "ux"]))
        # main merged in after the accepts: they carry; a later push needs fresh lens accepts
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "main\n")
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")
        self.assertEqual(run([l3, ux(), pot()]), (0, ["same"]))
        self.write("image/build.sh", "false\n")
        new = self.commit("later")
        l3new = self.rec("accept", new, "<!-- record: l3 -->\n", at="2")
        self.assertEqual(run([l3, ux(), pot(), l3new]), (1, ["needs-lens", "ux,potency"]))
        fresh = [l3, ux(), pot(), l3new, ux(head=new, at="3"), pot(head=new, at="3")]
        self.assertEqual(run(fresh), (1, ["needs-security", "image/build.sh"]))
        self.assertEqual(self.lens_run(fresh + [sec(head=new, at="5")]), (0, ["same"]))

    def test_check_gate_tier_a_needs_security(self):
        # #3817: #3811 (tier A, no gate file) merged on L3/combined, UX and Potency with no Security record.
        # Every tier-A PR owes the separate Security accept at an equal head; tiers B and C owe none.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "broker/clerk/camera").mkdir(parents=True)
        self.write("broker/clerk/camera/decode_test.go", "package camera\n")
        sha = self.commit("tier A")
        l3 = self.rec("accept", sha, "<!-- record: combined -->\n", at="0")
        lens = self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n")
        sec = lambda v="accept", head=sha, at="2", **k: self.rec(v, head, "<!-- record: security -->\n", at=at, **k)
        need = (1, ["needs-security", "broker/clerk/camera/decode_test.go"])
        self.assertEqual(self.lens_run([l3, lens]), need)
        self.assertEqual(self.lens_run([l3, lens, sec()]), (0, ["same"]))
        for bad in (sec(who="NONE"), sec(pr=8), sec("fix-list"), sec(head="0" * 40)):
            self.assertEqual(self.lens_run([l3, lens, bad]), need, bad)
        self.assertEqual(self.lens_run([l3, lens, sec(at="2"), sec("fix-list", at="3")]), need)
        # the lens comment or the L3 comment carrying a security marker is not the separate review
        self.assertEqual(self.lens_run([l3, self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n"
                                                     "<!-- record: security -->\n<!-- record: l3 -->\n")]), need)
        # a push after the Security accept needs a fresh one
        self.write("broker/clerk/camera/decode_test.go", "package camera // x\n")
        new = self.commit("later")
        again = [l3, lens, sec(), self.rec("accept", new, "<!-- record: combined -->\n", at="3"),
                 self.rec("accept", new, "<!-- record: ux -->\n<!-- record: potency -->\n", at="3")]
        self.assertEqual(self.lens_run(again), need)
        self.assertEqual(self.lens_run(again + [sec(head=new, at="4")]), (0, ["same"]))

    def test_check_gate_tiers_b_and_c_need_no_security(self):
        for path, marks in (("SPEC.md", "<!-- record: combined -->\n"), ("b.md", "<!-- record: l3 -->\n")):
            git(self.r, "checkout", "-q", "-B", "pr", "main")
            self.write(path, path + "\n")
            sha = self.commit(path)
            self.assertEqual(self.lens_run([self.rec("accept", sha, marks)]), (0, ["same"]), path)

    def test_check_gate_lens_comes_before_security(self):
        # A tier-A gate-file PR owes both; the lens screen is reported first, then the Security accept.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "tools").mkdir()
        self.write("tools/premerge.py", "x\n")
        sha = self.commit("gate")
        l3 = self.rec("accept", sha, "<!-- record: l3 -->\n", at="0")
        lens = self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n")
        self.assertEqual(self.lens_run([l3]), (1, ["needs-lens", "ux,potency"]))
        self.assertEqual(self.lens_run([l3, lens]), (1, ["needs-security", "tools/premerge.py"]))
        sec = self.rec("accept", sha, "<!-- record: security -->\n", at="2")
        self.assertEqual(self.lens_run([l3, lens, sec]), (0, ["same"]))

    def test_lenses_owed_by_tier(self):
        owed = premerge.lenses_owed
        self.assertEqual(owed(["b.md", "docs/x.md"]), [])  # tier C
        self.assertEqual(owed(["SPEC.md"]), ["combined"])  # tier B
        self.assertEqual(owed(["b.txt", "b.md"]), ["combined"])  # unmatched path: B
        self.assertEqual(owed(["image/build.sh", "SPEC.md"]), ["ux", "potency"])  # highest tier wins
        # D-086: a tier-A diff confined to assurance tooling owes potency only
        for files in (["tools/depaudit.py"], ["tools/canary.py", "tests/test_canary.py"], ["assurance/dep-targets.json"],
                      ["tools/risk_tier.py", "tests/test_risk_tier_custody.py"]):
            self.assertEqual(owed(files), ["potency"], files)
        for files in (["tools/canary.py", "image/build.sh"], ["tools/canary.py", "b.md"], ["tools/premerge.py"]):
            self.assertEqual(owed(files), ["ux", "potency"], files)


if __name__ == "__main__":
    unittest.main()
