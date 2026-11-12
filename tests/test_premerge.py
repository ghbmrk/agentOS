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
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _nogit_bg import setUpModule, tearDownModule  # noqa: E402,F401


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


EDITED = lambda kind: ["edited-verdict", kind + ":", *"a verdict edited after posting never counts, post a new comment".split()]
UNPARSED = lambda kind, pr=7: ["unparsed-record", kind + ":",
    *f'Record line must be "Record: PR #{pr} · package <ID-without-spaces> · head <sha>"'.split()]
MISPLACED = lambda kind: ["misplaced-marker", kind + ":",
    *"a <!-- record: <kind> --> marker must sit directly under the Record line, not above it or elsewhere".split()]
UNRESOLVED = lambda kind, sha: ["unresolved-record", kind + ":", "Record", "head", sha,
    *"resolves to no single commit here, post a new verdict naming the reviewed head".split()]


REPO = "o/agentOS"


def bundle(head=(), base=(), pr=7, repo=REPO, branch="pr"):
    """A --runs document for PR `pr` from `repo`'s `branch` into this repository."""
    return {"repo": REPO, "pr": {"number": pr, "repo": repo, "branch": branch}, "head": list(head), "base": list(base)}


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

    def runs(self, head=(), base=()):
        """A --runs file; with none, the repository has no workflows, so no held check is owed."""
        import json
        f = pathlib.Path(self._d.name + ".runs.json")
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        f.write_text(json.dumps(bundle(head, base)))
        return str(f)

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
        for rows in ("| D-2 | main |\n| D-4 | other |\n", "| D-2 | main |\n", "| D-3 | mine |\n", "| D-4 | main |\n| D-3 | mine |\n",
                     "| D-2 | main |\n| D-3 | mine |\n| D-5 | extra |\n", "| D-2 | main |\n| D-3 | mine |\n| D-2 | main |\n"):
            with self.subTest(rows=rows):
                self.setUp()
                reviewed = self.decisions_conflict()
                self.resolve("DECISIONS.md", rows)
                self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    def test_decisions_reviewed_row_renumbered_past_mains_is_same_unless_cited(self):
        # #4030: two PRs took D-244; the later one renumbered its row and owed a delta review for one cell.
        for rows in ("| D-2 | main |\n| D-4 | mine |\n", "| D-4 | mine |\n| D-2 | main |\n"):
            with self.subTest(rows=rows):
                self.setUp()
                reviewed = self.decisions_conflict(main="| D-1 | base |\n| D-3 | main |\n")
                self.resolve("DECISIONS.md", rows.replace("D-2 ", "D-3 "))
                self.assertEqual(self.check(reviewed), [])
        self.setUp()
        git(self.r, "checkout", "-q", "main")
        self.resolve("DECISIONS.md", "", base=True)
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("note.md", "Per D-3, the PR does this.\n")
        reviewed = self.resolve("DECISIONS.md", "| D-3 | mine |\n")
        git(self.r, "checkout", "-q", "main")
        self.resolve("DECISIONS.md", "| D-3 | main |\n")
        git(self.r, "checkout", "-q", "pr")
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                               cwd=self.r, capture_output=True)
        self.resolve("DECISIONS.md", "| D-3 | main |\n| D-4 | mine |\n")
        self.assertEqual(self.check(reviewed), ["DECISIONS.md"])  # note.md still names D-3, now main's row
        self.write("note.md", "Per D-4, the PR does this.\n")
        self.commit("cite the new ID")
        self.assertEqual(sorted(self.check(reviewed)), ["note.md"])
        # A reviewed row that cites another reviewed row's old ID, or any row whose ID cell was dropped, reads changed.
        for main, pr, rows in (("| D-2 | main |\n| D-3 | main2 |\n", "| D-2 | mine |\n| D-3 | amends D-2 |\n",
                                "| D-2 | main |\n| D-3 | main2 |\n| D-4 | mine |\n| D-5 | amends D-2 |\n"),
                               ("| D-2 | main |\n", "| D-3 | mine |\n", "| D-2 | main |\n|#| mine |\n")):
            with self.subTest(rows=rows):
                self.setUp()
                reviewed = self.decisions_conflict(main="| D-1 | base |\n" + main, pr="| D-1 | base |\n" + pr)
                self.resolve("DECISIONS.md", rows)
                self.assertEqual(self.check(reviewed), ["DECISIONS.md"])

    def allow_conflict(self):
        """The PR drops the last line of x_allow.txt while main appends after it (#3991); returns the reviewed head."""
        git(self.r, "checkout", "-q", "main")
        self.write("x_allow.txt", "# header\nallow a\nallow b\n")
        self.commit("allow")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("x_allow.txt", "# header\nallow a\nallow p\n")
        reviewed = self.commit("pr")
        git(self.r, "checkout", "-q", "main")
        self.write("x_allow.txt", "# header\nallow a\nallow b\nallow m\n")
        self.commit("main")
        git(self.r, "checkout", "-q", "pr")
        merge = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                               cwd=self.r, capture_output=True)
        self.assertNotEqual(merge.returncode, 0, "the merge was meant to conflict")
        return reviewed

    def test_allowlist_conflict_kept_both_sides_is_same_in_any_order(self):
        for text in ("# header\nallow a\nallow p\nallow m\n", "# header\nallow a\nallow m\nallow p\n"):
            with self.subTest(text=text):
                self.setUp()
                reviewed = self.allow_conflict()
                self.write("x_allow.txt", text)
                self.commit("resolved")
                self.assertEqual(self.check(reviewed), [])

    def test_allowlist_resolution_that_adds_drops_or_keeps_a_removed_line_is_changed(self):
        for text in ("# header\nallow a\nallow b\nallow p\nallow m\n", "# header\nallow a\nallow p\n",
                     "# header\nallow a\nallow p\nallow m\nallow x\n", "# header\nallow a\nallow p\nallow p\nallow m\n"):
            with self.subTest(text=text):
                self.setUp()
                reviewed = self.allow_conflict()
                self.write("x_allow.txt", text)
                self.commit("resolved")
                self.assertEqual(self.check(reviewed), ["x_allow.txt"])
        # The readers split on \n only, so a reviewed line holding \r is one entry; splitting it adds an unreviewed one.
        self.setUp()
        git(self.r, "checkout", "-q", "main")
        self.write("x_allow.txt", "# h\nallow a\n")
        self.commit("allow")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("x_allow.txt", "# h\nallow a\nallow p why\rallow q why\n")
        reviewed = self.commit("pr")
        git(self.r, "checkout", "-q", "main")
        self.write("x_allow.txt", "# h\nallow a\nallow m\n")
        self.commit("main")
        git(self.r, "checkout", "-q", "pr")
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                       cwd=self.r, capture_output=True)
        self.write("x_allow.txt", "# h\nallow a\nallow m\nallow p why\nallow q why\n")
        self.commit("resolved")
        self.assertEqual(self.check(reviewed), ["x_allow.txt"])

    def test_a_list_not_named_allow_keeps_line_order(self):
        reviewed = self.pr()
        self.write("b.txt", "c\nb\n")
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "b\nc\n")
        self.commit("main")
        git(self.r, "checkout", "-q", "pr")
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                               cwd=self.r, capture_output=True)
        self.write("b.txt", "c\nb\n")
        self.commit("reordered")
        self.assertEqual(self.check(reviewed), ["b.txt"])

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
                  "docs/LANES.md", "tools/trace.py", "tools/old_core.txt",
                  # KRN-2cap (#2935): the trusted core's budget and the tool that enforces it.
                  "tools/trusted_base.py", "tools/trusted_core.txt", "tools/ceilings.txt",
                  # #3955: the mutation gate's script, which .github/workflows/mutgate.yml runs from the PR's head.
                  "tools/mutgate.py",
                  # #4912: the claims check, which trusted-base.yml runs from the base copy.
                  "tools/claims.py",
                  # #2438: this gate's own tests and the lens rules need the Security accept too.
                  "tests/test_premerge.py", "tests/test_premerge_lens.py", "reviews/l3/README.md",
                  "reviews/security/README.md", "reviews/ux/README.txt"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        # The other gate tests stay as narrowed on Mark's "Narrow only" (2026-10-16).
        for f in ("tools/records.py", "reviews/l3/2026-10-15-pr1.md", "README.md", "docs/OTHER.md", "src/claude/x.go",
                  "reviews/README.md", "reviews/a/b/README.md", "tests/x/test_premerge.py", "tests/test_risk_tier.py",
                  "tests/test_ci_scope.py", "tests/test_workflows.py", "tests/test_merge_queue.py",
                  "tests/test_lane.py", "tools/trusted_base_parsers.txt", "tests/test_trusted_base.py",
                  "tools/mutgate.pyc", "tools/x/mutgate.py", "tests/test_mutgate.py",
                  "tools/claims.pyc", "tools/x/claims.py", "tests/test_claims.py"):
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
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--runs", self.runs(), "--base", "main", head],
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
        # #3856: a Record head naming no commit here (full or short) is named, not a git traceback; a later accept clears it
        full = lambda head, at: {**c("accept", sha, at), "body": c("accept", sha, at)["body"].replace(sha[:7], head)}
        for ghost in ("f" * 40, "fffffff"):
            self.assertEqual(run([full(ghost, "1")]), (1, UNRESOLVED("l3", ghost)))
            self.assertEqual(run([c("accept", sha, "1"), full(ghost, "2")]), (1, UNRESOLVED("l3", ghost)))
            self.assertEqual(run([full(ghost, "1"), c("accept", sha, "2")]), (0, ["same"]))
        self.assertEqual(run([full(sha, "1")]), (0, ["same"]))
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
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--runs", self.runs(), "--base", "main"],
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
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--runs", self.runs(), "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        need = (1, ["needs-security", "docs/OPERATING.md"])
        self.assertEqual(run([l3]), need)
        self.assertEqual(run([l3, sec()]), (0, ["same"]))
        # untrusted author, other PR, fix-list, unknown head: none counts
        self.assertEqual(run([l3, sec(who="NONE")]), need)
        self.assertEqual(run([l3, sec(pr=8)]), need)
        self.assertEqual(run([l3, sec("fix-list")]), need)
        self.assertEqual(run([l3, sec(head="0" * 40)]), (1, UNRESOLVED("security", "0" * 7)))  # #3856: named
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

    def bot_run(self, ref, run=None, output=None):
        """`--bot ref` with `run` (a dict, written as run.json) and `output` (zip members, written as the artifact)."""
        import json
        import zipfile
        d = pathlib.Path(self._d.name + ".bot")
        d.mkdir(exist_ok=True)
        extra = []
        if run is not None:
            (d / "run.json").write_text(json.dumps(run))
            extra += ["--run", str(d / "run.json")]
        if output is not None:
            with zipfile.ZipFile(d / "out.zip", "w") as z:
                for name, data in output:
                    z.writestr(name, data)
            extra += ["--output", str(d / "out.zip")]
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", ref, *extra, "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        return r.returncode, r.stdout.split()

    def main_run(self, workflow="trace.yml", **kw):
        sha = git(self.r, "rev-parse", "main")
        return {"id": 9, "run_attempt": 1, "path": ".github/workflows/" + workflow, "event": "schedule", "head_sha": sha,
                "repository": {"full_name": "o/r"}, "head_repository": {"full_name": "o/r"}, **kw}

    def test_bot_gate(self):
        # PREMERGE-wire (#1860): the generated-file bot PRs carry no L3 verdict, so `--bot` passes
        # them only when the branch is a known bot branch and the diff is that bot's file alone.
        git(self.r, "checkout", "-q", "-b", "pr")
        ok = lambda ref="bot/trace", wf="trace.yml", out=b"t\n": self.bot_run(ref, self.main_run(wf), [(ref[4:].upper() + ".md", out)])
        self.assertEqual(ok(), (1, ["not-bot"]))  # empty change
        self.write("TRACE.md", "t\n")
        self.commit("trace")
        self.assertEqual(ok(), (0, ["bot"]))
        for ref in ("bot/metrics", "bot/board"):  # another bot's file
            self.assertEqual(ok(ref, ref[4:] + ".yml"), (1, ["not-bot", "TRACE.md"]), ref)
        # not a bot branch; bot/records went with records.yml (#2235)
        for ref in ("pkg/x", "bot/trace2", "xbot/trace", "bot/trace/x", "bot/records"):
            self.assertEqual(self.bot_run(ref, self.main_run(), [("TRACE.md", b"t\n")]), (1, ["not-bot"]), ref)
        self.write("b.txt", "x\n")
        self.commit("smuggled code")
        self.assertEqual(ok(), (1, ["not-bot", "b.txt"]))

    def test_bot_gate_needs_the_bots_own_run(self):
        # MAIN-PROT-3 (#757): the diff being TRACE.md alone is not enough. Anyone who can push can push a
        # hand-edited TRACE.md to bot/trace under the bot's git name, or from a branch workflow with an
        # Actions token, so the file must equal the artifact a run of main's own trace.yml uploaded.
        git(self.r, "checkout", "-q", "-b", "side")
        self.write("x.txt", "branch code\n")
        side = self.commit("a branch's own commit")
        git(self.r, "checkout", "-q", "main")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("TRACE.md", "t\n")
        self.commit("trace")
        good = [("TRACE.md", b"t\n")]
        self.assertEqual(self.bot_run("bot/trace", self.main_run(), good), (0, ["bot"]))
        for event in ("workflow_dispatch", "push"):
            self.assertEqual(self.bot_run("bot/trace", self.main_run(event=event), good), (0, ["bot"]), event)
        unproven = lambda why: (1, ["bot-unproven", why])
        self.assertEqual(self.bot_run("bot/trace"), unproven("no-run"))
        self.assertEqual(self.bot_run("bot/trace", self.main_run()), unproven("no-run"))
        self.assertEqual(self.bot_run("bot/trace", output=good), unproven("no-run"))
        # The content: hand-edited, an extra member, a renamed member, an empty or broken zip.
        for out in ([("TRACE.md", b"hand-edited\n")], [("TRACE.md", b"x\n")], [("TRACE.md", b"t\n"), ("x", b"")], [("trace.md", b"t\n")],
                    [("TRACE.md", b"t")], [("TRACE.md", b"t\nmore\n")], []):
            self.assertEqual(self.bot_run("bot/trace", self.main_run(), out), unproven("output"), out)
        (pathlib.Path(self._d.name + ".bot") / "broken.zip").write_bytes(b"PK not a zip")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", "bot/trace", "--run",
                            str(pathlib.Path(self._d.name + ".bot") / "run.json"), "--output",
                            str(pathlib.Path(self._d.name + ".bot") / "broken.zip"), "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.split()), unproven("output"))
        # The run: another workflow, a non-main trigger, a fork's run, a run on a branch's own commit.
        for kw in ({"path": ".github/workflows/metrics.yml"}, {"path": ".github/workflows/x.yml"},
                   {"path": ".github/workflows/trace.yml@refs/heads/side"}, {"path": None},
                   {"event": "pull_request"}, {"event": "pull_request_target"}, {"event": "workflow_run"}, {"event": None},
                   {"head_repository": {"full_name": "fork/r"}}, {"head_repository": None},
                   {"repository": None, "head_repository": None},
                   # a rerun of an old main run uploads a fresh artifact of old output
                   {"run_attempt": 2}, {"run_attempt": None}, {"run_attempt": "1"}, {"run_attempt": True}):
            self.assertEqual(self.bot_run("bot/trace", self.main_run(**kw), good), unproven("run"), kw)
        for sha in (side, "f" * 40, "HEAD", "main", "-" + "a" * 39, None, 7):
            self.assertEqual(self.bot_run("bot/trace", self.main_run(head_sha=sha), good), unproven("run-not-on-main"), sha)
        # Not run JSON at all.
        for bad in ([], "x", 1):
            self.assertEqual(self.bot_run("bot/trace", bad, good), unproven("run"), bad)
        # Each bot answers to its own workflow only.
        git(self.r, "checkout", "-q", "main")
        git(self.r, "checkout", "-q", "-b", "board")
        self.write("BOARD.md", "b\n")
        self.commit("board")
        board = [("BOARD.md", b"b\n")]
        self.assertEqual(self.bot_run("bot/board", self.main_run("board.yml"), board), (0, ["bot"]))
        self.assertEqual(self.bot_run("bot/board", self.main_run("trace.yml"), board), unproven("run"))
        # A usage error, not a pass: a flag with no value.
        for tail in (["--run"], ["--output"], ["--base"]):
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", "bot/board", *tail],
                               cwd=self.r, capture_output=True, text=True)
            self.assertEqual(r.returncode, 2, tail)
        # A truncated member: still `output`, not a traceback.
        import zipfile
        z = pathlib.Path(self._d.name + ".bot") / "out.zip"
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as w:
            w.writestr("BOARD.md", b"b\n" * 4000)
        self.write("BOARD.md", "b\n" * 4000)
        self.commit("board, larger")
        data = bytearray(z.read_bytes())
        start = 30 + len("BOARD.md")  # no extra field: the member's deflate stream starts here
        data[start:start + 4] = b"\xff\xff\xff\xff"  # a broken stream (zlib.error), the directory intact
        z.write_bytes(bytes(data))
        import json
        (pathlib.Path(self._d.name + ".bot") / "run.json").write_text(json.dumps(self.main_run("board.yml")))
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", "bot/board", "--run",
                            str(pathlib.Path(self._d.name + ".bot") / "run.json"), "--output", str(z), "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.split()), unproven("output"))
        # A usage error, not a pass: two heads.
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", "bot/board", "HEAD", "HEAD"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def held_repo(self):
        """Main carries an unfiltered vulncheck and a path-filtered formal workflow; the PR changes b.md only."""
        (self.r / ".github/workflows").mkdir(parents=True)
        self.write(".github/workflows/vulncheck.yml", "name: vulncheck\non:\n  push:\n    branches: [main]\n  pull_request:\n")
        self.write(".github/workflows/formal.yml", "name: formal\non:\n  pull_request:\n    paths:\n"
                   "      - 'broker/kernel/**' # the kernel\n      - \".github/workflows/formal.yml\"\n")
        onto = self.commit("workflows")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("b.md", "x\n")
        return onto, self.commit("code")

    @staticmethod
    def wf(id, name, conclusion, sha, status="completed", event="pull_request", attempt=1, jobs=None, branch="pr",
           repo=REPO, prs=((7, "main"),)):
        r = {"id": id, "name": name, "path": f".github/workflows/{name}.yml", "head_sha": sha, "head_branch": branch,
             "event": event, "status": status, "conclusion": conclusion if status == "completed" else None,
             "run_attempt": attempt, "head_repository": {"full_name": repo},
             "pull_requests": [{"number": n, "base": {"ref": b}} for n, b in prs]}
        if jobs is not None:
            r["jobs"] = [{"run_id": id, "run_attempt": attempt, "name": n, "conclusion": c} for n, c in jobs]
        return r

    def test_held_checks_need_their_newest_pr_run_to_pass(self):
        # PREMERGE-cancelled-checks (#5366): GitHub merges an armed PR past a cancelled non-required check, so
        # --check holds each HELD workflow's newest pull_request run on the head to success or skipped.
        onto, sha = self.held_repo()
        held = lambda head=(), base=(): premerge.checks_held(self.r, bundle(head, base), "HEAD", "main")
        wf = self.wf
        self.assertEqual(held(), ["vulncheck:missing"])  # formal's paths miss b.md, so no formal run is owed
        for ok in ("success", "skipped"):
            self.assertEqual(held([wf(1, "vulncheck", ok, sha)]), [])
        for bad in ("cancelled", "timed_out", "failure", "action_required", "startup_failure", None):
            self.assertEqual(held([wf(1, "vulncheck", bad, sha)]), [f"vulncheck:{bad or 'unknown'}"])
        for status in ("queued", "in_progress", "waiting"):
            self.assertEqual(held([wf(1, "vulncheck", None, sha, status=status)]), [f"vulncheck:{status}"])
        # the newest run decides, whichever way: a cancel after a pass holds, a pass after a cancel clears
        self.assertEqual(held([wf(1, "vulncheck", "success", sha), wf(2, "vulncheck", "cancelled", sha)]), ["vulncheck:cancelled"])
        self.assertEqual(held([wf(2, "vulncheck", "cancelled", sha), wf(3, "vulncheck", "success", sha)]), [])
        # a run on another commit, from a push or dispatch, or of another workflow file named alike does not count
        for other in (wf(1, "vulncheck", "success", onto), wf(1, "vulncheck", "success", sha, event="workflow_dispatch"),
                      wf(1, "vulncheck", "success", sha, event="push"),
                      {**wf(1, "vulncheck", "success", sha), "path": ".github/workflows/fake.yml"}):
            self.assertEqual(held([other]), ["vulncheck:missing"])
        self.assertEqual(held([wf(1, "vulncheck", "success", sha, event="pull_request_target")]), [])
        # a run that exists is held even where the path filter owes none
        self.assertEqual(held([wf(1, "vulncheck", "success", sha), wf(2, "formal", "cancelled", sha)]), ["formal:cancelled"])
        with self.assertRaises(ValueError):
            premerge.checks_held(self.r, {"head": []}, "HEAD", "main")

    def test_held_checks_owe_a_path_filtered_run_its_filter_matches(self):
        onto, sha = self.held_repo()
        (self.r / "broker/kernel/key").mkdir(parents=True)
        self.write("broker/kernel/key/k.go", "package key\n")
        sha = self.commit("kernel")
        held = lambda head=(): premerge.checks_held(self.r, bundle(head), "HEAD", "main")
        self.assertEqual(held(), ["vulncheck:missing", "formal:missing"])
        self.assertEqual(held([self.wf(1, "vulncheck", "success", sha), self.wf(2, "formal", "success", sha)]), [])
        # a workflow the head deletes owes no run
        git(self.r, "rm", "-q", ".github/workflows/vulncheck.yml")
        sha = self.commit("drop")
        self.assertEqual(held([self.wf(2, "formal", "success", sha)]), [])

    def test_held_checks_count_only_this_prs_runs(self):
        # #5380 review: anyone can open a PR (from a fork, or into another base) whose head is this PR's commit, and
        # its runs share the head sha, so a run counts only when its head repository, branch and PR are this PR's.
        onto, sha = self.held_repo()
        wf = lambda id, c, **k: self.wf(id, "vulncheck", c, sha, **k)
        held = lambda *runs, **k: premerge.checks_held(self.r, bundle(runs, **k), "HEAD", "main")
        foreign = ({"repo": "outsider/agentOS", "prs": ()}, {"branch": "other"})
        # #5392: a run on this PR's own branch whose list is empty or names another PR or base is unbound, not missing
        unbound = ({"prs": ((8, "main"),)}, {"prs": ((7, "pkg/old"),)}, {"prs": ((7, "main"), (8, "pkg/old"))},
                   {"prs": ((7, "main"), (8, "main"))}, {"prs": ()})
        for k in foreign + unbound:
            # a newer foreign or unbound run neither holds this PR's pass nor clears its cancel
            self.assertEqual(held(wf(1, "success"), wf(2, "action_required", **k)), [], k)
            self.assertEqual(held(wf(1, "cancelled"), wf(2, "success", **k)), ["vulncheck:cancelled"], k)
            self.assertEqual(held(wf(2, "success", **k)), ["vulncheck:unbound" if k in unbound else "vulncheck:missing"], k)
        # an unbound run beside a foreign one still names the hold unbound; an unowed workflow is not held for one
        self.assertEqual(held(wf(2, "success", prs=()), wf(3, "success", branch="other")), ["vulncheck:unbound"])
        self.assertEqual(held(wf(1, "success"), self.wf(2, "formal", "success", sha, prs=())), [])
        # a list naming this PR twice is one PR (dedupe by number and base)
        self.assertEqual(held(wf(1, "success", prs=((7, "main"), (7, "main")))), [])
        self.assertEqual(held(wf(1, "cancelled", prs=((7, "main"), (7, "main")))), ["vulncheck:cancelled"])
        # a malformed list is unbound, never a crash and never a pass
        for prs in (None, "7", [7], [{"number": "7", "base": {"ref": "main"}}], [{"number": 7}],
                    [{"number": 7, "base": "main"}], [{"number": [7], "base": {"ref": "main"}}],
                    [{"number": 7, "base": {"ref": ["main"]}}]):
            self.assertEqual(held({**wf(1, "success"), "pull_requests": prs}), ["vulncheck:unbound"], prs)
        missing = {**wf(1, "success"), "head_repository": None}
        self.assertEqual(held(missing), ["vulncheck:missing"])
        # a fork PR's runs name no PR: its head repository and branch bind them
        fork = dict(repo="outsider/agentOS", branch="topic")
        self.assertEqual(held(wf(1, "success", repo="outsider/agentOS", branch="topic", prs=()), **fork), [])
        self.assertEqual(held(wf(1, "success", repo="outsider/agentOS", branch="topic", prs=()),
                              wf(2, "failure", repo="else/agentOS", branch="topic", prs=()), **fork), [])
        self.assertEqual(held(wf(1, "success", prs=()), **fork), ["vulncheck:missing"])
        for bad in ({"pr": None}, {"repo": 1}, {"pr": {"number": "7", "repo": REPO, "branch": "pr"}},
                    {"pr": {"number": 7, "repo": None, "branch": "pr"}}):
            with self.assertRaises(ValueError):
                premerge.checks_held(self.r, {**bundle(), **bad}, "HEAD", "main")

    def test_held_checks_read_a_target_trigger_from_the_base(self):
        # #5380 review: GitHub runs a pull_request_target workflow from the base's copy, so its filter comes from there.
        onto, sha = self.held_repo()
        git(self.r, "checkout", "-q", "main")
        self.write(".github/workflows/lane-gate.yml", "on:\n  pull_request_target:\n    paths:\n      - 'b.md'\n")
        self.commit("lane-gate on main")
        git(self.r, "checkout", "-q", "pr")
        ok = [self.wf(1, "vulncheck", "success", sha)]
        held = lambda: premerge.checks_held(self.r, bundle(ok), "HEAD", "main")
        self.assertEqual(held(), ["lane-gate:missing"])  # not on the head at all, owed by the base's copy
        self.write(".github/workflows/lane-gate.yml", "on:\n  pull_request_target:\n    paths:\n      - 'nothing'\n")
        sha = self.commit("head narrows it")
        ok = [self.wf(1, "vulncheck", "success", sha)]
        self.assertEqual(held(), ["lane-gate:missing"])  # the head's copy does not decide
        git(self.r, "checkout", "-q", "main")
        self.write(".github/workflows/lane-gate.yml", "on:\n  pull_request_target:\n    paths:\n      - 'nothing'\n")
        self.commit("main narrows it")
        git(self.r, "checkout", "-q", "pr")
        self.assertEqual(held(), [])

    def test_held_check_failure_passes_only_on_exempt_or_inherited_jobs(self):
        onto, sha = self.held_repo()
        held = lambda head=(), base=(): premerge.checks_held(self.r, bundle(head, base), "HEAD", "main")
        wf = self.wf
        failed = lambda jobs, attempt=1: wf(5, "vulncheck", "failure", sha, attempt=attempt, jobs=jobs)
        mainrun = lambda **k: wf(9, "vulncheck", "failure", onto, event=k.pop("event", "push"), branch=k.pop("branch", "main"),
                                 jobs=[("vulncheck", "failure")], **k)
        no = ["vulncheck:failure"]
        self.assertEqual(held([failed(None)]), no)  # jobs unread
        self.assertEqual(held([failed([("vulncheck", "failure")])]), no)  # no base failure
        # PREMERGE-inherited (#3532): the same job failed in main's own first-attempt push or scheduled run of the merge base
        self.assertEqual(held([failed([("vulncheck", "failure")])], [mainrun()]), [])
        self.assertEqual(held([failed([("vulncheck", "failure")])], [mainrun(event="schedule")]), [])
        self.assertEqual(held([failed([("vulncheck", "failure"), ("other", "success")], attempt=2)], [mainrun()]), [])
        rerun = mainrun(attempt=2)
        rerun["jobs"][0]["run_attempt"] = 1  # attempt 1's jobs, fetched as the workflow does, of a run a pusher reran
        for base in (rerun, {**mainrun(), "head_repository": {"full_name": "outsider/agentOS"}}, mainrun(event="pull_request"), mainrun(branch="pr"),
                     {**mainrun(), "head_sha": sha}, {**mainrun(), "jobs": [{"run_id": 8, "run_attempt": 1, "name": "vulncheck",
                                                                           "conclusion": "failure"}]},
                     [mainrun(), wf(10, "vulncheck", "success", onto, event="schedule", branch="main")][1]):
            self.assertEqual(held([failed([("vulncheck", "failure")])], [base]), no, base)
        # a cancelled or timed-out job is never excused, nor a failure in a job the base did not fail
        self.assertEqual(held([failed([("vulncheck", "cancelled")])], [mainrun()]), no)
        self.assertEqual(held([failed([("vulncheck", "failure"), ("deps", "failure")])], [mainrun()]), no)
        # jobs of another attempt or run are not this run's
        stale = failed([("vulncheck", "failure")], attempt=2)
        stale["jobs"][0]["run_attempt"] = 1
        self.assertEqual(held([stale], [mainrun()]), no)
        mixed = failed([("vulncheck", "failure")])
        mixed["jobs"].append({"run_id": 99, "run_attempt": 1, "name": "deps", "conclusion": "failure"})
        self.assertEqual(held([mixed], [mainrun()]), no)  # a list with any foreign job is unread, not filtered

    def test_image_vulncheck_is_the_one_exempt_job(self):
        # #5366: image-vulncheck stays out (Mark's #2919 paste); every other image job is held.
        self.assertEqual(premerge.HELD["image"], ("image-vulncheck",))
        self.assertEqual(sorted(premerge.HELD), ["assurance", "camnode-image", "drone-sitl", "enforcer-image", "formal", "image",
                                                 "infer-real", "keycheck", "lane-gate", "mutgate", "testkit", "vision-real",
                                                 "vulncheck", "word-budget"])
        self.assertEqual([x for x in premerge.HELD.values() if x != ()], [("image-vulncheck",)])
        onto, sha = self.held_repo()
        self.write(".github/workflows/image.yml", "on:\n  pull_request:\n")
        sha = self.commit("image")
        img = lambda jobs, c="failure": self.wf(3, "image", c, sha, jobs=jobs)
        held = lambda *runs: premerge.checks_held(self.r, bundle([self.wf(1, "vulncheck", "success", sha), *runs]),
                                                  "HEAD", "main")
        self.assertEqual(held(img([("build (a)", "success"), ("image-vulncheck", "failure")])), [])
        self.assertEqual(held(img([("build (a)", "failure"), ("image-vulncheck", "failure")])), ["image:failure"])
        self.assertEqual(held(img([("build (a)", "success"), ("image-vulncheck", "cancelled")], c="cancelled")), ["image:cancelled"])
        self.assertEqual(held(img([("image-vulncheck", "cancelled")])), ["image:failure"])
        self.assertEqual(held(), ["image:missing"])

    def test_every_pr_workflow_is_held_or_required(self):
        # PREMERGE-held-rest (#5385): a PR-triggered workflow outside HELD merges past a cancelled run unless main's
        # ruleset requires its jobs, so each workflow file with a PR trigger is HELD or UNHELD (ci, trusted-base,
        # premerge), never both or neither, and a new one fails here until it is placed.
        wfs = ROOT / ".github" / "workflows"
        pr = {f.stem for f in wfs.glob("*.yml")
              if any(premerge.pr_paths(f.read_text(), e) is not None for e in ("pull_request", "pull_request_target"))}
        self.assertEqual(pr, set(premerge.HELD) | set(premerge.UNHELD))
        self.assertFalse(set(premerge.HELD) & set(premerge.UNHELD))
        # a held workflow whose PR trigger has a paths filter must read as that filter, not as unfiltered, or every
        # PR outside it holds as `<wf>:missing` for good (#5432 L3: testkit.yml's flow-style list read as [])
        for stem in premerge.HELD:
            text = (wfs / f"{stem}.yml").read_text()
            pr_on = text.split("\njobs:", 1)[0].split("\n  pull_request", 1)[-1].split("\n  push:", 1)[0]
            if "pull_request" in text and "paths:" in pr_on:
                self.assertTrue(premerge.pr_paths(text) or premerge.pr_paths(text, "pull_request_target"), stem)
        # premerge reruns when each held workflow completes, else a hold stays until some other event: workflow_run
        # names a workflow by its `name:`, which for testkit.yml is testkit-image.
        on = (wfs / "premerge.yml").read_text().split("workflow_run:\n", 1)[1].split("\n")[0]
        listed = {w.strip() for w in on.split("[", 1)[1].split("]", 1)[0].split(",")}
        for stem in premerge.HELD:
            name = next(l[6:].strip() for l in (wfs / f"{stem}.yml").read_text().splitlines() if l.startswith("name: "))
            self.assertIn(name, listed, stem)
        # a mutgate shard cut at its timeout fails the run (mutgate.yml), and that failure is not excused
        onto, sha = self.held_repo()
        self.write(".github/workflows/mutgate.yml", "on:\n  pull_request:\n")
        sha = self.commit("mutgate")
        ok = self.wf(1, "vulncheck", "success", sha)
        held = lambda *runs: premerge.checks_held(self.r, bundle([ok, *runs]), "HEAD", "main")
        self.assertEqual(held(), ["mutgate:missing"])
        self.assertEqual(held(self.wf(2, "mutgate", "failure", sha, jobs=[("mutants x shard 0 of 2", "cancelled"),
                                                                          ("mutgate", "failure")])), ["mutgate:failure"])
        self.assertEqual(held(self.wf(2, "mutgate", "cancelled", sha)), ["mutgate:cancelled"])
        self.assertEqual(held(self.wf(2, "mutgate", "success", sha)), [])
        # the real testkit.yml filter: a PR changing only b.md and mutgate.yml owes no testkit run (#5432 L3)
        self.write(".github/workflows/testkit.yml", (wfs / "testkit.yml").read_text())
        sha = self.commit("testkit")
        mut = self.wf(2, "mutgate", "success", sha)
        self.assertEqual(premerge.checks_held(self.r, bundle([self.wf(1, "vulncheck", "success", sha), mut]), "HEAD", "main"),
                         ["testkit:missing"])  # the PR changes testkit.yml itself, so its run is owed
        git(self.r, "checkout", "-q", "main")
        git(self.r, "merge", "-q", "--no-edit", "pr")
        git(self.r, "checkout", "-q", "pr")
        self.write("c.md", "y\n")
        sha = self.commit("unrelated")
        self.assertEqual(premerge.checks_held(self.r, bundle([self.wf(1, "vulncheck", "success", sha),
                                                              self.wf(2, "mutgate", "success", sha)]), "HEAD", "main"), [])

    def test_pr_paths_reads_only_the_block_style_it_knows(self):
        p = premerge.pr_paths
        self.assertIsNone(p("on:\n  push:\n    paths:\n      - 'a/**'\n  schedule:\n    - cron: '1 1 * * *'\n"))
        self.assertEqual(p("on:\n  pull_request:\n    types: [opened]\n"), [])
        target = "on:\n  pull_request_target:\n    types: [opened, edited]\n# x\npermissions: {}\n"
        self.assertIsNone(p(target))  # each event reads only its own trigger
        self.assertEqual(p(target, "pull_request_target"), [])
        self.assertIsNone(p("on: [pull_request_target]\n"))
        self.assertEqual(p("on: [pull_request_target]\n", "pull_request_target"), [])
        self.assertEqual(p("on:\n  pull_request:\n    paths:\n      - a/**\n      # skip\n      - \"b.txt\"\n  push:\n"),
                         ["a/**", "b.txt"])
        both = "on:\n  pull_request:\n    paths:\n      - a/**\n  pull_request_target:\n"
        self.assertEqual((p(both), p(both, "pull_request_target")), (["a/**"], []))
        # anything else reads as unfiltered, so the run is owed (fail closed)
        for text in ("on: [push, pull_request]\n", "on: pull_request\n", "\"on\":\n  pull_request:\n    paths: [a]\n",
                     "on:\n  pull_request: {paths: [a]}\n", "on:\n  pull_request:\n    paths: [a]\n",
                     "on:\n  pull_request:\n    paths:\n      - '!a/**'\n", "on:\n  pull_request:\n    paths:\n      - 'a/?'\n",
                     "on:\n  pull_request:\n    paths-ignore:\n      - a\n", "on:\n  pull_request:\n    paths:\n  push:\n",
                     "on:\n  pull_request_target:\n    paths:\n  pull_request:\n    paths:\n"):
            self.assertEqual(p(text), [], text)
        g = lambda glob, f: bool(premerge._glob_re(glob).fullmatch(f))
        self.assertTrue(g("a/**", "a/b/c.go") and g("a/*", "a/b") and g("**/x.go", "x.go") and g("**/x.go", "a/b/x.go"))
        self.assertFalse(g("a/*", "a/b/c") or g("a/**", "ab/c") or g("a.b", "aXb") or g("a/**", "a"))

    def runs_helper(self, routes, onto, pr=None, drop=()):
        """Run tools/premerge_runs.sh with `gh` stubbed: `routes` maps each API route to the items its --jq selects.
        Returns the exit code, the parsed document (None if stdout is empty) and the routes read, in order."""
        import json, shutil
        self.assertTrue(shutil.which("jq") and shutil.which("bash"), "jq and bash are on the runner image; the test needs them")
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for i, (route, items) in enumerate(routes.items()):
            if route not in drop:
                (d / f"{i}.route").write_text(route)
                (d / f"{i}.out").write_text("".join(json.dumps(x) + "\n" for x in items))
        (d / "gh").write_text('#!/bin/sh\n[ "$1 $2 $4" = "api --paginate --jq" ] || exit 2\necho "$3" >> "$STUBS/calls"\n'
                              'for r in "$STUBS"/*.route; do [ "$(cat "$r")" = "$3" ] && exec cat "${r%.route}.out"; done\nexit 1\n')
        (d / "gh").chmod(0o755)
        f = d / "pr.json"
        f.write_text(json.dumps(pr if pr is not None else {"number": 7, "head": {"sha": git(self.r, "rev-parse", "HEAD"),
                                                                       "ref": "pr", "repo": {"full_name": REPO}}}))
        env = {"PATH": f"{d}:/usr/bin:/bin", "STUBS": str(d), "TMPDIR": str(d)}
        r = subprocess.run(["bash", str(ROOT / "tools/premerge_runs.sh"), REPO, str(f), onto],
                           env=env, capture_output=True, text=True, timeout=30)
        calls = (d / "calls").read_text().splitlines() if (d / "calls").exists() else []
        return r.returncode, json.loads(r.stdout) if r.stdout.strip() else None, calls

    def test_runs_helper_builds_what_the_check_reads(self):
        # PREMERGE-runs-local (#5386): premerge.yml runs main's tools/premerge_runs.sh, so a session running it locally
        # reads the held checks exactly as the gate does. Its document must be one checks_held reads: each failed run
        # with its jobs (the head's latest attempt, the base's first), the base's push and scheduled runs, the PR binding.
        onto, sha = self.held_repo()
        api = f"repos/{REPO}/actions/runs"
        head = [self.wf(11, "vulncheck", "failure", sha, attempt=2), self.wf(12, "formal", "success", sha)]
        push = [dict(self.wf(21, "vulncheck", "failure", onto, event="push", branch="main", prs=()))]
        sched = [dict(self.wf(19, "vulncheck", "success", onto, event="schedule", branch="main", prs=()))]
        job = lambda run, attempt, name: {"run_id": run, "run_attempt": attempt, "name": name, "conclusion": "failure"}
        routes = {f"{api}?head_sha={sha}&per_page=100": head,
                  f"{api}/11/jobs?per_page=100": [job(11, 2, "scan")],
                  f"{api}?head_sha={onto}&event=push&per_page=100": push,
                  f"{api}/21/attempts/1/jobs?per_page=100": [job(21, 1, "scan")],
                  f"{api}?head_sha={onto}&event=schedule&per_page=100": sched}
        code, doc, calls = self.runs_helper(routes, onto)
        self.assertEqual(code, 0)
        self.assertEqual(calls, list(routes))  # only failed runs' jobs are read, each by its own route
        self.assertEqual(doc, bundle([{**head[0], "jobs": [job(11, 2, "scan")]}, {**head[1], "jobs": []}],
                                     [{**push[0], "jobs": [job(21, 1, "scan")]}, {**sched[0], "jobs": []}]))
        # The gate's reader passes the head's vulncheck failure only because the same job failed in main's newest run on
        # the merge base (the push, id 21 over the schedule's 19).
        self.assertEqual(premerge.checks_held(self.r, doc, "HEAD", "main"), [])
        routes[f"{api}/21/attempts/1/jobs?per_page=100"] = [{**job(21, 1, "scan"), "name": "other"}]
        self.assertEqual(premerge.checks_held(self.r, self.runs_helper(routes, onto)[1], "HEAD", "main"), ["vulncheck:failure"])

    def test_runs_helper_fails_closed(self):
        # PREMERGE-runs-local (#5386): any failed read, a bad merge base or a pr.json without a head prints nothing, so
        # no caller reads a partial document as one with no failed runs.
        onto, sha = self.held_repo()
        api = f"repos/{REPO}/actions/runs"
        routes = {f"{api}?head_sha={sha}&per_page=100": [self.wf(11, "vulncheck", "failure", sha), self.wf(12, "formal", "failure", sha)],
                  f"{api}/11/jobs?per_page=100": [],
                  f"{api}/12/jobs?per_page=100": [],
                  f"{api}?head_sha={onto}&event=push&per_page=100": [],
                  f"{api}?head_sha={onto}&event=schedule&per_page=100": []}
        self.assertEqual(self.runs_helper(routes, onto)[0], 0)
        for route in routes:
            with self.subTest(drop=route):
                self.assertEqual(self.runs_helper(routes, onto, drop=(route,))[:2], (1, None))
        for bad in ("", onto[:39], onto.upper(), onto + "&event=push", "HEAD"):
            with self.subTest(onto=bad):
                self.assertEqual(self.runs_helper(routes, bad), (2, None, []))
        for pr in ({"number": 7}, {"number": 7, "head": {"sha": "HEAD"}}, {"number": 7, "head": {"sha": sha + "\nx"}}):
            with self.subTest(pr=pr):
                self.assertEqual(self.runs_helper(routes, onto, pr=pr), (1, None, []))  # nothing read

    def test_check_gate_holds_checks_after_every_verdict(self):
        import json
        onto, sha = self.held_repo()
        f = pathlib.Path(self._d.name + ".comments.json")
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        f.write_text(json.dumps([self.rec("accept", sha, "<!-- record: l3 -->\n")]))
        def run(*runs, extra=None):
            argv = extra if extra is not None else ["--runs", self.runs(head=runs)]
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", *argv, "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run(self.wf(1, "vulncheck", "success", sha)), (0, ["same"]))
        self.assertEqual(run(self.wf(1, "vulncheck", "cancelled", sha)), (1, ["needs-check", "vulncheck:cancelled"]))
        self.assertEqual(run(), (1, ["needs-check", "vulncheck:missing"]))
        self.assertEqual(run(extra=[]), (1, premerge.NO_RUNS.split()))  # no --runs never reads same
        self.assertIn("tools/premerge_runs.sh", premerge.NO_RUNS)  # and names what builds it (#5386)
        # either option order
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main",
                            "--runs", self.runs(head=[self.wf(1, "vulncheck", "success", sha)]), "HEAD"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.split()), (0, ["same"]))
        # a verdict that is owed is named before any check
        f.write_text(json.dumps([]))
        self.assertEqual(run(self.wf(1, "vulncheck", "cancelled", sha)), (1, ["no-verdict"]))

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
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--runs", self.runs(), "--base", "main"],
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
        for bad in (ux(who="NONE"), ux(pr=8), ux("fix-list")):
            self.assertEqual(run([l3, bad, pot()]), (1, ["needs-lens", "ux"]), bad)
        self.assertEqual(run([l3, ux(head="0" * 40), pot()]), (1, UNRESOLVED("ux", "0" * 7)))  # #3856: named
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
        for bad in (sec(who="NONE"), sec(pr=8), sec("fix-list")):
            self.assertEqual(self.lens_run([l3, lens, bad]), need, bad)
        self.assertEqual(self.lens_run([l3, lens, sec(head="0" * 40)]), (1, UNRESOLVED("security", "0" * 7)))  # #3856
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

    def test_check_gate_reads_markers_from_the_record_block_only(self):
        # #4261: in an accept, a marker on a line of its own outside the comment's record block (its first unfenced
        # Record line and the marker and blank lines under it) is quoted text: it neither hides the review's own
        # record nor lends it one. Any other verdict reads the whole comment, so a quote there fails closed.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "tools").mkdir()
        self.write("tools/premerge.py", "x\n")
        sha = self.commit("gate")
        quoting = lambda marks, quoted, at: self.rec("accept", sha, f"{marks}\nNext: owed\n{quoted}\n", at=at)
        l3 = self.rec("accept", sha, "<!-- record: combined -->\n", at="0")
        lens = self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n", at="1")
        sec = self.rec("accept", sha, "<!-- record: security -->\n", at="2")
        self.assertEqual(self.lens_run([l3, lens, sec]), (0, ["same"]))
        # the combined review quoting the security marker is a combined record, not a security one; the real one counts
        q_sec = "\n<!-- record: security -->"
        self.assertEqual(self.lens_run([lens, sec, quoting("<!-- record: combined -->", q_sec, "3")]), (0, ["same"]))
        # a Security review quoting the combined or l3 marker is still the separate Security record, and not an L3 one
        for q in ("\n<!-- record: combined -->", "\n<!-- record: l3 -->", "\n```\n<!-- record: combined -->\n```"):
            qs = quoting("<!-- record: security -->", q, "3")
            self.assertEqual(self.lens_run([l3, lens, qs]), (0, ["same"]), q)
            self.assertEqual(self.lens_run([lens, qs]), (1, ["no-verdict"]), q)
        # UX and Potency markers count only where the lens posts its own
        q_pot = quoting("<!-- record: ux -->", "\n<!-- record: potency -->", "1")
        self.assertEqual(self.lens_run([l3, q_pot, sec]), (1, ["needs-lens", "potency"]))
        q_ux = quoting("<!-- record: potency -->", "\n<!-- record: ux -->", "1")
        self.assertEqual(self.lens_run([l3, q_ux, sec]), (1, ["needs-lens", "ux"]))
        # a quoted Record line before the comment's own block names no head
        ghost = f"```\nRecord: PR #7 · package X-1 · head {'f' * 7}\n```\n\n"
        for g in (ghost, ghost.replace("```", "~~~")):
            ahead = {**sec, "body": sec["body"].replace("# t\n", "# t\n" + g)}
            self.assertEqual(self.lens_run([l3, lens, ahead]), (0, ["same"]), g)
        # a fenced Record line under the comment's own block is not its record either
        fence = f"\n```\nRecord: PR #7 · package X-1 · head {sha[:7]}\n<!-- record: security -->\n```"
        self.assertEqual(self.lens_run([l3, lens, sec, quoting("<!-- record: combined -->", fence, "3")]),
                         (0, ["same"]))
        # the record block spans blank lines between its own lines (#4100's shape) and a lens's opening paragraph
        rec = f"Record: PR #7 · package X-1 · head {sha[:7]}"
        spread = lambda v, mark, at: {**sec, "created_at": at, "updated_at": at, "body": f"Verdict: {v}\n\n{rec}\n\n{mark}\n"}
        self.assertEqual(self.lens_run([spread("accept", "<!-- record: combined -->", "0"), lens, sec]), (0, ["same"]))
        need = (1, ["needs-security", "tools/premerge.py"])
        self.assertEqual(self.lens_run([l3, lens, sec, spread("fix-list", "<!-- record: security -->", "3")]), need)
        lensy = {**sec, "body": f"Verdict: accept\n\nprose\n\n{rec}\n<!-- record: security -->\n\nNext: arm\n"}
        self.assertEqual(self.lens_run([l3, lens, lensy]), (0, ["same"]))
        # an accept with no marker in its record block has a misplaced one: it is named so (#5541) and supersedes
        UN, MIS = UNPARSED("security"), MISPLACED("security")
        late = lambda v: self.rec(v, sha, "\nprose\n\n<!-- record: security -->\n", at="3")
        self.assertEqual(self.lens_run([l3, lens, late("accept")]), (1, MIS))
        self.assertEqual(self.lens_run([l3, lens, sec, late("accept")]), (1, MIS))
        self.assertEqual(self.lens_run([self.rec("accept", sha, "prose\n<!-- record: combined -->\n", at="0")]),
                         (1, MISPLACED("l3")))
        # #5539's shape: the marker directly above a good Record line is still misplaced, and never accepts
        above = lambda mark, at: {**sec, "created_at": at, "updated_at": at, "body": f"Verdict: accept\n{mark}\n{rec}\n"}
        self.assertEqual(self.lens_run([l3, lens, above("<!-- record: security -->", "3")]), (1, MIS))
        self.assertEqual(self.lens_run([l3, lens, sec, above("<!-- record: security -->", "3")]), (1, MIS))
        self.assertEqual(premerge.verdict([sec, above("<!-- record: security -->", "3")], 7, security=True),
                         ("misplaced", None))
        self.assertEqual(self.lens_run([l3, above("<!-- record: ux -->\n<!-- record: potency -->", "3"), sec]),
                         (1, MISPLACED("ux,potency")))
        self.assertEqual(self.lens_run([above("<!-- record: combined -->", "0"), lens, sec]), (1, MISPLACED("l3")))
        # a misplaced marker over a Record line for another PR, or a malformed one, still names the Record line
        self.assertEqual(self.lens_run([l3, lens, {**above("<!-- record: security -->", "3"),
                                                   "body": f"Verdict: accept\n<!-- record: security -->\n{rec.replace('#7', '#8')}\n"}]),
                         (1, UN))
        self.assertEqual(self.lens_run([l3, lens, {**above("<!-- record: security -->", "3"),
                                                   "body": f"Verdict: accept\n<!-- record: security -->\n{rec.replace('X-1', 'X 1')}\n"}]),
                         (1, UN))
        other = f"```\nRecord: PR #8 · package X-1 · head {sha[:7]}\n```\n"
        norec = {**sec, "body": "Verdict: accept\n<!-- record: security -->\n\n" + other}
        self.assertEqual(self.lens_run([l3, lens, norec]), (1, UN))
        # any other verdict counts wherever its marker and Record line sit, so it cannot leave an accept standing:
        # prose before the marker, a fenced record, a second lens after prose, a first record block for another PR
        self.assertEqual(self.lens_run([l3, lens, sec, late("fix-list")]), need)
        for fixed in (fence, fence.replace("```", "~~~")):
            fenced = {**sec, "created_at": "3", "updated_at": "3", "body": f"Verdict: fix-list\nCause: defect\n{fixed}\n"}
            self.assertEqual(self.lens_run([l3, lens, sec, fenced]), need, fixed)
        second = self.rec("fix-list", sha, "<!-- record: security -->\n\nprose\n<!-- record: combined -->\n", at="3")
        self.assertEqual(self.lens_run([l3, lens, sec, second]), (1, ["not-accepted"]))
        self.assertEqual(premerge.verdict([sec, second], 7, security=True), ("fix-list", sha[:7]))
        two = {**sec, "created_at": "3", "updated_at": "3", "body": (
            f"Verdict: fix-list\nRecord: PR #8 · package X-1 · head {sha[:7]}\n<!-- record: security -->\n\n"
            f"Record: PR #7 · package X-1 · head {sha[:7]}\n<!-- record: security -->\n")}
        self.assertEqual(self.lens_run([l3, lens, sec, two]), need)
        # misplaced security and combined markers in a fix-list read as both a Security and an L3 fix-list
        both = {**late("fix-list"), "body": late("fix-list")["body"] + "<!-- record: combined -->\n"}
        self.assertEqual(self.lens_run([l3, lens, sec, both]), (1, ["not-accepted"]))
        self.assertEqual(premerge.verdict([sec, both], 7, security=True), ("fix-list", sha[:7]))
        # a Security fix-list quoting the combined marker also reads as an L3 fix-list: closed, never open
        qfix = self.rec("fix-list", sha, "<!-- record: security -->\nNext: owed\n\n<!-- record: combined -->\n", at="3")
        self.assertEqual(self.lens_run([l3, lens, sec, qfix]), (1, ["not-accepted"]))
        self.assertEqual(premerge.verdict([sec, qfix], 7, security=True), ("fix-list", sha[:7]))
        # the verdict word is read case-blind: a capitalised Accept quoting combined is still the Security record only
        cap = {**quoting("<!-- record: security -->", "\n<!-- record: combined -->", "3")}
        cap["body"] = cap["body"].replace("Verdict: accept", "Verdict: Accept")
        self.assertEqual(self.lens_run([lens, cap]), (1, ["no-verdict"]))
        self.assertEqual(self.lens_run([l3, lens, cap]), (0, ["same"]))
        # only a comment whose first line is a Verdict line is a verdict, whatever record it carries
        reply = {**sec, "created_at": "4", "updated_at": "4", "body": sec["body"].replace("Verdict: accept", "Re: accept")}
        self.assertEqual(self.lens_run([l3, lens, sec, late("fix-list"), reply]), need)
        # a fence left open runs to the end of the comment, as Markdown renders it, so an accept's record in it is quoted
        self.assertEqual(self.lens_run([l3, lens, {**sec, "body": sec["body"].replace("# t\n", "# t\n```\n")}]),
                         (1, UN))

    def test_verdict_reads_large_comments_in_linear_time(self):
        # #4262 review: a fence regex over every comment was quadratic, so anyone's large comments could stall the gate.
        import time
        rec = f"Record: PR #7 · package X-1 · head {'a' * 7}\n<!-- record: security -->\n"
        fences = "```x\n" * 20000
        comments = [{"author_association": who, "created_at": str(n), "updated_at": str(n),
                     "body": f"Verdict: accept\n{fences}{rec}"} for n, who in enumerate(["NONE", "OWNER"] * 5)]
        t = time.monotonic()
        for kw in ({}, {"security": True}, {"lens": "ux"}, {"lens": "potency"}):
            premerge.verdict(comments, 7, **kw)
        self.assertLess(time.monotonic() - t, 5)

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
