"""Tests for tools/specslice.py and tools/reviewpacket.py (CTX-slice, issue #1681).

Covers the three requirements of issue #1681 (they are not SPEC IDs, so no REQ marker).
"""
import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import reviewpacket  # noqa: E402
import specslice  # noqa: E402

SPEC = """# Spec

## 5. Trust

- **AA-1** First rule.
  Continuation of the first rule.
- **AA-2** Second rule, mentions AA-1 without defining it.

## 6. Table

| ID | Topic |
|---|---|
| **BB-1** | Row one |
| **BB-2** | Row two |

### 6.1 Sub

**CC-1a** A paragraph block
that runs two lines.

Not part of CC-1a.
"""


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def run(mod, argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = mod.main(argv)
    return code, out.getvalue(), err.getvalue()


class Repo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / "SPEC.md").write_text(SPEC)
        (self.root / "briefs").mkdir()
        (self.root / "briefs" / "PK-1.md").write_text("# PK-1\n\n**Needs:** AA-2, BB-1, ZZ-9\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "base")
        self.base = git(self.root, "rev-parse", "HEAD")
        git(self.root, "checkout", "-qb", "pkg/PK-1-x")
        (self.root / "tests").mkdir()
        (self.root / "tests" / "t.py").write_text("# " + "REQ" + ": CC-1a\nx = 1\n")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "PK-1: add test")
        self.head = git(self.root, "rev-parse", "HEAD")

    def tearDown(self):
        self.tmp.cleanup()


class SliceTest(Repo):
    def test_prints_only_cited_blocks_with_headings_and_stamp(self):
        code, out, _ = run(specslice, ["--root", str(self.root), "--ids", "AA-2,BB-1"])
        self.assertEqual(code, 0)
        self.assertIn(self.head, out)
        self.assertIn("## 5. Trust", out)
        self.assertIn("## 6. Table", out)
        self.assertIn("- **AA-2** Second rule", out)
        self.assertIn("| **BB-1** | Row one |", out)
        for absent in ("AA-1** First", "BB-2", "CC-1a", "Continuation"):
            self.assertNotIn(absent, out)

    def test_multiline_blocks(self):
        _, out, _ = run(specslice, ["--root", str(self.root), "--ids", "AA-1,CC-1a"])
        self.assertIn("Continuation of the first rule.", out)
        self.assertIn("that runs two lines.", out)
        self.assertNotIn("Not part of", out)
        self.assertIn("### 6.1 Sub", out)

    def test_unknown_id_exits_nonzero_and_prints_no_slice(self):
        code, out, err = run(specslice, ["--root", str(self.root), "--ids", "AA-1,NOPE-7"])
        self.assertNotEqual(code, 0)
        self.assertIn("NOPE-7", err)
        self.assertEqual(out, "")

    def test_mention_is_not_a_definition(self):
        # AA-1 is mentioned in AA-2's block; only the bold definition counts.
        _, out, _ = run(specslice, ["--root", str(self.root), "--ids", "AA-2"])
        self.assertEqual(out.count("**AA-1**"), 0)

    def test_ref_reads_spec_at_that_commit(self):
        (self.root / "SPEC.md").write_text(SPEC.replace("Second rule", "Edited rule"))
        _, out, _ = run(specslice, ["--root", str(self.root), "--ref", self.base, "--ids", "AA-2"])
        self.assertIn("Second rule", out)
        self.assertIn(self.base, out)

    def test_dirty_working_tree_is_stamped(self):
        (self.root / "SPEC.md").write_text(SPEC + "\n")
        _, out, _ = run(specslice, ["--root", str(self.root), "--ids", "AA-2"])
        self.assertIn("+dirty", out)


class PacketTest(Repo):
    def packet(self, *extra):
        dest = self.root / "packet.md"
        code, out, err = run(reviewpacket, ["--root", str(self.root), "--out", str(dest),
                                            f"{self.base}..{self.head}", *extra])
        return code, dest, out, err

    def test_packet_holds_tier_brief_ids_diff_and_head_sha(self):
        code, dest, _, err = self.packet("--id", "PK-1")
        self.assertEqual(code, 0, err)
        text = dest.read_text()
        self.assertIn(self.head, text)
        self.assertIn("Risk tier: C", text)
        self.assertIn("**Needs:** AA-2, BB-1, ZZ-9", text)
        self.assertIn("- **AA-2** Second rule", text)
        self.assertIn("| **BB-1** | Row one |", text)
        self.assertIn("**CC-1a** A paragraph block", text)  # cited by REQ marker in the diff
        self.assertIn("+# REQ" + ": CC-1a", text)
        self.assertIn("ZZ-9", text)  # reported as not defined in SPEC
        self.assertNotIn("**AA-1** First", text)

    def test_packet_says_it_is_a_starting_point(self):
        _, dest, _, _ = self.packet("--id", "PK-1")
        text = dest.read_text().lower()
        self.assertIn("starting point", text)
        self.assertIn("checked against the source", text)

    def test_brief_found_from_commit_subject_without_id(self):
        _, dest, _, _ = self.packet()
        self.assertIn("**Needs:** AA-2", dest.read_text())

    def test_missing_brief_is_stated_not_fatal(self):
        code, dest, _, _ = self.packet("--id", "NOBRIEF-1")
        self.assertEqual(code, 0)
        self.assertIn("no brief found", dest.read_text())

    def test_pr_number_resolves_through_resolver(self):
        calls = []

        def fake(n):
            calls.append(n)
            return {"base": self.base, "head": self.head, "title": "PK-1: add test", "body": "| BB-2 | t | pass |"}

        reviewpacket.resolve_pr = fake
        dest = self.root / "p.md"
        code, _, _ = run(reviewpacket, ["--root", str(self.root), "--out", str(dest), "42"])
        self.assertEqual(code, 0)
        self.assertEqual(calls, [42])
        text = dest.read_text()
        self.assertIn("PR #42", text)
        self.assertIn("| **BB-2** | Row two |", text)  # cited by the PR body's trace table


if __name__ == "__main__":
    unittest.main()


class RealSpecTest(unittest.TestCase):
    """Blocks of the real SPEC.md are whole: no indented text is left behind after a blank line."""

    @classmethod
    def setUpClass(cls):
        cls.text = (pathlib.Path(__file__).resolve().parent.parent / "SPEC.md").read_text()
        cls.table = specslice.parse(cls.text)

    def test_blocks_continue_across_blank_lines(self):
        tails = {
            "HW-8": "the box MUST NOT mention",
            "CLK-7": "non-interactive mode takes the brief",
            "STO-2": "The owner MAY replace the passphrase",
            "HLD-4": "Each adoption is logged",
        }
        for rid, tail in tails.items():
            with self.subTest(rid):
                self.assertIn(tail, self.table[rid][1])

    def test_every_slice_is_its_whole_block(self):
        lines = self.text.split("\n")
        for rid, (_chain, block) in self.table.items():
            first = block.split("\n")[0]
            if first.lstrip().startswith("|"):
                continue
            start = lines.index(first)
            end = start + len(block.split("\n"))
            self.assertEqual(lines[start:end], block.split("\n"), rid)
            item = specslice.ITEM.match(first)
            base = len(item.group(1)) if item else 0
            for nxt in lines[end:]:
                if not nxt.strip():
                    continue
                if (specslice.HEADING.match(nxt) or nxt.lstrip().startswith("```")
                        or specslice.ID_DEF.search(nxt) or len(nxt) - len(nxt.lstrip()) <= base):
                    break
                self.fail(f"{rid}: indented text left out of the slice: {nxt[:60]!r}")
