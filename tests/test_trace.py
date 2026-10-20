# Marker strings are split so this file makes no coverage claims itself.
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import trace as tr  # noqa: E402


def make_repo(spec, files):
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "SPEC.md").write_text(spec)
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return d


M = "# RE" "Q: "


class TraceTest(unittest.TestCase):
    SPEC = "- **OP-1** a\n- **OP-2** b\n- **OP-1** again\n"

    def test_ids_unique_in_order(self):
        self.assertEqual(tr.spec_ids(self.SPEC), ["OP-1", "OP-2"])

    def test_coverage_and_check(self):
        d = make_repo(self.SPEC, {"tests/t.py": M + "OP-1\n"})
        self.assertEqual(tr.main(["--root", str(d)]), 0)
        self.assertIn("Covered: 1 / 2", (d / "TRACE.md").read_text())
        self.assertEqual(tr.main(["--root", str(d), "--check"]), 0)

    def test_stale_trace_fails_check(self):
        d = make_repo(self.SPEC, {})
        (d / "TRACE.md").write_text("old")
        self.assertEqual(tr.main(["--root", str(d), "--check"]), 1)

    def test_unknown_id_fails(self):
        d = make_repo(self.SPEC, {"tests/t.py": M + "XX-9\n"})
        self.assertEqual(tr.main(["--root", str(d)]), 1)

    def test_lettered_sub_ids(self):
        spec = "- **HW-5** a\n- **HW-5a** b\n"
        self.assertEqual(tr.spec_ids(spec), ["HW-5", "HW-5a"])
        d = make_repo(spec, {"tests/t.py": M + "HW-5a, HW-5\n"})
        self.assertEqual(tr.main(["--root", str(d)]), 0)
        self.assertIn("Covered: 2 / 2", (d / "TRACE.md").read_text())

    def test_gate(self):
        d = make_repo(self.SPEC, {"tests/t.py": M + "OP-1\n"})
        self.assertEqual(tr.main(["--root", str(d), "--gate", "OP-1"]), 0)
        self.assertEqual(tr.main(["--root", str(d), "--gate", "OP-1,OP-2"]), 1)


    RETIRING = ("- **KEY-1** a\n\n## Appendix A. Retired requirement IDs\n\n"
                "| Retired | Now | What moved |\n|---|---|---|\n"
                "| OP-1, OP-2 | KEY-1 | x |\n| CAP-9 | dropped | y |\n")

    def test_retired_ids_from_appendix(self):
        self.assertEqual(tr.retired_ids(self.RETIRING), ["OP-1", "OP-2", "CAP-9"])
        self.assertEqual(tr.retired_ids(self.SPEC), [])

    def test_retired_marker_accepted_and_counted(self):
        d = make_repo(self.RETIRING, {"tests/t.py": M + "OP-1, KEY-1\n",
                                      "tests/u.py": M + "OP-1\n"})
        self.assertEqual(tr.main(["--root", str(d)]), 0)
        out = (d / "TRACE.md").read_text()
        self.assertIn("Covered: 1 / 1", out)
        self.assertIn("Old-core markers: 2 in 1 retired IDs", out)

    def test_no_old_core_markers(self):
        d = make_repo(self.RETIRING, {"tests/t.py": M + "KEY-1\n"})
        self.assertEqual(tr.main(["--root", str(d)]), 0)
        self.assertIn("Old-core markers: 0 in 0 retired IDs", (d / "TRACE.md").read_text())


if __name__ == "__main__":
    unittest.main()
