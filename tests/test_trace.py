# Marker strings are split so this file makes no coverage claims itself.
import pathlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

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


def git(d, *a):
    subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)


def commit(d, files, remove=()):
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    for rel in remove:
        (d / rel).unlink()
    git(d, "add", "-A")
    git(d, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "c")
    out = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], check=True, capture_output=True)
    return out.stdout.decode().strip()


class RatchetTest(unittest.TestCase):
    """The old core (tools/old_core.txt) never grows between a base and a head (D-139)."""

    IMP = 'import "github.com/ghbmrk/agentos/broker/journal"\n'

    def setUp(self):
        self.d = make_repo(TraceTest.RETIRING, {})
        git(self.d, "init", "-q")
        self.base = commit(self.d, {
            "tools/old_core.txt": "# old\nbroker/journal\nbroker/sim\n",
            "broker/journal/j.go": "package journal\n",
            "broker/sim/s.go": "package sim\n",
            "broker/daemon/d.go": "package daemon\n" + self.IMP,
            "tests/t.py": M + "OP-1\n",
        })

    def problems(self, head):
        return tr.ratchet(self.d, self.base, head, tr.retired_ids(TraceTest.RETIRING))

    def test_unchanged_and_shrinking_pass(self):
        self.assertEqual(self.problems(self.base), [])
        head = commit(self.d, {"broker/daemon/d.go": "package daemon\n"},
                      remove=["broker/journal/j.go", "tests/t.py"])
        self.assertEqual(self.problems(head), [])
        self.assertEqual(tr.main(["--root", str(self.d), "--ratchet", self.base]), 0)

    def test_new_marker_fails(self):
        head = commit(self.d, {"tests/u.py": M + "OP-2\n"})
        self.assertEqual(self.problems(head), ["old-core markers grew from 1 to 2"])
        self.assertEqual(tr.main(["--root", str(self.d), "--ratchet", self.base]), 1)

    def test_unmarked_old_core_code_fails(self):
        head = commit(self.d, {"broker/journal/new.go": "package journal\n\nfunc F() {}\n"})
        self.assertEqual(self.problems(head), ["lines in broker/journal grew from 1 to 4"])

    def test_new_wiring_fails(self):
        head = commit(self.d, {"broker/cmd/agentosd/m.go": "package main\n" + self.IMP})
        self.assertEqual(self.problems(head), ["imports of broker/journal grew from 1 to 2"])

    def test_imports_inside_old_core_are_not_wiring(self):
        head = commit(self.d, {"broker/sim/s.go": "package sim\n" + self.IMP})
        self.assertEqual(self.problems(head), ["lines in broker/sim grew from 1 to 2"])

    def test_port_retires_a_directory_by_deleting_its_old_files(self):
        head = commit(self.d, {"tools/old_core.txt": "broker/journal\n",
                               "broker/sim/kernel_sim.go": "package sim\n\nfunc Run() {}\n"},
                      remove=["broker/sim/s.go"])
        self.assertEqual(self.problems(head), [])

    def test_retiring_a_directory_without_deleting_fails(self):
        head = commit(self.d, {"tools/old_core.txt": "broker/journal\n"})
        self.assertEqual(self.problems(head),
                         ["old-core file broker/sim/s.go persists outside tools/old_core.txt at broker/sim/s.go"])

    J = "package journal\n\n" + "".join(f"func F{i}() {{}}\n" for i in range(20))

    def moved_base(self):
        self.base = commit(self.d, {"broker/journal/j.go": self.J})

    def test_moving_old_core_out_fails(self):
        self.moved_base()
        head = commit(self.d, {"tools/old_core.txt": "broker/sim\n", "broker/kernel/j.go": self.J + "func G() {}\n"},
                      remove=["broker/journal/j.go"])
        self.assertEqual(self.problems(head),
                         ["old-core file broker/journal/j.go persists outside tools/old_core.txt at broker/kernel/j.go"])

    def test_copying_old_core_out_fails(self):
        self.moved_base()
        head = commit(self.d, {"broker/kernel/j.go": self.J})
        self.assertEqual(self.problems(head),
                         ["old-core file broker/journal/j.go persists outside tools/old_core.txt at broker/kernel/j.go"])

    def test_copy_among_many_new_files_fails(self):
        # A rename limit of 1 stands in for a large repository: past the limit git
        # skips inexact copy detection, so moves() lifts it (-l0).
        git(self.d, "config", "diff.renameLimit", "1")
        self.moved_base()
        many = {f"misc/f{i}.txt": f"note {i}\n" * 3 for i in range(300)}
        head = commit(self.d, {"broker/kernel/j.go": self.J + "func G() {}\n", **many})
        self.assertEqual(self.problems(head),
                         ["old-core file broker/journal/j.go persists outside tools/old_core.txt at broker/kernel/j.go"])

    def test_skipped_rename_detection_fails_closed(self):
        skipped = subprocess.CompletedProcess([], 0, b"", b"warning: ... due to too many files.\n")
        with unittest.mock.patch.object(tr.subprocess, "run", return_value=skipped):
            with self.assertRaises(SystemExit):
                tr.moves(self.d, self.base, self.base)

    def test_moving_into_a_newly_listed_directory_fails(self):
        self.moved_base()
        head = commit(self.d, {"tools/old_core.txt": "broker/sim\nbroker/kernel\n", "broker/kernel/j.go": self.J},
                      remove=["broker/journal/j.go"])
        self.assertEqual(self.problems(head), ["lines in broker/kernel grew from 0 to 22"])


if __name__ == "__main__":
    unittest.main()
