"""PREMERGE-records-merge (#6716): premerge reads the MUTANTS-EQUIVALENT records on the merge it releases.

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic. The replays of main's two breaks
(#6713, #6715) are commands in #6717's body, not tests: a test reading this checkout's git store must run on ci.yml's
records-only step (tests/records_audit.py), which builds no Go.
"""
import contextlib
import io
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import premerge  # noqa: E402

PROBLEM = "mutgate: broker/p/MUTANTS-EQUIVALENT: the entry for a.go F 'return 1' cites G, declared outside its own declaration"


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class RecordsMerged(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.r = pathlib.Path(d.name)
        git(self.r, "init", "-q", "-b", "main")
        self.write("broker/p/a.go", "package p\n\nfunc F() int {\n\treturn 1\n}\n")
        self.write("broker/p/MUTANTS-EQUIVALENT", "# proofs\n")
        self.write("broker/q/b.go", "package q\n")
        self.write("tools/mutgate.py", "# gate\n")
        self.write("notes.md", "n\n")
        self.commit("base")
        git(self.r, "checkout", "-q", "-b", "pr")

    def write(self, name, text):
        (self.r / name).parent.mkdir(parents=True, exist_ok=True)
        (self.r / name).write_text(text)

    def commit(self, msg):
        git(self.r, "add", "-A"), git(self.r, "commit", "-qm", msg)
        return git(self.r, "rev-parse", "HEAD")

    def on_main(self, name, text):
        git(self.r, "checkout", "-q", "main")
        self.write(name, text)
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")

    def merged(self, answers):
        """records_merged of pr into main, with `_records` answering answers[side] ('merge' or 'base')."""
        base = git(self.r, "rev-parse", "main")
        calls = []
        def fake(cwd, treeish, tmp):
            side = "base" if treeish == "main" else "merge"
            calls.append(side)
            return set(answers.get(side, ()))
        with mock.patch.object(premerge, "_records", fake):
            got = premerge.records_merged(self.r, "pr", "main")
        self.assertEqual(git(self.r, "rev-parse", "main"), base)
        return got, calls

    def test_a_pr_outside_broker_reads_nothing(self):
        self.write("notes.md", "m\n")
        self.commit("docs")
        self.assertEqual(self.merged({"merge": {PROBLEM}}), ((None, []), []))

    def test_a_problem_the_merge_adds_holds_and_one_base_has_is_mains(self):
        self.write("broker/p/a.go", "package p\n\nfunc F() int {\n\treturn 2\n}\n")
        self.commit("code")
        self.assertEqual(self.merged({"merge": {PROBLEM}}),
                         (("needs-records broker/p/MUTANTS-EQUIVALENT", [PROBLEM]), ["merge", "base"]))
        # main's own red holds nothing; a second, new problem still holds
        self.assertEqual(self.merged({"merge": {PROBLEM}, "base": {PROBLEM}}), ((None, []), ["merge", "base"]))
        other = PROBLEM.replace("broker/p/", "broker/q/")
        self.assertEqual(self.merged({"merge": {PROBLEM, other}, "base": {PROBLEM}})[0],
                         ("needs-records broker/q/MUTANTS-EQUIVALENT", [other]))
        self.assertEqual(self.merged({}), ((None, []), ["merge"]))

    def test_a_check_that_could_not_run_holds_whatever_base_says(self):
        # The lister failing to build on both sides must not cancel out to a pass.
        self.write("broker/p/a.go", "package p\n")
        self.commit("code")
        for why in ("mutgate: cannot build tools/mutgate_stmts.go", "mutgate records exited 1", "mutgate records ran past 90s"):
            with self.subTest(why):
                self.assertEqual(self.merged({"merge": {why}, "base": {why}}),
                                 (("needs-records error", [why]), ["merge"]))

    def test_a_merge_tree_error_is_no_conflict(self):
        # In CI's unit tests the object store was not writable: merge-tree failed (not 1) and the read was skipped.
        self.write("broker/p/a.go", "package p // err\n")
        self.commit("code")
        real = subprocess.run
        def run(argv, *a, **kw):
            if argv[:2] == ["git", "merge-tree"]:
                return subprocess.CompletedProcess(argv, 128, b"", b"fatal: unable to write object\n")
            return real(argv, *a, **kw)
        with mock.patch.object(premerge, "_records", lambda *a: set()), mock.patch.object(premerge.subprocess, "run", run), \
                self.assertRaises(subprocess.CalledProcessError):
            premerge.records_merged(self.r, "pr", "main")

    def test_a_conflicted_merge_reads_nothing(self):
        self.write("broker/p/a.go", "package p // pr\n")
        self.commit("pr side")
        self.on_main("broker/p/a.go", "package p // main\n")
        self.assertEqual(self.merged({"merge": {PROBLEM}}), ((None, []), []))

    def test_main_moving_is_read_on_the_merge(self):
        # The incident shape: the PR's own base passes, main's later tree is what the merge carries.
        self.write("broker/p/MUTANTS-EQUIVALENT", "# proofs\n# one more\n")
        self.commit("record")
        self.on_main("broker/p/a.go", "package p\n\nfunc F() int {\n\treturn 3\n}\n")
        trees = []
        def fake(cwd, treeish, tmp):
            trees.append(treeish)
            return {PROBLEM} if treeish != "main" else set()
        with mock.patch.object(premerge, "_records", fake):
            self.assertEqual(premerge.records_merged(self.r, "pr", "main")[0], "needs-records broker/p/MUTANTS-EQUIVALENT")
        merge = trees[0]
        self.assertEqual(git(self.r, "show", f"{merge}:broker/p/a.go"), "package p\n\nfunc F() int {\n\treturn 3\n}")
        self.assertEqual(git(self.r, "show", f"{merge}:broker/p/MUTANTS-EQUIVALENT"), "# proofs\n# one more")

    def test_a_pr_changing_the_check_holds_until_main_is_merged_in(self):
        for tool in premerge.RECORDS_TOOLS:
            with self.subTest(tool):
                git(self.r, "checkout", "-q", "main")
                git(self.r, "branch", "-q", "-D", "pr")
                git(self.r, "checkout", "-q", "-b", "pr")
                self.write(tool, f"# stricter {tool}\n")
                self.commit("check")
                # main changed only what the check never reads: the merge is read as usual
                self.on_main("notes.md", f"main {tool}\n")
                self.on_main("broker/q/b.go", f"package q // no record here {tool}\n")
                self.assertEqual(self.merged({})[0][0], None)
                # main changed a record, or code under a directory holding one: the PR's check owes a CI run on it
                for name, text in (("broker/p/a.go", f"package p // {tool}\n"), ("broker/p/MUTANTS-EQUIVALENT", f"# {tool}\n")):
                    self.on_main(name, text)
                    self.assertEqual(self.merged({}), ((f"needs-main-merge {tool}", []), []))
                    git(self.r, "merge", "-q", "--no-edit", "main")
                    self.assertEqual(self.merged({})[0][0], None)

    def test_every_file_mutgate_loads_is_a_records_tool(self):
        # #6717 L3: risk_tier.py loads record_merge.py to read core.txt, so a PR changing it changes the check too.
        loaded = {f"tools/{m}.py" for m in premerge.gate_modules(roots=("mutgate",))}
        self.assertTrue({"tools/mutgate.py", "tools/risk_tier.py", "tools/record_merge.py"} <= loaded, loaded)
        built = {f"tools/{p.name}" for p in [__import__("mutgate").STMTS]}
        self.assertEqual(set(premerge.RECORDS_TOOLS), loaded | built | {"broker/core/core.txt"})
        # and the PR changing one holds while main changed a record
        self.write("tools/record_merge.py", "# changed\n")
        self.commit("tool")
        self.on_main("broker/p/MUTANTS-EQUIVALENT", "# p3\n")
        self.assertEqual(self.merged({})[0], ("needs-main-merge tools/record_merge.py", []))

    def test_the_tree_is_read_with_this_checkouts_tools_and_no_token(self):
        # The child runs this checkout's mutgate.py on a copy whose tools/ and core.txt are this checkout's,
        # and the gate step's tokens stay out of its environment.
        self.write("tools/mutgate.py", "raise SystemExit('the PR copy ran')\n")
        self.write("broker/core/core.txt", "the PR's tier list\n")
        self.write("broker/p/a.go", "package p\n")
        self.commit("pr tools")
        seen, real = {}, subprocess.run
        def run(argv, cwd=None, env=None, **kw):
            if argv[0] == "git":
                return real(argv, cwd=cwd, **kw)
            dest = pathlib.Path(cwd)
            seen.update(argv=argv, env=env, tool=(dest / "tools/mutgate.py").read_bytes(),
                        core=(dest / "broker/core/core.txt").read_bytes(), go=(dest / "broker/p/a.go").read_text())
            return subprocess.CompletedProcess(argv, 1, "", PROBLEM + "\nnoise\n")
        with mock.patch.dict(os.environ, {"GH_TOKEN": "canary-gh", "STATUS_TOKEN": "canary-status"}), \
                mock.patch.object(premerge.subprocess, "run", run), tempfile.TemporaryDirectory() as tmp:
            got = premerge._records(self.r, "pr", tmp)
        self.assertEqual(got, {PROBLEM})
        self.assertEqual(seen["tool"], (ROOT / "tools/mutgate.py").read_bytes())
        self.assertEqual(seen["core"], (ROOT / "broker/core/core.txt").read_bytes())
        self.assertEqual(seen["go"], "package p\n")
        self.assertEqual(seen["argv"][1:3], ["-I", str(pathlib.Path(seen["argv"][2]))])
        self.assertTrue(seen["argv"][2].endswith("/tools/mutgate.py") and seen["argv"][3:] == ["records"])
        self.assertFalse({"GH_TOKEN", "STATUS_TOKEN"} & set(seen["env"]), seen["env"])
        self.assertFalse(any("canary" in v for v in seen["env"].values()))
        self.assertEqual((seen["env"]["GOWORK"], seen["env"]["GOTOOLCHAIN"], seen["env"]["GOFLAGS"]), ("off", "local", ""))

    def child(self, outcome):
        """_records on the PR tree with the mutgate child replaced by outcome (a CompletedProcess's (code, stderr) or an exception)."""
        if (self.r / "broker/p/a.go").read_text() != "package p // child\n":
            self.write("broker/p/a.go", "package p // child\n")
            self.commit("code")
        real = subprocess.run
        def run(argv, cwd=None, env=None, **kw):
            if argv[0] == "git":
                return real(argv, cwd=cwd, **kw)
            if isinstance(outcome, BaseException):
                raise outcome
            return subprocess.CompletedProcess(argv, outcome[0], "", outcome[1])
        with mock.patch.object(premerge.subprocess, "run", run), tempfile.TemporaryDirectory() as tmp:
            return premerge._records(self.r, "pr", tmp)

    def test_a_child_that_crashes_naming_no_problem_holds(self):
        # #6717 Security: a traceback prints no `mutgate: ` line, so the exit code is what holds it.
        crash = "Traceback (most recent call last):\n  File \"tools/mutgate.py\"\nKeyError: 'x'\n"
        self.assertEqual(self.child((1, crash)), {"mutgate records exited 1"})
        self.assertEqual(self.child((2, "")), {"mutgate records exited 2"})
        self.assertEqual(self.child((0, "noise\n")), set())
        self.assertEqual(self.child((1, PROBLEM + "\n" + crash)), {PROBLEM})

    def test_a_child_that_hangs_holds(self):
        # #6717 Security: a crafted tree that keeps the child past the cap must not read as no problem.
        got = self.child(subprocess.TimeoutExpired(["mutgate"], premerge.RECORDS_TIMEOUT))
        self.assertEqual(got, {f"mutgate records ran past {premerge.RECORDS_TIMEOUT}s"})
        self.assertFalse(premerge.NAMED.search(next(iter(got))))  # never subtracted against base

    def test_a_tree_without_broker_reads_no_problem(self):
        empty = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's empty tree: no broker/ to read, so no child runs
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(premerge._records(self.r, empty, tmp), set())

    def test_a_link_out_of_the_tree_is_refused(self):
        (self.r / "broker/p/MUTANTS-EQUIVALENT").unlink()
        (self.r / "broker/p/MUTANTS-EQUIVALENT").symlink_to("/etc/passwd")
        self.commit("link")
        why, problems = premerge.records_merged(self.r, "pr", "main")
        self.assertTrue(why.startswith("needs-records "), why)
        self.assertEqual(len(problems), 1)
        self.assertIn("the tree is refused", problems[0])

    def test_the_real_check_reads_a_bad_record(self):
        # End to end with this checkout's mutgate.py and Go: a record line that is no entry is named.
        self.write("broker/zzfake/a.go", "package zzfake\n")
        self.write("broker/zzfake/MUTANTS-EQUIVALENT", '{"file": "a.go"}\n')
        self.commit("bad record")
        why, problems = premerge.records_merged(self.r, "pr", "main")
        self.assertEqual(why, "needs-records broker/zzfake/MUTANTS-EQUIVALENT", problems)


class CheckGate(unittest.TestCase):
    def test_check_prints_the_hold_only_where_it_would_print_same(self):
        out = io.StringIO()
        with mock.patch.object(premerge, "verdict", return_value=("accept", "a" * 40)), \
                mock.patch.object(premerge, "_named", return_value=None), \
                mock.patch.object(premerge, "compare", return_value=[]), \
                mock.patch.object(premerge, "mark_range", return_value=["b.md"]), \
                mock.patch.object(premerge, "checks_held", return_value=[]), \
                mock.patch.object(premerge, "records_merged",
                                  return_value=("needs-records broker/p/MUTANTS-EQUIVALENT", [PROBLEM])) as rm, \
                tempfile.NamedTemporaryFile("w", suffix=".json") as f, contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            f.write("[]"), f.flush()
            code = premerge.main(["premerge.py", "--check", f.name, "7", "--runs", f.name, "--base", "main", "h"])
        self.assertEqual((code, out.getvalue()), (1, "needs-records broker/p/MUTANTS-EQUIVALENT\n"))
        self.assertIn(PROBLEM, err.getvalue())
        rm.assert_called_once_with(".", "h", "main")


class Workflow(unittest.TestCase):
    def test_the_gate_job_installs_go_mods_toolchain(self):
        wf = (ROOT / ".github/workflows/premerge.yml").read_text()
        want = re.search(r"^toolchain go(\S+)$", (ROOT / "broker/go.mod").read_text(), re.M).group(1)
        self.assertEqual(re.findall(r'go-version: "([^"]+)"', wf), [want])
        gate = wf.split("\n  premerge-gate:\n", 1)[1].split("\n  merge:\n", 1)[0]
        self.assertLess(gate.index("actions/setup-go@"), gate.index("id: gate"))


if __name__ == "__main__":
    unittest.main()
