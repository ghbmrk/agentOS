"""tools/unit_tests.py: ci.yml's unit-test step runs modules in parallel, each traced alone (CI-par).

REQ: CI-PATHS
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "tools"))
import unit_tests  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import records_audit  # noqa: E402


class CommandTest(unittest.TestCase):
    def test_each_module_runs_alone_under_strace_into_its_own_trace(self):
        cmd = unit_tests.command("test_x", "/r")
        self.assertEqual(cmd[:cmd.index("-o")], ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-e",
                                                  "trace=open,openat,openat2", "-e", "signal=none"])
        self.assertEqual(cmd[cmd.index("-o") + 1], "/r/test_x.trace")
        self.assertEqual(cmd[cmd.index("-o") + 2:],
                         [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_x.py", "-v"])

    def test_every_test_module_is_run(self):
        names = unit_tests.modules()
        files = sorted(p.stem for p in pathlib.Path(unit_tests.ROOT, "tests").glob("test*.py"))
        self.assertEqual(names, files)
        self.assertIn("test_unit_tests", names)


class RunTest(unittest.TestCase):
    def fake(self, fail=(), log=None, delay=0.05):
        live = [0]
        peak = [0]
        lock = threading.Lock()

        def runner(module, trace_dir):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
                if log is not None:
                    log.append((module, live[0]))
            time.sleep(delay)
            with lock:
                live[0] -= 1
            return module, 1 if module in fail else 0, delay, f"{module} out\n"
        return runner, peak

    def test_modules_run_concurrently_up_to_jobs(self):
        runner, peak = self.fake()
        names = [f"test_{i}" for i in range(8)]
        lines = []
        results = unit_tests.run(names, "/r", 4, runner=runner, progress=lines.append)
        self.assertEqual(sorted(results), names)
        self.assertEqual(peak[0], 4)
        self.assertEqual(len(lines), 8)
        self.assertTrue(lines[-1].startswith("8/8 "), lines)

    def test_serial_modules_run_alone_after_the_pool(self):
        log = []
        runner, _ = self.fake(log=log)
        names = ["test_a", "test_b", "test_c", "test_d"]
        with mock.patch.dict(unit_tests.SERIAL, {"test_b": "shares a fixed port"}):
            results = unit_tests.run(names, "/r", 4, runner=runner, progress=lambda line: None)
        self.assertEqual(sorted(results), names)
        self.assertEqual(log[-1], ("test_b", 1))

    def test_the_biggest_module_starts_first(self):
        log = []
        runner, _ = self.fake(log=log, delay=0)
        names = unit_tests.modules()
        unit_tests.run(names, "/r", 1, runner=runner, progress=lambda line: None)
        self.assertEqual(log[0][0], max(names, key=unit_tests.size))

    def test_a_failed_or_missing_module_fails_the_step(self):
        names = ["test_a", "test_b", "test_c"]
        out = []
        ok = {m: (0, 1.0, "") for m in names}
        self.assertEqual(unit_tests.report(names, ok, out.append), 0)
        self.assertEqual(unit_tests.report(names, {**ok, "test_b": (1, 1.0, "")}, out.append), 1)
        missing = dict(ok)
        del missing["test_c"]
        out.clear()
        self.assertEqual(unit_tests.report(names, missing, out.append), 1)
        self.assertIn("::error::test_c failed\n", out)
        self.assertIn("did not run", "".join(out))

    def test_output_is_grouped_whole_per_module_in_name_order(self):
        out = []
        results = {"test_b": (0, 2.0, "b1\nb2\n"), "test_a": (1, 5.0, "a1\n")}
        unit_tests.report(["test_a", "test_b"], results, out.append)
        text = "".join(out)
        self.assertLess(text.index("::group::test_a (FAILED, 5s)\na1\n::endgroup::"),
                        text.index("::group::test_b (ok, 2s)\nb1\nb2\n::endgroup::"))


def traced():
    """Whether this process is already traced: a nested strace cannot attach (PTRACE_TRACEME)."""
    try:
        with open("/proc/self/status") as f:
            return any(line.split()[1:2] not in (["0"], []) for line in f if line.startswith("TracerPid:"))
    except OSError:
        return False


class SplitTest(unittest.TestCase):
    """CI-par-3: a SPLIT module's tests run across forked workers inside its one strace tree."""
    # REQ: CI-PATHS

    BODY = textwrap.dedent("""\
        import os, time, unittest

        def log(case):
            with open(os.environ["SPLIT_LOG"], "a") as f:
                f.write(f"{os.getpid()} {case.id()}\\n")

        class A(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                cls.ready = True

            def test_1(self): log(self); time.sleep(0.3); self.assertTrue(self.ready)
            def test_2(self): log(self); time.sleep(0.3); self.assertTrue(self.ready)
            def test_3(self): log(self); time.sleep(0.3); self.assertTrue(self.ready)

        class B(unittest.TestCase):
            def test_4(self): log(self); time.sleep(0.3)
            def test_5(self): log(self); time.sleep(0.3)
            def test_6(self): log(self); time.sleep(0.3)
        """)

    def run_split(self, body, prefix=()):
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "tests").mkdir()
        (root / "tests" / "test_fake.py").write_text(body)
        log = root / "log"
        log.touch()
        p = subprocess.run([*prefix, sys.executable, str(pathlib.Path(unit_tests.__file__).resolve()), "--split",
                            "test_fake", "--workers", "3"], cwd=root, capture_output=True, text=True,
                           env={**os.environ, "SPLIT_LOG": str(log)}, timeout=120)
        return p, [line.split() for line in log.read_text().splitlines()], root

    def test_a_split_module_runs_under_one_strace_into_its_own_trace(self):
        cmd = unit_tests.command("test_image", "/r", workers=4)
        self.assertIn("test_image", unit_tests.SPLIT)
        self.assertEqual(cmd, [*unit_tests.STRACE, "-o", "/r/test_image.trace", sys.executable,
                               str(pathlib.Path(unit_tests.__file__).resolve()), "--split", "test_image",
                               "--workers", "4"])

    def test_split_modules_exist(self):
        self.assertTrue(set(unit_tests.SPLIT) <= set(unit_tests.modules()), unit_tests.SPLIT)
        self.assertFalse(set(unit_tests.SPLIT) & set(unit_tests.SERIAL))

    def test_split_runs_every_test_once_across_workers(self):
        p, log, _ = self.run_split(self.BODY)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(sorted(t for _, t in log), [f"test_fake.{c}.test_{i}" for c, i in
                                                     (("A", 1), ("A", 2), ("A", 3), ("B", 4), ("B", 5), ("B", 6))])
        self.assertGreater(len({pid for pid, _ in log}), 1, log)
        self.assertIn("test_fake: 6 of 6 tests run across 3 workers\n", p.stdout)

    def test_split_fails_on_a_failed_test(self):
        p, log, _ = self.run_split(self.BODY.replace("def test_5(self): log(self);", "def test_5(self): self.fail('x');"))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("FAIL: test_5", p.stdout)
        self.assertEqual(len(log), 5)

    def test_split_fails_when_a_worker_is_lost(self):
        p, log, _ = self.run_split(self.BODY.replace("def test_5(self): log(self);", "def test_5(self): os._exit(0);"))
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("1 worker(s) lost", p.stdout)
        self.assertIn("not run", p.stdout)

    def test_split_fails_on_an_empty_module(self):
        p, log, _ = self.run_split("import unittest\n")
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("test_fake: no tests found", p.stdout)

    @unittest.skipUnless(shutil.which("strace"), "strace is not installed (CI installs it)")
    @unittest.skipIf(traced(), "already under strace (CI's step), which audits test_image's real trace instead")
    def test_split_trace_is_one_finished_tree(self):
        trace_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, trace_dir)
        prefix = unit_tests.command("test_x", trace_dir)
        prefix = prefix[:prefix.index("-o") + 2]
        p, log, root = self.run_split(self.BODY, prefix)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        trace = pathlib.Path(trace_dir, "test_x.trace").read_text(errors="surrogateescape")
        self.assertTrue(records_audit.finished(trace))
        opened = records_audit.opened(trace, root=os.path.realpath(root))
        self.assertIn(("tests/test_fake.py", False), opened)
        self.assertIn(str(root / "log"), trace)
        # The first process, the one strace started, exits after every worker it forked.
        first = trace.split(None, 1)[0]
        self.assertTrue(trace.rstrip().endswith("+++ exited with 0 +++"), trace[-300:])
        self.assertTrue(trace.rstrip().splitlines()[-1].startswith(first + " "), trace[-300:])


if __name__ == "__main__":
    unittest.main()
