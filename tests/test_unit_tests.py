"""tools/unit_tests.py: ci.yml's unit-test step runs modules in parallel, each traced alone (CI-par).

REQ: CI-PATHS
"""
import os
import pathlib
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "tools"))
import unit_tests  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
