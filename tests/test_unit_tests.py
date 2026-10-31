"""tools/unit_tests.py: ci.yml's unit-test step runs modules in parallel, each traced alone (CI-par),
split where one module would set the step's length, with no two units sharing a written path or a
bound address (tests/clash_audit.py, CI-par-clash).

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import clash_audit  # noqa: E402
import records_audit  # noqa: E402


class CommandTest(unittest.TestCase):
    def test_each_module_runs_alone_under_strace_into_its_own_trace(self):
        cmd = unit_tests.command("test_x", "/r")
        self.assertEqual(cmd[:cmd.index("-o")], ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-e",
                                                  "trace=open,openat,openat2,bind", "-e", "signal=none"])
        self.assertEqual(cmd[cmd.index("-o") + 1], "/r/test_x.trace")
        self.assertEqual(cmd[cmd.index("-o") + 2:],
                         [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_x.py", "-v"])

    def test_a_split_module_runs_as_shards_each_into_its_own_trace(self):
        with mock.patch.dict(unit_tests.SPLIT, {"test_x": 3}):
            self.assertEqual(unit_tests.units(["test_a", "test_x"]), ["test_a", "test_x@1", "test_x@2", "test_x@3"])
            cmd = unit_tests.command("test_x@2", "/r")
        self.assertEqual(cmd[cmd.index("-o") + 1], "/r/test_x@2.trace")
        self.assertEqual(cmd[cmd.index("-o") + 2:], [sys.executable, str(unit_tests.ROOT / "tools/unit_tests.py"),
                                                     "--shard", "2/3", "test_x"])

    def test_shards_split_the_expected_time_evenly_and_the_same_in_every_process(self):
        ids = [f"m.C.test_{i}" for i in range(10)]
        with mock.patch.dict(unit_tests.SLOW_TESTS, {"m.C.test_3": 9, "m.C.test_7": 8, "m.C.test_8": 2}, clear=True), \
                mock.patch.object(unit_tests, "DEFAULT_TEST", 1):
            shards = unit_tests.assign(ids, 3)
            self.assertEqual(shards, unit_tests.assign(list(ids), 3))
        self.assertEqual(sorted(sum(shards, [])), sorted(ids))
        self.assertEqual(shards, [["m.C.test_3"], ["m.C.test_7", "m.C.test_9"],
                                  ["m.C.test_0", "m.C.test_1", "m.C.test_2", "m.C.test_4", "m.C.test_5",
                                   "m.C.test_6", "m.C.test_8"]])

    def test_shards_together_run_each_test_of_the_module_once(self):
        # Each shard loads the module as `unittest discover` does and runs its share.
        ran = []

        def fake_run(runner, suite):
            ran.append([t.id() for t in unit_tests.flatten(suite)])
            return mock.Mock(wasSuccessful=lambda: True)
        whole = [t.id() for t in unit_tests.flatten(unittest.defaultTestLoader.discover(
            str(unit_tests.ROOT / "tests"), pattern="test_unit_tests.py"))]
        cwd = os.getcwd()
        path0 = sys.path[0]
        try:
            os.chdir(unit_tests.ROOT)
            with mock.patch.object(unittest.TextTestRunner, "run", fake_run), \
                    mock.patch("sys.stderr", new=mock.Mock()):
                for k in (1, 2, 3):
                    self.assertEqual(unit_tests.shard("test_unit_tests", k, 3), 0)
        finally:
            os.chdir(cwd)
            sys.path[0] = path0
        self.assertEqual(sorted(sum(ran, [])), sorted(whole))
        self.assertTrue(all(ran), ran)

    def test_units_run_without_gits_optional_index_lock(self):
        # git status/diff in the shared worktree would each write .git/index.lock (a clash).
        self.assertEqual(unit_tests.ENV["GIT_OPTIONAL_LOCKS"], "0")

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

    def test_the_longest_units_start_first(self):
        # Measured seconds first (a shard is its module's over n), then unmeasured by file size.
        log = []
        runner, _ = self.fake(log=log, delay=0)
        names = unit_tests.modules()
        with mock.patch.dict(unit_tests.SECONDS, {"test_unit_tests": 100, "test_ci_scope": 30}, clear=True), \
                mock.patch.dict(unit_tests.SPLIT, {"test_unit_tests": 4}, clear=True):
            unit_tests.run(names, "/r", 1, runner=runner, progress=lambda line: None)
        order = [m for m, _ in log]
        self.assertEqual(order[:5], ["test_ci_scope", "test_unit_tests@1", "test_unit_tests@2",
                                     "test_unit_tests@3", "test_unit_tests@4"])
        self.assertEqual(order[5], max(set(names) - {"test_ci_scope", "test_unit_tests"}, key=unit_tests.size))

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

    def test_the_step_prints_each_unit_and_the_critical_path(self):
        results = {"test_a": (0, 50.0, ""), "test_b": (0, 30.0, ""), "test_c": (0, 30.0, ""), "test_s": (0, 5.0, "")}
        lanes = [("w0", "test_b"), ("w1", "test_c"), ("w0", "test_a"), ("serial", "test_s")]
        out = []
        with mock.patch.dict(unit_tests.SERIAL, {"test_s": "why"}):
            self.assertEqual(unit_tests.report(list(results), results, out.append, jobs=2, lanes=lanes, wall=86), 0)
        text = "".join(out)
        self.assertIn("     50.0s  test_a\n     30.0s  test_b\n", text)
        self.assertIn("115s of tests over 2 jobs: 58s ideal, 86s wall\n", text)
        self.assertIn("critical path 85s: test_b 30s, test_a 50s, test_s 5s\n", text)

    def test_one_unit_over_the_long_pole_share_fails_the_step(self):
        # 4 jobs, 400 s in all: ideal 100 s, so a 130 s unit is over 1.25 times it and fails.
        names = [f"test_{i}" for i in range(9)]
        base = {m: (0, 33.75, "") for m in names[1:]}
        for pole, rc in ((130.0, 1), (120.0, 0)):
            results = {**base, "test_0": (0, pole, "")}
            results["test_8"] = (0, 400 - pole - 33.75 * 7, "")
            out = []
            self.assertEqual(unit_tests.report(names, results, out.append, jobs=4), rc, pole)
            self.assertEqual(any("::error::test_0 took" in line and "SPLIT" in line for line in out), bool(rc))
        # A short step never fails it: the pole must also be over FLOOR seconds.
        small = {"test_0": (0, 50.0, ""), "test_1": (0, 1.0, "")}
        self.assertEqual(unit_tests.report(["test_0", "test_1"], small, [].append, jobs=4), 0)

    def test_a_split_module_is_complete_only_with_every_shard(self):
        names = ["test_x"]
        ok = {f"test_x@{k}": (0, 1.0, "") for k in (1, 2)}
        with mock.patch.dict(unit_tests.SPLIT, {"test_x": 2}):
            self.assertEqual(unit_tests.report(names, ok, [].append), 0)
            out = []
            self.assertEqual(unit_tests.report(names, {"test_x@1": ok["test_x@1"]}, out.append), 1)
        self.assertIn("::error::test_x@2 failed\n", out)


R = str(unit_tests.ROOT)
OWN = '1 openat(AT_FDCWD<{r}>, "{r}/tests/test_m.py", O_RDONLY) = 3<{r}/tests/test_m.py>\n'.format(r=R)
END = "1 +++ exited with 0 +++\n"


class ShardRecordsTest(unittest.TestCase):
    def test_records_audit_needs_every_shard_traced_and_finished(self):
        listed = ["tests.test_m"]
        self.assertEqual(records_audit.problems({"test_m": [OWN + END, OWN + END]}, listed), [])
        self.assertEqual(records_audit.problems({"test_m": [OWN + END, ""]}, listed),
                         ["tests.test_m\tno open of the module's own file: tracing did not run"])
        self.assertEqual(records_audit.problems({"test_m": [OWN + END, OWN]}, listed),
                         ["tests.test_m\tthe trace ends before the module's run exits: it was cut short"])
        read = '2 openat(AT_FDCWD<{r}>, "README.md", O_RDONLY) = 3<{r}/README.md>\n'.format(r=R)
        self.assertEqual(records_audit.problems({"test_m": [OWN + END, OWN + read + END]}, []),
                         ["tests.test_m\tREADME.md"])

    def test_records_audit_reads_a_split_modules_shard_traces(self):
        with mock.patch.dict(unit_tests.SPLIT, {"test_m": 2}):
            self.assertEqual(records_audit.unit_tests.units(["test_m"]), ["test_m@1", "test_m@2"])


def w(pid, path, flags="O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC"):
    return f'{pid} openat(AT_FDCWD</w>, "{path}", {flags}, 0666) = 3<{path}>\n'


class ClashTest(unittest.TestCase):
    """CI-par-clash: CI-par-1 (no two modules share a fixed path, port or name) is checked, not assumed."""

    def test_two_units_writing_one_path_fail_naming_both_and_the_path(self):
        traces = {"test_a": w(1, "/tmp/agentos-x/out"), "test_b": w(2, "/tmp/agentos-x/out"), "test_c": ""}
        self.assertEqual(clash_audit.clashes(traces, serial={}), [("path", "/tmp/agentos-x/out", "test_a", "test_b")])

    def test_each_write_flag_counts_and_a_read_does_not(self):
        for flags in ("O_WRONLY", "O_RDWR|O_CLOEXEC", "O_RDONLY|O_CREAT|O_EXCL"):
            self.assertEqual(len(clash_audit.clashes({"test_a": w(1, "/f", flags), "test_b": w(2, "/f")}, serial={})), 1, flags)
        self.assertEqual(clash_audit.clashes({"test_a": w(1, "/f", "O_RDONLY|O_CLOEXEC"), "test_b": w(2, "/f")}, serial={}), [])

    def test_disjoint_temporary_directories_pass(self):
        traces = {"test_a": w(1, "/tmp/tmpa1b2c3/out"), "test_b": w(2, "/tmp/tmpz9y8x7/out"),
                  "test_c@1": w(3, "/tmp/tmpq/out"), "test_c@2": w(4, "/tmp/tmpr/out")}
        self.assertEqual(clash_audit.clashes(traces, serial={}), [])

    def test_shards_of_one_module_clash_with_each_other_too(self):
        traces = {"test_c@1": w(3, "/r/build/x"), "test_c@2": w(4, "/r/build/x")}
        self.assertEqual(clash_audit.clashes(traces, serial={}), [("path", "/r/build/x", "test_c@1", "test_c@2")])

    def test_a_serial_module_is_the_escape_hatch(self):
        traces = {"test_a": w(1, "/f"), "test_b": w(2, "/f"), "test_c@1": w(3, "/f")}
        self.assertEqual(clash_audit.clashes(traces, serial={"test_b": "why", "test_c": "why"}), [])

    def test_relative_resumed_and_failed_creates_resolve_to_one_path(self):
        a = ('1 openat(AT_FDCWD</r>, "build/out", O_WRONLY|O_CREAT <unfinished ...>\n'
             '2 openat(AT_FDCWD</r>, "x", O_WRONLY|O_CREAT, 0666) = 3</r/x>\n'
             '1 <... openat resumed>) = 4</r/build/out>\n')
        b = '5 openat(7</r/build>, "out", O_WRONLY|O_CREAT|O_EXCL, 0666) = -1 EEXIST (File exists)\n'
        self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": b}, serial={}),
                         [("path", "/r/build/out", "test_a", "test_b")])

    def test_a_fixed_port_or_socket_name_clashes_and_port_zero_does_not(self):
        def bind(pid, addr, result="= 0"):
            return f"{pid} bind(3<socket:[9]>, {{{addr}}}, 16) {result}\n"
        fixed = 'sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")'
        six = 'sa_family=AF_INET6, sin6_port=htons(8080), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0'
        zero = 'sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")'
        self.assertEqual(clash_audit.clashes({"test_a": bind(1, fixed), "test_b": bind(2, six, "= -1 EADDRINUSE (Address already in use)")}, serial={}),
                         [("bind", "port 8080", "test_a", "test_b")])
        self.assertEqual(clash_audit.clashes({"test_a": bind(1, zero), "test_b": bind(2, zero)}, serial={}), [])
        abstract = 'sa_family=AF_UNIX, sun_path=@"agentos-probe"'
        self.assertEqual(clash_audit.clashes({"test_a": bind(1, abstract), "test_b": bind(2, abstract)}, serial={}),
                         [("bind", "unix @agentos-probe", "test_a", "test_b")])
        sock = 'sa_family=AF_UNIX, sun_path="/run/agentos.sock"'
        self.assertEqual(clash_audit.clashes({"test_a": bind(1, sock), "test_b": w(2, "/run/agentos.sock")}, serial={}),
                         [("path", "/run/agentos.sock", "test_a", "test_b")])

    def test_paths_built_for_concurrent_writers_are_not_clashes(self):
        home = os.path.expanduser("~")
        for path in ("/dev/null", "/proc/self/oom_score_adj", f"{R}/tools/__pycache__/x.cpython-312.pyc.140230",
                     f"{home}/.cache/go-build/ab/abcdef-d", f"{home}/go/pkg/mod/cache/lock",
                     f"{home}/.config/go/telemetry/local/go@go1.26-x.v1.count"):
            self.assertTrue(clash_audit.shared(path, home=home), path)
            self.assertEqual(clash_audit.clashes({"test_a": w(1, path), "test_b": w(2, path)}, serial={}), [], path)
        for path in (f"{R}/.git/index.lock", "/tmp/agentos-x", f"{R}/build/out"):
            self.assertFalse(clash_audit.shared(path, home=home), path)

    def test_the_step_fails_naming_both_units_and_the_escape_hatch(self):
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            for unit, text in {"test_a": w(1, "/tmp/agentos-x"), "test_b@2": w(2, "/tmp/agentos-x"),
                               "test_c": w(3, "/tmp/tmpc/y")}.items():
                pathlib.Path(d, f"{unit}.trace").write_text(text)
            out, err = io.StringIO(), io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), mock.patch.dict(unit_tests.SERIAL, clear=True):
                self.assertEqual(clash_audit.main(["clash_audit.py", d]), 1)
            self.assertEqual(out.getvalue(), "::error::test_a and test_b@2 both write /tmp/agentos-x\n")
            self.assertIn("SERIAL", err.getvalue())
            pathlib.Path(d, "test_b@2.trace").write_text(w(2, "/tmp/tmpb/x"))
            with mock.patch("sys.stdout", io.StringIO()), mock.patch.dict(unit_tests.SERIAL, clear=True):
                self.assertEqual(clash_audit.main(["clash_audit.py", d]), 0)

    def test_ci_runs_the_clash_check_on_the_unit_traces(self):
        ci = (unit_tests.ROOT / ".github/workflows/ci.yml").read_text()
        step = ci[ci.index("python tests/records_audit.py"):]
        step = step[step.index("\n      - "):][1:]
        step = step[:step.index("\n      - ")]
        self.assertEqual(step.splitlines()[1:], ["        if: env.RECORDS != 'true'",
                                                 '        run: python tests/clash_audit.py "$RUNNER_TEMP/reads"'])


if __name__ == "__main__":
    unittest.main()
