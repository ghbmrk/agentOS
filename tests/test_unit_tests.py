"""tools/unit_tests.py: ci.yml's unit-test step runs modules in parallel, each traced alone (CI-par),
longest first, failing when one module sets the step's length, with no two modules sharing a
written path or a bound address (tests/clash_audit.py, CI-par-clash).

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

    def test_every_test_module_is_run(self):
        names = unit_tests.modules()
        files = sorted(p.stem for p in pathlib.Path(unit_tests.ROOT, "tests").glob("test*.py"))
        self.assertEqual(names, files)
        self.assertIn("test_unit_tests", names)

    def test_modules_run_without_gits_optional_index_lock(self):
        # git status/diff in the shared worktree would each write .git/index.lock (a clash).
        self.assertEqual(unit_tests.ENV["GIT_OPTIONAL_LOCKS"], "0")


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

    def test_the_longest_modules_start_first(self):
        # Measured seconds first, then unmeasured modules by file size.
        log = []
        runner, _ = self.fake(log=log, delay=0)
        names = unit_tests.modules()
        with mock.patch.dict(unit_tests.SECONDS, {"test_unit_tests": 100, "test_ci_scope": 30}, clear=True):
            unit_tests.run(names, "/r", 1, runner=runner, progress=lambda line: None)
        order = [m for m, _ in log]
        self.assertEqual(order[:2], ["test_unit_tests", "test_ci_scope"])
        self.assertEqual(order[2], max(set(names) - {"test_ci_scope", "test_unit_tests"}, key=unit_tests.size))

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

    def test_the_step_prints_each_module_and_the_critical_path(self):
        results = {"test_a": (0, 50.0, ""), "test_b": (0, 30.0, ""), "test_c": (0, 30.0, ""), "test_s": (0, 5.0, "")}
        lanes = [("w0", "test_b"), ("w1", "test_c"), ("w0", "test_a"), ("serial", "test_s")]
        out = []
        with mock.patch.dict(unit_tests.SERIAL, {"test_s": "why"}):
            self.assertEqual(unit_tests.report(list(results), results, out.append, jobs=2, lanes=lanes, wall=86), 0)
        text = "".join(out)
        self.assertIn("     50.0s  test_a\n     30.0s  test_b\n", text)
        self.assertIn("115s of tests over 2 jobs: 58s ideal, 86s wall\n", text)
        self.assertIn("critical path 85s: test_b 30s, test_a 50s, test_s 5s\n", text)

    def test_one_module_over_the_long_pole_share_fails_the_step(self):
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

    def test_an_already_split_module_is_judged_by_its_slowest_part(self):
        # test_image's place on main: 1.11 times the ideal. Grown 15% it is over 1.25 times, but
        # its parts are short, so the step passes and says nothing of splitting it.
        names = [f"test_{i}" for i in range(9)]
        line = "test_0: slowest part {:.3f}s tests.test_0.A.test_a\n"
        for grown in (111.0, 111.0 * 1.15):
            results = {m: (0, (400 - grown) / 8, "") for m in names[1:]}
            results["test_0"] = (0, grown, "ok\n" + line.format(20.0))
            out = []
            self.assertEqual(unit_tests.report(names, results, out.append, jobs=4, split={"test_0": "x"}), 0, out)
            self.assertFalse(any("::error::" in o for o in out), out)
            self.assertTrue(any("test_0  (split; slowest part 20.0s, tests.test_0.A.test_a)" in o for o in out), out)
            # The same time on an unsplit module still says split it.
            out = []
            self.assertEqual(unit_tests.report(names, results, out.append, jobs=4, split={}), int(grown > 125), grown)
            self.assertEqual(any("split it (tools/unit_tests.py SPLIT)" in o for o in out), grown > 125)
        # A part over the line fails, naming the part and the split limit, never "split it".
        results = {m: (0, 33.75, "") for m in names[1:]}
        results["test_0"] = (0, 130.0, line.format(130.0))
        out = []
        self.assertEqual(unit_tests.report(names, results, out.append, jobs=4, split={"test_0": "x"}), 1)
        err = [o for o in out if "::error::" in o]
        self.assertEqual(len(err), 1, out)
        self.assertIn("test_0 is already split", err[0])
        self.assertIn("tests.test_0.A.test_a, took 130s", err[0])
        self.assertIn("at its split limit", err[0])
        self.assertNotIn("split it", err[0])
        # A split run that named no part (it died before its last line) counts its whole time.
        results["test_0"] = (1, 130.0, "test_0: 3 of 4 tests run across 2 workers, 1 not run\n")
        out = []
        self.assertEqual(unit_tests.report(names, results, out.append, jobs=4, split={"test_0": "x"}), 1)
        self.assertTrue(any("named no slowest part and took 130s" in o for o in out), out)
        # Only the run's own last line counts: a test printing the format earlier does not.
        self.assertIsNone(unit_tests.slowest_part("test_0", line.format(1.0) + "more\n"))
        self.assertIsNone(unit_tests.slowest_part("test_0", "test_01: slowest part 1.000s x\n"))


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

    def test_split_names_its_slowest_part_on_its_last_line(self):
        p, log, _ = self.run_split(self.BODY.replace("def test_5(self): log(self); time.sleep(0.3)",
                                                     "def test_5(self): log(self); time.sleep(1.2)"))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        secs, test = unit_tests.slowest_part("test_fake", p.stdout)
        self.assertEqual(test, "test_fake.B.test_5")
        self.assertGreaterEqual(secs, 1.2)
        self.assertLess(secs, 30)

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



R = str(unit_tests.ROOT)


class RecordsAuditTest(unittest.TestCase):
    """CI-PATHS: a record read through a split or padded open counts by the file it reached."""

    def test_a_record_reached_through_a_link_on_a_padded_line_counts(self):
        own = f'1 openat(AT_FDCWD<{R}>, "tests/test_m.py", O_RDONLY|O_CLOEXEC) = 3<{R}/tests/test_m.py>\n'
        end = "1 +++ exited with 0 +++\n"
        reads = {
            # strace's own shape for a split call: the asked path is a link outside the tree,
            # the resumed line, padded to strace's column, names the record it reached.
            "split": ('2 openat(AT_FDCWD</tmp/l>, "link.md", O_RDONLY|O_CLOEXEC <unfinished ...>\n'
                      '3 openat(AT_FDCWD</tmp>, "y", O_RDONLY) = 4</tmp/y>\n'
                      f'2 <... openat resumed>)            = 5<{R}/LEDGER.md>\n'),
            "padded": f'4 open("/tmp/l/x", O_RDONLY)          = 3<{R}/LEDGER.md>\n',
            # -y escapes the reached path as strace quotes it: `\76` for `>`, octal or hex bytes.
            "escaped": f'5 openat(AT_FDCWD</tmp>, "l", O_RDONLY) = 3<{R}/LEDGER\\056md>\n',
        }
        for name, line in reads.items():
            trace = own + line + end
            self.assertIn("LEDGER.md", {rel for rel, _ in records_audit.opened(trace)}, name)
            self.assertEqual(records_audit.problems({"test_m": trace}, []), ["tests.test_m\tLEDGER.md"], name)
            self.assertEqual(records_audit.problems({"test_m": trace}, ["tests.test_m"]), [], name)
        # The asked path decodes as the reached one does.
        asked = f'6 openat(AT_FDCWD<{R}>, "LEDGER\\x2emd", O_RDONLY <unfinished ...>\n'
        self.assertIn(("LEDGER.md", False), records_audit.opened(asked))


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
                  "test_c": w(3, "/tmp/tmpq/out")}
        self.assertEqual(clash_audit.clashes(traces, serial={}), [])

    def test_a_serial_module_is_the_escape_hatch(self):
        traces = {"test_a": w(1, "/f"), "test_b": w(2, "/f"), "test_c": w(3, "/f")}
        self.assertEqual(clash_audit.clashes(traces, serial={"test_b": "why", "test_c": "why"}), [])

    def test_relative_resumed_and_failed_creates_resolve_to_one_path(self):
        # As strace prints them: a split call's result on a padded `<... resumed>` line, and the
        # file it reached (through a link) differing from the path asked for.
        a = ('1 openat(AT_FDCWD</r>, "link/out", O_WRONLY|O_CREAT <unfinished ...>\n'
             '2 openat(AT_FDCWD</r>, "x", O_WRONLY|O_CREAT, 0666) = 3</r/x>\n'
             '1 <... openat resumed>)             = 4</r/build/out>\n')
        b = '5 openat(7</r/build>, "out", O_WRONLY|O_CREAT|O_EXCL, 0666) = -1 EEXIST (File exists)\n'
        self.assertIn(("path", "/r/build/out"), clash_audit.writes(a))
        self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": b}, serial={}),
                         [("path", "/r/build/out", "test_a", "test_b")])
        padded = '6 openat(AT_FDCWD</r>, "link/out", O_WRONLY|O_CREAT, 0666)    = 3</r/build/out>\n'
        self.assertEqual(clash_audit.writes(padded), {("path", "/r/build/out")})

    def test_asked_and_reached_paths_decode_alike(self):
        # strace 6.8's own lines for one odd name: quoted as asked, `\76` for `>` after -y.
        a = ('7  openat(AT_FDCWD</e>, "w/we>ird\\"q\\\\b/out\\tx", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3'
             '</e/w/we\\76ird\\"q\\\\b/out\\tx>\n')
        b = '8  openat(AT_FDCWD</e>, "w/we>ird\\"q\\\\b/out\\tx", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0777) = -1 EEXIST (File exists)\n'
        name = '/e/w/we>ird"q\\b/out\tx'
        self.assertEqual(clash_audit.writes(a), {("path", name)})
        self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": b}, serial={}), [("path", name, "test_a", "test_b")])
        self.assertEqual(clash_audit._decode("\\x41\\101\\60\\n"), "AA0\n")

    def test_a_write_cut_off_mid_call_counts_its_asked_path(self):
        a = '1 openat(AT_FDCWD</r>, "build/out", O_WRONLY|O_CREAT <unfinished ...>\n1 +++ killed by SIGKILL +++\n'
        self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, "/r/build/out")}, serial={}),
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
        for path in (f"{R}/.git/index.lock", "/tmp/agentos-x", f"{R}/build/out", f"{R}/x/__pycache__/out.pyc",
                     "/dev/shm/sem.agentos"):
            self.assertFalse(clash_audit.shared(path, home=home), path)

    @mock.patch.object(unit_tests, "modules", lambda root=None: ["test_a", "test_b", "test_c"])
    def test_the_step_fails_naming_both_units_and_the_escape_hatch(self):
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            for unit, text in {"test_a": w(1, "/tmp/agentos-x"), "test_b": w(2, "/tmp/agentos-x"),
                               "test_c": w(3, "/tmp/tmpc/y")}.items():
                pathlib.Path(d, f"{unit}.trace").write_text(text)
            out, err = io.StringIO(), io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), mock.patch.dict(unit_tests.SERIAL, clear=True):
                self.assertEqual(clash_audit.main(["clash_audit.py", d]), 1)
            self.assertEqual(out.getvalue(), "::error::test_a and test_b both write /tmp/agentos-x\n")
            self.assertIn("SERIAL", err.getvalue())
            pathlib.Path(d, "test_b.trace").write_text(w(2, "/tmp/tmpb/x"))
            with mock.patch("sys.stdout", io.StringIO()), mock.patch.dict(unit_tests.SERIAL, clear=True):
                self.assertEqual(clash_audit.main(["clash_audit.py", d]), 0)
            # A module with no trace fails: an empty directory never passes.
            pathlib.Path(d, "test_c.trace").unlink()
            out = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch.dict(unit_tests.SERIAL, clear=True):
                self.assertEqual(clash_audit.main(["clash_audit.py", d]), 1)
            self.assertIn("::error::test_c has no trace", out.getvalue())

    def test_ci_runs_the_clash_check_on_the_unit_traces(self):
        ci = (unit_tests.ROOT / ".github/workflows/ci.yml").read_text()
        step = ci[ci.index("python tests/records_audit.py"):]
        step = step[step.index("\n      - "):][1:]
        step = step[:step.index("\n      - ")]
        self.assertEqual(step.splitlines()[1:], ["        if: steps.scope.outputs.records != 'true'",
                                                 '        run: python tests/clash_audit.py "$RUNNER_TEMP/reads"'])


if __name__ == "__main__":
    unittest.main()
