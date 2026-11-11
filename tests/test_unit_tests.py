"""tools/unit_tests.py: ci.yml's unit-test step runs modules in parallel, each traced alone (CI-par),
longest first, failing when one module sets the step's length, with no two modules sharing a
written path or a bound address (tests/clash_audit.py, CI-par-clash).

REQ: CI-PATHS
"""
import io
import os
import pathlib
import pwd
import re
import shutil
import stat
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


def boundary_unready():
    """Why the real uid boundary (#5413) cannot be run here, or None."""
    if os.geteuid() != 0:
        return "needs root, as tools/unit_tests.py does (ci.yml's own step for it runs as root)"
    missing = [t for t in ("strace", "setpriv", "setfacl", "useradd") if not shutil.which(t)]
    return f"missing {', '.join(missing)}" if missing else None


def stat_of(path):
    st = os.stat(path)
    return stat.S_IMODE(st.st_mode), st.st_uid


class CommandTest(unittest.TestCase):
    def test_each_module_runs_alone_under_strace_into_its_own_trace(self):
        cmd = unit_tests.command("test_x", "/r")
        self.assertEqual(cmd[:cmd.index("-o")], ["strace", "-f", "--kill-on-exit", "--seccomp-bpf", "-q", "-y", "-e",
                                                  "trace=open,openat,openat2,bind,symlink,symlinkat,chdir,fchdir,"
                                                  "unlink,unlinkat,rename,renameat,renameat2,truncate",
                                                  "-e", "signal=none"])
        self.assertEqual(cmd[cmd.index("-o") + 1], "/r/test_x.trace")
        # #5413: a root sh gives the module /dev/null for stdin and joins its stderr to its stdout,
        # then setpriv runs it as its own user, with no new privileges, before Python (and so any
        # site hook) starts.
        self.assertEqual(cmd[cmd.index("-o") + 2:],
                         ["/bin/sh", "-c", 'exec "$@" 0</dev/null 2>&1', "sh",
                          "setpriv", "--reuid=ut-x", "--regid=ut-x", "--init-groups", "--no-new-privs", "--",
                          sys.executable, "-c",
                          "import runpy, sys; runpy.run_module(sys.argv.pop(1), run_name='__main__', "
                          "alter_sys=True)", "unittest", "discover", "-s", "tests", "-p", "test_x.py", "-v"])

    def test_every_test_module_is_run(self):
        names = unit_tests.modules()
        files = sorted(p.stem for p in pathlib.Path(unit_tests.ROOT, "tests").glob("test*.py"))
        self.assertEqual(names, files)
        self.assertIn("test_unit_tests", names)

    def test_modules_run_without_gits_optional_index_lock(self):
        # git status/diff in the shared worktree would each write .git/index.lock (a clash).
        self.assertEqual(unit_tests.ENV["GIT_OPTIONAL_LOCKS"], "0")

    def test_each_module_runs_as_a_user_of_its_own_with_its_own_home(self):
        # #5413: one user per module, so no module's process can reach another's.
        names = unit_tests.modules()
        users = {unit_tests.user(m) for m in names}
        self.assertEqual(len(users), len(names))
        self.assertTrue(all(len(u) <= 32 and u.startswith("ut-") for u in users), users)
        self.assertEqual(unit_tests.user("test_" + "x" * 40), unit_tests.user("test_" + "x" * 40))
        self.assertNotEqual(unit_tests.user("test_" + "x" * 40), unit_tests.user("test_" + "x" * 41))
        e = unit_tests.env("test_x", "/r/reads")
        self.assertEqual((e["HOME"], e["USER"], e["LOGNAME"]), ("/r/reads.run/home/test_x", "ut-x", "ut-x"))
        self.assertEqual((e["GOCACHE"], e["GOMODCACHE"]), ("/r/reads.run/go/build", "/r/reads.run/go/mod"))
        self.assertEqual(e["GIT_OPTIONAL_LOCKS"], "0")
        n = int(unit_tests.ENV.get("GIT_CONFIG_COUNT", 0))  # git reads the worktree, another user's
        self.assertEqual((e["GIT_CONFIG_COUNT"], e[f"GIT_CONFIG_KEY_{n}"], e[f"GIT_CONFIG_VALUE_{n}"]),
                         (str(n + 1), "safe.directory", str(unit_tests.ROOT)))

    def test_the_runner_refuses_to_run_as_a_user(self):
        # #5413: only root can run strace over another user and make the modules' users.
        with mock.patch("os.geteuid", return_value=1000), self.assertRaisesRegex(OSError, "run as root"):
            unit_tests.prepare(["test_x"], "/nonexistent/reads")
        out = io.StringIO()
        with mock.patch("os.geteuid", return_value=1000), mock.patch("sys.stdout", out):
            self.assertEqual(unit_tests.main(["/nonexistent/reads"]), 1)
        self.assertIn("::error::run as root (sudo", out.getvalue())

    def test_the_trace_directory_must_be_new(self):
        # #5413 (Lens R1): nothing in it may predate the run, made by whoever.
        with tempfile.TemporaryDirectory() as d:
            me = (os.getuid(), os.getgid())
            reads = unit_tests.private(os.path.join(d, "reads"), owner=me)
            self.assertEqual(stat_of(reads), (0o700, os.getuid()))
            with self.assertRaisesRegex(OSError, "exists: the trace directory must be new"):
                unit_tests.private(os.path.join(d, "reads"), owner=me)
            os.mkdir(os.path.join(d, "made"), 0o700)  # empty, mode and owner right: still refused
            with self.assertRaisesRegex(OSError, "exists"):
                unit_tests.private(os.path.join(d, "made"), owner=me)

    def test_a_directory_above_the_traces_another_user_may_change_is_refused(self):
        # #5413 (Lens R1): a module may not move the trace directory or a directory above it. Each
        # case is a fresh trace directory, so only the check on the directories above it refuses.
        me = (os.getuid(), os.getgid())
        with tempfile.TemporaryDirectory() as d:
            up = os.path.join(d, "up")
            os.mkdir(up)
            for mode, others, refused in ((0o755, (), False), (0o777, (), True), (0o1777, (), False),
                                          (0o775, (), False), (0o775, (os.getgid(),), True),
                                          (0o1775, (os.getgid(),), False)):
                os.chmod(up, mode)
                reads = os.path.join(up, "reads")
                if refused:
                    with self.assertRaisesRegex(OSError, f"{up} is writable by other users", msg=oct(mode)):
                        unit_tests.private(reads, owner=me, others=others)
                else:
                    unit_tests.private(reads, owner=me, others=others)
                if os.path.exists(reads):
                    os.rmdir(reads)
            os.chmod(up, 0o755)
            os.symlink(up, os.path.join(d, "link"))
            with self.assertRaisesRegex(OSError, "link is not a directory"):
                unit_tests.private(os.path.join(d, "link", "reads"), owner=me)
            if os.geteuid() == 0:  # chown to another uid takes root
                os.chown(up, 4242, 4242)
                with self.assertRaisesRegex(OSError, "owned by uid 4242"):
                    unit_tests.private(os.path.join(up, "reads2"), owner=me)

    def test_a_module_reaches_no_trace_stream_and_no_other_module(self):
        # #5413: the real boundary, end to end, as root (ci.yml's own step for it). Two modules run
        # at once under real strace, each as its own user, and try every route to a trace stream
        # rounds 1-4 of #5426 found: strace's and the runner's /proc fds, a signal to strace, the
        # trace directory and a link into it, the other module's /proc fds, a privilege raise. Each
        # is refused; each module holds /dev/null and its own output only; a process of its user
        # left outside strace is killed by sweep().
        # ci.yml's root step sets AGENTOS_REQUIRE_UID_BOUNDARY, so there it fails rather than skips.
        if boundary_unready() and os.environ.get("AGENTOS_REQUIRE_UID_BOUNDARY") != "1":
            self.skipTest(boundary_unready())
        self.assertIsNone(boundary_unready())
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        os.chmod(root, 0o755)
        (root / "tests").mkdir()
        meet = root / "meet"
        meet.mkdir()
        os.chmod(meet, 0o1777)
        trace_dir = root / "reads"
        names = ["test_zz_boundary_a", "test_zz_boundary_b"]
        for name in names:
            (root / "tests" / f"{name}.py").write_text(textwrap.dedent(f"""\
                import os, pathlib, subprocess, sys, time, unittest
                MEET, TRACES = pathlib.Path({str(meet)!r}), {str(trace_dir)!r}
                def ancestors():
                    pid = os.getpid()
                    while True:
                        pid = int(pathlib.Path(f"/proc/{{pid}}/stat").read_text().rsplit(")", 1)[1].split()[1])
                        if pid <= 1:
                            return
                        yield pid
                class Boundary(unittest.TestCase):
                    def test_boundary(self):
                        self.assertNotEqual(os.getuid(), 0)
                        self.assertEqual(os.readlink("/proc/self/fd/0"), "/dev/null")
                        self.assertEqual(os.readlink("/proc/self/fd/1"), os.readlink("/proc/self/fd/2"))
                        self.assertEqual(sorted(os.listdir("/proc/self/fd")), ["0", "1", "2", "3"])  # 3: listdir's own
                        def meet(suffix):  # wait for the other module, so both run at once
                            (MEET / ("{name}" + suffix)).write_text(str(os.getpid()))
                            for _ in range(300):
                                if len([p for p in MEET.iterdir() if p.name.endswith(suffix)]) == 2:
                                    return
                                time.sleep(0.1)
                        meet(".up")
                        peers = [int(p.read_text()) for p in MEET.iterdir() if p.name.endswith(".up") and p.name != "{name}.up"]
                        self.assertEqual(len(peers), 1)
                        for pid in [*ancestors(), *peers]:  # strace, the runner and above; the other module
                            with self.subTest(pid=pid):
                                for reach in (lambda: os.listdir(f"/proc/{{pid}}/fd"),
                                              lambda: open(f"/proc/{{pid}}/fd/2", "a"),
                                              lambda: open(f"/proc/{{pid}}/fd/1", "a"),
                                              lambda: os.kill(pid, 0)):
                                    self.assertRaises(PermissionError, reach)
                        self.assertRaises(PermissionError, os.listdir, TRACES)
                        self.assertRaises(PermissionError, open, TRACES + "/{name}.trace", "a")
                        self.assertRaises(PermissionError, os.symlink, "/tmp/x", TRACES + "/test_q.trace")
                        self.assertRaises(PermissionError, os.rename, TRACES, {str(root / "moved")!r})
                        self.assertNotEqual(subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode, 0)
                        raised = subprocess.run([{str(root / "suid-id")!r}, "-u"], capture_output=True, text=True)
                        self.assertEqual(raised.stdout.strip(), str(os.getuid()))  # no new privileges: setuid root is ignored
                        print("BOUNDARY HELD", os.getuid(), flush=True)
                        meet(".done")  # the other module is still alive through all of the above
                """))
        shutil.copy("/usr/bin/id", root / "suid-id")
        os.chmod(root / "suid-id", 0o4755)
        unit_tests.prepare(names, trace_dir)
        self.addCleanup(shutil.rmtree, unit_tests.scratch(trace_dir), True)
        self.assertEqual(stat_of(trace_dir), (0o700, unit_tests._owner()[0]))
        results = unit_tests.run(names, str(trace_dir), 2, runner=lambda m, d: unit_tests.run_one(m, d, root=root))
        uids = set()
        for name in names:
            rc, _, out = results[name]
            self.assertEqual(rc, 0, out)
            held = re.findall(r"BOUNDARY HELD (\d+)", out)
            self.assertEqual(len(held), 1, out)
            uids.add(int(held[0]))
            trace = (trace_dir / f"{name}.trace").read_text()
            self.assertIn("EACCES", trace)  # strace saw the refused opens
            self.assertTrue(records_audit.finished(trace), trace[-500:])
        self.assertEqual(uids, {pwd.getpwnam(unit_tests.user(m)).pw_uid for m in names})
        # sweep(): a process of the module's user that strace does not trace is killed.
        stray = subprocess.Popen([*unit_tests.drop(names[0]), "sleep", "300"], start_new_session=True)
        self.addCleanup(stray.kill)
        time.sleep(0.2)
        unit_tests.sweep(names[0])
        self.assertEqual(stray.wait(timeout=10), -9)


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
        self.assertIn("class or module setup and teardown", err[0])
        self.assertNotIn("split it", err[0])
        # A split run that named no part (it died before its last line) counts its whole time.
        results["test_0"] = (1, 130.0, "test_0: 3 of 4 tests run across 2 workers, 1 not run\n")
        out = []
        self.assertEqual(unit_tests.report(names, results, out.append, jobs=4, split={"test_0": "x"}), 1)
        err = [o for o in out if "::error::test_0 is already split" in o]
        self.assertEqual(len(err), 1, out)
        self.assertIn("its run gave no slowest part", err[0])
        self.assertIn("its whole time counts: 130s", err[0])
        # It names no test, so it says nothing of shortening one or of a split limit.
        self.assertNotIn("shorten", err[0])
        self.assertNotIn("split limit", err[0])
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
        self.assertEqual(cmd, [*unit_tests.STRACE, "-o", "/r/test_image.trace", *unit_tests.JOIN,
                               *unit_tests.drop("test_image"), sys.executable, "-c",
                               "import runpy, sys; sys.argv.pop(0); runpy.run_path(sys.argv[0], run_name='__main__')",
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

    def test_a_workers_last_part_counts_its_final_class_teardown(self):
        # #4538: the last class's teardown runs after the worker's last test; it is that part's.
        body = textwrap.dedent("""\
            import time, unittest

            class A(unittest.TestCase):
                @classmethod
                def tearDownClass(cls):
                    time.sleep(1.5)

                def test_1(self): time.sleep(0.1)
                def test_2(self): time.sleep(0.1)
            """)
        p, _, _ = self.run_split(body)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        secs, _ = unit_tests.slowest_part("test_fake", p.stdout)
        self.assertGreaterEqual(secs, 1.5)
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



class StraceFaultTest(unittest.TestCase):
    """#5358: strace failing itself (PTRACE_LISTEN EIO on the runner) cuts the run and its trace, so
    the module reruns whole into a fresh trace; it never reruns past a failed test, and a module
    strace cuts every time fails."""
    # REQ: CI-PATHS
    CUT = "strace: ptrace(PTRACE_LISTEN,pid:24103,sig:0): Input/output error"
    # step: (the module's output, strace's own stderr, strace's exit status)
    SAY = {"ok": ("test_a ... ok\n\nOK\n", "", 0),
           "cut": ("test_a ... ok\ncoverage: 100.0% of statements\n", f"{CUT}\n", 1),
           "cut-exit-0": ("test_a ... ok\ntest_b ... ", f"{CUT}\n", 0),
           "fail-then-cut": ("test_a ... FAIL\ntest_b ... ", f"{CUT}\n", 1),
           "fail": ("test_a ... FAIL\n\nFAILED (failures=1)\n", "", 1),
           # #5355's shape: a child's PASS and coverage lines, then unittest's verdict on a bare line.
           "bare-fail-then-cut": ("test_a ... PASS\ncoverage: 100.0% of statements\nFAIL\ntest_b ... ", f"{CUT}\n", 1),
           # #5407: a test printing strace's text is the module's output, not strace's.
           "says-cut": (f"test_a ... {CUT}\n{CUT}\nok\n\nOK\n", "", 0)}

    def setUp(self):
        # These fake strace and run as whoever runs the tests: no module user to drop to or sweep
        # (the real boundary: test_a_module_reaches_no_trace_stream_and_no_other_module).
        for name, fake in (("drop", lambda module: []), ("sweep", lambda module: None)):
            patcher = mock.patch.object(unit_tests, name, fake)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_plan(self, *plan):
        """run_one under a fake strace that plays plan's steps in order, one per call, writing
        each step's name as its trace. (rc, output, the trace kept, calls made)."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "plan").write_text("\n".join(plan))
        fake = d / "strace"
        fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""\
            import pathlib, sys, time
            say = {self.SAY!r}
            plan = pathlib.Path({str(d / "plan")!r})
            steps = plan.read_text().split("\\n")
            plan.write_text("\\n".join(steps[1:]))
            pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text(steps[0])
            time.sleep(0.2)
            sys.stdout.write(say[steps[0]][0])
            sys.stderr.write(say[steps[0]][1])
            sys.exit(say[steps[0]][2])
            """))
        fake.chmod(0o755)
        with mock.patch.dict(unit_tests.ENV, {"PATH": f"{d}{os.pathsep}{os.environ.get('PATH', '')}"}):
            module, rc, secs, out = unit_tests.run_one("test_x", str(d))
        self.assertEqual(module, "test_x")
        left = [s for s in (d / "plan").read_text().split("\n") if s]
        calls = len(plan) - len(left)
        self.assertGreaterEqual(secs, 0.2 * calls)  # every attempt's time counts
        self.cut = (d / "test_x.trace.cut").read_text() if (d / "test_x.trace.cut").exists() else None
        return rc, out, (d / "test_x.trace").read_text(), calls

    def test_a_cut_run_reruns_whole_and_keeps_the_passing_runs_trace(self):
        rc, out, trace, calls = self.run_plan("cut", "ok")
        self.assertEqual((rc, trace, calls), (0, "ok", 2))
        self.assertEqual(self.cut, "cut")  # #5364: the cut attempt's trace stays, for records_audit
        self.assertIn("strace failed itself on attempt 1 of 2", out)
        self.assertIn("the module reruns whole into a fresh trace", out)
        self.assertTrue(out.startswith(self.SAY["cut"][0] + self.CUT), out)  # the cut attempt's own log stays
        self.assertTrue(out.endswith(self.SAY["ok"][0]), out)

    def test_a_cut_run_is_no_pass_even_when_strace_exits_zero(self):
        rc, out, _, calls = self.run_plan("cut-exit-0", "cut-exit-0")
        self.assertEqual((rc, calls), (1, 2))
        self.assertIn("strace failed itself on attempt 2 of 2", out)
        self.assertIn("the module fails\n", out)
        self.assertEqual(self.cut, "cut-exit-0")  # attempt 1's; attempt 2's is the module's trace
        rc, _, _, _ = self.run_plan("ok")
        self.assertEqual((rc, self.cut), (0, None))

    def test_a_stale_cut_trace_is_not_this_runs(self):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "test_x.trace.cut").write_text("an earlier run's")
        with mock.patch.object(unit_tests, "attempt", return_value=(0, "OK\n", "")):
            self.assertEqual(unit_tests.run_one("test_x", str(d))[1], 0)
        self.assertFalse((d / "test_x.trace.cut").exists())

    def test_nothing_of_a_cut_attempt_runs_on_into_the_rerun(self):
        # #5364: a fake strace that, cut, exits and leaves two children of the run behind, one that
        # keeps the run's output open and one that does not, both ignoring SIGTERM. The rerun
        # finds both gone, and the first does not hold the run open until it ends.
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        left = d / "left"
        fake = d / "strace"
        fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""\
            import os, pathlib, signal, subprocess, sys, time
            left = pathlib.Path({str(left)!r})
            pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text("x")
            def alive(pid):
                try:
                    return pathlib.Path(f"/proc/{{pid}}/stat").read_text().split(") ")[1][0] != "Z"
                except OSError:
                    return False
            if left.exists():
                print("left alive:", [alive(int(p)) for p in left.read_text().split()])
                sys.exit(0)
            stay = [sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"]
            ps = [subprocess.Popen(stay), subprocess.Popen(stay, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
            left.write_text(" ".join(str(p.pid) for p in ps))
            print("{self.CUT}", file=sys.stderr)
            sys.exit(1)
            """))
        fake.chmod(0o755)
        with mock.patch.dict(unit_tests.ENV, {"PATH": f"{d}{os.pathsep}{os.environ.get('PATH', '')}"}):
            _, rc, secs, out = unit_tests.run_one("test_x", str(d))
        self.assertIn("left alive: [False, False]\n", out)
        self.assertEqual(rc, 0, out)
        self.assertLess(secs, 30)

    def test_a_module_strace_cuts_every_time_fails(self):
        rc, out, _, calls = self.run_plan("cut", "cut", "ok")
        self.assertEqual((rc, calls), (1, unit_tests.STRACE_ATTEMPTS))
        # #5407: pinned, so at most one attempt is cut and kept, whole (a cut trace ends mid-line).
        self.assertEqual(unit_tests.STRACE_ATTEMPTS, 2)
        self.assertEqual(self.cut, "cut")

    def test_a_test_printing_straces_fault_text_is_not_rerun(self):
        # #5407: the module's output never counts as strace's, however it is printed.
        rc, out, trace, calls = self.run_plan("says-cut", "ok")
        self.assertEqual((rc, trace, calls, self.cut), (0, "says-cut", 1, None))
        self.assertNotIn("strace failed itself", out)

    def test_a_tests_stdout_and_stderr_never_reach_straces_stderr(self):
        # #5407: a fake strace with strace's file descriptors (the command inherits its stdout and
        # stderr) runs the real command; a test prints the fault text every way it can. JOIN gives
        # the test the module's stream, so strace's own stays clean: one attempt, the verdict kept.
        # #5413: so does a sitecustomize, which Python runs before any of the module's own code,
        # and a child it starts that writes after the test has run.
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "tests").mkdir()
        (root / "tests" / "test_fake.py").write_text(textwrap.dedent(f"""\
            import os, subprocess, sys, unittest
            class A(unittest.TestCase):
                def test_a(self):
                    print("{self.CUT}", flush=True)
                    print("{self.CUT}", file=sys.stderr, flush=True)
                    os.write(2, b"{self.CUT}\\n")
                    subprocess.run([sys.executable, "-c", "import sys; sys.stderr.write('{self.CUT}\\\\n')"])
            """))
        site = root / "site"
        site.mkdir()
        (site / "sitecustomize.py").write_text(textwrap.dedent(f"""\
            import os, subprocess, sys
            os.write(2, b"{self.CUT}\\n")
            subprocess.Popen([sys.executable, "-I", "-c", "import os, time; time.sleep(1); os.write(2, b'{self.CUT}\\\\n')"])
            """))
        fake = root / "strace"
        # -I: the fake strace runs no sitecustomize of its own.
        fake.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent(f"""\
            import pathlib, subprocess, sys, time
            calls = pathlib.Path({str(root / "calls")!r})
            calls.write_text(calls.read_text() + "x" if calls.exists() else "x")
            pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text("t")
            rc = subprocess.run(sys.argv[sys.argv.index("-o") + 2:]).returncode
            time.sleep(2)  # the hook's child writes meanwhile
            sys.exit(rc)
            """))
        fake.chmod(0o755)
        with mock.patch.dict(unit_tests.ENV, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                                              "PYTHONPATH": str(site)}):
            _, rc, _, out = unit_tests.run_one("test_fake", str(root), root=root)
        self.assertEqual((rc, (root / "calls").read_text()), (0, "x"), out)
        self.assertEqual(out.count(self.CUT), 4 + 2 * 2, out)  # the test's 4, and the hook's 2 in each of 2 Pythons
        self.assertIn("\nok\n", out)
        self.assertNotIn("strace failed itself", out)

    def test_a_cut_faked_through_straces_proc_fd_hides_no_write(self):
        # #5413: were a cut faked on attempt 1 only (here through a fake strace's /proc entry, which
        # the module's own user cannot open under the real one), its write sits in the cut trace
        # alone; clash_audit reads that as the module's, so the clash with another module still
        # fails the step.
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "tests").mkdir()
        (root / "tests" / "test_fake.py").write_text(textwrap.dedent(f"""\
            import os, pathlib, unittest
            class A(unittest.TestCase):
                def test_a(self):
                    first = pathlib.Path({str(root / "first")!r})
                    if not first.exists():
                        first.write_text("")
                        with open(f"/proc/{{os.getppid()}}/fd/2", "a") as f:  # the fake strace's
                            f.write("{self.CUT}\\n")
            """))
        fake = root / "strace"
        # Each call's trace: the first run's shows the shared write, the rerun's does not.
        fake.write_text(f"#!{sys.executable} -I\n" + textwrap.dedent(f"""\
            import pathlib, subprocess, sys
            first = not pathlib.Path({str(root / "first")!r}).exists()
            pathlib.Path(sys.argv[sys.argv.index("-o") + 1]).write_text({w(5, "/tmp/agentos-x")!r} if first else "")
            sys.exit(subprocess.run(sys.argv[sys.argv.index("-o") + 2:]).returncode)
            """))
        fake.chmod(0o755)
        with mock.patch.dict(unit_tests.ENV, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
            _, rc, _, out = unit_tests.run_one("test_fake", str(root), root=root)
        self.assertEqual(rc, 0, out)
        self.assertIn("strace failed itself on attempt 1 of 2", out)
        self.assertEqual((root / "test_fake.trace").read_text(), "")
        (root / "test_other.trace").write_text(w(6, "/tmp/agentos-x"))
        stdout = io.StringIO()
        with mock.patch.object(unit_tests, "modules", lambda root=None: ["test_fake", "test_other"]), \
             mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", io.StringIO()), \
             mock.patch.dict(unit_tests.SERIAL, clear=True):
            self.assertEqual(clash_audit.main(["clash_audit.py", str(root)]), 1)
        self.assertEqual(stdout.getvalue(), "::error::test_fake and test_other both write /tmp/agentos-x\n")

    def test_a_failed_test_is_never_rerun(self):
        rc, out, trace, calls = self.run_plan("fail-then-cut", "ok")
        self.assertEqual((rc, trace, calls), (1, "fail-then-cut", 1))
        self.assertIn("a test had already failed, so the module fails without a rerun", out)
        rc, out, _, calls = self.run_plan("fail", "ok")
        self.assertEqual((rc, out, calls), (1, self.SAY["fail"][0], 1))
        rc, out, _, calls = self.run_plan("bare-fail-then-cut", "ok")
        self.assertEqual((rc, calls), (1, 1))
        self.assertIn("a test had already failed", out)

    def test_a_split_module_cut_after_a_failed_test_is_not_rerun(self):
        # A SPLIT module's workers buffer their reports until they end; a failed test's verdict
        # still reaches the shared stdout as the test ends, so a cut after it stops the rerun.
        root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root)
        (root / "tests").mkdir()
        (root / "tests" / "test_fake.py").write_text(textwrap.dedent("""\
            import os, time, unittest
            class A(unittest.TestCase):
                def test_a(self): self.fail("x")
                def test_z_slow(self):  # last, so one worker reaches the others first
                    for _ in range(100):
                        time.sleep(0.1)
                def test_c(self):
                    with self.subTest(i=1): raise OSError("y")
                @unittest.expectedFailure
                def test_d(self): pass
            """))
        fake = root / "strace"
        # Runs the command in its own group, then fails as strace does once the verdicts are out:
        # its fault line, then the group killed (strace's cleanup), exit 1. Later calls pass.
        fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""\
            import os, pathlib, signal, subprocess, sys, time
            calls = pathlib.Path({str(root / "calls")!r})
            calls.write_text(calls.read_text() + "x" if calls.exists() else "x")
            if len(calls.read_text()) > 1:
                print("OK"); sys.exit(0)
            p = subprocess.Popen(sys.argv[sys.argv.index("-o") + 2:], start_new_session=True)
            time.sleep(3)
            sys.stderr.write("{self.CUT}\\n"); sys.stderr.flush()
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            sys.exit(1)
            """))
        fake.chmod(0o755)
        with mock.patch.dict(unit_tests.SPLIT, {"test_fake": "#5358"}), \
             mock.patch.dict(unit_tests.ENV, {"PATH": f"{root}{os.pathsep}{os.environ.get('PATH', '')}"}):
            _, rc, _, out = unit_tests.run_one("test_fake", str(root), root=root)
        self.assertEqual((rc, (root / "calls").read_text()), (1, "x"), out)
        self.assertIn("test_fake.A.test_a ... FAIL\n", out)
        self.assertIn("test_fake.A.test_c (i=1) ... ERROR\n", out)
        self.assertIn("test_fake.A.test_d ... unexpected success\n", out)
        self.assertNotIn("test_z_slow ... ok", out)  # the cut came first
        self.assertIn("a test had already failed, so the module fails without a rerun", out)

    def test_a_long_pole_after_a_rerun_says_so_instead_of_split_it(self):
        out = []
        cut = f"x\n{self.CUT}\nunit_tests: ...; {unit_tests.RERAN}\nOK\n"
        results = {"test_a": (0, 300.0, cut), "test_b": (0, 10.0, ""), "test_c": (0, 10.0, "")}
        self.assertEqual(unit_tests.report(list(results), results, out.append, jobs=3), 1)
        text = "".join(out)
        self.assertIn("counting the run strace cut short and its rerun", text)
        self.assertNotIn("split it", text)

    def test_strace_faults_are_its_own_ptrace_failures(self):
        # Read on strace's own stderr (#5258, #5355), where each of its lines starts `strace: `.
        for err in (self.CUT, f"strace: other\n{self.CUT}\n", "strace: ptrace(PTRACE_CONT,pid:1,sig:0): x"):
            self.assertTrue(unit_tests.STRACE_FAULT.search(err), err)
        for err in ("", "strace: exec: No such file or directory\n", "x " + self.CUT):
            self.assertFalse(unit_tests.STRACE_FAULT.search(err), err)
        for line in ("t (m.T.t) ... FAIL", "t (m.T.t) ... ERROR", "ERROR: setUpClass (m.T)", "FAILED (errors=1)",
                     "FAIL", "t (m.T.t) ... partialFAIL", "t (m.T.t) ... unexpected success",
                     "  t (m.T.t) (i=1) ... ERROR"):
            self.assertTrue(unit_tests.TEST_FAILED.search(line), line)
        for line in ("t (m.T.t) ... ok", "t (m.T.t) ... expected failure", "OK (skipped=2)"):
            self.assertFalse(unit_tests.TEST_FAILED.search(line), line)


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

    def test_a_record_only_a_cut_attempt_opened_counts(self):
        # #5364: tools/unit_tests.py keeps a cut attempt's trace as <module>.trace.cut. Its opens
        # count for the record check; partial, it needs neither the module's file nor an exit.
        own = f'1 openat(AT_FDCWD<{R}>, "tests/test_m.py", O_RDONLY|O_CLOEXEC) = 3<{R}/tests/test_m.py>\n'
        rerun = own + "1 +++ exited with 0 +++\n"
        cut = f'7 openat(AT_FDCWD<{R}>, "LEDGER.md", O_RDONLY) = 3<{R}/LEDGER.md>\n'
        self.assertEqual(records_audit.problems({"test_m": rerun}, [], cut={"test_m": cut}),
                         ["tests.test_m\tLEDGER.md"])
        self.assertEqual(records_audit.problems({"test_m": rerun}, ["tests.test_m"], cut={"test_m": cut}), [])
        self.assertEqual(records_audit.problems({"test_m": rerun}, [], cut={"test_m": "7 openat(AT_FDCWD</tmp>, \"y\", O_RDONLY) = 3</tmp/y>\n"}), [])
        # main reads it from the trace directory, under unit_tests' name for it.
        self.assertEqual(unit_tests.CUT, ".trace.cut")
        with tempfile.TemporaryDirectory() as d:
            for stem in unit_tests.modules():
                pathlib.Path(d, f"{stem}.trace").write_text(rerun.replace("test_m", stem))
            pathlib.Path(d, "test_unit_tests.trace.cut").write_text(cut)
            out = []
            with mock.patch("builtins.print", lambda *a, **k: out.append(" ".join(map(str, a)))), \
                 mock.patch.object(records_audit, "records_run_tests", return_value=[]):
                self.assertEqual(records_audit.main(["records_audit.py", d]), 1)
            self.assertIn("tests.test_unit_tests\tLEDGER.md", out)

    def test_a_write_in_the_trace_directory_fails_the_module(self):
        # #5407: the traces are the audit's evidence. A write open there, in any attempt, by the
        # path it reached or asked for, fails the module whether or not it is listed; a read does not.
        own = f'1 openat(AT_FDCWD<{R}>, "tests/test_m.py", O_RDONLY|O_CLOEXEC) = 3<{R}/tests/test_m.py>\n'
        end = "1 +++ exited with 0 +++\n"
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            tamper = f"tests.test_m\twrote {d}/test_b.trace: {records_audit.TAMPER}"
            for listed in ([], ["tests.test_m"]):
                for line in (w(2, f"{d}/test_b.trace"), w(2, f"{d}/test_b.trace", "O_RDWR"),
                             f'2 openat(AT_FDCWD<{d}>, "test_b.trace", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)\n'):
                    self.assertEqual(records_audit.problems({"test_m": own + line + end}, listed, trace_dir=d),
                                     [tamper], line)
                    self.assertEqual(records_audit.problems({"test_m": own + end}, listed, cut={"test_m": line},
                                                            trace_dir=d), [tamper], line)
                read = f'2 openat(AT_FDCWD<{d}>, "test_b.trace", O_RDONLY) = 3<{d}/test_b.trace>\n'
                self.assertEqual(records_audit.problems({"test_m": own + read + w(3, f"{d}x/y") + end}, listed,
                                                        trace_dir=d), [])
            # main reads the directory it is given, and asks for no records-step change for it.
            for stem in unit_tests.modules():
                pathlib.Path(d, f"{stem}.trace").write_text(
                    (own + end).replace("test_m", stem) + (w(2, f"{d}/x") if stem == "test_unit_tests" else ""))
            out, err = io.StringIO(), io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), \
                 mock.patch.object(records_audit, "records_run_tests", return_value=[]):
                self.assertEqual(records_audit.main(["records_audit.py", d]), 1)
            self.assertEqual(out.getvalue(), f"tests.test_unit_tests\twrote {d}/x: {records_audit.TAMPER}\n")
            self.assertEqual(err.getvalue(), "")

    def test_an_escaped_resumed_path_and_an_escaped_directory_fd_decode(self):
        # Each _decode call keeps one escaped name from reading as another (#4538): the file a
        # resumed line reached, and the directory fd a failed relative open is joined to.
        resumed = ('2 openat(AT_FDCWD</tmp>, "l", O_RDONLY <unfinished ...>\n'
                   f'2 <... openat resumed>)            = 5<{R}/LEDGER\\056md>\n')
        self.assertIn(("LEDGER.md", True), records_audit.opened(resumed))
        base = R[:-1] + "\\%03o" % ord(R[-1])
        failed = f'3 openat(AT_FDCWD<{base}>, "LEDGER.md", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
        self.assertIn(("LEDGER.md", False), records_audit.opened(failed))
        failed = f'3 openat(AT_FDCWD<{R}/x\\057..>, "LEDGER.md", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
        self.assertIn(("LEDGER.md", False), records_audit.opened(failed))


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

    def test_a_failed_create_through_a_symlinked_directory_clashes_with_the_real_path(self):
        # #4424: the asked path is walked as the kernel walked it, through the links the tree made
        # before the call (strace 6.8's lines for os.symlink and ln -s) or that are on disk.
        excl = "O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0777) = -1 EEXIST (File exists)"
        real = w(9, "/w/real/x")
        cases = {
            "symlinkat": f'1 symlinkat("real", AT_FDCWD</w>, "link") = 0\n1 openat(AT_FDCWD</w>, "link/x", {excl}\n',
            # symlink() names no directory: a relative name is the cwd the pid last showed.
            "symlink, relative": ('1 openat(AT_FDCWD</w>, "a", O_RDONLY) = 3</w/a>\n'
                                  f'1 symlink("/w/real", "link") = 0\n1 openat(AT_FDCWD</w>, "link/x", {excl}\n'),
            # `..` after a link leaves the link's target, not the link's own directory.
            "dotdot": ('1 symlink("/w/real/sub", "/w/up") = 0\n'
                       f'1 openat(AT_FDCWD</>, "w/up/../x", {excl}\n'),
            "a link to a link": ('1 symlink("real", "/w/l1") = 0\n1 symlink("l1", "/w/l2") = 0\n'
                                 f'1 openat(AT_FDCWD</w>, "l2/x", {excl}\n'),
            "split symlink": ('1 symlink("/w/real", "/w/link" <unfinished ...>\n'
                              '1 <... symlink resumed>)            = 0\n'
                              f'1 openat(AT_FDCWD</w>, "link/x", {excl}\n'),
            "chdir through a link": ('1 symlink("/w/real", "/w/link") = 0\n1 chdir("/w/link") = 0\n'
                                     f'1 open("x", {excl}\n'),
            "chdir, then ..": ('1 symlink("/w/real/sub", "/w/up") = 0\n1 chdir("/w/up") = 0\n'
                               f'1 open("../x", {excl}\n'),
            # The cwd is the directory chdir reached, whatever later becomes of the link.
            "chdir, then the link changes": ('1 symlink("/w/real", "/w/up2") = 0\n1 chdir("/w/up2") = 0\n'
                                             f'1 symlink("/w/other", "/w/up2") = 0\n1 open("x", {excl}\n'),
            "fchdir": f'1 fchdir(4</w/real>) = 0\n1 open("x", {excl}\n',
            "cut off": ('1 symlink("/w/real", "/w/link") = 0\n'
                        '1 openat(AT_FDCWD</w>, "link/x", O_WRONLY|O_CREAT|O_EXCL <unfinished ...>\n'
                        '1 +++ killed by SIGKILL +++\n'),
            "socket": ('1 symlink("/w/real", "/w/link") = 0\n'
                       '1 bind(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="/w/link/x"}, 110) = -1 EADDRINUSE\n'),
        }
        for name, a in cases.items():
            self.assertIn(("path", "/w/real/x"), clash_audit.writes(a, ondisk=lambda p: None), name)
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": real}, serial={}),
                             [("path", "/w/real/x", "test_a", "test_b")], name)
        # The link's own name is walked when it is made, and symlinkat's directory fd is decoded.
        made_through = ('1 symlink("/w/r0", "/w/link") = 0\n1 symlink("/w/real", "/w/link/l2") = 0\n'
                        f'1 openat(AT_FDCWD</>, "/w/r0/l2/x", {excl}\n')
        escaped_dirfd = ('1 symlinkat("/w/real", 3</w/d\\151r>, "link") = 0\n'
                         f'1 openat(AT_FDCWD</>, "/w/dir/link/x", {excl}\n')
        # An open without O_EXCL follows a final link too: a failed plain create of the link.
        final = '1 symlink("/w/real/x", "/w/x") = 0\n1 openat(AT_FDCWD</w>, "x", O_WRONLY|O_CREAT, 0666) = -1 EACCES\n'
        for name, a in (("made through a link", made_through), ("escaped dirfd", escaped_dirfd), ("final", final)):
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": real}, serial={}),
                             [("path", "/w/real/x", "test_a", "test_b")], name)
        # A link on disk that the trace did not make (made before the run, or by another tree).
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.mkdir(os.path.join(d, "real"))
            os.symlink("real", os.path.join(d, "link"))
            a = f'1 openat(AT_FDCWD<{d}>, "link/x", {excl}\n'
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, f"{d}/real/x")}, serial={}),
                             [("path", f"{d}/real/x", "test_a", "test_b")])

    def test_a_link_the_tree_made_after_the_open_is_not_read_from_disk(self):
        # The directory dd is replaced by a link after the failed create in it, and the link is
        # still on disk at the audit: the create walked the directory, not the link.
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.mkdir(os.path.join(d, "other"))
            os.symlink("other", os.path.join(d, "dd"))
            a = (f'1 openat(AT_FDCWD<{d}>, "dd/y", O_WRONLY|O_CREAT|O_EXCL, 0666) = -1 EEXIST (File exists)\n'
                 f'1 symlink("other", "{d}/dd") = 0\n')
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, f"{d}/dd/y")}, serial={}),
                             [("path", f"{d}/dd/y", "test_a", "test_b")])
            self.assertEqual(clash_audit.writes(a), {("path", f"{d}/dd/y")})
            # A link on disk the tree never made is still followed.
            self.assertIn(("path", f"{d}/other/y"), clash_audit.writes(a.splitlines()[0]))

    def test_a_link_elsewhere_later_or_failed_does_not_join_two_names(self):
        excl = "O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0777) = -1 EEXIST (File exists)"
        open_x = f'1 openat(AT_FDCWD</w>, "link/x", {excl}\n'
        controls = {
            "a link to another directory": '1 symlink("/w/other", "/w/link") = 0\n' + open_x,
            "a link made after the open": open_x + '1 symlink("/w/real", "/w/link") = 0\n',
            "a failed symlink": '1 symlink("/w/real", "/w/link") = -1 EEXIST (File exists)\n' + open_x,
            "a split symlink that failed": ('1 symlink("/w/real", "/w/link" <unfinished ...>\n'
                                            '1 <... symlink resumed>) = -1 EEXIST (File exists)\n' + open_x),
            # The final component is the name made, never followed: a link named x is not real/x.
            "the final component": '1 symlink("/w/real/x", "/w/x") = 0\n' + open_x.replace("link/x", "x"),
        }
        for name, a in controls.items():
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(9, "/w/real/x")}, serial={}), [], name)
        # A link made by one module's tree is that tree's: another pid's walk in it still follows it.
        b = '2 openat(AT_FDCWD</w>, "q", O_RDONLY) = 3</w/q>\n' + open_x.replace("1 ", "2 ", 1)
        self.assertEqual(clash_audit.writes('1 symlink("/w/real", "/w/link") = 0\n' + b, ondisk=lambda p: None),
                         {("path", "/w/real/x"), ("path", "/w/link/x")})
        # A link name reused as a directory (renamed away, untraced) still counts the name asked.
        reused = '1 symlink("/w/real", "/w/link") = 0\n' + open_x
        self.assertEqual(clash_audit.clashes({"test_a": reused, "test_b": w(9, "/w/link/x")}, serial={}),
                         [("path", "/w/link/x", "test_a", "test_b")])
        # One pid's cwd is known and the other's is not (a forked child): the relative name main
        # read still clashes, as a socket and as a file.
        known = '1 openat(AT_FDCWD</w>, "q", O_RDONLY) = 3</w/q>\n'
        for call in ('{pid} bind(3<socket:[9]>, {{sa_family=AF_UNIX, sun_path="sock"}}, 110) = -1 EADDRINUSE\n',
                     f'{{pid}} open("sock", {excl}\n'):
            a, b = known + call.format(pid=1), call.format(pid=2)
            self.assertIn(("path", "sock", "test_a", "test_b"), clash_audit.clashes({"test_a": a, "test_b": b}, serial={}), call)
        # Main's own name, exactly: a relative open with no dirfd as asked (`./x` stays `./x`), and
        # a socket path normpath'd (`./sock` is `sock`), whether or not the pid's cwd is known.
        for a, b, name in ((known + f'1 open("./x", {excl}\n', f'2 open("./x", {excl}\n', "./x"),
                           ('1 bind(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="./sock"}, 110) = 0\n',
                            '2 bind(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="sock"}, 110) = -1 EADDRINUSE\n', "sock")):
            self.assertIn(("path", name, "test_a", "test_b"), clash_audit.clashes({"test_a": a, "test_b": b}, serial={}), name)
        self.assertEqual(clash_audit.writes(f'2 open("./x", {excl}\n'), {("path", "./x")})
        # O_NOFOLLOW and a bind make the final name; symlinkat's AT_FDCWD is the pid's cwd.
        final = '1 symlink("/w/real/x", "/w/s") = 0\n'
        self.assertEqual(clash_audit.writes(final + '1 openat(AT_FDCWD</w>, "s", O_WRONLY|O_NOFOLLOW) = -1 ELOOP\n',
                                            ondisk=lambda p: None), {("path", "/w/s")})
        self.assertEqual(clash_audit.writes(final + '1 bind(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="/w/s"}, 110) = -1 EADDRINUSE\n',
                                            ondisk=lambda p: None), {("path", "/w/s")})
        self.assertIn(("path", "/w/real/x"), clash_audit.writes(
            f'1 symlinkat("/w/real", AT_FDCWD</w>, "link") = 0\n1 open("link/x", {excl}\n', ondisk=lambda p: None))
        # A relative chdir from an unknown cwd leaves later relative names as asked.
        self.assertEqual(clash_audit.writes(f'1 chdir("rel") = 0\n1 open("x", {excl}\n'), {("path", "x")})
        # Links past the kernel's 40 fail with ELOOP: the name stays as asked, and the walk ends.
        loop = '1 symlink("l", "/w/l") = 0\n1 openat(AT_FDCWD</w>, "l/x", ' + excl + "\n"
        self.assertEqual(clash_audit.writes(loop, ondisk=lambda p: None), {("path", "/w/l/x")})
        for n, reached in ((40, "/w/real/x"), (41, "/w/l0/x")):
            chain = "".join(f'1 symlink("l{i + 1}", "/w/l{i}") = 0\n' for i in range(n - 1))
            chain += f'1 symlink("real", "/w/l{n - 1}") = 0\n1 openat(AT_FDCWD</w>, "l0/x", {excl}\n'
            self.assertEqual(clash_audit.writes(chain, ondisk=lambda p: None), {("path", reached), ("path", "/w/l0/x")}, n)
        # /proc's links on disk are the auditor's own (self, its fds), never followed.
        proc = f'1 openat(AT_FDCWD</w>, "/proc/self/fd/0/x", {excl}\n'
        self.assertEqual(clash_audit.writes(proc), {("path", "/proc/self/fd/0/x")})

    def test_a_write_cut_off_mid_call_counts_its_asked_path(self):
        a = '1 openat(AT_FDCWD</r>, "build/out", O_WRONLY|O_CREAT <unfinished ...>\n1 +++ killed by SIGKILL +++\n'
        self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, "/r/build/out")}, serial={}),
                         [("path", "/r/build/out", "test_a", "test_b")])

    def test_main_s_name_folds_dotdot_in_an_absolute_path(self):
        # CI-par-7b: the walk reaches /o/x through the link, and main read /w/a/../x as /w/x.
        a = ('1 symlink("/o/p", "/w/a") = 0\n'
             '1 openat(AT_FDCWD</>, "/w/a/../x", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0777) = -1 EEXIST (File exists)\n')
        self.assertEqual(clash_audit.writes(a, ondisk=lambda p: None), {("path", "/o/x"), ("path", "/w/x")})
        self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, "/w/x")}, serial={}),
                         [("path", "/w/x", "test_a", "test_b")])

    def test_an_openat2_write_counts(self):
        # strace 6.8's openat2 line: the flags sit in its open_how struct.
        how = "{flags=O_WRONLY|O_CREAT|O_CLOEXEC, mode=0644, resolve=0}, 24)"
        for a in (f'1 openat2(AT_FDCWD</w>, "x", {how} = 3</w/x>\n',
                  f'1 openat2(AT_FDCWD</w>, "x", {how} = -1 EACCES (Permission denied)\n'):
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, "/w/x")}, serial={}),
                             [("path", "/w/x", "test_a", "test_b")], a)
        read = '1 openat2(AT_FDCWD</w>, "x", {flags=O_RDONLY|O_CLOEXEC, resolve=0}, 24) = 3</w/x>\n'
        self.assertEqual(clash_audit.writes(read), set())

    def test_a_result_inside_the_quoted_path_is_not_the_reached_file(self):
        # Security on #4598: strace prints `)` and `<` in a quoted name as is, so `) = 3<` there
        # is no result. A split create that failed counts its asked name; a completed one its file.
        split = ('1 openat(AT_FDCWD</w>, "a) = 3<b", O_WRONLY|O_CREAT|O_EXCL, 0666 <unfinished ...>\n'
                 '1 <... openat resumed>) = -1 EEXIST (File exists)\n')
        done = '1 openat(AT_FDCWD</w>, "a) = 3<b", O_WRONLY|O_CREAT, 0666) = 3</w/a) = 3\\74b>\n'
        for a in (split, done):
            self.assertEqual(clash_audit.writes(a, ondisk=lambda p: None), {("path", "/w/a) = 3<b")}, a)
            self.assertEqual(clash_audit.clashes({"test_a": a, "test_b": w(2, "/w/a) = 3<b")}, serial={}),
                             [("path", "/w/a) = 3<b", "test_a", "test_b")], a)

    def test_only_an_unresolved_write_open_is_walked(self):
        # CI-par-7b: a read, and a write open the kernel gave a file for, read nothing from disk;
        # a write open it gave none walks its path (a split one, before its result is known).
        def ondisk(name):
            raise AssertionError(f"walked {name}")
        trace = ('1 openat(AT_FDCWD</w>, "l/r", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)\n'
                 '1 openat(AT_FDCWD</w>, "l/x", O_WRONLY|O_CREAT, 0666) = 3</w/real/x>\n'
                 '1 openat(AT_FDCWD</w>, "l/y", O_RDONLY <unfinished ...>\n'
                 '2 openat(AT_FDCWD</w>, "q", O_RDONLY) = 3</w/q>\n'
                 '1 <... openat resumed>) = -1 ENOENT (No such file or directory)\n')
        self.assertEqual(clash_audit.writes(trace, ondisk=ondisk), {("path", "/w/real/x")})
        seen = []
        failed = '1 openat(AT_FDCWD</w>, "l/z", O_WRONLY|O_CREAT|O_EXCL, 0666) = -1 EEXIST (File exists)\n'
        clash_audit.writes(failed, ondisk=lambda name: seen.append(name))
        self.assertEqual(seen, ["/w", "/w/l"])

    def test_unlink_rename_and_truncate_change_a_name_as_a_write_does(self):
        # #5413: strace 6.8's lines for each, whatever the result. Each name counts, resolved from
        # its directory fd or the process's cwd; truncate follows a link the tree made, unlink does not.
        cwd = '1 openat(AT_FDCWD</d>, "x", O_RDONLY) = 3</d/x>\n'
        for line, names in (('1 unlink("c")                       = 0\n', ["/d/c"]),
                            ('1 unlink("/d/c")                     = -1 ENOENT (No such file or directory)\n', ["/d/c"]),
                            ('1 unlinkat(3</e>, "f", 0)      = 0\n', ["/e/f"]),
                            ('1 unlinkat(AT_FDCWD</e>, "g", AT_REMOVEDIR) = 0\n', ["/e/g"]),
                            ('1 rename("a", "b")                  = 0\n', ["/d/a", "/d/b"]),
                            ('1 renameat(3</e>, "a", 4</f>, "b") = 0\n', ["/e/a", "/f/b"]),
                            ('1 renameat2(AT_FDCWD</e>, "a", AT_FDCWD</f>, "b", RENAME_NOREPLACE) = 0\n', ["/e/a", "/f/b"]),
                            ('1 truncate("c", 0)                  = 0\n', ["/d/c"]),
                            ('1 unlink("c" <unfinished ...>\n', ["/d/c"])):
            self.assertLessEqual({("path", n) for n in names}, clash_audit.writes(cwd + line), line)
            for name in names:
                self.assertEqual(clash_audit.clashes({"test_a": cwd + line, "test_b": w(2, name)}, serial={}),
                                 [("path", name, "test_a", "test_b")], line)
        # No directory fd: the name joins the cwd the pid's lines showed, else stays as asked.
        self.assertEqual(clash_audit.writes(cwd + '1 unlink("c") = 0\n'), {("path", "/d/c")})
        self.assertEqual(clash_audit.writes('1 unlink("c") = 0\n'), {("path", "c")})
        link = '1 symlink("/t/real", "/d/l") = 0\n'
        self.assertEqual(clash_audit.writes(link + '1 truncate("/d/l", 0) = 0\n'), {("path", "/t/real"), ("path", "/d/l")})
        self.assertEqual(clash_audit.writes(link + '1 unlink("/d/l") = 0\n'), {("path", "/d/l")})
        # records_audit: removing or renaming a trace, or another module's cut trace, is a write there.
        own = f'1 openat(AT_FDCWD<{R}>, "tests/test_m.py", O_RDONLY|O_CLOEXEC) = 3<{R}/tests/test_m.py>\n'
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            for line, path in ((f'2 unlink("{d}/test_b.trace.cut") = 0\n', "test_b.trace.cut"),
                               (f'2 renameat(AT_FDCWD</>, "{d}/test_m.trace", AT_FDCWD</>, "/tmp/y") = 0\n', "test_m.trace"),
                               (f'2 truncate("{d}/test_b.trace", 0) = 0\n', "test_b.trace")):
                trace = own + line + "1 +++ exited with 0 +++\n"
                self.assertEqual(records_audit.problems({"test_m": trace}, ["tests.test_m"], trace_dir=d),
                                 [f"tests.test_m\twrote {d}/{path}: {records_audit.TAMPER}"], line)

    def test_a_cut_attempts_writes_are_the_modules(self):
        # #5413: tools/unit_tests.py keeps a cut attempt's trace as <module>.trace.cut; a write
        # only it shows still clashes, and main reads it from the trace directory.
        self.assertEqual(clash_audit.clashes({"test_a": "", "test_b": w(2, "/x")}, serial={}, cut={"test_a": w(1, "/x")}),
                         [("path", "/x", "test_a", "test_b")])
        self.assertEqual(clash_audit.clashes({"test_a": w(1, "/x"), "test_b": ""}, serial={}, cut={"test_a": w(1, "/x")}), [])
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, "test_a.trace").write_text("")
            pathlib.Path(d, "test_b.trace").write_text(w(2, "/x"))
            pathlib.Path(d, "test_a" + unit_tests.CUT).write_text(w(1, "/x"))
            out = io.StringIO()
            with mock.patch.object(unit_tests, "modules", lambda root=None: ["test_a", "test_b"]), \
                 mock.patch("sys.stdout", out), mock.patch("sys.stderr", io.StringIO()), \
                 mock.patch.dict(unit_tests.SERIAL, clear=True):
                self.assertEqual(clash_audit.main(["clash_audit.py", d]), 1)
            self.assertEqual(out.getvalue(), "::error::test_a and test_b both write /x\n")

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
            # A cut attempt's trace (tools/unit_tests.py CUT) is its module's, not a unit of its own.
            pathlib.Path(d, "test_b" + unit_tests.CUT).write_text(w(9, "/tmp/tmpb/x"))
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

    def test_ci_runs_the_uid_boundary_test_as_root_where_it_cannot_skip(self):
        # #5413: under tools/unit_tests.py the test runs as a module's user and skips; this step runs it.
        ci = (unit_tests.ROOT / ".github/workflows/ci.yml").read_text()
        step = ci[ci.index("python tests/clash_audit.py"):]
        step = step[step.index("\n      - "):][1:]
        step = step[:step.index("\n      - ")].splitlines()
        self.assertEqual(step[1], "        if: steps.scope.outputs.records != 'true'")
        self.assertEqual(step[-1], '        run: sudo -E env "PATH=$PATH" AGENTOS_REQUIRE_UID_BOUNDARY=1 python -m unittest '
                                   'tests.test_unit_tests -v')


if __name__ == "__main__":
    unittest.main()
