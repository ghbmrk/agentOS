"""Tests for tools/race_reads.py and ci_scope's race-blind scope (CI-race-scope, #6692)."""
import gzip
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import ci_scope  # noqa: E402
import race_reads  # noqa: E402

R = "/repo"


def acc(lines, cwd=R + "/broker"):
    return [(n, p) for _, n, p, _ in race_reads.accesses(lines, cwd)]


def trace(*lines, test=True, exited=True):
    """A synthetic strace -f -y -q trace: a go test that execs a test binary, then lines."""
    out = ['1 execve("/usr/bin/go", ["go", "test"]) = 0']
    if test:
        out.append('1 execve("/tmp/go-build1/b001/x.test", ["x.test"]) = 0')
    out += lines
    if exited:
        out.append("1 +++ exited with 0 +++")
    return [l + "\n" for l in out]


FILES = {"image/a", "tests/t.py", "tools/x.py", "SPEC.md", "broker/b.go", "docs/x.txt"}


def audit(lines, read, files=FILES):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.gz")
        with gzip.open(p, "wt") as f:
            f.writelines(lines)
        return race_reads.audit([p], R, read=read, files=files)


class AccessesTest(unittest.TestCase):
    def test_relative_paths_resolve_against_the_dirfd_decoration(self):
        got = acc(['1 openat(AT_FDCWD</repo/broker/x>, "../../image/a", O_RDONLY) = 3</repo/image/a>',
                   '1 newfstatat(5</repo/tests>, "f.py", {}, 0) = 0',
                   '1 openat(AT_FDCWD</q>, "/repo/SPEC.md", O_RDONLY) = -1 ENOENT (No such file or directory)'])
        self.assertEqual(got, [("openat", "/repo/image/a"), ("newfstatat", "/repo/tests/f.py"),
                               ("openat", "/repo/SPEC.md")])

    def test_a_link_counts_as_the_file_it_reached(self):
        got = acc(['1 openat(AT_FDCWD</repo/broker>, "testdata/l", O_RDONLY) = 3</repo/tests/x>'])
        self.assertEqual(got, [("openat", "/repo/broker/testdata/l"), ("openat", "/repo/tests/x")])

    def test_unfinished_calls_join_their_resumed_half(self):
        got = acc(['1 openat(AT_FDCWD</repo/broker>, "../tools/a.py", O_RDONLY <unfinished ...>',
                   '1 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD}, 88) = 2',
                   '2 openat(AT_FDCWD</repo/broker>, "../b", O_RDONLY) = 4</repo/b>',
                   '1 <... openat resumed>)             = 3</repo/tools/a.py>'])
        self.assertEqual(got, [("openat", "/repo/b"), ("openat", "/repo/tools/a.py")])

    def test_working_directories_follow_chdir_and_clone(self):
        got = acc(['1 chdir("../image") = 0',
                   '1 stat("a", {}) = 0',
                   '1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 7',
                   '7 chdir("mkosi") = 0',
                   '7 execve("./run", ["run"]) = 0',
                   '1 stat("b", {}) = 0',
                   '1 clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD, exit_signal=0}, 88) = 8',
                   '8 chdir("/repo/tests") = 0',
                   '1 access("c", R_OK) = 0'])
        self.assertEqual(got, [("chdir", "/repo/image"), ("stat", "/repo/image/a"),
                               ("chdir", "/repo/image/mkosi"), ("execve", "/repo/image/mkosi/run"),
                               ("stat", "/repo/image/b"), ("chdir", "/repo/tests"), ("access", "/repo/tests/c")])

    def test_a_vfork_child_waits_for_its_clone_line(self):
        # The parent's clone prints its child's pid only after the child has chdir'd and exec'd.
        got = acc(['1 chdir("../image") = 0',
                   '1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
                   '4 chdir("mkosi") = 0',
                   '4 execve("./run", ["run"]) = 0',
                   '1 <... clone resumed>) = 4',
                   '4 stat("x", {}) = 0'])
        self.assertEqual(got, [("chdir", "/repo/image"), ("chdir", "/repo/image/mkosi"),
                               ("execve", "/repo/image/mkosi/run"), ("stat", "/repo/image/mkosi/x")])

    def test_two_unborn_processes_on_one_pid_wait_for_their_own_clones(self):
        # Each clone is unfinished across its child's calls; the first child exits before its clone prints.
        got = acc(['1 stat("z", {}) = 0', '1 vfork( <unfinished ...>', '4 chdir("a") = 0', '4 +++ exited with 0 +++',
                   '1 <... vfork resumed>) = 4', '1 chdir("/q") = 0', '1 vfork( <unfinished ...>',
                   '4 chdir("b") = 0', '1 <... vfork resumed>) = 4', '4 stat("c", {}) = 0'])
        self.assertEqual(got, [("stat", "/repo/broker/z"), ("chdir", "/repo/broker/a"), ("chdir", "/q"),
                               ("chdir", "/q/b"), ("stat", "/q/b/c")])

    def test_a_dead_child_never_shadows_its_pids_next_process(self):
        # A vfork child exits before its clone line prints; later a whole clone returns the same pid, whose new
        # process inherits the cloner's cwd and stamp, not the dead one's.
        got = acc(['1 stat("z", {}) = 0', '1 vfork( <unfinished ...>', '4 chdir("/a") = 0', '4 +++ exited with 0 +++',
                   '1 <... vfork resumed>) = 4', '1 chdir("/q") = 0',
                   '1 clone(child_stack=NULL, flags=SIGCHLD) = 4', '4 stat("c", {}) = 0'])
        self.assertEqual(got, [("stat", "/repo/broker/z"), ("chdir", "/a"), ("chdir", "/q"), ("stat", "/q/c")])

    def test_a_stale_life_before_a_whole_clone_is_unplaced(self):
        # A whole clone line means its child printed nothing yet: buffered calls on that pid were an earlier
        # process no clone placed, so they resolve from an unknown cwd (fail closed).
        got = acc(['1 stat("z", {}) = 0', '4 stat("a", {}) = 0', '4 +++ exited with 0 +++',
                   '1 clone(child_stack=NULL, flags=SIGCHLD) = 4', '4 stat("c", {}) = 0'])
        self.assertEqual(got, [("stat", "/repo/broker/z"), ("stat", None), ("stat", "/repo/broker/c")])

    def test_a_thread_killed_before_its_first_call_leaves_nothing(self):
        got = acc(['1 stat("z", {}) = 0', '6 +++ killed by SIGKILL +++',
                   '1 clone(child_stack=NULL, flags=SIGCHLD) = 6', '6 stat("y", {}) = 0'])
        self.assertEqual(got, [("stat", "/repo/broker/z"), ("stat", "/repo/broker/y")])

    def test_a_clone_in_a_pid_namespace_links_by_strace_s_pid(self):
        got = acc(['1 chdir("/repo/image") = 0',
                   "1 clone(child_stack=NULL, flags=SIGCHLD) = 2 /* 18866 in strace's PID NS */",
                   '18866 stat("a", {}) = 0'])
        self.assertEqual(got, [("chdir", "/repo/image"), ("stat", "/repo/image/a")])

    def test_a_relative_path_in_an_unknown_directory_is_unresolved(self):
        got = acc(['1 stat("x", {}) = 0', '9 execve("rel", ["rel"]) = 0'])
        self.assertEqual(got, [("stat", "/repo/broker/x"), ("execve", None)])

    def test_a_reused_pid_starts_from_its_own_clone(self):
        got = acc(['1 stat("z", {}) = 0', '1 clone(child_stack=NULL, flags=SIGCHLD) = 3',
                   '3 chdir("/repo/image") = 0', '3 +++ exited with 0 +++',
                   '1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 3',
                   '3 stat("a", {}) = 0'])
        self.assertEqual(got, [("stat", "/repo/broker/z"), ("chdir", "/repo/image"), ("stat", "/repo/broker/a")])

    def test_go_vcs_stamp_git_reads_nothing_of_the_tree(self):
        # Exactly go's two stamp commands, their threads included; any other git reads the store.
        got = acc(['1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 5',
                   '1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 7',
                   '1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 8',
                   '5 execve("/usr/bin/git", ["git", "status", "--porcelain"], 0x1 /* 3 vars */ <unfinished ...>',
                   '5 <... execve resumed>) = 0',
                   '5 clone3({flags=CLONE_VM|CLONE_FS|CLONE_THREAD}, 88) = 6',
                   '6 newfstatat(AT_FDCWD</repo>, "reviews/x", {}, 0) = 0',
                   '5 openat(AT_FDCWD</repo>, ".git/index", O_RDONLY) = 3</repo/.git/index>',
                   '8 execve("/usr/bin/git", ["git", "-c", "log.showsignature=false", "log", "-1", "--format=%H:%ct"], 0x1) = 0',
                   '8 openat(AT_FDCWD</repo>, ".git/HEAD", O_RDONLY) = 3</repo/.git/HEAD>',
                   '7 execve("/usr/bin/git", ["git", "status", "--porcelain", "--ignored"], 0x1) = 0',
                   '7 openat(AT_FDCWD</repo>, ".git/x", O_RDONLY) = 3</repo/.git/x>'])
        self.assertEqual(got, [("execve", "/usr/bin/git"), ("openat", "/repo/.git/x")])

    def test_a_descriptor_past_path_max_resolves_from_its_open(self):
        # -y prints no path for a directory past PATH_MAX; threads sharing CLONE_FILES share fds.
        got = acc(['1 openat(AT_FDCWD</repo/broker>, "../tests", O_RDONLY|O_DIRECTORY) = 7</repo/tests>',
                   '1 openat(7</repo/tests>, "c", O_RDONLY|O_DIRECTORY) = 8',
                   '1 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD}, 88) = 2',
                   '2 openat(8, "d", O_RDONLY) = 3',
                   '1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 4',
                   '4 openat(9, "e", O_RDONLY) = 3'])
        self.assertEqual(got, [("openat", "/repo/tests"), ("openat", "/repo/tests/c"),
                               ("openat", "/repo/tests/c/d"), ("openat", None)])

    def test_a_link_s_content_is_not_an_access(self):
        self.assertEqual(acc(['1 symlinkat("../../tests/x", AT_FDCWD</tmp>, "l") = 0',
                              '1 symlink("tests", "/tmp/m") = 0']), [])

    def test_escapes_decode(self):
        got = acc([r'1 openat(AT_FDCWD</repo>, "a\"b\\c\303\251\x41", O_RDONLY) = -1 ENOENT'])
        self.assertEqual(got, [("openat", '/repo/a"b\\céA')])


class AuditTest(unittest.TestCase):
    def test_a_tracked_file_read_outside_the_set_fails(self):
        lines = trace('1 openat(AT_FDCWD</repo/broker>, "../image/a", O_RDONLY) = 3</repo/image/a>',
                      '1 newfstatat(AT_FDCWD</repo/broker>, "../tests/t.py", {}, 0) = 0',
                      '1 openat(AT_FDCWD</repo/broker>, "b.go", O_RDONLY) = 3</repo/broker/b.go>',
                      '1 openat(AT_FDCWD</repo/broker>, "/etc/passwd", O_RDONLY) = 3</etc/passwd>')
        self.assertEqual(audit(lines, ("image/", "tests/t.py"))[0], [])
        problems, reads = audit(lines, ("image/",))
        self.assertEqual(problems, ["read outside RACE_READ: newfstatat(tests/t.py); add it to tools/ci_scope.py RACE_READ"])
        self.assertEqual(reads, {"image/a", "tests/t.py", "broker/b.go"})

    def test_directories_untracked_and_missing_paths_are_not_reads(self):
        # A race-blind change only modifies tracked files: listings, types and absent names stay.
        lines = trace('1 openat(AT_FDCWD</repo/broker>, "..", O_RDONLY|O_DIRECTORY) = 3</repo>',
                      '1 openat(AT_FDCWD</repo>, "tools", O_RDONLY|O_DIRECTORY) = 3</repo/tools>',
                      '1 openat(AT_FDCWD</repo>, "tools/__pycache__/x.pyc", O_RDONLY) = 3</repo/tools/__pycache__/x.pyc>',
                      '1 newfstatat(AT_FDCWD</repo>, "go.work", 0x1, 0) = -1 ENOENT (No such file or directory)')
        self.assertEqual(audit(lines, ()), ([], set()))

    def test_the_git_object_store_fails(self):
        lines = trace('1 openat(AT_FDCWD</repo>, ".git/objects/pack/p.idx", O_RDONLY) = 3</repo/.git/objects/pack/p.idx>',
                      '1 openat(AT_FDCWD</repo>, ".git/HEAD", O_RDONLY) = 3</repo/.git/HEAD>')
        self.assertEqual(len(audit(lines, ())[0]), 1)
        self.assertIn("git object store", audit(lines, ())[0][0])

    def test_the_committed_set_covers_the_tree_as_it_is(self):
        files = race_reads.tracked(str(ROOT))
        self.assertIn("tools/canary.py", files)
        for e in ci_scope.RACE_READ:
            self.assertTrue(any(f == e or e.endswith("/") and f.startswith(e) for f in files), e)

    def test_it_fails_closed(self):
        self.assertIn("unresolved", audit(trace('4 stat("x", {}) = 0'), ())[0][0])
        # The CLI reads the tracked set from git; a root that is not a repository is an error.
        self.assertIn("no test binary ran", audit(trace(test=False), ())[0][0])
        self.assertIn("cut short", audit(trace(exited=False), ())[0][0])
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OSError):
                race_reads.audit([os.path.join(d, "missing.gz")], R, read=(), files=FILES)
            cut = os.path.join(d, "cut.gz")
            with open(cut, "wb") as f:
                f.write(gzip.compress("".join(trace()).encode())[:-12])
            with self.assertRaises(EOFError):
                race_reads.audit([cut], R, read=(), files=FILES)

    def test_the_cli_exits_nonzero_on_a_problem(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t")
            pathlib.Path(p).write_text("".join(trace(test=False)))
            out = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "race_reads.py"), "audit",
                                  "--root", str(ROOT), "--reads-out", os.path.join(d, "r"), p],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 1)
            self.assertIn("no test binary ran", out.stdout)

    @unittest.skipUnless(shutil.which("strace") and os.geteuid() == 0, "needs strace, as root")
    def test_a_real_trace_of_an_exec_child(self):
        # A traced process cannot be traced again (unit-tests runs every module under strace), so
        # this runs where it can; broker-race's own audit is the live case on every run.
        status = pathlib.Path("/proc/self/status").read_text()
        if "\nTracerPid:\t0\n" not in status:
            self.skipTest("already traced")
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            os.makedirs(os.path.join(d, "broker"))
            os.makedirs(os.path.join(d, "image"))
            pathlib.Path(d, "image", "a").write_text("x\n")
            t = pathlib.Path(d, "broker", "x.test")
            t.write_text("#!/bin/sh\ncd ../image && cat a >/dev/null && sh -c 'cat a' >/dev/null\n")
            t.chmod(0o755)
            tr = os.path.join(d, "t")
            self.assertEqual(subprocess.call([sys.executable, "-I", str(ROOT / "tools" / "race_reads.py"), "run",
                                              "--trace", tr, "--", "./x.test"], cwd=os.path.join(d, "broker")), 0)
            files = {"image/a", "broker/x.test"}
            self.assertEqual(race_reads.audit([tr], d, read=("image/",), files=files)[0], [])
            problems, reads = race_reads.audit([tr], d, read=(), files=files)
            self.assertIn("image/a", reads)
            self.assertTrue(problems and all("image/a" in p for p in problems), problems)


def stat_audit(stat_lines, read=("image/",), files=FILES | {race_reads.STAT_CONTROL}):
    with tempfile.TemporaryDirectory() as d:
        t, st = os.path.join(d, "t.gz"), os.path.join(d, "s.txt")
        with gzip.open(t, "wt") as f:
            f.writelines(trace())
        pathlib.Path(st).write_text("".join(l + "\n" for l in stat_lines))
        problems, reads = race_reads.audit([t], R, read=read, files=files, stats=[st])
        return [p.replace(st + ": ", "") for p in problems], reads


CONTROL = f"S 1 {R}/{race_reads.STAT_CONTROL}"


class StatTraceTest(unittest.TestCase):

    def test_a_stat_outside_the_set_fails_and_one_inside_passes(self):
        problems, reads = stat_audit(["Attaching 4 probes...", "START", CONTROL, f"S 9 {R}/tests/t.py",
                                      f"S 9 {R}/image/a", f"S 9 {R}/image/../SPEC.md", "END"])
        self.assertEqual(sorted(problems), ["read outside RACE_READ: stat(SPEC.md); add it to tools/ci_scope.py RACE_READ",
                                            "read outside RACE_READ: stat(tests/t.py); add it to tools/ci_scope.py RACE_READ"])
        self.assertIn("image/a", reads)

    def test_the_git_object_store_fails(self):
        problems, _ = stat_audit(["START", CONTROL, f"S 9 {R}/.git/objects/ab/cd", f"S 9 {R}/.git/HEAD", "END"])
        self.assertEqual(problems, ["git object store read: stat(.git/objects/ab/cd): it holds every file"])

    def test_a_trace_not_whole_fails_closed(self):
        for lines, want in (([CONTROL, "END"], "did not run from start to end"),
                            (["START", CONTROL], "did not run from start to end"),
                            ([], "did not run from start to end"),
                            (["START", "END"], "control stat"),
                            (["START", CONTROL, "Lost 12 events", "END"], "unexpected line"),
                            (["START", CONTROL, "S x /repo/a", "END"], "unreadable line"),
                            (["START", CONTROL, "S 9 " + R + "/" + "a" * 200, "END"], "cut short")):
            with self.subTest(lines=lines):
                problems, _ = stat_audit(lines)
                self.assertTrue(problems)
                self.assertTrue(any(want in p for p in problems), problems)

    def test_a_clean_stat_trace_passes(self):
        self.assertEqual(stat_audit(["Attaching 4 probes...", "START", CONTROL, f"S 3 {R}/image/a", "END"])[0], [])

    def test_the_program_filters_in_the_kernel_and_refuses_an_odd_root(self):
        prog = race_reads.stats_program("/home/runner/work/agentOS/agentOS")
        self.assertIn('strncmp($p, "/home/runner/work/agentOS/agentOS/", 34) == 0', prog)
        self.assertIn('strncmp($p, "/home/runner/work/agentOS/agentOS/broker/", 41) != 0', prog)
        self.assertIn("fexit:vfs_getattr", prog)
        self.assertIn('== "--porcelain"', prog)
        self.assertIn('== "log.showsignature=false"', prog)
        for bad in ('/a"b', "/a b", "/a\\n", "/a$b"):
            with self.subTest(root=bad), self.assertRaises(ValueError):
                race_reads.stats_program(bad)

    @unittest.skipUnless(shutil.which("bpftrace") and os.geteuid() == 0, "needs bpftrace, as root")
    def test_a_real_stat_trace(self):
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            for f in ("tools/race_reads.py", "image/a", "broker/b"):
                os.makedirs(os.path.dirname(os.path.join(d, f)), exist_ok=True)
                pathlib.Path(d, f).write_text("x\n")
            out = os.path.join(d, "s.txt")
            try:
                code = race_reads.with_stats(out, d, [], lambda: subprocess.call(
                    ["sh", "-c", "cd image && stat a >/dev/null && stat ../broker/b >/dev/null"], cwd=d), wait=60)
            except OSError as e:
                self.skipTest(f"no bpftrace here: {e}")
            text = pathlib.Path(out).read_text()
            if code == 2 and "START" not in text:
                self.skipTest(f"bpftrace cannot attach here: {text[-300:]}")
            self.assertEqual(code, 0)
            got = list(race_reads.stat_lines(text.splitlines(True), d))
            self.assertEqual([p for p, _ in got if p], [])
            paths = {q for _, q in got}
            self.assertIn(f"{d}/image/a", paths)
            self.assertIn(f"{d}/tools/race_reads.py", paths)
            self.assertNotIn(f"{d}/broker/b", paths)


class RaceBlindScopeTest(unittest.TestCase):
    def test_only_a_modification_outside_the_read_set_is_race_blind(self):
        for p in ("tests/test_x.py", "tools/board.py", "docs/x.txt", "LICENSE"):
            self.assertTrue(ci_scope.is_race_blind(p, "M"), p)
            for st in ("A", "D", "T", None, ""):
                self.assertFalse(ci_scope.is_race_blind(p, st), (p, st))
        for p in ("broker/x.go", ".github/workflows/ci.yml", ".github/actions/scope/action.yml",
                  "tools/ci_scope.py", "tools/ci_split.py", "tools/race_reads.py", ".git/config",
                  "image/mkosi/x", "SPEC.md", "tools/canary.py", "guest/codex/launch.json",
                  "tests/../broker/x.go", "tests//x", "./x.txt", "broker"):
            self.assertFalse(ci_scope.is_race_blind(p, "M"), p)

    def test_scope_of_changes(self):
        self.assertEqual(ci_scope.scope_of([("M", "tests/test_x.py"), ("A", "BOARD.md")]), ("race-blind", None))
        self.assertEqual(ci_scope.scope_of([("D", "BOARD.md")]), ("records", None))
        self.assertEqual(ci_scope.scope_of([("A", "tests/test_y.py")]), ("full", "tests/test_y.py"))
        self.assertEqual(ci_scope.scope_of([("M", "tests/test_x.py"), ("M", "broker/x.go")]), ("full", "broker/x.go"))
        self.assertEqual(ci_scope.scope_of(["tests/test_x.py"]), ("full", "tests/test_x.py"))  # no status
        self.assertEqual(ci_scope.scope_of([]), ("full", None))

    def test_changed_paths_carry_git_status(self):
        with tempfile.TemporaryDirectory() as d:
            g = lambda *a: subprocess.run(["git", *a], cwd=d, check=True, capture_output=True)
            g("init", "-q", "-b", "main")
            g("config", "user.email", "t@example.invalid")
            g("config", "user.name", "t")
            for f in ("a", "b", "c d", "m", "n"):
                pathlib.Path(d, f).write_text("x\n")
            g("add", "-A")
            g("commit", "-qm", "base")
            pathlib.Path(d, "a").write_text("y\n")
            pathlib.Path(d, "m").write_text("y\n")
            os.chmod(os.path.join(d, "m"), 0o755)  # a stat shows the new mode: never race-blind
            os.chmod(os.path.join(d, "n"), 0o755)
            os.remove(os.path.join(d, "b"))
            os.rename(os.path.join(d, "c d"), os.path.join(d, "e"))
            g("add", "-A")
            g("commit", "-qm", "change")
            cwd = os.getcwd()
            try:
                os.chdir(d)
                got = sorted(ci_scope.changed_paths("HEAD^", "HEAD"))
            finally:
                os.chdir(cwd)
            self.assertEqual(got, [("A", "e"), ("D", "b"), ("D", "c d"), ("M", "a"), ("X", "m"), ("X", "n")])
            self.assertFalse(ci_scope.is_race_blind("m", "X"))

    def test_the_trace_leaves_out_only_the_stat_family(self):
        names = {n.lstrip("?") for n in race_reads.TRACED}
        self.assertFalse(names & {"stat", "lstat", "newfstatat", "statx", "fstat", "fstatat64"})
        for n in ("open", "openat", "openat2", "execve", "execveat", "readlink", "readlinkat", "access",
                  "faccessat2", "chdir", "fchdir", "clone", "clone3", "vfork", "rename", "unlinkat"):
            self.assertIn(n, names)

    def test_the_sets_are_plain_and_apart(self):
        for e in (*ci_scope.RACE_READ, *ci_scope.NEVER_BLIND):
            self.assertTrue(ci_scope._plain(e.rstrip("/")), e)
        for e in ci_scope.RACE_READ:
            for n in ci_scope.NEVER_BLIND:
                self.assertFalse(e.startswith(n), (e, n))


if __name__ == "__main__":
    unittest.main()
