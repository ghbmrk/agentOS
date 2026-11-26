"""Tests for tools/race_reads.py and ci_scope's race-blind scope (CI-race-scope, #6692)."""
import gzip
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import ci_scope  # noqa: E402
import race_reads  # noqa: E402

R = "/repo"
FILES = {"image/a", "tests/t.py", "tools/x.py", "SPEC.md", "broker/b.go", "docs/x.txt", race_reads.CONTROL}


def ev(rel, kind="o", tid=1, pid=None):
    """The lines the probe prints for one access of R/rel: its parts leaf first, then the end line."""
    names = rel.split("/")[::-1]
    return [f"C {tid} {i} {n}" for i, n in enumerate(names)] + [f"E {kind} {tid} {pid or tid} {len(names)}"]


CONTROLS = [l for kind, rel in sorted(race_reads.CONTROLS) for l in ev(rel, kind)]
TEST = "X 7 0 /tmp/go-build1/b001/x.test"


def trace(*lines, start=True, end=True):
    """A synthetic whole trace: the tracer's banner, its controls, a test binary's exec, then lines."""
    return ["Attaching 9 probes...", *(["START"] if start else []), *CONTROLS, TEST, *lines, *(["END"] if end else [])]


def audit(lines, read=(), files=FILES, gz=False):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.gz" if gz else "t")
        with (gzip.open if gz else open)(p, "wt") as f:
            f.writelines(l + "\n" for l in lines)
        return race_reads.audit([p], R, read=read, files=files)


class AuditTest(unittest.TestCase):
    def test_a_tracked_file_read_outside_the_set_fails(self):
        lines = trace(*ev("image/a"), *ev("tests/t.py", "s", tid=9), *ev("SPEC.md", "l"), *ev("docs/x.txt", "f"))
        self.assertEqual(audit(lines, ("image/", "tests/t.py", "SPEC.md", "docs/"))[0], [])
        problems, reads = audit(lines, ("image/",))
        self.assertEqual(sorted(problems), [
            "read outside RACE_READ: follow_link(docs/x.txt); add it to tools/ci_scope.py RACE_READ",
            "read outside RACE_READ: readlink(SPEC.md); add it to tools/ci_scope.py RACE_READ",
            "read outside RACE_READ: stat(tests/t.py); add it to tools/ci_scope.py RACE_READ"])
        self.assertEqual(reads, {"image/a", "tests/t.py", "SPEC.md", "docs/x.txt", race_reads.CONTROL})

    def test_two_threads_parts_interleave(self):
        a, b = ev("tests/t.py", tid=3), ev("image/a", tid=4)
        problems, reads = audit(trace(a[0], b[0], b[1], a[1], b[2], a[2]), ("image/",))
        self.assertEqual(problems, ["read outside RACE_READ: open(tests/t.py); add it to tools/ci_scope.py RACE_READ"])
        self.assertIn("image/a", reads)

    def test_directories_and_untracked_paths_are_not_reads(self):
        # A race-blind change only modifies tracked files: listings, types and absent names stay.
        lines = trace(*ev("tools"), *ev("tools/__pycache__/x.pyc"), *ev(".git/HEAD"), *ev(".git"))
        self.assertEqual(audit(lines), ([], {race_reads.CONTROL}))

    def test_the_git_object_store_fails(self):
        problems, _ = audit(trace(*ev(".git/objects/ab/cd", "s"), *ev(".git/HEAD")))
        self.assertEqual(problems, ["git object store read: stat(.git/objects/ab/cd): it holds every file"])

    def test_the_committed_set_covers_the_tree_as_it_is(self):
        files = race_reads.tracked(str(ROOT))
        self.assertIn(race_reads.CONTROL, files)
        self.assertNotIn(race_reads.CONTROL_LINK, files)
        for e in ci_scope.RACE_READ:
            self.assertTrue(any(f == e or e.endswith("/") and f.startswith(e) for f in files), e)

    def test_it_fails_closed(self):
        for lines, want in ((trace(start=False), "did not run from start to end"),
                            (trace(end=False), "did not run from start to end"),
                            ([], "did not run from start to end"),
                            ([l for l in trace() if l != TEST], "no test binary ran"),
                            (trace("X 7 0 /usr/bin/go", "A 7 go git status --porcelain  "), None),
                            (trace("X 7 /usr/bin/go"), "unexpected line"),
                            (trace("Lost 12 events"), "unexpected line"),
                            (trace("FULL"), "process map is full"),
                            (trace("E x 1 1 1"), "unreadable line"),
                            (trace("E o 1 1"), "unreadable line"),
                            (trace("C 1 x a"), "unreadable line"),
                            (trace(*ev("image/a")[1:]), "did not all arrive"),
                            (trace(*ev("image/a")[:-1]), "no end line"),
                            (trace(*ev("image/" + "a" * 63)), "cut short"),
                            ([*trace(), "E o 1 1 1"], "after END"),
                            ([*trace(), ""], None)):
            with self.subTest(lines=lines):
                problems, _ = audit(lines, ("image/",))
                if want is None:
                    self.assertEqual(problems, [])
                    continue
                self.assertTrue(any(want in p for p in problems), problems)
        for kind, rel in sorted(race_reads.CONTROLS):
            with self.subTest(control=(kind, rel)):
                drop = ev(rel, kind)
                lines = [l for l in trace() if l not in drop[-1:]]
                problems, _ = audit([l for l in lines if l not in drop[:-1]] if kind in "lf" else lines)
                self.assertTrue(any(f"control {race_reads.KINDS[kind]} of {rel} is missing" in p for p in problems),
                                problems)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OSError):
                race_reads.audit([os.path.join(d, "missing.gz")], R, read=(), files=FILES)
            cut = os.path.join(d, "cut.gz")
            with open(cut, "wb") as f:
                f.write(gzip.compress("".join(l + "\n" for l in trace()).encode())[:-12])
            with self.assertRaises(EOFError):
                race_reads.audit([cut], R, read=(), files=FILES)

    def test_a_clean_trace_passes_gzipped_or_not(self):
        for gz in (False, True):
            self.assertEqual(audit(trace(*ev("image/a"), ""), ("image/",), gz=gz), ([], {"image/a", race_reads.CONTROL}))

    def test_a_tracked_file_deeper_than_the_probe_looks_fails(self):
        deep = "/".join(["image"] + ["d"] * race_reads.LEVELS)
        problems, _ = audit(trace(), files=FILES | {deep})
        self.assertEqual(problems, [f"tracked file deeper than the probe looks ({race_reads.LEVELS} parts): {deep}"])
        self.assertEqual(race_reads.too_deep({"broker/" + deep, "image/a"}), [])
        self.assertEqual(race_reads.too_deep(race_reads.tracked(str(ROOT))), [])

    def test_the_cli_exits_nonzero_on_a_problem(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t")
            pathlib.Path(p).write_text("".join(l + "\n" for l in trace() if l != TEST))
            out = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "race_reads.py"), "audit",
                                  "--root", str(ROOT), "--reads-out", os.path.join(d, "r"), p],
                                 capture_output=True, text=True)
            self.assertEqual(out.returncode, 1)
            self.assertIn("no test binary ran", out.stdout)
            self.assertEqual(pathlib.Path(d, "r").read_text(), race_reads.CONTROL + "\n")


class ProgramTest(unittest.TestCase):
    def test_the_program_walks_to_root_by_inode_and_device(self):
        prog = race_reads.program(1234, 5 << 20 | 6, 99)
        self.assertIn(f"$d1->d_inode->i_ino == 1234 && $d1->d_sb->s_dev == {5 << 20 | 6}", prog)
        self.assertIn(f"$d{race_reads.LEVELS} = $d{race_reads.LEVELS - 1}->d_parent;", prog)
        self.assertIn('!= "broker"', prog)
        self.assertIn("@tree[99] = 1;", prog)
        for kind, _, fn, dentry in race_reads.HOOKS:
            self.assertIn(f"fentry:{fn} /@tree[pid] && @stamp[pid] == 0/", prog)
            self.assertIn(f"$d0 = {dentry};", prog)
            self.assertIn(f'printf("E {kind} %d %d %d\\n", tid, pid, $k);', prog)
        self.assertNotIn("path(", prog)  # bpf_d_path is missing on the runner's kernel
        self.assertNotIn("vfs_getattr", prog)  # fentry saw no call of it on the runner
        self.assertIn('args->argv[2] != 0 && str(args->argv[2], 32) == "--porcelain" && args->argv[3] == 0', prog)
        self.assertNotIn('== ""', prog)  # str() of a NULL pointer can hold a stale string
        self.assertIn('str(args->argv[2], 32) == "log.showsignature=false"', prog)
        self.assertIn("(args->clone_flags & 0x10000) == 0", prog)  # threads share their process's key
        self.assertEqual(race_reads.kernel_dev(os.makedev(8, 1)), 8 << 20 | 1)

    @unittest.skipUnless(shutil.which("bpftrace") and os.geteuid() == 0, "needs bpftrace, as root")
    def test_a_real_trace(self):
        # broker-race's own audit is the live case on every run; this runs where eBPF can attach.
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            for f in (race_reads.CONTROL, "image/a", "image/b", "broker/b"):
                os.makedirs(os.path.dirname(os.path.join(d, f)), exist_ok=True)
                pathlib.Path(d, f).write_text("x\n")
            out = os.path.join(d, "s.txt")
            test = os.path.join(d, "x.test")
            shutil.copy("/bin/sh", test)
            try:
                code = race_reads.run(out, d, [test, "-c", "cd image && cat a >/dev/null && stat -c %s b >/dev/null"
                                               " && cat ../broker/b >/dev/null"], wait=60)
            except OSError as e:
                self.skipTest(f"no bpftrace here: {e}")
            text = pathlib.Path(out).read_text()
            if code == 2 and "START" not in text:
                self.skipTest(f"bpftrace cannot attach here: {text[-300:]}")
            self.assertEqual(code, 0)
            problems, reads = race_reads.audit([out], d, read=("image/",),
                                               files={race_reads.CONTROL, "image/a", "image/b", "broker/b"})
            self.assertEqual(problems, [])
            self.assertEqual(reads, {race_reads.CONTROL, "image/a", "image/b"})


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

    def test_a_record_a_broker_test_reads_never_skips_broker_race(self):
        # The audit sends a record a test reads into RACE_READ; from then on a change to it,
        # records-only or not, runs full, so broker-race runs the test that reads it.
        read = (*ci_scope.RACE_READ, "briefs/x.md", "docs/learning/")
        with unittest.mock.patch.object(ci_scope, "RACE_READ", read):
            self.assertEqual(ci_scope.scope_of([("M", "briefs/x.md")]), ("full", "briefs/x.md"))
            self.assertEqual(ci_scope.scope_of(["docs/learning/a.md", "BOARD.md"]), ("full", "docs/learning/a.md"))
            self.assertEqual(ci_scope.scope_of([("M", "BOARD.md"), ("M", "tests/t.py"), ("M", "briefs/x.md")]),
                             ("full", "briefs/x.md"))
            self.assertEqual(ci_scope.scope_of([("M", "briefs/y.md")]), ("records", None))
        self.assertEqual(ci_scope.scope_of([("M", "briefs/x.md")]), ("records", None))

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

    def test_the_sets_are_plain_and_apart(self):
        for e in (*ci_scope.RACE_READ, *ci_scope.NEVER_BLIND):
            self.assertTrue(ci_scope._plain(e.rstrip("/")), e)
        for e in ci_scope.RACE_READ:
            for n in ci_scope.NEVER_BLIND:
                self.assertFalse(e.startswith(n), (e, n))


if __name__ == "__main__":
    unittest.main()
