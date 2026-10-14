"""Tests for tools/g1_scope.py, its lists and its workflow (G1-freeze, #1687).

No requirement IDs: CI tooling that holds work to the G1 path (A1, D-104), not SPEC.md
behaviour. The local cases are G1-freeze-a (paths outside the list fail, listed paths and
G1 fixes pass), -b (exempt PRs and builders), -c (records-only and empty changes), -d (the
switch), -e (fail closed) and -f (the list keeps up with the G1 binaries' imports).
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import g1_scope as g  # noqa: E402

LIST = (ROOT / "tools" / "g1_scope.txt").read_text()
EXEMPT = (ROOT / "tools" / "g1_scope_exempt.txt").read_text()

# The binaries the G1 path ships or runs (see the header of tools/g1_scope.txt).
G1_BINARIES = (
    "agentosd", "agentos-egress", "agentos-localui", "agentos-ap", "agentos-modem",
    "agentos-netjoin", "agentos-guest-bridge", "agentos-seller", "agentos-checker",
    "agentos-clock-boot", "agentos-hostdisk",
)

SMALL = """
freeze on
allow broker/localui/
allow image/
allow SPEC.md
frozen-import broker/loops/
"""
EX = "pr 1500\nissue 1638 PACE-allowance-race\n"


def run(paths, list_text=SMALL, exempt=EX, pr=None, branch="", title=""):
    return g.check(paths, list_text, exempt, pr, branch, title)


class CheckTest(unittest.TestCase):
    def test_outside_paths_fail_and_are_named(self):  # G1-freeze-a
        ok, msg = run(["broker/localui/a.go", "broker/voice/v.go", "broker/loops/l.go"])
        self.assertFalse(ok)
        text = "\n".join(msg)
        self.assertIn("  broker/loops/l.go", text)
        self.assertIn("  broker/voice/v.go", text)
        self.assertNotIn("broker/localui/a.go", text)

    def test_g1_fix_on_listed_paths_passes(self):  # G1-freeze-a
        self.assertTrue(run(["broker/localui/a.go", "image/build.sh", "SPEC.md", "reviews/x.md"])[0])

    def test_entries_are_prefixes_only_with_a_slash(self):  # G1-freeze-a
        self.assertFalse(run(["SPEC.md.bak"])[0])
        self.assertFalse(run(["broker/localuix/a.go"])[0])
        self.assertFalse(run(["broker/localui/../voice/v.go"])[0])

    def test_exempt_pr_number(self):  # G1-freeze-b
        self.assertTrue(run(["broker/voice/v.go"], pr=1500)[0])
        self.assertFalse(run(["broker/voice/v.go"], pr=1501)[0])

    def test_exempt_builder_by_branch_or_title(self):  # G1-freeze-b
        self.assertTrue(run(["broker/voice/v.go"], branch="pkg/1638-pace-x1")[0])
        self.assertTrue(run(["broker/voice/v.go"], title="PACE-allowance-race: fix")[0])
        self.assertTrue(run(["broker/voice/v.go"], title="PACE-allowance-race fix")[0])
        # A longer ID or another issue's stem is not the row.
        self.assertFalse(run(["broker/voice/v.go"], title="PACE-allowance-race-2: x")[0])
        self.assertFalse(run(["broker/voice/v.go"], branch="pkg/16380-x")[0])
        self.assertFalse(run(["broker/voice/v.go"], branch="claude/pkg/1638-x")[0])

    def test_records_only_and_empty_changes_pass(self):  # G1-freeze-c
        ok, msg = run(["reviews/l3/pr9.md", "BOARD.md", "decisions/D-200.md"], list_text="freeze on\n")
        self.assertTrue(ok, msg)
        self.assertTrue(run([""], list_text="freeze on\n")[0])
        # A record directory's non-Markdown file is not a record.
        self.assertFalse(run(["reviews/x.py"], list_text="freeze on\n")[0])

    def test_switch_off_passes_everything(self):  # G1-freeze-d
        self.assertTrue(run(["broker/voice/v.go"], list_text=SMALL.replace("freeze on", "freeze off"))[0])

    def test_unreadable_lists_fail_closed(self):  # G1-freeze-e
        for bad in ("allow x/\n", "freeze on\nfreeze off\n", "freeze maybe\n",
                    "freeze on\nallow ../x\n", "freeze on\nallow /etc/\n", "freeze on\nexempt 4\n",
                    "freeze on\nallow broker/\nfrozen-import broker/loops/\n",
                    "freeze on\nfrozen-import broker/loops\n"):
            with self.assertRaises(g.ListError, msg=bad):
                run(["x"], list_text=bad)
        for bad in ("pr x\n", "issue 4\n", "issue 4 bad;id\n"):
            with self.assertRaises(g.ListError, msg=bad):
                run(["x"], exempt=bad)

    def test_cli_on_a_git_range(self):  # G1-freeze-a, -b, -e
        if not shutil.which("git"):
            self.skipTest("no git")
        with tempfile.TemporaryDirectory() as d:
            def git(*a):
                subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
            git("init", "-q", "-b", "main")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            pathlib.Path(d, "f").write_text("0")
            git("add", "f")
            git("commit", "-qm", "base")
            os.makedirs(pathlib.Path(d, "broker/voice"))
            pathlib.Path(d, "broker/voice/v.go").write_text("package voice")
            git("add", ".")
            git("commit", "-qm", "head")
            cwd = os.getcwd()
            os.chdir(d)
            try:
                with _quiet():
                    self.assertEqual(g.main(["--git", "HEAD~1", "HEAD"]), 1)
                    self.assertEqual(g.main(["--git", "HEAD~1", "HEAD", "--pr-branch", "pkg/1638-x"]),
                                     0 if "issue 1638 " in EXEMPT else 1)
                    self.assertEqual(g.main(["--git", "HEAD~1", "nosuchref"]), 2)
            finally:
                os.chdir(cwd)


class _quiet:
    def __enter__(self):
        self.out, self.err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = open(os.devnull, "w")

    def __exit__(self, *a):
        sys.stdout.close()
        sys.stdout, sys.stderr = self.out, self.err


class SnapshotTest(unittest.TestCase):
    def test_snapshot_lists_open_prs_and_building_rows(self):  # G1-freeze-b
        def fetch(endpoint):
            if "/pulls?" in endpoint:
                return [{"number": 12}, {"number": 3}]
            return [
                {"number": 40, "title": "CTX-slice: SPEC slicer"},
                {"number": 41, "title": "PR as issue", "pull_request": {}},
                {"number": 42, "title": "no id here"},
            ]
        text = g.snapshot(fetch)
        prs, issues = g.parse_exempt(text)
        self.assertEqual(prs, {3, 12})
        self.assertEqual(issues, {40: "CTX-slice"})

    def test_gh_pages_reads_every_page(self):
        calls = []

        def fake(argv, **kw):
            calls.append(argv)
            n = 100 if len(calls) == 1 else 7
            return subprocess.CompletedProcess(argv, 0, stdout=str(list(range(n))))
        self.assertEqual(len(g.gh_pages("repos/o/r/pulls?state=open", run=fake)), 107)
        self.assertEqual(calls[1][-1], "repos/o/r/pulls?state=open&per_page=100&page=2")
        self.assertNotIn("--paginate", sum(calls, []))


class ListTest(unittest.TestCase):
    def test_checked_in_lists_parse_and_freeze_is_on(self):  # G1-freeze-d, -e
        freeze, allow, frozen = g.parse_list(LIST)
        self.assertTrue(freeze)
        g.parse_exempt(EXEMPT)
        # The switch is one line, so lifting the freeze is a one-line diff.
        self.assertEqual([l for l in LIST.splitlines() if l.startswith("freeze")], ["freeze on"])

    def test_every_entry_exists(self):  # G1-freeze-f
        _, allow, frozen = g.parse_list(LIST)
        # broker/provagent/ is listed ahead of #1314 (CAP-11-plan), which creates it.
        new = {"broker/provagent/"}
        for e in allow + frozen:
            if e not in new:
                self.assertTrue((ROOT / e).exists(), f"{e} names nothing in the repo")

    def test_frozen_paths_stay_out(self):  # G1-freeze-a
        for p in ("broker/voice/v.go", "broker/cmd/agentos-builder/main.go", "guest/builder/x",
                  "spikes/S10-pact/x", "broker/loops/x.go", "broker/newpkg/x.go", "newdir/x",
                  # One model route (D-104, ChatGPT plan): the API-key adapters freeze.
                  "broker/route/anthropic.go", "broker/route/testdata/anthropic_stream.sse",
                  "broker/route/openai.go", "broker/route/testdata/openai_stream.sse"):
            self.assertFalse(g.check([p], LIST)[0], p)
        for p in ("broker/localui/x.go", "broker/cmd/agentosd/main.go", "image/build.sh",
                  "guest/openclaw/x", "spikes/CTRL-spike/x", "tools/g1_scope.txt", "SPEC.md",
                  "guest/codex/x", "broker/provagent/x.go", "broker/route/route.go"):
            self.assertTrue(g.check([p], LIST)[0], p)

    def test_list_covers_the_g1_binaries_imports(self):  # G1-freeze-f
        go = shutil.which("go")
        if not go:
            if os.environ.get("CI"):
                self.fail("go is not on PATH in CI")
            self.skipTest("no go toolchain")
        broker = ROOT / "broker"
        mod = subprocess.run([go, "list", "-m"], cwd=broker, check=True,
                             capture_output=True, text=True).stdout.strip()
        out = subprocess.run([go, "list", "-deps", *[f"./cmd/{b}" for b in G1_BINARIES]],
                             cwd=broker, check=True, capture_output=True, text=True).stdout
        _, allow, frozen = g.parse_list(LIST)
        missing = []
        for pkg in out.split():
            if pkg.startswith(mod + "/"):
                path = "broker/" + pkg[len(mod) + 1:] + "/"
                # A package listed file by file (broker/route/) counts when any entry is in it.
                if not any(path.startswith(e) if e.endswith("/") else e.startswith(path)
                           for e in allow + frozen):
                    missing.append(path)
        self.assertEqual(missing, [], "G1 binaries import packages tools/g1_scope.txt does not name")


if __name__ == "__main__":
    unittest.main()
