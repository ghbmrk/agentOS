"""Tests for tools/g1_scope.py, its lists and its workflow (G1-freeze, #1687).

No requirement IDs: CI tooling that holds work to the G1 path (A1, D-104), not SPEC.md
behaviour. The local cases are G1-freeze-a (paths outside the list fail, listed paths and
G1 fixes pass), -b (PRs opened before the freeze and exempt-pr lines), -c (records-only and empty changes), -d (the
switch), -e (fail closed), -f (the list keeps up with the G1 binaries' imports) and -g (a PR
reopened, force-pushed or retargeted after the freeze began loses the time exemption, #1717).
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

# The binaries the G1 path ships or runs (see the header of tools/g1_scope.txt).
G1_BINARIES = (
    "agentosd", "agentos-egress", "agentos-localui", "agentos-ap", "agentos-modem",
    "agentos-netjoin", "agentos-guest-bridge", "agentos-seller", "agentos-checker",
    "agentos-clock-boot", "agentos-hostdisk",
)

SMALL = """
freeze on
since 2026-10-14T19:55:00Z
exempt-pr 1500
allow broker/localui/
allow image/
allow SPEC.md
frozen-import broker/loops/
"""
S = "since 2026-10-14T19:55:00Z\n"
ON = "freeze on\n" + S
BEFORE, AFTER = "2026-10-14T19:54:59Z", "2026-10-14T19:55:00Z"


def run(paths, list_text=SMALL, pr=None, created="", history=""):
    return g.check(paths, list_text, pr, created, history)


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

    def test_pr_opened_before_the_freeze_passes(self):  # G1-freeze-b
        # Every PR open when the freeze began finishes, whatever its row's state.
        ok, msg = run(["broker/voice/v.go"], pr=1600, created=BEFORE)
        self.assertTrue(ok)
        self.assertIn("before the freeze began", msg[0])
        self.assertFalse(run(["broker/voice/v.go"], pr=1600, created=AFTER)[0])
        self.assertFalse(run(["broker/voice/v.go"], pr=1600)[0])

    def test_reuse_after_the_freeze_loses_the_time_exemption(self):  # G1-freeze-g
        # #1717: created_at belongs to the PR, not its work. A reopen, force-push or
        # retarget at or after `since` drops the time exemption; the path check decides.
        for event in ("reopened", "head_ref_force_pushed", "base_ref_changed"):
            ok, msg = run(["broker/voice/v.go"], pr=1600, created=BEFORE, history=f"{event}\t{AFTER}\n")
            self.assertFalse(ok, event)
            self.assertIn(f"{event} at {AFTER}", "\n".join(msg))
            # A listed path still passes, and an exempt-pr line still exempts.
            self.assertTrue(run(["image/x"], pr=1600, created=BEFORE, history=f"{event}\t{AFTER}\n")[0])
            self.assertTrue(run(["broker/voice/v.go"], pr=1500, created=BEFORE, history=f"{event}\t{AFTER}\n")[0])
            # Before the freeze began, the same event is part of the in-flight work.
            self.assertTrue(run(["broker/voice/v.go"], pr=1600, created=BEFORE, history=f"{event}\t{BEFORE}\n")[0])
            # An earlier event before the freeze does not hide a later one after it.
            later = f"reopened\t{BEFORE}\n{event}\t{AFTER}\n"
            self.assertFalse(run(["broker/voice/v.go"], pr=1600, created=BEFORE, history=later)[0], event)
        # Plain pushes, reviews, comments and closes keep it: the work finishes.
        quiet = f"committed\t\nreviewed\t\ncommented\t{AFTER}\nclosed\t{AFTER}\nlabeled\t{AFTER}\n"
        self.assertTrue(run(["broker/voice/v.go"], pr=1600, created=BEFORE, history=quiet)[0])

    def test_unreadable_history_fails_closed(self):  # G1-freeze-g, -e
        # A PR opened before the freeze needs its history read; without it, no decision.
        with self.assertRaises(g.ListError):
            g.check(["broker/voice/v.go"], SMALL, 1600, BEFORE, None)
        for bad in ("reopened\tyesterday\n", "reopened\n", "reopened\t\n", "base_ref_changed\tx\ty\n"):
            with self.assertRaises(g.ListError, msg=bad):
                run(["broker/voice/v.go"], pr=1600, created=BEFORE, history=bad)

    def test_workflow_hands_over_the_timeline(self):  # G1-freeze-g
        # The base copy gets the PR's timeline through a read-only token, as data.
        text = (ROOT / ".github" / "workflows" / "g1-freeze.yml").read_text()
        self.assertIn('gh api --paginate "repos/$REPO/issues/$PR_NUMBER/timeline"', text)
        self.assertIn("'.[] | [(.event // \"\"), (.created_at // \"\")] | @tsv'", text)
        self.assertIn('timeline=(--timeline "$RUNNER_TEMP/timeline.tsv")', text)
        self.assertIn('--pr-created "$PR_CREATED" \\\n            "${timeline[@]}"', text)
        self.assertIn("issues: read", text)
        self.assertNotRegex(text, r":\s*write\b")

    def test_exempt_pr_line(self):  # G1-freeze-b
        self.assertTrue(run(["broker/voice/v.go"], pr=1500, created=AFTER)[0])
        self.assertFalse(run(["broker/voice/v.go"], pr=1501, created=AFTER)[0])

    def test_failure_says_how_to_route_in_flight_work(self):  # G1-freeze-b
        ok, msg = run(["broker/voice/v.go"], pr=1501, created=AFTER)
        text = "\n".join(msg)
        self.assertFalse(ok)
        self.assertIn("`exempt-pr 1501`", text)
        self.assertIn("a plain Re-run replays the old event", text)
        self.assertIn("fail=0 xfail=0 blocked=0", text)

    def test_records_only_and_empty_changes_pass(self):  # G1-freeze-c
        ok, msg = run(["reviews/l3/pr9.md", "BOARD.md", "decisions/D-200.md"], list_text=ON)
        self.assertTrue(ok, msg)
        self.assertTrue(run([""], list_text=ON)[0])
        # A record directory's non-Markdown file is not a record.
        self.assertFalse(run(["reviews/x.py"], list_text=ON)[0])

    def test_switch_off_passes_everything(self):  # G1-freeze-d
        self.assertTrue(run(["broker/voice/v.go"], list_text=SMALL.replace("freeze on", "freeze off"))[0])

    def test_unreadable_lists_fail_closed(self):  # G1-freeze-e
        for bad in ("allow x/\n", ON + "freeze off\n", "freeze maybe\n" + S,
                    ON + "allow ../x\n", ON + "allow /etc/\n", ON + "exempt 4\n",
                    ON + "allow broker/\nfrozen-import broker/loops/\n",
                    ON + "frozen-import broker/loops\n", "freeze on\n",
                    ON + S, "freeze on\nsince 2026-10-14\n", "freeze on\nsince 2026-10-14T19:55:00+01:00\n",
                    ON + "exempt-pr x\n", ON + "exempt-pr\n"):
            with self.assertRaises(g.ListError, msg=bad):
                run(["x"], list_text=bad)
        with self.assertRaises(g.ListError):
            run(["x"], created="yesterday")

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
                    old = ["--git", "HEAD~1", "HEAD", "--pr-created", "2000-01-01T00:00:00Z"]
                    hist = pathlib.Path(d, "timeline.tsv")
                    hist.write_text("committed\t\n")
                    self.assertEqual(g.main(old + ["--timeline", str(hist)]), 0)
                    hist.write_text("reopened\t2030-01-01T00:00:00Z\n")
                    self.assertEqual(g.main(old + ["--timeline", str(hist)]), 1)
                    self.assertEqual(g.main(old), 2)
                    self.assertEqual(g.main(old + ["--timeline", str(pathlib.Path(d, "missing"))]), 2)
                    self.assertEqual(g.main(["--git", "HEAD~1", "HEAD", "--pr-created", "nonsense"]), 2)
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


class ListTest(unittest.TestCase):
    def test_checked_in_list_parses(self):  # G1-freeze-d, -e
        g.parse_list(LIST)
        # The switch is one line, so lifting the freeze is a one-line diff.
        self.assertEqual(len([l for l in LIST.splitlines() if l.startswith("freeze ")]), 1)

    def test_every_entry_exists(self):  # G1-freeze-f
        _, _, allow, frozen, _ = g.parse_list(LIST)
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
        _, _, allow, frozen, _ = g.parse_list(LIST)
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
