"""Tests for tools/g1_scope.py, its lists and its workflow (G1-freeze, #1687; G2, D-128).

No requirement IDs: CI tooling that holds work to a gate's path (G1: A1, D-104; G2: A4, A5,
A9 and A14, D-128), not SPEC.md behaviour. The local cases are G1-freeze-a (paths outside the list fail, listed paths and
G1 fixes pass), -b (PRs opened before the freeze and exempt-pr lines), -c (records-only and empty changes), -d (the
switch), -e (fail closed), -f (the list keeps up with the G1 binaries' imports) and -g (a PR
reopened, force-pushed or retargeted after the freeze began loses the time exemption, #1717).
D-128 adds -h: every gate's list applies, G1's is off and G2's is on.
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
G2_LIST = (ROOT / "tools" / "g1_scope_g2.txt").read_text()
G2 = g.GATES[1]

# The binaries the G1 path ships or runs (see the header of tools/g1_scope.txt).
G1_BINARIES = (
    "agentosd", "agentos-egress", "agentos-localui", "agentos-ap", "agentos-modem",
    "agentos-netjoin", "agentos-guest-bridge", "agentos-seller", "agentos-checker",
    "agentos-clock-boot", "agentos-hostdisk",
)
# G2's binaries: G1's plus the key holder and the release signer (header of g1_scope_g2.txt).
G2_BINARIES = G1_BINARIES + ("agentos-holder", "agentos-release")

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
            os.makedirs(pathlib.Path(d, "broker/attention"))
            pathlib.Path(d, "broker/attention/a.go").write_text("package attention")
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

    def test_messages_name_the_gate_and_its_list(self):  # G1-freeze-h
        ok, msg = g.check(["broker/attention/a.go"], SMALL, gate=G2)
        self.assertFalse(ok)
        self.assertTrue(msg[0].startswith("g2 freeze:"), msg)
        text = "\n".join(msg)
        self.assertIn("outside the G2 list (tools/g1_scope_g2.txt)", text)
        self.assertIn("A4, A5, A9 and A14 pass on a VM", text)
        self.assertNotIn("g1_scope.txt", text)
        with self.assertRaisesRegex(g.ListError, "g1_scope_g2.txt"):
            g.check(["x"], "freeze on\n", gate=G2)

    def test_a_pr_must_pass_every_gate(self):  # G1-freeze-h
        with tempfile.TemporaryDirectory() as d:
            here, g.HERE = g.HERE, pathlib.Path(d)
            shutil.copy(here / "ci_scope.py", d)
            try:
                lists = {"g1_scope.txt": SMALL.replace("freeze on", "freeze off"),
                         "g1_scope_g2.txt": SMALL}
                for name, text in lists.items():
                    pathlib.Path(d, name).write_text(text)
                with _quiet():
                    self.assertEqual(g.main(["broker/localui/x.go"]), 0)
                    self.assertEqual(g.main(["broker/voice/v.go"]), 1)
                    pathlib.Path(d, "g1_scope.txt").write_text(SMALL.replace("allow image/\n", ""))
                    self.assertEqual(g.main(["image/build.sh"]), 1)
                    pathlib.Path(d, "g1_scope_g2.txt").unlink()
                    self.assertEqual(g.main(["broker/localui/x.go"]), 2)
            finally:
                g.HERE = here


class _quiet:
    def __enter__(self):
        self.out, self.err = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = open(os.devnull, "w")

    def __exit__(self, *a):
        sys.stdout.close()
        sys.stdout, sys.stderr = self.out, self.err


class ListTest(unittest.TestCase):
    def test_checked_in_lists_parse(self):  # G1-freeze-d, -e, -h
        for name, text in (("g1_scope.txt", LIST), ("g1_scope_g2.txt", G2_LIST)):
            g.parse_list(text, name)
            # The switch is one line, so lifting a freeze is a one-line diff.
            self.assertEqual(len([l for l in text.splitlines() if l.startswith("freeze ")]), 1, name)

    def test_g1_is_off_and_g2_is_on(self):  # G1-freeze-h (D-128)
        self.assertEqual([gate[1] for gate in g.GATES], ["g1_scope.txt", "g1_scope_g2.txt"])
        self.assertFalse(g.parse_list(LIST)[0])
        self.assertTrue(g.parse_list(G2_LIST, "g1_scope_g2.txt")[0])

    def test_every_entry_exists(self):  # G1-freeze-f
        for name, text in (("g1_scope.txt", LIST), ("g1_scope_g2.txt", G2_LIST)):
            _, _, allow, frozen, _ = g.parse_list(text, name)
            for e in allow + frozen:
                self.assertTrue((ROOT / e).exists(), f"{name}: {e} names nothing in the repo")

    def test_frozen_paths_stay_out(self):  # G1-freeze-a, -h
        # D-098's groups and what no G2 test needs.
        for p in ("broker/loops/x.go", "broker/loop7/x.go", "broker/machprobe/x.go",
                  "broker/sockprobe/x.go", "broker/compile/x.go", "broker/skill/x.go",
                  "broker/cleanroom/x.go", "broker/hint/x.go", "broker/pubid/x.go",
                  "broker/pubsend/x.go", "broker/sipsign/x.go", "broker/smsapi/x.go",
                  "broker/sendrules/x.go", "broker/attention/x.go", "broker/floor/x.go",
                  "broker/probecmd/x.go", "broker/cmd/agentos-builder/main.go",
                  "broker/cmd/agentos-a8scan/main.go", "guest/builder/x", "spikes/S10-pact/x",
                  "evals/review/x", "broker/newpkg/x.go", "broker/projection/x.go", "newdir/x"):
            self.assertFalse(g.check([p], G2_LIST, gate=G2)[0], p)
        for p in ("broker/localui/x.go", "broker/cmd/agentosd/main.go", "image/build.sh",
                  "guest/openclaw/x", "guest/codex/x", "spikes/CTRL-spike/x", "spikes/S8-live/x",
                  "tools/g1_scope_g2.txt", "SPEC.md", "broker/provagent/x.go",
                  "broker/route/route.go", "broker/route/anthropic.go", "broker/voice/v.go",
                  "broker/browser/x.go", "broker/recall/x.go",
                  "broker/holder/x.go", "broker/cmd/agentos-holder/main.go",
                  "broker/cmd/agentos-release/main.go", "broker/test/a9/x.sh",
                  "broker/photo/x.go", "broker/cmd/agentos-photo/main.go"):
            self.assertTrue(g.check([p], G2_LIST, gate=G2)[0], p)


class GoImportsTest(unittest.TestCase):
    # Its own class so the records-only CI run, which sets up no Go, can name the other two:
    # a records-only change cannot change what the G1 binaries import.
    def test_lists_cover_their_binaries_imports(self):  # G1-freeze-f, -h
        go = shutil.which("go")
        if not go:
            if os.environ.get("CI"):
                self.fail("go is not on PATH in CI")
            self.skipTest("no go toolchain")
        broker = ROOT / "broker"
        mod = subprocess.run([go, "list", "-m"], cwd=broker, check=True,
                             capture_output=True, text=True).stdout.strip()
        for gate, text, binaries in (("G1", LIST, G1_BINARIES), ("G2", G2_LIST, G2_BINARIES)):
            out = subprocess.run([go, "list", "-deps", *[f"./cmd/{b}" for b in binaries]],
                                 cwd=broker, check=True, capture_output=True, text=True).stdout
            _, _, allow, frozen, _ = g.parse_list(text)
            missing = []
            for pkg in out.split():
                if pkg.startswith(mod + "/"):
                    path = "broker/" + pkg[len(mod) + 1:] + "/"
                    # A package listed file by file (broker/route/) counts when any entry is in it.
                    if not any(path.startswith(e) if e.endswith("/") else e.startswith(path)
                               for e in allow + frozen):
                        missing.append(path)
            self.assertEqual(missing, [], f"{gate} binaries import packages its list does not name")


if __name__ == "__main__":
    unittest.main()
