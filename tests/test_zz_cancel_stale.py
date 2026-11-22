"""CI-cancel-stale-sha (#6529): tools/cancel_stale.py and its workflow, cancel-stale.yml.

REQ: CI-cancel-stale-sha
"""
import json
import os
import pathlib
import random
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import cancel_stale  # noqa: E402

REPO = "o/r"
OLD, NEW, OTHER, MAIN = "a" * 40, "b" * 40, "c" * 40, "d" * 40
CI, TB, GATE = ".github/workflows/ci.yml", ".github/workflows/trusted-base.yml", ".github/workflows/premerge.yml"


def run(rid, sha, status="queued", event="pull_request", attempt=1, path=CI, prs=(7,)):
    return {"id": rid, "name": path.rsplit("/", 1)[-1][:-4], "head_sha": sha, "status": status, "event": event,
            "run_attempt": attempt, "path": path, "pull_requests": [{"number": n} for n in prs]}


class Fake:
    """The REST API over one state; `heads` may be a list of states, one per open-PR read."""

    def __init__(self, heads, runs, fail=()):
        self.heads = heads if isinstance(heads, list) else [heads]
        self.runs = {r["id"]: r for r in runs}
        self.later = {}  # run id -> the run as a re-read returns it
        self.fail = set(fail)
        self.calls = []
        self.reads = 0

    def __call__(self, method, path):
        self.calls.append((method, path))
        for f in self.fail:
            if f in path:
                raise cancel_stale.Unreadable(path)
        page = int(re.search(r"[?&]page=(\d+)", path).group(1)) if "page=" in path else 1
        if method == "GET" and path.startswith(f"repos/{REPO}/pulls?state=open"):
            heads = self.heads[min(self.reads, len(self.heads) - 1)]
            if page == 1:
                self.reads += 1
            items = [{"number": n, "head": {"sha": s}} for n, s in heads.items()]
            return items[(page - 1) * 100:page * 100]
        m = re.fullmatch(rf"repos/{REPO}/actions/runs\?status=(\w+)&per_page=100&page=\d+", path)
        if method == "GET" and m:
            items = [r for r in self.runs.values() if r["status"] == m.group(1)]
            return {"workflow_runs": items[(page - 1) * 100:page * 100]}
        m = re.fullmatch(rf"repos/{REPO}/actions/runs/(\d+)", path)
        if method == "GET" and m:
            rid = int(m.group(1))
            return self.later.get(rid, self.runs[rid])
        m = re.fullmatch(rf"repos/{REPO}/actions/runs/(\d+)/cancel", path)
        if method == "POST" and m and int(m.group(1)) in self.runs:
            return {}
        raise AssertionError(f"unexpected call {method} {path}")

    def cancelled(self):
        return sorted(int(p.split("/")[-2]) for m, p in self.calls if m == "POST")


def sweep(fake, dry=False):
    lines = []
    code = cancel_stale.main(["--repo", REPO] + (["--dry-run"] if dry else []), api=fake, out=lines.append)
    return code, lines


def scenario():
    """PR #7 moved OLD -> NEW: old attempt 1 pending, old attempt 2 queued, old premerge pending; the
    current head has a first attempt, a rerun attempt and a pending premerge."""
    return [run(1, OLD, "pending"), run(2, OLD, attempt=2, path=TB, event="pull_request_target"),
            run(3, OLD, "pending", event="pull_request_target", path=GATE),
            run(11, NEW), run(12, NEW, attempt=3, path=TB, event="pull_request_target"),
            run(13, NEW, "pending", event="pull_request_target", path=GATE),
            run(14, MAIN, "pending", event="workflow_run", path=GATE, prs=())]


class SweepTest(unittest.TestCase):
    def test_only_old_sha_runs_are_cancelled_and_never_the_heads(self):
        fake = Fake({7: NEW, 8: OTHER}, scenario())
        code, lines = sweep(fake)
        self.assertEqual(code, 0)
        self.assertEqual(fake.cancelled(), [1, 2])
        self.assertIn("Cancelled 2 stale run(s).", lines)

    def test_cancel_is_by_run_id_and_the_only_write(self):
        fake = Fake({7: NEW}, scenario())
        sweep(fake)
        writes = [(m, p) for m, p in fake.calls if m != "GET"]
        self.assertEqual(writes, [("POST", f"repos/{REPO}/actions/runs/1/cancel"),
                                  ("POST", f"repos/{REPO}/actions/runs/2/cancel")])
        # each cancel follows a re-read of that same run
        for m, p in writes:
            i = fake.calls.index((m, p))
            self.assertEqual(fake.calls[i - 1], ("GET", p[:-len("/cancel")]))

    def test_premerge_is_never_cancelled_whatever_its_sha(self):
        runs = [run(i, OLD, s, event=e, path=GATE + suffix, prs=p)
                for i, (s, e, suffix, p) in enumerate([("pending", "pull_request_target", "", (7,)),
                                                       ("queued", "pull_request_target", "@refs/heads/main", (7,)),
                                                       ("queued", "workflow_run", "", ()),
                                                       ("pending", "issue_comment", "", ())], 1)]
        fake = Fake({7: NEW}, runs)
        self.assertEqual(sweep(fake), (0, ["Cancelled 0 stale run(s)."]))
        self.assertEqual(fake.cancelled(), [])

    def test_an_unreadable_head_or_listing_cancels_nothing(self):
        bad_heads = [{7: None}, {7: "b" * 39}, {7: NEW.upper()}, {7: NEW + "\n"}, {"7": NEW}]
        for heads in bad_heads:
            fake = Fake(heads, scenario())
            fake.heads = [{n: s for n, s in heads.items()}]
            code, lines = sweep(fake)
            self.assertEqual((code, fake.cancelled()), (1, []), heads)
            self.assertTrue(lines[-1].startswith("::error::nothing cancelled"), lines)
        for fail in ("pulls?state=open", "status=queued", "status=pending"):
            fake = Fake({7: NEW}, scenario(), fail=[fail])
            self.assertEqual((sweep(fake)[0], fake.cancelled()), (1, []), fail)
        # the second read of the open PRs fails: still nothing
        fake = Fake([{7: NEW}, {7: None}], scenario())
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (1, []))
        for body in ({"message": "Not Found"}, None, "x"):
            fake = Fake({7: NEW}, scenario())
            fake.__class__ = type("F", (Fake,), {"__call__": lambda s, m, p, b=body: b if "pulls?" in p
                                                 else Fake.__call__(s, m, p)})
            self.assertEqual((sweep(fake)[0], fake.cancelled()), (1, []), body)

    def test_runs_naming_no_open_pr_are_left_alone(self):
        runs = [run(1, OLD, prs=()), run(2, OLD, prs=(9,)), run(3, OLD, prs=(7, 9)), run(4, OLD, event="push", prs=(7,)),
                run(5, OLD, event="schedule"), run(6, OLD, event="workflow_dispatch")]
        runs[0]["pull_requests"] = None
        fake = Fake({7: NEW}, runs + [run(8, OLD, prs=())])
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))
        for broken in ([{"number": "7"}], [7], [{"number": 7}, {}], [{"number": True}]):
            r = run(1, OLD)
            r["pull_requests"] = broken
            fake = Fake({7: NEW}, [r])
            self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []), broken)

    def test_any_open_prs_head_is_never_cancelled(self):
        # OLD is PR #8's head (another branch or a fork on the same commit): #7's run there stays.
        fake = Fake({7: NEW, 8: OLD}, [run(1, OLD), run(2, OLD, attempt=2)])
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))

    def test_only_queued_or_pending_runs_are_cancelled(self):
        runs = [run(i, OLD, s) for i, s in enumerate(["in_progress", "waiting", "requested", "completed", None], 1)]
        fake = Fake({7: NEW}, runs)
        fake.runs.update({r["id"]: r for r in runs})
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))

    def test_a_malformed_run_is_left_alone(self):
        good = run(1, OLD)
        variants = [dict(good, head_sha=None), dict(good, head_sha="a" * 39), dict(good, head_sha=OLD.upper()),
                    dict(good, path=None), dict(good, id="1"), dict(good, id=True), dict(good, event=None)]
        for v in variants:
            self.assertFalse(cancel_stale.stale(v, {7: NEW}), v)
        self.assertTrue(cancel_stale.stale(good, {7: NEW}))

    def test_the_second_read_and_the_run_reread_must_agree(self):
        # #7 is pushed back to OLD between the two reads: OLD is a head again, nothing cancelled.
        fake = Fake([{7: NEW}, {7: OLD}], [run(1, OLD)])
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))
        # #7 moves on again (NEW -> OTHER): its head changed between the reads, so leave it for the next sweep.
        fake = Fake([{7: NEW}, {7: OTHER}], [run(1, OLD)])
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))
        # #7 closed between the reads.
        fake = Fake([{7: NEW}, {}], [run(1, OLD)])
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))
        # the run started, was re-run onto another head, or now names another PR before the cancel
        for later in (dict(run(1, OLD), status="in_progress"), dict(run(1, OLD), head_sha=NEW),
                      dict(run(1, OLD), pull_requests=[{"number": 8}]), dict(run(1, OLD), id=2), None):
            fake = Fake({7: NEW, 8: OTHER}, [run(1, OLD)])
            fake.later[1] = later
            self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []), later)
        fake = Fake({7: NEW}, [run(1, OLD), run(2, OLD)], fail=["runs/1"])
        code, lines = sweep(fake)
        self.assertEqual((code, fake.cancelled()), (0, [2]))
        self.assertTrue(any(l.startswith("::warning::run 1: not re-read") for l in lines), lines)

    def test_a_refused_cancel_warns_and_the_sweep_goes_on(self):
        fake = Fake({7: NEW}, [run(1, OLD), run(2, OLD)])

        class Refuses(Fake):
            def __call__(self, method, path):
                got = Fake.__call__(self, method, path)
                if method == "POST" and path.endswith("/1/cancel"):
                    raise cancel_stale.Unreadable("HTTP 409")
                return got
        fake.__class__ = Refuses
        code, lines = sweep(fake)
        self.assertEqual(code, 0)
        self.assertEqual([p for m, p in fake.calls if m == "POST"],
                         [f"repos/{REPO}/actions/runs/1/cancel", f"repos/{REPO}/actions/runs/2/cancel"])
        self.assertTrue(lines[0].startswith("::warning::cancel refused for run 1"), lines)
        self.assertIn("Cancelled 1 stale run(s).", lines)

    def test_dry_run_writes_nothing(self):
        fake = Fake({7: NEW}, scenario())
        code, lines = sweep(fake, dry=True)
        self.assertEqual((code, fake.cancelled()), (0, []))
        self.assertEqual([l.split(" (")[0] for l in lines[:-1]], ["would cancel run 1", "would cancel run 2"])

    def test_listings_page_until_a_short_page_and_refuse_past_the_cap(self):
        heads = {n: NEW for n in range(1, 251)}
        runs = [run(1000 + i, OLD, prs=(i % 250 + 1,)) for i in range(230)]
        fake = Fake(heads, runs)
        self.assertEqual((sweep(fake)[0], len(fake.cancelled())), (0, 230))
        heads[251] = OLD  # a PR on the third page holds OLD as its head
        fake = Fake(heads, runs)
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (0, []))
        many = {n: NEW for n in range(1, cancel_stale.PAGES * 100 + 1)}
        fake = Fake(many, runs)
        self.assertEqual((sweep(fake)[0], fake.cancelled()), (1, []))

    def test_random_states_never_cancel_a_head_or_a_gate_run(self):
        rng = random.Random(6529)
        shas = [c * 40 for c in "0123456789abcdef"]
        for _ in range(400):
            heads = [{n: rng.choice(shas) for n in rng.sample(range(1, 9), rng.randint(0, 6))} for _ in range(2)]
            runs = [run(i, rng.choice(shas), rng.choice(["queued", "pending", "in_progress", "waiting"]),
                        rng.choice(["pull_request", "pull_request_target", "push", "workflow_run"]),
                        rng.randint(1, 4), rng.choice([CI, TB, GATE]), tuple(rng.sample(range(1, 10), rng.randint(0, 2))))
                    for i in range(1, rng.randint(1, 30))]
            fake = Fake(heads, runs)
            sweep(fake)
            every_head = set(heads[0].values()) | set(heads[1].values())
            for rid in fake.cancelled():
                r = fake.runs[rid]
                self.assertNotIn(r["head_sha"], every_head)
                self.assertNotEqual(r["path"], GATE)
                self.assertIn(r["status"], ("queued", "pending"))
                self.assertIn(r["event"], ("pull_request", "pull_request_target"))
                self.assertTrue(r["pull_requests"])
                self.assertTrue(all(p["number"] in heads[0] and p["number"] in heads[1] for p in r["pull_requests"]))


class GhTest(unittest.TestCase):
    """The script end to end through a stand-in `gh` on PATH: argv form, exit codes, nothing cancelled on error."""

    def run_script(self, state):
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d, "log")
            pathlib.Path(d, "state.json").write_text(json.dumps(state))
            gh = pathlib.Path(d, "gh")
            gh.write_text("#!%s\n" % sys.executable + '''import json, os, re, sys
d = os.path.dirname(os.path.abspath(__file__))
open(os.path.join(d, "log"), "a").write(json.dumps(sys.argv[1:]) + "\\n")
st = json.load(open(os.path.join(d, "state.json")))
a = sys.argv[1:]
assert a[:2] == ["api", "-X"] and a[3:5] == ["-H", "Accept: application/vnd.github+json"], a
method, path = a[2], a[5]
if st.get("fail"):
    sys.stderr.write("HTTP 502\\n"); sys.exit(1)
if path.startswith("repos/o/r/pulls?"):
    print(json.dumps([{"number": 7, "head": {"sha": st["head"]}}] if "page=1" in path else []))
elif "/actions/runs?status=queued" in path:
    print(json.dumps({"workflow_runs": st["runs"] if "page=1" in path else []}))
elif "/actions/runs?status=" in path:
    print(json.dumps({"workflow_runs": []}))
elif method == "GET":
    rid = int(path.rsplit("/", 1)[1]); print(json.dumps([r for r in st["runs"] if r["id"] == rid][0]))
else:
    print("{}")
''')
            gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ.get("PATH", ""))
            r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "cancel_stale.py"), "--repo", REPO],
                               capture_output=True, text=True, env=env)
            calls = [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []
        return r, calls

    def test_cancels_through_gh_by_id(self):
        r, calls = self.run_script({"head": NEW, "runs": [run(5, OLD), run(6, NEW, attempt=2)]})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c[5] for c in calls if c[2] == "POST"], ["repos/o/r/actions/runs/5/cancel"])
        self.assertIn("cancelled run 5 (ci, pull_request, attempt 1", r.stdout)

    def test_a_failed_read_exits_1_and_cancels_nothing(self):
        r, calls = self.run_script({"head": NEW, "runs": [run(5, OLD)], "fail": True})
        self.assertEqual(r.returncode, 1)
        self.assertIn("::error::nothing cancelled", r.stdout)
        self.assertFalse([c for c in calls if c[2] != "GET"])

    def test_a_bad_repo_reads_nothing(self):
        for repo in ("o", "o/r/x", "o/r?x=1", "../r"):
            out = []
            self.assertEqual(cancel_stale.main(["--repo", repo], api=lambda m, p: self.fail(p), out=out.append), 1)


# cancel-stale.yml holds `actions: write`, so it is pinned line by line like intake.yml: a schedule and
# dispatch only (no PR event), main's code, a credential-free checkout, one run line with no event value.
CANCEL_STALE_LINES = [
    "name: cancel-stale",
    "on:",
    "  schedule:",
    '    - cron: "*/15 * * * *"',
    "  workflow_dispatch:",
    "permissions:",
    "  contents: read",
    "concurrency:",
    "  group: cancel-stale",
    "  cancel-in-progress: false",
    "jobs:",
    "  cancel:",
    "    if: github.ref == 'refs/heads/main'",
    "    runs-on: ubuntu-24.04",
    "    timeout-minutes: 10",
    "    permissions:",
    "      actions: write # cancel a stale run by its id (the script's only write)",
    "      contents: read",
    "      pull-requests: read",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
    "        with:",
    "          persist-credentials: false",
    "      - name: Cancel queued or pending PR runs for no open PR's head (tools/cancel_stale.py)",
    "        env:",
    "          GH_TOKEN: ${{ github.token }}",
    '        run: python3 -I tools/cancel_stale.py --repo "$GITHUB_REPOSITORY"',
]


class WorkflowTest(unittest.TestCase):
    def test_cancel_stale_is_pinned(self):
        text = (ROOT / ".github" / "workflows" / "cancel-stale.yml").read_text()
        self.assertFalse(re.search(r"[^\x20-\x7e\n]", text))
        code = [l for l in text.split("\n") if l.strip() and not l.lstrip().startswith("#")]
        self.assertEqual(code, CANCEL_STALE_LINES)

    def test_the_run_attempt_grouping_is_untouched(self):
        # The sweep relies on CI-cancel-superseded's grouping and never edits it: every PR workflow but premerge
        # still sends a rerun to its own run-<id> group (tests/test_workflows.py SUPERSEDE pins the block).
        for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = wf.read_text()
            if wf.name in ("premerge.yml", "cancel-stale.yml") or not re.search(r"^  pull_request(_target)?:", text, re.M):
                continue
            self.assertIn("github.run_attempt == 1", text, wf.name)


if __name__ == "__main__":
    unittest.main()
