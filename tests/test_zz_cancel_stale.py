"""CI-cancel-stale-sha (#6529): trusted-base-rerun.yml's first step cancels waiting trusted-base attempts whose
commit is no open PR's head. The step is pinned line by line in tests/test_trusted_base.py (RERUN_PIN); this
runs it against a stub `gh` that answers each read from JSON with the step's own --jq expression.

REQ: CI-cancel-stale-sha
"""
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows" / "trusted-base-rerun.yml"
STEP = "      - name: Cancel waiting trusted-base attempts on no open PR's head"
OLD, NEW, OTHER = "a" * 40, "b" * 40, "c" * 40
LISTING = "repos/o/r/actions/workflows/trusted-base.yml/runs?event=pull_request_target&status={}&per_page=100"


def cancel_script():
    """The cancel step's `run:` block, as one bash script."""
    lines = WF.read_text().split("\n")
    i = lines.index(STEP)
    start = next(j for j in range(i, len(lines)) if lines[j].strip() == "run: |") + 1
    end = next(j for j in range(start, len(lines)) if lines[j].startswith("      - name:"))
    return "\n".join(l[10:] for l in lines[start:end] if l.strip()) + "\n"


STUB = r'''import json, os, subprocess, sys
st = json.load(open(os.environ["STUB"] + "/state.json"))
a = sys.argv[1:]
open(os.environ["STUB"] + "/calls", "a").write(json.dumps(a) + "\n")
assert a[0] == "api", a
a = a[1:]
if a[:2] == ["-X", "POST"]:
    rid = int(a[2].split("/")[-2])
    sys.exit(1 if rid in st.get("refuse", []) else 0)
if a[0] == "--paginate":
    a = a[1:]
path, jq = a[0], a[2]
assert a[1] == "--jq", a
if path in st.get("fail", []):
    sys.exit(1)
if path.startswith("repos/o/r/pulls?state=open&per_page=100"):
    body = st["prs"]
elif path.startswith("repos/o/r/actions/workflows/trusted-base.yml/runs?"):
    status = path.split("status=")[1].split("&")[0]
    body = {"workflow_runs": [r for r in st["runs"] if r["status"] == status]}
elif path.startswith("repos/o/r/actions/runs/"):
    rid = path.rsplit("/", 1)[1]
    body = st.get("later", {}).get(rid) or [r for r in st["runs"] if str(r["id"]) == rid][0]
else:
    sys.exit(7)
sys.exit(subprocess.run(["jq", "-r", jq], input=json.dumps(body), text=True).returncode)
'''


def run(rid, sha, status="queued", attempt=2, prs=(7,)):
    return {"id": rid, "head_sha": sha, "status": status, "run_attempt": attempt,
            "pull_requests": [{"number": n} for n in prs]}


class CancelStep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "bin"))
        gh = pathlib.Path(self.tmp, "bin", "gh")
        gh.write_text("#!%s\n%s" % (sys.executable, STUB))
        gh.chmod(0o755)

    def sweep(self, heads, runs, **extra):
        state = {"prs": [{"number": n, "head": {"sha": s}} for n, s in heads.items()], "runs": runs, **extra}
        pathlib.Path(self.tmp, "state.json").write_text(json.dumps(state))
        calls = pathlib.Path(self.tmp, "calls")
        if calls.exists():
            calls.unlink()
        env = {**os.environ, "PATH": os.path.join(self.tmp, "bin") + os.pathsep + os.environ["PATH"],
               "STUB": self.tmp, "REPO": "o/r", "GITHUB_STEP_SUMMARY": os.path.join(self.tmp, "summary")}
        r = subprocess.run(["bash", "-eo", "pipefail", "-c", cancel_script()], env=env, capture_output=True, text=True)
        self.calls = [json.loads(l) for l in calls.read_text().splitlines()] if calls.exists() else []
        cancelled = [int(c[3].split("/")[-2]) for c in self.calls if c[1:3] == ["-X", "POST"]]
        return r.returncode, r.stdout + r.stderr, cancelled

    def test_only_waiting_attempts_on_an_old_sha_are_cancelled(self):
        # #7 moved OLD -> NEW: OLD's attempt 1 pending, attempt 2 queued; NEW's attempts 1 and 3 waiting.
        runs = [run(1, OLD, "pending", 1), run(2, OLD), run(11, NEW, attempt=1), run(12, NEW, "pending", 3),
                run(3, OLD, "in_progress"), run(4, OLD, "waiting")]
        code, out, cancelled = self.sweep({7: NEW, 8: OTHER}, runs)
        self.assertEqual((code, sorted(cancelled)), (0, [1, 2]), out)
        self.assertIn("Cancelled 2 waiting trusted-base attempt(s) on no open PR's head.", out)
        self.assertIn(f"cancelled run 2 ({OLD}, PR 7): no open PR's head", out)

    def test_each_cancel_is_by_id_after_a_reread_and_only_trusted_base_is_listed(self):
        self.sweep({7: NEW}, [run(1, OLD), run(2, OLD, "pending")])
        writes = [c for c in self.calls if "-X" in c]
        self.assertEqual([c[1:] for c in writes], [["-X", "POST", "repos/o/r/actions/runs/1/cancel"],
                                                   ["-X", "POST", "repos/o/r/actions/runs/2/cancel"]])
        for w in writes:
            i = self.calls.index(w)
            self.assertEqual(self.calls[i - 1][1], w[3][:-len("/cancel")])
        listed = [c[2] for c in self.calls if c[1] == "--paginate" and "/runs?" in c[2]]
        self.assertEqual(listed, [LISTING.format("queued"), LISTING.format("pending")])
        # the heads are read after the runs, so no head is older than a run it is compared with
        order = [c[2] for c in self.calls if c[1] == "--paginate"]
        self.assertTrue(order[-1].startswith("repos/o/r/pulls?state=open"), order)

    def test_any_open_prs_head_is_never_cancelled(self):
        code, out, cancelled = self.sweep({7: NEW, 8: OLD}, [run(1, OLD), run(2, OLD, attempt=5)])
        self.assertEqual((code, cancelled), (0, []), out)

    def test_runs_naming_no_open_pr_are_left_alone(self):
        runs = [run(1, OLD, prs=()), run(2, OLD, prs=(9,)), run(3, OLD, prs=(7, 9))]
        code, out, cancelled = self.sweep({7: NEW}, runs)
        self.assertEqual((code, cancelled), (0, []), out)

    def test_an_unreadable_head_or_listing_cancels_nothing_and_warns(self):
        for heads in ({7: None}, {7: "b" * 39}, {7: NEW.upper()}, {7: NEW + " x"}):
            code, out, cancelled = self.sweep(heads, [run(1, OLD)])
            self.assertEqual((code, cancelled), (0, []), heads)
            self.assertIn("::warning::an open PR's head is unreadable; nothing cancelled", out)
        for fail in (LISTING.format("queued"), LISTING.format("pending"), "repos/o/r/pulls?state=open&per_page=100"):
            code, out, cancelled = self.sweep({7: NEW}, [run(1, OLD)], fail=[fail])
            self.assertEqual((code, cancelled), (0, []), fail)
            self.assertIn("nothing cancelled", out)
        # a run whose pull_requests is not a list makes the listing's jq fail: nothing cancelled
        bad = run(1, OLD)
        bad["pull_requests"] = None
        self.assertEqual(self.sweep({7: NEW}, [bad, run(2, OLD)])[2], [])
        # no open PR at all: nothing to compare with, nothing cancelled
        code, out, cancelled = self.sweep({}, [run(1, OLD)])
        self.assertEqual((code, cancelled), (0, []), out)

    def test_the_reread_must_still_be_waiting_on_the_same_sha_and_prs(self):
        for later in ({"status": "in_progress"}, {"head_sha": NEW}, {"pull_requests": [{"number": 8}]},
                      {"status": "completed"}):
            r = run(1, OLD)
            code, out, cancelled = self.sweep({7: NEW, 8: OTHER}, [r], later={"1": {**r, **later}})
            self.assertEqual((code, cancelled), (0, []), later)
        code, out, cancelled = self.sweep({7: NEW}, [run(1, OLD), run(2, OLD)], fail=["repos/o/r/actions/runs/1"])
        self.assertEqual((code, cancelled), (0, [2]), out)
        self.assertIn("::warning::run 1 not re-read; left alone", out)

    def test_a_refused_cancel_warns_and_the_step_goes_on(self):
        code, out, cancelled = self.sweep({7: NEW}, [run(1, OLD), run(2, OLD)], refuse=[1])
        self.assertEqual((code, cancelled), (0, [1, 2]), out)
        self.assertIn("::warning::cancel of run 1 refused", out)
        self.assertIn("Cancelled 1 waiting", out)

    def test_only_patterned_values_reach_the_log(self):
        # GitHub writes these fields, but nothing the step prints may carry a workflow command or a newline.
        evil = [run(1, "::error::x" + "a" * 30), run(2, OLD + "\n::warning::y"), {**run(3, OLD), "id": "3\n::x"}]
        code, out, cancelled = self.sweep({7: NEW}, evil)
        self.assertEqual((code, cancelled), (0, []), out)
        for s in ("::error::x", "::warning::y", "::x"):
            self.assertNotIn(s, out)
        text = WF.read_text()
        step = text[text.index(STEP):text.index("      - name: Rerun every open PR")]
        self.assertNotIn("${{ github.event", step)
        self.assertNotIn(".name", step)

    def test_random_states_cancel_exactly_the_stale_waiting_runs(self):
        rng = random.Random(6529)
        shas = [c * 40 for c in "0123456789abcdef"]
        for _ in range(60):
            heads = {n: rng.choice(shas) for n in rng.sample(range(1, 9), rng.randint(1, 6))}
            runs = [run(i, rng.choice(shas), rng.choice(["queued", "pending", "in_progress"]), rng.randint(1, 4),
                        tuple(rng.sample(range(1, 10), rng.randint(0, 2)))) for i in range(1, rng.randint(2, 12))]
            code, out, cancelled = self.sweep(heads, runs)
            self.assertEqual(code, 0, out)
            want = [r["id"] for s in ("queued", "pending") for r in runs if r["status"] == s and r["pull_requests"]
                    and r["head_sha"] not in heads.values() and all(p["number"] in heads for p in r["pull_requests"])]
            self.assertEqual(cancelled, want)


class Grouping(unittest.TestCase):
    def test_the_run_attempt_grouping_is_untouched(self):
        # The step relies on CI-cancel-superseded and never edits it: every PR workflow but premerge still sends a
        # rerun to its own run-<id> group (tests/test_workflows.py SUPERSEDE pins the block).
        for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = wf.read_text()
            if wf.name == "premerge.yml" or "\n  pull_request" not in text.split("\njobs:")[0]:
                continue
            self.assertIn("github.run_attempt == 1", text, wf.name)


if __name__ == "__main__":
    unittest.main()
