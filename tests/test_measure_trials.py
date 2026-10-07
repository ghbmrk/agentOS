import copy, hashlib, pathlib, tempfile, unittest
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import measure_trials as b


class TrialTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "oracle.txt").write_text("synthetic correctness only")
        self.t = {
            "schema": 1,
            "run_id": "a",
            "arm": "agentos",
            "task_id": "fixture-1",
            "workload_sha256": "a" * 64,
            "profile_id": "synthetic-self-test",
            "start_state_sha256": "b" * 64,
            "versions": {"agent": "fixture"},
            "route_id": "fixture",
            "repetition": 1,
            "phase": "first-use",
            "started_at": "2026-10-07T00:00:00Z",
            "finished_at": "2026-10-07T00:02:00Z",
            "owner_active_seconds": 60,
            "necessary_approvals": 1,
            "avoidable_approvals": 0,
            "failures": 0,
            "fallbacks": 0,
            "judgment": "accepted",
            "judgment_source": "external-reviewer",
            "evidence": [
                {
                    "path": "oracle.txt",
                    "sha256": hashlib.sha256(
                        (self.root / "oracle.txt").read_bytes()
                    ).hexdigest(),
                }
            ],
            "resources": {},
        }

    def test_complete_requires_all_arms(self):
        self.assertFalse(b.summarize(self.root, [self.t])["matched_three_arm_complete"])
        ts = [dict(self.t, arm=a, run_id=a) for a in b.ARMS]
        self.assertTrue(b.summarize(self.root, ts)["matched_three_arm_complete"])

    def test_pending_has_no_pairwise_comparison(self):
        ts = [
            dict(
                self.t,
                arm=a,
                run_id=a,
                judgment="pending" if a == "agentos" else "accepted",
            )
            for a in b.ARMS
        ]
        r = b.summarize(self.root, ts)
        self.assertFalse(r["matched_three_arm_complete"])
        self.assertNotIn("paired_owner_seconds_differences_both_accepted", r)

    def test_rejected_effort_counts(self):
        r = b.summarize(
            self.root,
            [self.t, dict(self.t, run_id="b", repetition=2, judgment="rejected")],
        )
        self.assertEqual(r["arms"]["agentos"]["owner_minutes_per_accepted_task"], 2)

    def test_fake_judgment_source_refused(self):
        with self.assertRaises(ValueError):
            b.validate(self.root, dict(self.t, judgment_source="agent"))

    def test_bool_negative_nan_and_impossible_effort_refused(self):
        for value in [True, -1, float("nan"), 121]:
            with self.assertRaises(ValueError):
                b.validate(self.root, dict(self.t, owner_active_seconds=value))

    def test_resource_conversion_refused(self):
        for metrics in [
            {"plan_quota": {"value": 1, "unit": "USD"}},
            {"tokens": {"value": 1, "unit": "USD"}},
            {"plan_quota": {"value": 1, "unit": "declared-pool-units"}},
        ]:
            with self.assertRaises(ValueError):
                b.validate(self.root, dict(self.t, resources=metrics))

    def test_escaped_or_tampered_evidence_refused(self):
        for evidence in [
            [{"path": "../oracle.txt", "sha256": "a" * 64}],
            [{"path": "oracle.txt", "sha256": "a" * 64}],
        ]:
            with self.assertRaises(ValueError):
                b.validate(self.root, dict(self.t, evidence=evidence))

    def test_duplicate_run_or_arm_refused(self):
        for ts in [[self.t, self.t], [self.t, dict(self.t, run_id="other")]]:
            with self.assertRaises(ValueError):
                b.summarize(self.root, ts)

    def test_different_start_state_is_not_matched(self):
        ts = [
            dict(
                self.t,
                run_id=a,
                arm=a,
                start_state_sha256=("c" if a == "provider-cli" else "b") * 64,
            )
            for a in b.ARMS
        ]
        self.assertFalse(b.summarize(self.root, ts)["matched_three_arm_complete"])

    def test_rejected_goal_has_no_accepted_pair_gain(self):
        ts = [
            dict(
                self.t,
                arm=a,
                run_id=a,
                judgment="rejected" if a == "agentos" else "accepted",
            )
            for a in b.ARMS
        ]
        r = b.summarize(self.root, ts)
        self.assertEqual(
            r["paired_owner_seconds_differences_both_accepted"]["openclaw"], []
        )


if __name__ == "__main__":
    unittest.main()
