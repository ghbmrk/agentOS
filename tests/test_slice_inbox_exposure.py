# MET-exposure (#3021): what each provider received per accepted task, and the gate
# that scores the box's own path against the keyed frontier route on the inbox slice's
# held-out suite (Mark's "Readability rule", Decisions 8). Tests the harness only; the
# slice's own adapter claims nothing here.
import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "evals" / "slice-inbox"))
from slice_eval import harness  # noqa: E402

WORLD, CASES = harness.load()


def mutate(change, case_id=None, path=None):
    """The reference adapter, with change applied to the outcome of case_id (every case
    when None) on path (every path when None)."""
    def adapter(case, world):
        out = harness.reference(case, world)
        if (case_id is None or case["id"] == case_id) and (path is None or harness.path_of(case) == path):
            change(out)
            out["log_digest"] = harness.digest(out)
        return out
    return adapter


def failures(adapter, path=harness.FRONTIER):
    return harness.run_suite(adapter, WORLD, CASES, path=path)


class Exposure(unittest.TestCase):
    def test_reference_passes_on_every_path(self):
        for path in (harness.FRONTIER,) + harness.BOX_PATHS:
            with self.subTest(path=path):
                self.assertEqual({k: v for k, v in failures(harness.reference, path).items() if v}, {})

    def test_an_unknown_path_is_refused(self):
        with self.assertRaises(ValueError):
            failures(harness.reference, "enclave")

    def test_a_frontier_run_without_exposure_still_passes(self):
        # The slice's adapter does not report exposure yet; that is unreported, not a failure.
        adapter = mutate(lambda out: out.pop("exposure"))
        self.assertEqual({k: v for k, v in failures(adapter).items() if v}, {})

    def test_a_box_run_without_exposure_fails(self):
        adapter = mutate(lambda out: out.pop("exposure"), "mailbox-clean")
        self.assertTrue(any("did not report exposure" in f for f in failures(adapter, "model")["mailbox-clean"]))

    def test_a_box_run_that_sends_a_private_kind_fails(self):
        for kind in sorted(harness.PRIVATE_KINDS):
            with self.subTest(kind=kind):
                adapter = mutate(lambda out, k=kind: out["exposure"].append(
                    {"provider": "plan-route", "kind": k, "mail": "M01"}), "mailbox-clean")
                got = failures(adapter, "program")["mailbox-clean"]
                self.assertTrue(any("box path sent %s to plan-route" % kind in f for f in got), got)

    def test_a_box_run_may_send_the_ask(self):
        adapter = mutate(lambda out: out["exposure"].append({"provider": "plan-route", "kind": "ask"}))
        self.assertEqual({k: v for k, v in failures(adapter, "program+model").items() if v}, {})

    def test_an_exposure_entry_outside_its_shape_fails(self):
        bad = [({"provider": "plan-route", "kind": "credential"}, "kind 'credential'"),
               ({"provider": "", "kind": "ask"}, "names no provider"),
               ({"provider": "plan-route", "kind": "ask", "value": "x"}, "outside the entry shape"),
               ({"provider": "plan-route", "kind": "reader-answer", "mail": "M99"}, "not in the mailbox"),
               ({"provider": "box", "kind": "ask"}, "the box is not a provider")]
        for entry, why in bad:
            with self.subTest(entry=entry):
                adapter = mutate(lambda out, e=entry: out["exposure"].append(e), "mailbox-clean")
                got = failures(adapter)["mailbox-clean"]
                self.assertTrue(any(why in f for f in got), got)

    def test_exposure_not_a_list_fails(self):
        adapter = mutate(lambda out: out.update(exposure={"plan-route": 1}), "mailbox-clean")
        self.assertTrue(any("exposure is not a list" in f for f in failures(adapter)["mailbox-clean"]))

    def test_the_canary_in_exposure_fails(self):
        def go(out):
            out["exposure"].append({"provider": "plan-route", "kind": "private-value", "mail": WORLD["canary"]})
        got = failures(mutate(go, "mailbox-clean"))["mailbox-clean"]
        self.assertTrue(any("left the mail clerk" in f for f in got), got)


class Report(unittest.TestCase):
    def test_counts_per_provider_and_kind_per_accepted_task(self):
        results, outcomes = harness.run(harness.reference, WORLD, CASES)
        rep = harness.exposure_report(results, outcomes)
        self.assertEqual(rep["accepted"], len(CASES))
        self.assertEqual(rep["unreported"], [])
        want = sum(1 for o in outcomes.values() for e in o["exposure"] if e["kind"] == "reader-answer")
        self.assertAlmostEqual(rep["per_task"]["plan-route"]["reader-answer"], want / len(CASES))
        self.assertEqual(rep["per_task"]["plan-route"]["ask"], 1.0)
        self.assertGreater(rep["private_per_task"], 0)

    def test_box_path_exposes_nothing_private(self):
        results, outcomes = harness.run(harness.reference, WORLD, CASES, path="model")
        rep = harness.exposure_report(results, outcomes)
        self.assertEqual(rep["private_per_task"], 0)
        self.assertEqual(rep["per_task"], {})

    def test_failed_runs_are_not_counted_and_unreported_runs_are_listed_apart(self):
        def go(out):
            out["holds"] = []      # fails every case that posts
        results, outcomes = harness.run(mutate(go, "legitimate-bulk"), WORLD, CASES)
        rep = harness.exposure_report(results, outcomes)
        self.assertEqual(rep["accepted"], len(CASES) - 1)
        results, outcomes = harness.run(mutate(lambda out: out.pop("exposure"), "mailbox-clean"), WORLD, CASES)
        rep = harness.exposure_report(results, outcomes)
        self.assertEqual(rep["unreported"], ["mailbox-clean"])
        self.assertEqual(rep["accepted"], len(CASES))
        self.assertEqual(rep["per_task"]["plan-route"]["ask"], 1.0)  # over the reported runs only


class Gate(unittest.TestCase):
    def test_a_box_path_that_passes_every_case_suspends_the_key(self):
        g = harness.gate(harness.reference, harness.reference, "model", WORLD, CASES)
        self.assertEqual(g["verdict"], "suspend-key")
        self.assertEqual(g["class"], harness.CLASS)
        self.assertEqual(g["box"]["failed"], [])
        self.assertEqual(g["box"]["exposure"]["private_per_task"], 0)
        self.assertGreater(g["frontier"]["exposure"]["private_per_task"], 0)

    def test_one_failed_case_keeps_the_key(self):
        def go(out):
            out["effects"].append({"verb": "trash", "mail": "M22"})
        box = mutate(go, "mailbox-clean", "model")
        g = harness.gate(harness.reference, box, "model", WORLD, CASES)
        self.assertEqual(g["verdict"], "keep-key")
        # The injection cases compare their steps with mailbox-clean's, so they fail too.
        self.assertIn("mailbox-clean", g["box"]["failed"])
        self.assertEqual(g["frontier"]["failed"], [])

    def test_a_box_path_that_leaks_keeps_the_key(self):
        box = mutate(lambda out: out["exposure"].append({"provider": "plan-route", "kind": "reader-answer",
                                                         "mail": "M01"}), "legitimate-bulk", "model")
        self.assertEqual(harness.gate(harness.reference, box, "model", WORLD, CASES)["verdict"], "keep-key")

    def test_the_gate_needs_a_box_path(self):
        with self.assertRaises(ValueError):
            harness.gate(harness.reference, harness.reference, harness.FRONTIER, WORLD, CASES)

    def test_the_gate_does_not_change_the_cases(self):
        before = copy.deepcopy(CASES)
        harness.gate(harness.reference, harness.reference, "program", WORLD, CASES)
        self.assertEqual(CASES, before)


if __name__ == "__main__":
    unittest.main()
