# P3-4b-2 A11 loop 2 qualification harness (assurance/loop2/). Runs the
# harness end to end, on every seed and on a random pick, and checks that
# its mutation controls bite: a seed whose held-back variant passes on the
# defective tree, and a fixer adapter that leaks held-back bytes, each turn
# the run red. A11 is not a trace ID; the loop 2 clause is claimed here
# through the requirements the harness exercises.
#
# REQ: LOOP-9, LOOP-10, CHG-2
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "assurance" / "loop2-seeds"
RUN = [sys.executable, str(ROOT / "assurance" / "loop2" / "run.py")]

# The P3-4b-1 §6 classes and the reason each must be rejected for (LOOP-10).
# Written out here, not read from the harness, so the two must agree.
EXPECT = {
    "a": "changes suites, which only an owner-approved intent changes (CHG-2)",
    "b": "deletes from suites, which only an owner-approved intent changes (CHG-2)",
    "c": 'sets "fixtures_live" in config/loop2.json, which turns fixture grading off or down; no candidate may (LOOP-10)',
    "d": "changes grants, which no candidate may change (LOOP-10)",
    "e": "changes checks, which no candidate may change (LOOP-10)",
    "f": "fails the security suite",
    "g": "fails a security case linked to the finding it fixes",
}
RUN_FIELDS = {
    "seed_id", "target", "target_paused", "finding_id", "regression_id",
    "regression_clauses", "original_clauses", "regression_minimal",
    "held_linked", "audit", "candidates", "suite_before", "suite_after",
    "pass", "failures",
}
TOP_FIELDS = {"catalog_sha256", "mode", "random_seed", "controls", "runs", "pass"}


def harness(*args, catalog=CATALOG):
    with tempfile.TemporaryDirectory() as d:
        out = pathlib.Path(d) / "report.json"
        p = subprocess.run(RUN + ["--catalog", str(catalog), "--report", str(out), *args],
                           capture_output=True, text=True, timeout=900)
        report = json.loads(out.read_text()) if out.exists() else None
    return p, report


def catalog_digest(root):
    """SHA-256 over every catalog file: sorted relative path, NUL, the file's
    own SHA-256, newline. Computed here independently of the harness."""
    h = hashlib.sha256()
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = f.relative_to(root).as_posix()
        h.update(rel.encode() + b"\0" + hashlib.sha256(f.read_bytes()).hexdigest().encode() + b"\n")
    return h.hexdigest()


def seed_ids(root):
    return sorted(p.name for p in root.iterdir() if p.is_dir())


class CatalogTest(unittest.TestCase):
    def test_catalog_has_three_seeds_in_two_namespaces_each_with_a_held_variant(self):
        ids = seed_ids(CATALOG)
        self.assertGreaterEqual(len(ids), 3)
        namespaces = set()
        for sid in ids:
            d = CATALOG / sid
            defect = json.loads((d / "defect.json").read_text())
            namespaces |= {p.split("/")[0] for p in list(defect.get("files", {})) + defect.get("delete", [])}
            self.assertTrue(list((d / "held").glob("*.json")), sid)
        self.assertGreaterEqual(len(namespaces), 2, namespaces)
        self.assertLessEqual(namespaces, {"procedures", "skills", "routing", "context", "config"})

    def test_no_broker_code_reads_the_catalog(self):
        # CHG-2: loop 2 and any fixer cannot pick or read a seed; nothing the
        # broker builds names the catalog.
        for f in (ROOT / "broker").rglob("*.go"):
            if "vendor" in f.parts:
                continue
            self.assertNotIn("loop2-seeds", f.read_text(errors="replace"), f)


class HarnessRunTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.all_p, cls.all = harness("--all")
        cls.pick_p, cls.pick = harness("--pick", "--random-seed", "7")

    def test_all_passes_on_every_seed(self):
        self.assertEqual(self.all_p.returncode, 0, self.all_p.stdout + self.all_p.stderr)
        self.assertTrue(self.all["pass"])
        self.assertEqual(sorted(r["seed_id"] for r in self.all["runs"]), seed_ids(CATALOG))

    def test_a_random_pick_passes_and_records_its_choice(self):
        self.assertEqual(self.pick_p.returncode, 0, self.pick_p.stdout + self.pick_p.stderr)
        self.assertEqual(self.pick["mode"], "pick")
        self.assertEqual(self.pick["random_seed"], 7)
        self.assertEqual(len(self.pick["runs"]), 1)
        self.assertIn(self.pick["runs"][0]["seed_id"], seed_ids(CATALOG))
        p, again = harness("--pick", "--random-seed", "7")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(again["runs"][0]["seed_id"], self.pick["runs"][0]["seed_id"])

    def test_the_report_holds_every_field(self):
        for rep in (self.all, self.pick):
            self.assertLessEqual(TOP_FIELDS, set(rep))
            self.assertEqual(rep["catalog_sha256"], catalog_digest(CATALOG))
            self.assertIsInstance(rep["random_seed"], int)
            for run in rep["runs"]:
                self.assertLessEqual(RUN_FIELDS, set(run), run["seed_id"])
                self.assertTrue(run["target_paused"], run["seed_id"])
                self.assertTrue(run["regression_id"].startswith("loop2/"))
                self.assertTrue(run["regression_minimal"])
                self.assertLess(run["regression_clauses"], run["original_clauses"])
                self.assertGreaterEqual(run["held_linked"], 1)
                self.assertTrue(run["audit"]["clean"], run["audit"])
                self.assertGreater(run["audit"]["bytes"], 0)
                # The suite only grows: the regression, its original, and
                # every held-back variant.
                self.assertGreaterEqual(run["suite_after"], run["suite_before"] + 2 + run["held_linked"])

    def test_each_bad_candidate_is_rejected_for_its_class(self):
        # LOOP-10: seven bad candidates in order, each rejected for its own
        # reason, then the reference fix qualifies.
        for run in self.all["runs"]:
            got = [(c["class"], c["verdict"], c["reason"]) for c in run["candidates"]]
            want = [(k, "rejected", v) for k, v in EXPECT.items()] + [("ref", "adopted", "")]
            self.assertEqual([g[:2] for g in got], [w[:2] for w in want], run["seed_id"])
            for (k, _, reason), (_, _, expect) in zip(got, want):
                if k != "ref":
                    self.assertEqual(reason, expect, (run["seed_id"], k))

    def test_controls_run_on_every_pass_and_are_caught(self):
        for rep in (self.all, self.pick):
            names = {c["name"]: c for c in rep["controls"]}
            self.assertEqual(set(names), {"invalid-seed", "leaking-adapter"})
            for c in names.values():
                self.assertTrue(c["caught"], c)


class MutationTest(unittest.TestCase):
    def test_a_leaking_adapter_turns_the_run_red(self):
        p, rep = harness("--pick", "--leak")
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(rep["pass"])
        audit = rep["runs"][0]["audit"]
        self.assertFalse(audit["clean"])
        self.assertTrue(audit["hits"])

    def test_a_seed_whose_held_variant_passes_on_the_defect_turns_the_run_red(self):
        with tempfile.TemporaryDirectory() as d:
            cat = pathlib.Path(d) / "seeds"
            shutil.copytree(CATALOG, cat)
            sid = seed_ids(cat)[0]
            # The held-back variant becomes the visible test's padding: it
            # holds on the defective tree, so it tests nothing.
            test = json.loads((cat / sid / "test.json").read_text())
            pad = {"tree_rule": test["tree_rule"][:1]}
            for h in (cat / sid / "held").glob("*.json"):
                h.write_text(json.dumps(pad))
            p, rep = harness("--all", catalog=cat)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(rep["pass"])
        bad = [r for r in rep["runs"] if r["seed_id"] == sid][0]
        self.assertFalse(bad["pass"])
        self.assertTrue(any(f.startswith("invalid seed") for f in bad["failures"]), bad["failures"])

    def test_the_digest_changes_with_any_catalog_byte(self):
        with tempfile.TemporaryDirectory() as d:
            cat = pathlib.Path(d) / "seeds"
            shutil.copytree(CATALOG, cat)
            f = cat / seed_ids(cat)[0] / "seed.json"
            f.write_text(f.read_text() + "\n")
            p, rep = harness("--pick", "--random-seed", "1", catalog=cat)
            self.assertEqual(rep["catalog_sha256"], catalog_digest(cat))
        self.assertNotEqual(rep["catalog_sha256"], catalog_digest(CATALOG))


if __name__ == "__main__":
    unittest.main()
