"""A marker or a skipped test must never turn into passing evidence."""
import copy
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import gate_evidence as ge


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "SPEC.md").write_text("- **OP-1** MUST deduplicate.\n")
        self.revision = "a" * 40
        self.events = [{"Action": "run", "Package": "demo", "Test": "TestIntent"},
                       {"Action": "pass", "Package": "demo", "Test": "TestIntent"},
                       {"Action": "pass", "Package": "demo"}]
        self.manifest = {"schema": 1, "gate": "G2", "revision": self.revision, "profile": "vm-fixture",
                         "required": ["OP-1"], "cases": [{"id": "intent", "requirements": ["OP-1"],
                         "package": "demo", "test": "TestIntent", "record": "run.json"}]}
        self.record()

    def record(self, events=None, **changes):
        raw = "".join(json.dumps(e) + "\n" for e in (self.events if events is None else events))
        (self.root / "go.jsonl").write_text(raw)
        r = {"schema": 1, "revision": self.revision, "profile": "vm-fixture", "exit_code": 0,
             "command": ["go", "test", "-json", "-race", "-count=1", "./demo"],
             "started_at": "2026-10-07T00:00:00Z", "finished_at": "2026-10-07T00:01:00Z",
             "artifact": "go.jsonl", "sha256": hashlib.sha256(raw.encode()).hexdigest()}
        r.update(changes)
        (self.root / "run.json").write_text(json.dumps(r))

    def assess(self):
        return ge.assess(self.root, self.manifest, {"OP-1"})

    def test_named_test_and_package_pass_required(self):
        r = self.assess()
        self.assertTrue(r["evidence_complete"])
        self.assertTrue(r["external_review_required"])
        self.assertNotIn("qualified", r)

    def test_skip_fail_absent_or_package_failure_is_incomplete(self):
        for action in ("skip", "fail"):
            events = copy.deepcopy(self.events)
            events[1]["Action"] = action
            self.record(events)
            self.assertFalse(self.assess()["evidence_complete"])
        self.record([self.events[-1]])
        self.assertFalse(self.assess()["evidence_complete"])
        self.record(self.events[:-1])
        self.assertFalse(self.assess()["evidence_complete"])

    def test_fail_then_pass_does_not_hide_failed_repeat(self):
        events = [self.events[0], dict(self.events[1], Action="fail"), *self.events]
        self.record(events)
        self.assertFalse(self.assess()["evidence_complete"])

    def test_revision_profile_and_exit_code_must_match(self):
        for changes in ({"revision": "b" * 40}, {"profile": "different"}, {"exit_code": 1}):
            self.record(**changes)
            self.assertFalse(self.assess()["evidence_complete"])

    def test_modified_missing_or_escaped_artifact_fails(self):
        (self.root / "go.jsonl").write_text("tampered\n")
        self.assertFalse(self.assess()["evidence_complete"])
        self.record(artifact="../outside")
        self.assertFalse(self.assess()["evidence_complete"])
        self.record(artifact="absent")
        self.assertFalse(self.assess()["evidence_complete"])

    def test_unknown_requirement_and_unmapped_required_id_rejected(self):
        self.manifest["required"] = ["XX-9"]
        with self.assertRaises(ValueError):
            self.assess()
        self.manifest["required"] = ["OP-1"]
        self.manifest["cases"] = []
        self.assertFalse(self.assess()["evidence_complete"])

    def test_documentation_marker_supplies_no_execution_evidence(self):
        (self.root / "RESULT.md").write_text("RE" + "Q: OP-1\n")
        self.manifest["cases"][0]["record"] = "RESULT.md"
        self.assertFalse(self.assess()["evidence_complete"])

    def test_cached_or_malformed_events_refused(self):
        self.record(command=["go", "test", "-json", "./demo"])
        self.assertFalse(self.assess()["evidence_complete"])
        self.record([{"Action": "pass", "Package": "demo", "Test": "TestIntent"}, self.events[-1]])
        self.assertFalse(self.assess()["evidence_complete"])
        self.record(command=["go", "test", "-json", "-count=1", "-count=0", "./demo"])
        self.assertFalse(self.assess()["evidence_complete"])

    def test_duplicate_case_ids_rejected(self):
        self.manifest["cases"].append(copy.deepcopy(self.manifest["cases"][0]))
        with self.assertRaises(ValueError):
            self.assess()

    def test_skipped_or_failed_descendant_prevents_parent_completeness(self):
        for action in ('skip', 'fail'):
            events = [self.events[0], {'Action':'run','Package':'demo','Test':'TestIntent/required'},
                      {'Action':action,'Package':'demo','Test':'TestIntent/required'}, *self.events[1:]]
            self.record(events)
            self.assertFalse(self.assess()['evidence_complete'])
        self.record([self.events[0], {'Action':'run','Package':'demo','Test':'TestIntent/required'},
                     {'Action':'pass','Package':'demo','Test':'TestIntent/required'}, *self.events[1:]])
        self.assertTrue(self.assess()['evidence_complete'])

    def test_flags_after_args_cannot_satisfy_uncached_command(self):
        self.record(command=['go','test','-json','./demo','-args','-count=1'])
        self.assertFalse(self.assess()['evidence_complete'])

    def test_invalid_reversed_or_naive_timestamps_refused(self):
        for changes in [ {'started_at':'not-a-time'}, {'finished_at':'2026-10-06T00:00:00Z'},
                         {'started_at':'2026-10-07T00:00:00'} ]:
            self.record(**changes)
            self.assertFalse(self.assess()['evidence_complete'])
