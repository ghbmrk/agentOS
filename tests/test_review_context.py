"""Context packets must stay bounded, current, and separate by review role."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import review_context as rc


class ContextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.write("SPEC.md", "# Spec\n- **OP-1** MUST deduplicate.\n  Across restart too.\n- **OP-2** Persist.\n")
        self.write("BOARD.md", "| ID | Package | Needs | State |\n|---|---|---|---|\n| DEMO | journal | H0 | queued |\n")
        self.write("CLAUDE.md", "Fresh reviewers do not receive builder reasoning.\n")
        self.write("broker/demo.go", "package demo\n")
        self.write("broker/ASSUMPTIONS.md", "# Assumptions\n| K1 | restart | OP-1 |\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture")
        self.brief = {"schema": 1, "package": "DEMO", "revision": self.git("rev-parse", "HEAD").strip(),
                      "requirements": ["OP-1"], "scope": ["broker/demo.go"],
                      "references": [{"path": "broker/ASSUMPTIONS.md", "start": 2, "end": 2}],
                      "tests": ["go test ./demo"], "dependencies": ["H0"],
                      "out_of_scope": ["spec changes"], "pending_reviews": [],
                      "budget": {"estimate": "one focused patch", "checkpoint": "after first test run"}}

    def write(self, name, value):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True)

    def test_exact_requirement_and_board_context(self):
        p = rc.build(self.root, self.brief, "builder")
        self.assertIn("Across restart", p["requirements"]["OP-1"])
        self.assertNotIn("OP-2", p["requirements"])
        self.assertIn("queued", p["board_row"])
        self.assertEqual(p["sources"]["broker/ASSUMPTIONS.md"]["content"], "| K1 | restart | OP-1 |\n")

    def test_reviewer_excludes_handoff(self):
        h = {"next_step": "run tests", "builder_reasoning": "BUILDER_PRIVATE_REASONING"}
        self.assertIn("BUILDER_PRIVATE_REASONING", json.dumps(rc.build(self.root, self.brief, "builder", h)))
        self.assertNotIn("BUILDER_PRIVATE_REASONING", json.dumps(rc.build(self.root, self.brief, "reviewer", h)))

    def test_stale_revision_rejected(self):
        self.brief["revision"] = "0" * 40
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder")

    def test_hash_check_catches_uncommitted_change(self):
        p = rc.build(self.root, self.brief, "builder")
        rc.check(self.root, p)
        self.write("broker/demo.go", "package changed\n")
        with self.assertRaises(ValueError):
            rc.check(self.root, p)

    def test_paths_cannot_escape_root_or_follow_external_symlink(self):
        for path in ("../outside", "/etc/passwd"):
            self.brief["scope"] = [path]
            with self.assertRaises(ValueError):
                rc.build(self.root, self.brief, "builder")
        (self.root / "broker/link").symlink_to("/etc/passwd")
        self.brief["scope"] = ["broker/link"]
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder")

    def test_missing_unknown_and_invalid_range_rejected(self):
        self.brief["requirements"] = ["XX-9"]
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder")
        self.brief["requirements"] = ["OP-1"]
        self.brief["references"][0]["end"] = 99
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder")

    def test_budget_overflow_fails_without_truncating(self):
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder", max_bytes=100)

    def test_untracked_files_not_sent(self):
        self.write("private.txt", "not repository context")
        self.brief["scope"] = ["private.txt"]
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder")

    def test_tracked_symlink_cannot_read_git_metadata(self):
        (self.root / "broker/link").symlink_to("../.git/config")
        self.git("add", "broker/link")
        self.brief["scope"] = ["broker/link"]
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, "builder")

    def test_normative_table_definitions_and_gate_ids_supported(self):
        self.write('SPEC.md', '| ID | Capability | Contract |\n| **CAP-5** | Compounding | MUST qualify skills. |\n| **A10** | Measured benefit. | CAP-5 |\n| Other | references **CAP-6** | not a definition |\n')
        self.brief['requirements'] = ['CAP-5', 'A10']
        packet = rc.build(self.root, self.brief, 'builder')
        self.assertIn('MUST qualify', packet['requirements']['CAP-5'])
        self.assertIn('Measured benefit', packet['requirements']['A10'])
        with self.assertRaises(ValueError):
            rc.requirement((self.root / 'SPEC.md').read_text(), 'CAP-6')

    def test_reviewer_exposes_changes_outside_declared_scope(self):
        base = self.git('rev-parse', 'HEAD').strip()
        self.write('broker/demo.go', 'package revised\n')
        self.write('other.go', 'package outside\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'mixed scope')
        self.brief.update(revision=self.git('rev-parse', 'HEAD').strip(), base=base)
        packet = rc.build(self.root, self.brief, 'reviewer')
        self.assertEqual(packet['changes_outside_scope'], ['other.go'])
        self.assertIn('other.go', packet['changed_paths'])

    def test_builder_declares_new_files_without_reading_untracked_contents(self):
        self.brief['scope'].append('broker/new.go')
        self.brief['planned_files'] = ['broker/new.go']
        packet = rc.build(self.root, self.brief, 'builder')
        self.assertEqual(packet['sources']['broker/new.go'], {'state':'planned-absent'})
        rc.check(self.root, packet)
        self.write('broker/new.go', 'PRIVATE_UNTRACKED_CONTENT')
        with self.assertRaises(ValueError):
            rc.check(self.root, packet)
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, 'builder')

    def test_planned_paths_reject_escape_symlink_existing_and_reviewer_role(self):
        for name in ['../outside.go', '.git/new', 'broker/demo.go']:
            self.brief['scope'] = [name]
            self.brief['planned_files'] = [name]
            with self.assertRaises(ValueError):
                rc.build(self.root, self.brief, 'builder')
        (self.root/'link').symlink_to('/tmp')
        self.brief.update(scope=['link/new.go'], planned_files=['link/new.go'])
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, 'builder')
        self.brief.update(scope=['broker/new.go'], planned_files=['broker/new.go'])
        with self.assertRaises(ValueError):
            rc.build(self.root, self.brief, 'reviewer')

    def test_planned_files_must_be_unique_and_in_scope(self):
        for names in [['broker/new.go'], ['broker/demo.go','broker/demo.go']]:
            self.brief['planned_files'] = names
            with self.assertRaises(ValueError):
                rc.build(self.root, self.brief, 'builder')

    def test_freshness_catches_changed_file_outside_scope(self):
        self.write('outside.go', 'package outside\n')
        self.git('add','outside.go')
        self.git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','outside fixture')
        self.brief['revision'] = self.git('rev-parse','HEAD').strip()
        packet = rc.build(self.root,self.brief,'reviewer')
        self.write('outside.go','package modified\n')
        with self.assertRaises(ValueError):
            rc.check(self.root,packet)

    def test_duplicate_normative_bullets_and_requirement_ids_refused(self):
        self.write('SPEC.md','- **OP-1** First definition.\n- **OP-1** Different definition.\n')
        with self.assertRaises(ValueError):
            rc.build(self.root,self.brief,'builder')
        self.write('SPEC.md','- **OP-1** Single definition.\n')
        self.brief['requirements'] = ['OP-1','OP-1']
        with self.assertRaises(ValueError):
            rc.build(self.root,self.brief,'builder')

    def test_tooling_brief_can_explicitly_have_no_product_requirement_ids(self):
        self.brief['requirements'] = []
        packet = rc.build(self.root,self.brief,'reviewer')
        self.assertEqual(packet['requirements'],{})
        self.assertIn('broker/demo.go',packet['sources'])

    def test_scoped_contract_files_are_included_once_with_full_contents(self):
        self.brief['scope'] += ['BOARD.md','CLAUDE.md','SPEC.md']
        packet = rc.build(self.root,self.brief,'reviewer')
        self.assertIn('| ID | Package',packet['sources']['BOARD.md']['content'])
        self.assertIn('OP-2',packet['sources']['SPEC.md']['content'])
        self.assertEqual(packet['sources']['CLAUDE.md']['content'],(self.root/'CLAUDE.md').read_text())
