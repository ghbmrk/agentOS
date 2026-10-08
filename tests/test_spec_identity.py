import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1] / 'tools'
sys.path.insert(0, str(TOOLS))
import spec_identity


class SpecIdentityTests(unittest.TestCase):
    def test_reused_id_and_definition_changes(self):
        report = spec_identity.compare(
            '| **CAP-13** | Local leverage | Hosts |\n| **CAP-2** | Old | X |\n',
            '| **CAP-13** | Peer substrates | Executors |\n| **CAP-3** | New | X |\n')
        self.assertEqual(report['label_changes'], [{'id': 'CAP-13',
            'reference': 'Local leverage', 'candidate': 'Peer substrates'}])
        self.assertEqual(report['changed_rows'], ['CAP-13'])
        self.assertEqual(report['added_rows'], ['CAP-3'])
        self.assertEqual(report['removed_rows'], ['CAP-2'])
        self.assertFalse(report['approval_asserted'])

    def test_body_change_without_label_change(self):
        report = spec_identity.compare('| **CAP-1** | Same | Before |',
                                       '| **CAP-1** | Same | After |')
        self.assertEqual(report['changed_rows'], ['CAP-1'])
        self.assertEqual(report['label_changes'], [])

    def test_identical_bytes_do_not_assert_approval(self):
        text = '| **CAP-11** | Workers | Original |'
        report = spec_identity.compare(text, text)
        self.assertEqual(report['changed_rows'], [])
        self.assertEqual(report['reference_sha256'], report['candidate_sha256'])
        self.assertFalse(report['approval_asserted'])

    def test_duplicate_ids_are_not_silently_deduplicated(self):
        with self.assertRaisesRegex(ValueError, 'duplicate requirement table ID'):
            spec_identity.compare('| **CAP-13** | One | A |\n'
                                  '| **CAP-13** | Two | B |', '')

    def test_fenced_examples_are_ignored(self):
        for fence in [chr(96)*3, '~'*4]:
            text = (fence+'markdown\n| **CAP-13** | Fake | X |\n'+fence+
                    '\n| **CAP-13** | Real | X |')
            self.assertEqual(spec_identity.compare(text, text)['reference_rows'], 1)

    def test_trace_id_syntax_and_missing_tables(self):
        text = ('| **CRED-4** | Valid | X |\n| **CAP-2a** | Suffix | X |\n'
                '| **INVALID-13** | Invalid ID | X |')
        self.assertEqual(spec_identity.compare(text, text)['reference_rows'], 2)
        with self.assertRaisesRegex(ValueError, 'no requirement table rows'):
            spec_identity.compare('plain prose', 'other prose')

    def test_bounds(self):
        with self.assertRaises(ValueError):
            spec_identity.compare('x'*(spec_identity.MAX_BYTES+1), '')
        with self.assertRaisesRegex(ValueError, 'invalid requirement table label'):
            spec_identity.compare('| **CAP-1** | '+'a'*201+' | X |', '')

    def test_cli_preserves_inputs_and_reports_identity_differences(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d)/'reference', Path(d)/'candidate'
            a.write_text('| **CAP-13** | Local leverage | A |')
            b.write_text('| **CAP-13** | Peer substrates | B |')
            original = a.read_bytes(), b.read_bytes()
            result = subprocess.run([sys.executable, str(TOOLS/'spec_identity.py'),
                '--reference', str(a), '--candidate', str(b)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(json.loads(result.stdout)['approval_asserted'])
            self.assertEqual(original, (a.read_bytes(), b.read_bytes()))
            self.assertEqual({p.name for p in Path(d).iterdir()}, {'reference', 'candidate'})

    def test_invalid_cli_input_has_fixed_error(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d)/'private-canary'; bad.write_bytes(b'\xff')
            result = subprocess.run([sys.executable, str(TOOLS/'spec_identity.py'),
                '--reference', str(bad), '--candidate', str(bad)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('private-canary', result.stderr)


if __name__ == '__main__':
    unittest.main()
