import importlib.util
import pathlib
import os
from unittest import mock
import subprocess
import tempfile
import unittest

path = pathlib.Path(__file__).resolve().parents[1] / 'tools/runtime_reconciliation.py'
spec = importlib.util.spec_from_file_location('runtime_reconciliation', path)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
TREE = b'a' * 40
OID = b'b' * 40


def conflicted(path=b'BOARD.md'):
    stages = b''.join(b'100644 ' + OID + b' ' + str(i).encode() + b'\t' + path + b'\0' for i in (1, 2, 3))
    return TREE + b'\0' + stages + b'\0' + b'1\0' + path + b'\0CONFLICT (contents)\0complete diagnostic\n\0'


class RehearsalEvidenceTests(unittest.TestCase):
    def test_clean_text_never_implies_semantic_acceptance(self):
        result = runtime.parse_rehearsal(TREE + b'\0', 0)
        self.assertTrue(result['text_merge_clean'])
        self.assertFalse(result['semantic_accepted'])

    def test_empty_or_invalid_tree_evidence_refused(self):
        for output in (b'', b'not-a-tree\0', TREE[:-1] + b'\0', TREE + b'\n', b'0' * 40 + b'\0'):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    runtime.parse_rehearsal(output, 0)

    def test_conflict_exit_without_conflict_evidence_refused(self):
        with self.assertRaises(ValueError):
            runtime.parse_rehearsal(TREE + b'\0', 1)

    def test_all_stages_and_messages_preserved(self):
        result = runtime.parse_rehearsal(conflicted(), 1)
        self.assertFalse(result['text_merge_clean'])
        self.assertEqual([s['stage'] for s in result['stages']], [1, 2, 3])
        self.assertEqual(result['messages'][0]['paths'], ['BOARD.md'])
        self.assertEqual(result['messages'][0]['message'], 'complete diagnostic\n')
        self.assertFalse(result['semantic_accepted'])

    def test_newline_and_tab_paths_are_not_split_or_omitted(self):
        name = b'broker/name\nwith\ttabs.go'
        result = runtime.parse_rehearsal(conflicted(name), 1)
        self.assertEqual(result['stages'][0]['path'], name.decode())
        self.assertEqual(result['messages'][0]['paths'], [name.decode()])

    def test_every_truncated_conflict_record_refused(self):
        parts = conflicted().split(b'\0')
        for end in range(1, len(parts) - 1):
            with self.subTest(end=end):
                with self.assertRaises(ValueError):
                    runtime.parse_rehearsal(b'\0'.join(parts[:end]) + b'\0', 1)

    def test_exit_status_disagreement_refused(self):
        for code in (0, 2, -1):
            with self.subTest(code=code):
                with self.assertRaises(ValueError):
                    runtime.parse_rehearsal(conflicted(), code)

    def test_unreported_stage_path_refused(self):
        with self.assertRaises(ValueError):
            runtime.parse_rehearsal(conflicted().replace(b'1\0BOARD.md\0CONFLICT', b'1\0other.md\0CONFLICT'), 1)

    def test_duplicate_stage_refused(self):
        line = b'100644 ' + OID + b' 1\tBOARD.md\0'
        with self.assertRaises(ValueError):
            runtime.parse_rehearsal(conflicted().replace(TREE + b'\0', TREE + b'\0' + line), 1)

    def test_invalid_message_path_count_refused(self):
        for count in (b'-1', b'0', b'01', b'999999999999999999999'):
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    runtime.parse_rehearsal(conflicted().replace(b'\0\0' + b'1\0', b'\0\0' + count + b'\0'), 1)

    def test_trailing_records_and_invalid_utf8_refused(self):
        for output in (conflicted() + b'junk\0', conflicted().replace(b'BOARD.md', b'\xff')):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    runtime.parse_rehearsal(output, 1)


class NativeRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = pathlib.Path(self.temp.name)
        self.git('init', '-q')
        self.name = 'broker/grants/name\nwith\ttabs.go'
        f = self.repo / self.name
        f.parent.mkdir(parents=True)
        f.write_text('base\n')
        self.base = self.commit('base')
        f.write_text('source\n')
        (self.repo / 'source-only').write_text('synthetic\n')
        self.source = self.commit('source')
        self.git('checkout', '--detach', self.base)
        f.write_text('public\n')
        (self.repo / 'public-only').write_text('synthetic\n')
        self.public = self.commit('public')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), '-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid', *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, message):
        self.git('add', '.')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def test_complete_native_report_preserves_inputs_paths_and_refs(self):
        before = (self.git('show-ref'), self.git('rev-parse', 'HEAD'), self.git('status', '--porcelain'))
        result = runtime.rehearse(self.repo, self.source, self.public)
        self.assertEqual(result['source']['commit'], self.source)
        self.assertEqual(result['public']['commit'], self.public)
        self.assertEqual(result['merge_base'], self.base)
        self.assertEqual(result['source_changes'], [self.name, 'source-only'])
        self.assertEqual(result['public_changes'], [self.name, 'public-only'])
        self.assertEqual(result['shared_changed_paths'], [self.name])
        self.assertEqual(result['rehearsal']['messages'][-1]['paths'], [self.name])
        self.assertFalse(result['semantic_accepted'])
        self.assertEqual(before, (self.git('show-ref'), self.git('rev-parse', 'HEAD'), self.git('status', '--porcelain')))

    def test_replacement_refs_cannot_substitute_pinned_source_objects(self):
        expected = self.git('rev-parse', self.source + '^{tree}')
        self.git('replace', self.source, self.public)
        result = runtime.rehearse(self.repo, self.source, self.public)
        self.assertEqual(result['source']['tree'], expected)
        self.assertFalse(result['rehearsal']['text_merge_clean'])

    def test_dirty_worktree_and_index_untouched(self):
        (self.repo / self.name).write_text('uncommitted synthetic content\n')
        (self.repo / 'untracked').write_text('synthetic\n')
        before = self.git('status', '--porcelain')
        result = runtime.rehearse(self.repo, self.source, self.public)
        self.assertEqual(before, self.git('status', '--porcelain'))
        self.assertFalse(result['semantic_accepted'])

    def test_symbolic_or_missing_pin_refused(self):
        for pin in ('HEAD', '--all', '0' * 40, 'c' * 40):
            with self.subTest(pin=pin):
                with self.assertRaises(ValueError):
                    runtime.rehearse(self.repo, pin, self.public)

    def test_blob_pin_refused(self):
        blob = self.git('hash-object', 'public-only')
        with self.assertRaises(ValueError):
            runtime.rehearse(self.repo, blob, self.public)

    def test_custom_external_merge_driver_refused(self):
        self.git('config', 'merge.synthetic.driver', 'false')
        with self.assertRaises(ValueError):
            runtime.rehearse(self.repo, self.source, self.public)

    def test_clean_native_rehearsal_remains_unapproved(self):
        result = runtime.rehearse(self.repo, self.source, self.source)
        self.assertTrue(result['rehearsal']['text_merge_clean'])
        self.assertFalse(result['semantic_accepted'])


if __name__ == '__main__':
    unittest.main()


class OfflineRehearsalTests(unittest.TestCase):
    setUp = NativeRehearsalTests.setUp
    git = NativeRehearsalTests.git
    commit = NativeRehearsalTests.commit
    def helper_environment(self):
        helper_dir = self.repo / 'synthetic-helpers'
        helper_dir.mkdir()
        marker = self.repo / 'helper-invoked'
        helper = helper_dir / 'git-remote-audit'
        helper.write_text('#!/bin/sh\nprintf synthetic > "$AUDIT_MARKER"\nexit 1\n')
        helper.chmod(0o700)
        self.git('config', 'remote.origin.promisor', 'true')
        self.git('config', 'remote.origin.partialclonefilter', 'blob:none')
        self.git('config', 'remote.origin.url', 'audit::synthetic')
        self.git('config', 'extensions.partialClone', 'origin')
        return marker, dict(PATH=str(helper_dir) + os.pathsep + os.environ['PATH'],
                           AUDIT_MARKER=str(marker), GIT_ALLOW_PROTOCOL='audit',
                           GIT_NO_LAZY_FETCH='0')

    # REQ: OP-8 — missing local objects must not execute remote helpers.
    def test_missing_commit_refuses_without_remote_helper(self):
        marker, env = self.helper_environment()
        with mock.patch.dict(os.environ, env):
            with self.assertRaises(ValueError):
                runtime.rehearse(self.repo, 'f' * 40, self.public)
        self.assertFalse(marker.exists(), 'offline audit invoked a remote helper')

    def test_missing_conflict_blob_refuses_without_remote_helper(self):
        oid = self.git('rev-parse', self.source + ':' + self.name)
        obj = self.repo / '.git/objects' / oid[:2] / oid[2:]
        self.assertTrue(obj.is_file())
        obj.unlink()
        marker, env = self.helper_environment()
        with mock.patch.dict(os.environ, env):
            with self.assertRaises(ValueError):
                runtime.rehearse(self.repo, self.source, self.public)
        self.assertFalse(marker.exists(), 'offline merge invoked a remote helper')

    def test_complete_promisor_history_needs_no_helper(self):
        expected = runtime.rehearse(self.repo, self.source, self.public)
        marker, env = self.helper_environment()
        # Keep helper fixture artifacts outside the tracked tree and preserve refs.
        before = self.git('show-ref')
        with mock.patch.dict(os.environ, env):
            result = runtime.rehearse(self.repo, self.source, self.public)
        self.assertEqual(result, expected)
        self.assertEqual(self.git('show-ref'), before)
        self.assertFalse(marker.exists())

    def test_transport_denial_independent_of_lazy_fetch_support(self):
        marker, env = self.helper_environment()
        with mock.patch.dict(os.environ, env):
            with self.assertRaises(ValueError):
                runtime.git(self.repo, 'fetch', 'origin')
        self.assertFalse(marker.exists(), 'transport guard invoked a remote helper')
