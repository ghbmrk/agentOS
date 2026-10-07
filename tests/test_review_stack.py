import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from review_stack import audit


class ReviewStackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic reviewer')
        self.git('config', 'user.email', 'review@example.invalid')
        (self.repo / 'file.txt').write_text('before\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'base')
        base = self.git('rev-parse', 'HEAD').strip()
        (self.repo / 'file.txt').write_text('after\n')
        self.git('commit', '-qam', 'candidate')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.package = self.root / 'package'
        self.package.mkdir()
        self.item = {'key': 'sample', 'branch': 'pkg/h7-sample-review',
                     'local_head': self.head, 'tree': self.git('rev-parse', 'HEAD^{tree}').strip(),
                     'source_base': base, 'pr_base': 'main', 'depends_on': [],
                     'files': ['file.txt'], 'body_file': 'pr-bodies/sample.md', 'draft': True}
        (self.package / 'pr-bodies').mkdir()
        (self.package / 'pr-bodies/sample.md').write_text('External review pending.\n')
        source = self.package / 'source/sample'
        source.mkdir(parents=True)
        (source / 'file.txt').write_text('after\n')
        self.save()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.repo), *args], text=True)

    def save(self, items=None):
        (self.package / 'stack.json').write_text(json.dumps(items or [self.item]))
        self.checksums()

    def checksums(self):
        files = sorted(p for p in self.package.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
        (self.package / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(self.package)) + '\n'
            for p in files))

    def test_valid_read_only_without_network_or_checkout(self):
        before = self.git('status', '--porcelain')
        report = audit(self.package, self.repo)
        self.assertEqual(report['candidates'], 1)
        self.assertTrue(report['content_matches'])
        self.assertFalse(report['qualification_asserted'])
        self.assertEqual(self.git('status', '--porcelain'), before)
        self.assertEqual(self.git('rev-parse', 'HEAD').strip(), self.head)

    def test_changed_checksum_refused(self):
        (self.package / 'pr-bodies/sample.md').write_text('Changed\n')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            audit(self.package, self.repo)

    def test_extra_file_refused(self):
        (self.package / 'extra').write_text('Not inventoried')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            audit(self.package, self.repo)

    def test_wrong_source_even_after_checksum_update(self):
        (self.package / 'source/sample/file.txt').write_text('wrong\n')
        self.checksums()
        with self.assertRaisesRegex(ValueError, 'source'):
            audit(self.package, self.repo)

    def test_extra_source_even_after_checksum_update(self):
        (self.package / 'source/sample/extra.txt').write_text('Not in the commit')
        self.checksums()
        with self.assertRaisesRegex(ValueError, 'source inventory'):
            audit(self.package, self.repo)

    def test_wrong_tree_even_after_checksum_update(self):
        self.item['tree'] = self.git('rev-parse', self.item['source_base'] + '^{tree}').strip()
        self.save()
        with self.assertRaisesRegex(ValueError, 'tree'):
            audit(self.package, self.repo)

    def test_changed_path_inventory_refused(self):
        self.item['files'] = []
        self.save()
        with self.assertRaisesRegex(ValueError, 'changed'):
            audit(self.package, self.repo)

    def test_duplicate_candidates_refused(self):
        self.save([self.item, self.item])
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            audit(self.package, self.repo)

    def test_unknown_dependency_refused(self):
        self.item['depends_on'] = ['missing']
        self.save()
        with self.assertRaisesRegex(ValueError, 'dependency'):
            audit(self.package, self.repo)

    def test_dependency_base_mismatch_refused(self):
        parent = dict(self.item, key='parent', branch='pkg/h7-parent-review')
        parent_source = self.package / 'source/parent'
        parent_source.mkdir()
        (parent_source / 'file.txt').write_text('after\n')
        self.item['depends_on'] = ['parent']
        self.item['pr_base'] = parent['branch']
        self.save([parent, self.item])
        with self.assertRaisesRegex(ValueError, 'dependency base'):
            audit(self.package, self.repo)

    def test_non_pkg_branch_refused(self):
        self.item['branch'] = 'main'
        self.save()
        with self.assertRaisesRegex(ValueError, 'branch'):
            audit(self.package, self.repo)

    def test_traversal_refused(self):
        self.item['body_file'] = '../outside'
        self.save()
        with self.assertRaisesRegex(ValueError, 'path'):
            audit(self.package, self.repo)

    def test_symlink_refused(self):
        p = self.package / 'source/sample/file.txt'
        p.unlink()
        p.symlink_to(self.repo / 'file.txt')
        self.checksums()
        with self.assertRaisesRegex(ValueError, 'symlink'):
            audit(self.package, self.repo)

    def test_dirty_checkout_uses_pinned_objects(self):
        (self.repo / 'file.txt').write_text('local review edits\n')
        self.assertTrue(audit(self.package, self.repo)['content_matches'])
        self.assertEqual((self.repo / 'file.txt').read_text(), 'local review edits\n')


if __name__ == '__main__':
    unittest.main()
