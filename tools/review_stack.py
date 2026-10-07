#!/usr/bin/env python3
"""Read-only consistency audit of a review package against pinned Git objects.

Checksums are integrity checks, not signatures. This tool does not run tests,
execute packaged commands, authenticate authors or qualify acceptance gates.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

LIMIT = 32 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}')


def relative(name):
    if not isinstance(name, str) or not name:
        raise ValueError('invalid path')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or str(path) != name or '\\' in name:
        raise ValueError('path must be canonical and relative')
    return path


def read(root, name):
    path = relative(name)
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('symlink artifact refused')
    if not current.is_file() or current.stat().st_size > LIMIT:
        raise ValueError('artifact missing or exceeds size limit: ' + name)
    with current.open('rb') as stream:
        result = stream.read(LIMIT + 1)
    if len(result) > LIMIT:
        raise ValueError('artifact exceeds size limit: ' + name)
    return result


def git(repo, *args):
    return subprocess.check_output(
        ['git', '-C', str(repo), '--no-pager', *args], stderr=subprocess.PIPE)


def inventory(package):
    expected = {}
    for line in read(package, 'SHA256SUMS').decode('utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('malformed checksum inventory')
        digest, name = match.groups()
        relative(name)
        if name in expected or name == 'SHA256SUMS':
            raise ValueError('duplicate/self-referential checksum entry')
        expected[name] = digest
    actual = set()
    for path in package.rglob('*'):
        if path.is_symlink():
            raise ValueError('symlink artifact refused')
        if path.is_file() and path != package / 'SHA256SUMS':
            actual.add(path.relative_to(package).as_posix())
    if actual != set(expected):
        raise ValueError('checksum inventory differs from package files')
    for name, digest in expected.items():
        if hashlib.sha256(read(package, name)).hexdigest() != digest:
            raise ValueError('checksum differs: ' + name)
    return len(expected)


def audit(package, repo):
    package, repo = Path(package).resolve(), Path(repo).resolve()
    artifact_count = inventory(package)
    stack = json.loads(read(package, 'stack.json'))
    if not isinstance(stack, list) or not stack:
        raise ValueError('stack needs a nonempty candidate list')
    seen, branches, source_paths = {}, set(), set()
    for item in stack:
        if not isinstance(item, dict):
            raise ValueError('candidate must be an object')
        key, branch = item.get('key'), item.get('branch')
        if not isinstance(key, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', key):
            raise ValueError('invalid candidate key')
        if key in seen or branch in branches:
            raise ValueError('duplicate candidate key or branch')
        if not isinstance(branch, str) or not branch.startswith('pkg/'):
            raise ValueError('candidate branch must use pkg/')
        git(repo, 'check-ref-format', '--branch', branch)
        for field in ('local_head', 'source_base', 'tree'):
            if not isinstance(item.get(field), str) or not SHA.fullmatch(item[field]):
                raise ValueError('candidate needs full Git object hashes')
        if item.get('draft') is not True:
            raise ValueError('candidate must be a draft')
        deps = item.get('depends_on')
        if not isinstance(deps, list) or any(not isinstance(d, str) for d in deps) or len(set(deps)) != len(deps):
            raise ValueError('invalid dependency list')
        if len(deps) > 1:
            raise ValueError('one PR base cannot encode multiple direct dependency bases')
        if deps:
            parent = seen.get(deps[0])
            if parent is None:
                raise ValueError('dependency must precede candidate')
            if item['source_base'] != parent['local_head'] or item.get('pr_base') != parent['branch']:
                raise ValueError('dependency base differs from parent head/branch')
        elif item.get('pr_base') != 'main':
            raise ValueError('independent candidate PR base must be main')
        git(repo, 'cat-file', '-e', item['source_base'] + '^{commit}')
        git(repo, 'cat-file', '-e', item['local_head'] + '^{commit}')
        git(repo, 'merge-base', '--is-ancestor', item['source_base'], item['local_head'])
        tree = git(repo, 'rev-parse', item['local_head'] + '^{tree}').decode().strip()
        if tree != item['tree']:
            raise ValueError('pinned tree differs: ' + key)
        git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--check', item['source_base'], item['local_head'], '--')
        changed = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--name-only', '-z',
                      item['source_base'], item['local_head'], '--').decode('utf-8').split('\0')[:-1]
        if not changed or changed != item.get('files'):
            raise ValueError('changed path inventory differs: ' + key)
        body = str(relative(item.get('body_file')))
        if not body.startswith('pr-bodies/'):
            raise ValueError('PR body path must be inside pr-bodies')
        read(package, body).decode('utf-8')
        for name in changed:
            relative(name)
            source_paths.add('source/' + key + '/' + name)
            blob = git(repo, 'show', item['local_head'] + ':' + name)
            if read(package, 'source/' + key + '/' + name) != blob:
                raise ValueError('source copy differs from pinned Git content: ' + name)
        seen[key] = item
        branches.add(branch)
    actual_sources = {p.relative_to(package).as_posix()
                      for p in (package / 'source').rglob('*') if p.is_file()}
    if source_paths != actual_sources:
        raise ValueError('source inventory differs from declared changed files')
    return {'schema': 1, 'candidates': len(seen), 'checksummed_artifacts': artifact_count,
            'content_matches': True, 'qualification_asserted': False,
            'limitations': 'Integrity and internal consistency only; editable hashes do not '
                           'authenticate authors, validate patch application, establish test '
                           'outcomes or qualify gates. No packaged commands were executed.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--checkout', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(audit(args.package, args.checkout), indent=2))
        return 0
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        print('review audit refused: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
