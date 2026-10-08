#!/usr/bin/env python3
"""Capture complete pinned native merge evidence without changing source refs.

Creates Git rehearsal objects only. A textual merge, this report and downstream
synthetic tests never confer integration/security/release acceptance. Inputs must
be full SHA-1 commit pins in an existing trusted local repository; no fetching,
checkout, index update, conflict resolution, commit or publication occurs.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess

OID = re.compile(r'[0-9a-f]{40}')
STAGE = re.compile(r'([0-7]{6}) ([0-9a-f]{40}) ([123])\t(.+)', re.DOTALL)


def checked_oid(value):
    if not isinstance(value, str) or not OID.fullmatch(value) or value == '0' * 40:
        raise ValueError('full nonzero SHA-1 pin required')
    return value


def parse_rehearsal(output, returncode):
    """Parse native merge-tree --write-tree -z, retaining every stage/message.

    NUL framing preserves tabs/newlines in paths. Unsupported encoding, partial
    framing, duplicate stages or inconsistent conflict evidence fail closed.
    This parses a completed native command capture, not an authenticated image.
    """
    if returncode not in (0, 1) or not isinstance(output, bytes) or not output.endswith(b'\0'):
        raise ValueError('incomplete native merge evidence')
    try:
        parts = output[:-1].decode('utf-8').split('\0')
    except UnicodeDecodeError as exc:
        raise ValueError('unsupported path/message encoding') from exc
    tree = checked_oid(parts[0])
    stages, messages, seen = [], [], set()
    i = 1
    while i < len(parts) and parts[i]:
        m = STAGE.fullmatch(parts[i])
        if not m:
            raise ValueError('invalid stage record')
        mode, oid, stage, path = m.groups()
        checked_oid(oid)
        key = (path, stage)
        if key in seen:
            raise ValueError('duplicate stage record')
        seen.add(key)
        stages.append(dict(mode=mode, object=oid, stage=int(stage), path=path))
        i += 1
    if i < len(parts):
        i += 1  # empty stage/message separator
    while i < len(parts):
        count = parts[i]
        if not re.fullmatch(r'[1-9][0-9]*', count) or len(count) > 9:
            raise ValueError('invalid diagnostic path count')
        n = int(count)
        if n > len(parts) - i - 3:
            raise ValueError('truncated diagnostic')
        paths = parts[i + 1:i + 1 + n]
        kind, message = parts[i + n + 1:i + n + 3]
        if not all(paths) or not kind or not message:
            raise ValueError('empty diagnostic field')
        messages.append(dict(paths=paths, type=kind, message=message))
        i += n + 3
    conflicts = [m for m in messages if m['type'].startswith('CONFLICT')]
    covered = {p for m in conflicts for p in m['paths']}
    if returncode == 1:
        if not stages or not conflicts or any(s['path'] not in covered for s in stages):
            raise ValueError('incomplete conflict evidence')
    elif stages or conflicts:
        raise ValueError('exit status disagrees with conflict evidence')
    return dict(tree=tree, stages=stages, messages=messages,
                text_merge_clean=returncode == 0, semantic_accepted=False,
                native_output_sha256=hashlib.sha256(output).hexdigest())


def git(repo, *args, allowed=(0,)):
    r = subprocess.run(['git', '--no-replace-objects', '-C', str(repo), '-c', 'core.hooksPath=/dev/null',
                        '-c', 'core.attributesFile=/dev/null', *args],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode not in allowed:
        raise ValueError('native Git command failed; no compatibility claimed')
    return r


def snapshot(repo, commit):
    checked_oid(commit)
    if git(repo, 'cat-file', '-t', commit).stdout != b'commit\n':
        raise ValueError('commit pin required')
    tree = checked_oid(git(repo, 'rev-parse', commit + '^{tree}').stdout.decode().strip())
    raw = git(repo, 'ls-tree', '-r', '-z', tree).stdout
    entries = []
    for record in raw.split(b'\0')[:-1]:
        metadata, name = record.split(b'\t', 1)
        mode, kind, oid = metadata.decode('ascii').split(' ')
        entries.append(dict(path=name.decode('utf-8'), mode=mode, type=kind, object=checked_oid(oid)))
    if raw and not raw.endswith(b'\0'):
        raise ValueError('incomplete tree inventory')
    return dict(commit=commit, tree=tree, inventory=entries,
                inventory_sha256=hashlib.sha256(raw).hexdigest())


def changes(repo, base, head):
    raw = git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
              '--name-only', '-z', base, head).stdout
    if raw and not raw.endswith(b'\0'):
        raise ValueError('incomplete change inventory')
    return [p.decode('utf-8') for p in raw.split(b'\0')[:-1]]


def rehearse(repo, source, public):
    checked_oid(source)
    checked_oid(public)
    # A locally configured custom merge driver can execute arbitrary commands.
    # Refuse it, rather than claiming the native operation has no ref side effects.
    drivers = git(repo, 'config', '--get-regexp', r'^merge\..*\.driver$', allowed=(0, 1))
    if drivers.returncode == 0:
        raise ValueError('custom external merge drivers are unsupported')
    source_image, public_image = snapshot(repo, source), snapshot(repo, public)
    bases = git(repo, 'merge-base', '--all', source, public).stdout.decode().splitlines()
    if len(bases) != 1:
        raise ValueError('one explicit common base required')
    base = checked_oid(bases[0])
    a, b = changes(repo, base, source), changes(repo, base, public)
    result = git(repo, 'merge-tree', '--write-tree', '-z', public, source, allowed=(0, 1))
    if result.stderr:
        raise ValueError('unexpected native diagnostic; preserve it externally and investigate')
    parsed = parse_rehearsal(result.stdout, result.returncode)
    if git(repo, 'cat-file', '-t', parsed['tree']).stdout != b'tree\n':
        raise ValueError('rehearsal tree unavailable')
    return dict(version=1, git_version=git(repo, '--version').stdout.decode().strip(),
                source=source_image, public=public_image, merge_base=base,
                source_changes=a, public_changes=b, shared_changed_paths=sorted(set(a) & set(b)),
                rehearsal=parsed, semantic_accepted=False, runtime_checks='not performed by this tool',
                writes_git_objects=True, writes_refs_or_index=False,
                qualifications='Independent exact runtime/security and external release review required.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=pathlib.Path, required=True)
    p.add_argument('--source', required=True)
    p.add_argument('--public', required=True)
    args = p.parse_args()
    try:
        report = rehearse(args.repo, args.source, args.public)
    except (ValueError, UnicodeError, OSError) as exc:
        p.exit(2, f'reconciliation unavailable: {exc}\n')
    print(json.dumps(report, indent=2, ensure_ascii=True))


if __name__ == '__main__':
    main()
