#!/usr/bin/env python3
"""Read-only requirement-table identity comparison; never semantic approval.

Exit 0: table rows identical; 1: differences for review; 2: invalid input.
No network, Git operations, candidate code execution or output-file writes.
Only ordinary single-line requirement table rows are compared. Prose clauses
and changes outside these rows still require independent review.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from trace import ID_DEF

MAX_BYTES = 2 * 1024 * 1024
FENCE = re.compile(r'^ {0,3}(`{3,}|~{3,})(.*)$')


def rows(text):
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise ValueError('input size exceeds bound')
    result = {}
    fence = None
    for line in text.splitlines():
        marker = FENCE.match(line)
        if fence:
            if (marker and marker[1][0] == fence[0] and
                    len(marker[1]) >= len(fence) and not marker[2].strip()):
                fence = None
            continue
        if marker:
            fence = marker[1]
            continue
        if not line.lstrip().startswith('|'):
            continue
        cells = line.strip().split('|')
        if len(cells) < 5:
            continue
        definition = ID_DEF.fullmatch(cells[1].strip())
        if not definition:
            continue
        rid = definition[1]
        label = ' '.join(cells[2].split())
        if not label or len(label) > 200:
            raise ValueError('invalid requirement table label')
        if rid in result:
            raise ValueError('duplicate requirement table ID')
        result[rid] = {'label': label, 'row': line.strip()}
    return result


def compare(reference, candidate):
    before, after = rows(reference), rows(candidate)
    if not before and not after:
        raise ValueError('no requirement table rows')
    common = sorted(before.keys() & after.keys())
    return {
        'reference_sha256': hashlib.sha256(reference.encode('utf-8')).hexdigest(),
        'candidate_sha256': hashlib.sha256(candidate.encode('utf-8')).hexdigest(),
        'reference_rows': len(before), 'candidate_rows': len(after),
        'label_changes': [{'id': rid, 'reference': before[rid]['label'],
                           'candidate': after[rid]['label']} for rid in common
                          if before[rid]['label'] != after[rid]['label']],
        'changed_rows': [rid for rid in common if before[rid]['row'] != after[rid]['row']],
        'added_rows': sorted(after.keys() - before.keys()),
        'removed_rows': sorted(before.keys() - after.keys()),
        'approval_asserted': False,
    }


def read(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('input size exceeds bound')
    return data.decode('utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--candidate', required=True)
    args = parser.parse_args(argv)
    try:
        report = compare(read(args.reference), read(args.candidate))
    except (OSError, ValueError):
        print('spec identity: invalid input', file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(bool(report['changed_rows'] or report['added_rows'] or report['removed_rows']))


if __name__ == '__main__':
    raise SystemExit(main())
