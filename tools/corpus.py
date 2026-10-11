#!/usr/bin/env python3
"""Vendored injection corpora for Loop 2's corpus probe (LOOP-7, D-067).

Each corpus is a directory under assurance/corpora/ holding a published file
copied byte for byte, its LICENSE, and SOURCE.json: {name, url, commit,
license, files: {file: sha256}, tables}. `build` checks the digests and
writes items.json, the attack texts the probe replays, read from the named
tables of prompt_data.py without running it (ast.literal_eval). No item is
written or generated here or by a model: an item is a published string.

  corpus.py build assurance/corpora/promptinject
  corpus.py verify assurance/corpora/promptinject
"""
import ast
import hashlib
import json
import pathlib
import sys

# Licenses compatible with vendoring into this repository.
LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "CC-BY-4.0"}


def digest(b):
    return hashlib.sha256(b).hexdigest()


def verify(d):
    """Raise ValueError unless every recorded file matches its digest."""
    d = pathlib.Path(d)
    src = json.loads((d / "SOURCE.json").read_text())
    if src.get("license") not in LICENSES:
        raise ValueError("%s: license %r" % (d, src.get("license")))
    for name, want in src["files"].items():
        if digest((d / name).read_bytes()) != want:
            raise ValueError("%s: %s does not match its digest" % (d, name))
    return src


def extract(d):
    """The corpus's items, in file order."""
    d = pathlib.Path(d)
    src = verify(d)
    tree = ast.parse((d / "prompt_data.py").read_bytes())
    tables = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in src["tables"]:
                tables[node.targets[0].id] = ast.literal_eval(node.value)
    items = []
    for t in src["tables"]:
        if t not in tables:
            raise ValueError("%s: no table %s" % (d, t))
        for key, entry in tables[t].items():
            items.append({"id": "%s/%s/%s" % (src["name"], t, key), "text": entry["instruction"]})
    return {"name": src["name"], "url": src["url"], "commit": src["commit"],
            "license": src["license"], "items": items}


def main(argv):
    if len(argv) != 2 or argv[0] not in ("build", "verify"):
        print(__doc__, file=sys.stderr)
        return 2
    d = pathlib.Path(argv[1])
    try:
        if argv[0] == "verify":
            verify(d)
        else:
            (d / "items.json").write_text(json.dumps(extract(d), indent=1, ensure_ascii=False) + "\n")
    except (ValueError, OSError, SyntaxError) as e:
        print("FAIL %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
