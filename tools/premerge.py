#!/usr/bin/env python3
"""Check that the diff about to merge equals the diff its L3 accept reviewed (OPERATING §7).

  tools/premerge.py [--base origin/main] <reviewed-sha> [head]

Compares each file's diff against the base (`base...sha`, by `git patch-id --stable`) for the reviewed
commit and for `head` (default HEAD). Prints `same` and exits 0, or `changed <files>` and exits 1: those
files need a delta review. Git only, no network; fetch first. Patch ids include context lines, so an
unrelated base change next to a hunk reads as changed: conservative, never unsafe.
"""
import subprocess
import sys


def _git(cwd, *args, stdin=None):
    return subprocess.run(["git", *args], cwd=cwd, input=stdin, check=True, capture_output=True, text=True).stdout


def _ids(cwd, base, sha):
    out = {}
    for f in _git(cwd, "diff", "--name-only", f"{base}...{sha}").splitlines():
        patch = _git(cwd, "diff", f"{base}...{sha}", "--", f)
        out[f] = _git(cwd, "patch-id", "--stable", stdin=patch).split()[:1]
    return out


def compare(cwd, reviewed, head="HEAD", base="origin/main"):
    a, b = _ids(cwd, base, reviewed), _ids(cwd, base, head)
    return sorted(f for f in a.keys() | b.keys() if a.get(f) != b.get(f))


def main(argv):
    args, base = argv[1:], "origin/main"
    if args[:1] == ["--base"]:
        base, args = args[1], args[2:]
    if not 1 <= len(args) <= 2:
        print(__doc__)
        return 2
    changed = compare(".", args[0], args[1] if len(args) > 1 else "HEAD", base)
    print("changed " + " ".join(changed) if changed else "same")
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
