#!/usr/bin/env python3
"""Check that the diff about to merge equals the diff its L3 accept reviewed (OPERATING §7).

  tools/premerge.py [--base origin/main] <reviewed-sha> [head]

Compares each file's diff against the base (`base...sha`) for the reviewed commit and for `head` (default
HEAD), by a SHA-256 of the exact diff bytes: whitespace, binary content and modes count. Only `index`
lines and hunk line numbers are dropped, so main merged in elsewhere reads as same. Not `git patch-id`:
it ignores whitespace, so an indentation-only change that flips a branch would read as same. Prints `same` and exits 0, or `changed <files>` and exits 1: those
files need a delta review. Git only, no network; fetch first. Patch ids include context lines, so an
unrelated base change next to a hunk reads as changed: conservative, never unsafe.
"""
import hashlib
import re
import subprocess
import sys

# Pinned so local config (renames, algorithm, external or textconv drivers, colour) cannot change the bytes.
DIFF = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--binary", "--full-index",
        "--diff-algorithm=myers", "--src-prefix=a/", "--dst-prefix=b/"]
HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@.*$")


def _git(cwd, *args):
    return subprocess.run(["git", "-c", "core.quotePath=true", *args], cwd=cwd, check=True, capture_output=True).stdout


def _fingerprint(patch):
    lines = [b"@@" if HUNK.match(l) else l for l in patch.split(b"\n") if not l.startswith(b"index ")]
    return hashlib.sha256(b"\n".join(lines)).hexdigest()


def _ids(cwd, base, sha):
    out = {}
    for f in _git(cwd, *DIFF, "--name-only", "-z", f"{base}...{sha}").decode(errors="surrogateescape").split("\0"):
        if f:
            out[f] = _fingerprint(_git(cwd, *DIFF, f"{base}...{sha}", "--", f":(literal){f}"))
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
