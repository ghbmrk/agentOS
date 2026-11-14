#!/usr/bin/env python3
"""Lint a review verdict comment before posting it, with the parser the `premerge` gate uses (RECORD-lint, #5679).

  tools/record_lint.py <pr-number> [--head <sha>] [draft.md]    (the draft on stdin without a file)

Three verdicts in one day failed `premerge --check` only after posting, each costing a repost round: a package
written `VULN-debian-r8 (#5660)` (#5661), a head that names no commit (#5652) and a Record line with no head (#5669).
This reads the draft as `tools/premerge.py` would read it as a trusted comment on PR `pr-number`, so a draft that
passes here is one the gate reads with the verdict and head it states. It checks:

- the first line is `Verdict: accept|fix-list|reject`;
- the comment carries at least one `<!-- record: <lens> -->` marker, each lens one of l3, security, potency, ux, combined;
- its first unfenced `Record:` line is `Record: PR #<pr-number> · package <ID-without-spaces> · head <sha>`, and
  if not, which part is wrong;
- the head names exactly one commit in this checkout (fetch the PR head first), and equals `--head` when given;
- for each marker, `premerge.verdict` reads this verdict and this head, not `unparsed`, `misplaced` or nothing;
  a `security` marker beside `l3` or `combined` never counts as the Security verdict (D-137).

Prints `ok <verdict> <head> <lenses>` and exits 0, or one `record-lint: <problem>` line per problem and exits 1;
usage errors exit 2. Never edit a posted verdict: fix the draft and post a new comment.
"""
import importlib.util
import pathlib
import re
import subprocess
import sys

# By path, as premerge loads risk_tier: `python3 -I` keeps tools/ off sys.path.
_spec = importlib.util.spec_from_file_location("premerge", pathlib.Path(__file__).resolve().parent / "premerge.py")
premerge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(premerge)

LENSES = ("l3", "security", "potency", "ux", "combined")
VERDICTS = ("accept", "fix-list", "reject")
FORMAT = "Record: PR #{} · package <ID-without-spaces> · head <sha>"
_ANY_MARKER = re.compile(r"^\s*<!--\s*record:\s*(.*?)\s*-->\s*$")
_PARTS = re.compile(r"^Record:\s*PR\s*#?(?P<pr>\S*?)\s*·\s*package\s+(?P<pkg>.*?)\s*(?:·\s*head(?P<head>.*))?$")


def _record_problems(line, pr):
    """Why the Record line `line` is not one premerge reads for PR `pr`, part by part; [] when it is."""
    if re.fullmatch(rf"Record: PR #{pr} · package \S+ · head [0-9a-f]{{7,40}}\s*", line):
        return []
    want = "expected " + repr(FORMAT.format(pr))
    m = _PARTS.match(line)
    if not m:
        return [f"Record line {line!r} is not in the record shape; {want} (literal words and middle dots)"]
    out = []
    if m["pr"] != str(pr):
        out.append(f"Record line names PR #{m['pr']}, not #{pr}")
    if m["head"] is None:
        out.append("Record line has no `· head <sha>` part")
    pkg = m["pkg"]
    if not pkg or re.search(r"\s", pkg):
        out.append(f"package {pkg!r} must be one ID with no spaces (write `{pkg.split()[0] if pkg.split() else '<ID>'}`;"
                   " put issue numbers in the comment body)")
    if m["head"] is not None:
        head = m["head"]
        if not re.fullmatch(r" [0-9a-f]{7,40}\s*", head):
            out.append(f"head {head.strip()!r} must be 7 to 40 lowercase hex characters, alone after `head `")
    if not out:  # e.g. a doubled space or a stray character between parts
        out.append(f"Record line {line!r} does not match exactly; {want}")
    return out


def _full(sha, cwd="."):
    r = subprocess.run(["git", "rev-parse", "-q", "--verify", f"{sha}^{{commit}}"], cwd=cwd, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def lint(body, pr, head=None, cwd="."):
    """(problems, summary): every problem premerge would have with `body` as PR `pr`'s verdict comment;
    the heads resolve in the git checkout at `cwd`."""
    out = []
    first = body.split("\n", 1)[0].strip()
    state = first.split(":", 1)[1].strip().lower() if first.startswith("Verdict:") else None
    if state is None:
        out.append(f"first line {first!r} must be `Verdict: accept|fix-list|reject`; premerge skips any other comment")
    elif state not in VERDICTS:
        out.append(f"verdict {state!r} must be one of {', '.join(VERDICTS)}")
    _, _, line = premerge._record_block(body)
    lenses = []
    for raw in body.split("\n"):
        m = _ANY_MARKER.match(raw)
        if not m:
            continue
        if raw != f"<!-- record: {m[1]} -->" or m[1] not in LENSES:
            out.append(f"marker {raw.strip()!r} must be exactly `<!-- record: <lens> -->` on its own line,"
                       f" lens one of {', '.join(LENSES)}")
        elif m[1] not in lenses:
            lenses.append(m[1])
    if not lenses:
        out.append("no `<!-- record: <lens> -->` marker; premerge counts no comment without one")
    if line is None:
        out.append(f"no Record line; add {FORMAT.format(pr)!r} right under the Verdict/Cause lines")
        return out, None
    parts = _record_problems(line, pr)
    out += parts
    if parts:
        return out, None
    sha = line.rsplit(" ", 1)[1].strip()
    full = _full(sha, cwd)
    if full is None:
        out.append(f"head {sha} names no single commit in this checkout: fetch the PR head, copy its sha"
                   " (`git rev-parse HEAD`), never retype it")
    elif head is not None and _full(head, cwd) is None:
        out.append(f"--head {head} names no single commit in this checkout")
    elif head is not None and full != _full(head, cwd):
        out.append(f"head {sha} is {full[:12]}, not the --head {head}")
    if state is None:
        return out, None
    stamp = "2000-01-01T00:00:00Z"
    comment = [{"author_association": "MEMBER", "created_at": stamp, "updated_at": stamp, "body": body}]
    if "security" in lenses and ({"l3", "combined"} & set(lenses)):
        out.append("a `security` marker beside `l3` or `combined` never counts as the Security verdict;"
                   " post Security in its own comment (D-137)")
    reads = {"l3": [{}], "security": [{"security": True}], "combined": [{}, {"lens": "combined"}]}
    for lens in lenses:
        for kw in reads.get(lens, [{"lens": lens}]):
            got = premerge.verdict(comment, pr, **kw)
            if got is None:
                if lens != "security" or not {"l3", "combined"} & set(lenses):  # named above
                    out.append(f"premerge reads no {lens} verdict in this comment")
            elif got[0] in ("unparsed", "misplaced", "edited"):
                out.append(premerge._named(got, lens, pr))
            elif got != (state, sha):
                out.append(f"premerge reads the {lens} verdict as {got[0]} at {got[1]}, not {state} at {sha}")
    return out, f"{state} {sha} {','.join(lenses)}"


def main(argv):
    args, head = argv[1:], None
    if "--head" in args:
        at = args.index("--head")
        if at + 1 >= len(args):
            print(__doc__)
            return 2
        head, args = args[at + 1], args[:at] + args[at + 2:]
    if not 1 <= len(args) <= 2 or not re.fullmatch(r"[1-9][0-9]{0,9}", args[0]):
        print(__doc__)
        return 2
    body = open(args[1], encoding="utf-8").read() if len(args) == 2 else sys.stdin.read()
    body = body.replace("\r\n", "\n")
    problems, summary = lint(body, int(args[0]), head)
    for p in problems:
        print("record-lint: " + p)
    if problems:
        return 1
    print("ok " + summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
