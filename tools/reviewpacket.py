#!/usr/bin/env python3
"""Write one review packet for a PR or a commit range (CTX-slice, issue #1681).

The packet holds, in one file: the risk tier (tools/risk_tier.py), the package brief, the SPEC
requirement blocks the PR cites (tools/specslice.py), and the diff, all stamped with the head SHA.
It is a starting point for a reviewer, not a substitute for the source: any claim a finding relies
on is checked against the files (docs/OPERATING.md §4).

IDs cited = SPEC IDs named in the brief, in `REQ:` markers on added diff lines, and in the PR
body's trace table. An ID the brief cites that SPEC does not define is listed, not dropped.

Usage:
  tools/reviewpacket.py 1234                 a PR number (REST via gh api; commits fetched if absent)
  tools/reviewpacket.py origin/main..HEAD    a range
  options: --id PKG-ID (brief name; default: first word of the PR title or head commit subject)
           --out FILE (default: reviewpacket-<head7>.md in the system temp dir)  --root DIR
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import specslice  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOKEN = re.compile(r"\b[A-Z]{2,4}-\d+[a-z]?\b")
MARKER = re.compile(r"REQ:\s*([A-Z]{2,4}-\d+[a-z]?(?:\s*,\s*[A-Z]{2,4}-\d+[a-z]?)*)")
PKG_ID = re.compile(r"^([A-Za-z0-9][A-Za-z0-9.-]*)[:\s]")


def sh(root, *cmd, check=True):
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if check and r.returncode:
        raise SystemExit(f"reviewpacket: {' '.join(cmd[:3])} failed: {r.stderr.strip()[:300]}")
    return r


def resolve_pr(n):
    """PR number -> {base, head, title, body} via the REST API (GraphQL is not available)."""
    r = subprocess.run(["gh", "api", f"repos/ghbmrk/agentOS/pulls/{n}"], capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"reviewpacket: gh api pulls/{n} failed: {r.stderr.strip()[:300]}")
    d = json.loads(r.stdout)
    return {"base": d["base"]["sha"], "head": d["head"]["sha"], "title": d["title"], "body": d.get("body") or ""}


def ensure_commits(root, shas, pr):
    for sha in shas:
        if sh(root, "git", "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode:
            if pr:
                sh(root, "git", "fetch", "-q", "origin", f"refs/pull/{pr}/head")
            if sh(root, "git", "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode:
                raise SystemExit(f"reviewpacket: commit {sha[:10]} not available locally")


def find_brief(root, head, pkg):
    """Return (path, text) of briefs/<pkg>.md at head, else the working tree, else None."""
    if not pkg:
        return None
    rel = f"briefs/{pkg}.md"
    shown = sh(root, "git", "show", f"{head}:{rel}", check=False)
    if shown.returncode == 0:
        return rel, shown.stdout
    f = pathlib.Path(root) / rel
    return (rel, f.read_text()) if f.is_file() else None


def cited_ids(brief_text, diff, body, defined):
    """Return (ids defined in SPEC in first-seen order, brief-cited IDs SPEC does not define)."""
    found, missing = [], []
    for tok in TOKEN.findall(brief_text or ""):
        if tok in defined:
            if tok not in found:
                found.append(tok)
        elif tok not in missing:
            missing.append(tok)
    for line in diff.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            for m in MARKER.finditer(line):
                for tok in re.split(r"\s*,\s*", m.group(1)):
                    if tok in defined and tok not in found:
                        found.append(tok)
    for tok in TOKEN.findall(body or ""):
        if tok in defined and tok not in found:
            found.append(tok)
    return found, [m for m in missing if m not in found]


def build(root, base, head, label, title, body, pkg):
    diff = sh(root, "git", "diff", f"{base}...{head}").stdout
    tier = sh(root, sys.executable, str(ROOT / "tools" / "risk_tier.py"), "--git", base, head, check=False)
    tier_line = f"Risk tier: {(tier.stdout.strip() or 'unknown').split(chr(10))[0]}"
    if not pkg:
        pkg_m = PKG_ID.match(title or sh(root, "git", "log", "-1", "--format=%s", head).stdout)
        pkg = pkg_m.group(1) if pkg_m else None
    brief = find_brief(root, head, pkg)
    spec_text, _ = specslice.read_spec(root, head)
    defined = set(specslice.parse(spec_text))
    ids, missing = cited_ids(brief[1] if brief else "", diff, body, defined)
    parts = [
        f"# Review packet: {label}",
        "",
        f"Head: {head}",
        f"Base: {base}",
        f"Package: {pkg or 'unknown'}" + (f" ({title})" if title else ""),
        "",
        "This packet is a starting point, generated from the sources below. Any claim a finding "
        "relies on is checked against the source files, not against this packet (docs/OPERATING.md §4).",
        "",
        "## Risk tier",
        "",
        tier_line,
        "",
        "## Brief",
        "",
        f"`{brief[0]}`\n\n{brief[1].rstrip()}" if brief else f"no brief found for `{pkg}` (briefs/{pkg}.md)",
        "",
        "## Cited SPEC requirements",
        "",
    ]
    if ids:
        parts.append(specslice.render(spec_text, head, ids).rstrip())
    else:
        parts.append("none cited")
    if missing:
        parts += ["", "Cited in the brief but not defined in SPEC.md at this head: " + ", ".join(missing)]
    parts += ["", "## Diff", "", "```diff", diff.rstrip("\n"), "```", ""]
    return "\n".join(parts)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("target", help="PR number, or a git range BASE..HEAD")
    ap.add_argument("--id", help="package ID (briefs/<ID>.md)")
    ap.add_argument("--out")
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args(argv)
    root = args.root
    title = body = ""
    if args.target.isdigit():
        n = int(args.target)
        pr = resolve_pr(n)
        base, head, title, body = pr["base"], pr["head"], pr["title"], pr["body"]
        ensure_commits(root, (base, head), n)
        label = f"PR #{n}"
    else:
        m = re.fullmatch(r"(.+?)\.\.\.?(.+)", args.target)
        if not m:
            ap.error("target must be a PR number or BASE..HEAD")
        base = sh(root, "git", "rev-parse", "--verify", f"{m.group(1)}^{{commit}}").stdout.strip()
        head = sh(root, "git", "rev-parse", "--verify", f"{m.group(2)}^{{commit}}").stdout.strip()
        label = args.target
    text = build(root, base, head, label, title, body, args.id)
    out = pathlib.Path(args.out or pathlib.Path(tempfile.gettempdir()) / f"reviewpacket-{head[:7]}.md")
    out.write_text(text)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
