#!/usr/bin/env python3
"""Risk tier of a change, decided by the paths it touches (docs/OPERATING.md §3).

  A  credentials, isolation, irreversible effects, update and supply chain,
     the image and its systemd units, the guest's build inputs, CI workflows
     and agent permissions: L3 review on the session's model with an explicit
     threat check, plus the batched lens screen with Security; a later
     security-relevant delta needs a re-sign.
  B  other broker and guest code, SPEC.md, and any path no rule names:
     L3 review plus one combined lens pass in the batched screen.
  C  the explicit list in TIER_C_*: docs, briefs, reviews, decisions, spikes,
     tests, tooling outside the tier-A prefixes: L3 review and CI only.

A change takes the highest tier of any path it touches. A path matching no
rule is B, so a new top-level directory gets a lens pass until it is classed.

Usage:
  tools/risk_tier.py PATH...            tier of the listed paths
  tools/risk_tier.py --git BASE [HEAD]  tier of `git diff --name-only BASE...HEAD`
  --markdown                            print a short table (for a CI step summary)
"""
import argparse
import subprocess
import sys

# broker/ packages that hold credentials, enforce isolation, gate effects,
# or sign and apply updates. Keep in step with docs/OPERATING.md §3.
TIER_A_BROKER = {
    "apply", "attest", "bridgeclient", "bridgeproto", "browser", "card", "cgroup", "change",
    "cleanroom", "clock", "cmd", "control", "corpus", "daemon", "digestqueue", "egress",
    "grants", "guest", "hint", "hostchange", "hostdisk", "journal", "localapi", "localsrv",
    "localui", "loop7", "loops", "machprobe", "mail", "modelroute", "modem", "modemlink",
    "owner", "probecmd", "pubid", "recovery", "replay", "reversible", "sendrules", "sim", "sipsign",
    "smsapi", "sockets", "sockprobe", "tpmseal", "update", "vault", "vendor", "verb", "vm",
    "workers",
}
TIER_A_FILES = {"broker/go.mod", "broker/go.sum"}
# risk_tier itself is A: CI runs the PR's own copy, so an edit to it decides its own tier.
# image/ builds what ships (image/fuzz-targets.json too: build.sh installs it as
# the release's fuzz manifest, so it is not test-only); .github/ builds the image,
# gates merges and pushes to main; .claude/ holds agent permissions.
TIER_A_PREFIXES = (
    "assurance/", "tools/canary", "tools/depaudit", "tools/risk_tier",
    "image/", ".github/", ".claude/",
)
# guest/<name>/<file>: what the guest runs or installs.
TIER_A_GUEST_FILES = {"build-rootfs.sh", "package.json", "package-lock.json", "launch.json"}
TIER_A_GUEST_PATHS = {"guest/openclaw/openclaw.json5"}
UNIT_SUFFIXES = (".service", ".socket", ".timer")
TIER_B_FILES = {"SPEC.md"}
TIER_B_PREFIXES = ("broker/", "guest/")
# Explicit tier C. Top-level *.md other than SPEC.md and image/*.md are C by
# rule in tier_of; everything here is checked after the tier-A rules.
TIER_C_PREFIXES = ("docs/", "briefs/", "reviews/", "decisions/", "spikes/", "tests/", "tools/")

REASONS = {
    "A": "credentials, isolation, effects, update or supply chain",
    "B": "broker or owner-facing behaviour",
    "C": "docs, tooling, spikes or tests",
}


def tier_of(path):
    """Return (tier, rule) for one repo-relative path."""
    p = path.strip().removeprefix("./")
    parts = p.split("/")
    name = parts[-1]
    # image/'s own top-level docs are the one exception to image/ being A.
    if len(parts) == 2 and parts[0] == "image" and name.endswith(".md"):
        return "C", "image/*.md"
    if p in TIER_A_FILES:
        return "A", p
    for pre in TIER_A_PREFIXES:
        if p.startswith(pre):
            return "A", pre
    if parts[0] == "broker" and len(parts) > 2 and parts[1] in TIER_A_BROKER:
        return "A", "broker/" + parts[1] + "/"
    if parts[0] == "guest" and len(parts) == 3 and name in TIER_A_GUEST_FILES:
        return "A", "guest/*/" + name
    if p in TIER_A_GUEST_PATHS:
        return "A", p
    if parts[0] != "spikes":
        if name.endswith(UNIT_SUFFIXES):
            return "A", "systemd unit"
        if "systemd" in parts[:-1] and name.endswith(".conf"):
            return "A", "systemd/*.conf"
    if p in TIER_B_FILES:
        return "B", p
    for pre in TIER_B_PREFIXES:
        if p.startswith(pre):
            return "B", pre
    if len(parts) == 1 and name.endswith(".md"):
        return "C", "top-level *.md"
    for pre in TIER_C_PREFIXES:
        if p.startswith(pre):
            return "C", pre
    return "B", "unmatched"


def tier_of_change(paths):
    """Highest tier over paths, and the paths that set it."""
    tiers = {}
    for p in paths:
        if p.strip():
            tiers[p] = tier_of(p)
    if not tiers:
        return "C", []
    top = min(t for t, _ in tiers.values())  # "A" < "B" < "C"
    return top, sorted(p for p, (t, _) in tiers.items() if t == top)


def changed_paths(base, head):
    # --no-renames lists a moved file under its old path too, so moving
    # image/build.sh to docs/ is still tier A. -z keeps git from quoting
    # names with non-ASCII bytes, quotes or newlines, which would match
    # no prefix.
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", f"{base}...{head}"],
        check=True, capture_output=True,
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--git", nargs="+", metavar="REF")
    ap.add_argument("--markdown", action="store_true")
    a = ap.parse_args(argv)
    paths = changed_paths(a.git[0], a.git[1] if len(a.git) > 1 else "HEAD") if a.git else a.paths
    tier, why = tier_of_change(paths)
    if a.markdown:
        print(f"### Risk tier {tier}: {REASONS[tier]}\n")
        print("See docs/OPERATING.md §3 for the review this tier needs.\n")
        for p in why[:20]:
            print(f"- `{p}`")
        if len(why) > 20:
            print(f"- … and {len(why) - 20} more")
    else:
        print(tier)
        for p in why:
            print(f"  {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
