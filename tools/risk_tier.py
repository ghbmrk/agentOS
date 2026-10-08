#!/usr/bin/env python3
"""Risk tier of a change, decided by the paths it touches (docs/OPERATING.md §3).

  A  credentials, isolation, irreversible effects, update and supply chain:
     L3 review on the session's model with an explicit threat check, plus the
     batched lens screen with Security; a later security-relevant delta needs a re-sign.
  B  other broker code and owner-facing behaviour: L3 review plus one combined
     lens pass in the batched screen.
  C  docs, tests outside tier-A code, tooling, CI, spikes: L3 review and CI only.

A change takes the highest tier of any path it touches. Unknown paths under
broker/ are B; anything else unmatched is C.

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
    "cleanroom", "clock", "cmd", "control", "daemon", "egress", "grants", "guest", "hint",
    "hostchange", "hostdisk", "journal", "localapi", "localsrv", "localui",
    "mail", "modelroute", "modem", "modemlink", "owner", "pubid", "recovery", "replay",
    "reversible", "sendrules", "sipsign", "smsapi", "sockets", "tpmseal",
    "update", "vault", "vendor", "verb", "vm", "workers",
}
TIER_A_FILES = {"broker/go.mod", "broker/go.sum"}
# risk_tier itself is A: CI runs the PR's own copy, so an edit to it decides its own tier.
TIER_A_PREFIXES = ("assurance/", "tools/canary", "tools/depaudit", "tools/risk_tier")
TIER_B_FILES = {"SPEC.md"}
TIER_B_PREFIXES = ("broker/", "guest/")

REASONS = {
    "A": "credentials, isolation, effects, update or supply chain",
    "B": "broker or owner-facing behaviour",
    "C": "docs, tooling, CI, spikes or tests",
}


def tier_of(path):
    """Return (tier, rule) for one repo-relative path."""
    p = path.strip().removeprefix("./")
    if p in TIER_A_FILES:
        return "A", p
    for pre in TIER_A_PREFIXES:
        if p.startswith(pre):
            return "A", pre
    parts = p.split("/")
    if parts[0] == "broker" and len(parts) > 2 and parts[1] in TIER_A_BROKER:
        return "A", "broker/" + parts[1] + "/"
    if p in TIER_B_FILES:
        return "B", p
    for pre in TIER_B_PREFIXES:
        if p.startswith(pre):
            return "B", pre
    return "C", "default"


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
    out = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [line for line in out.splitlines() if line]


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
