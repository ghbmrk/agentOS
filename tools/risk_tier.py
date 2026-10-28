#!/usr/bin/env python3
"""Risk tier of a change, decided by the paths it touches (docs/OPERATING.md §3).

  A  the trusted core, its wiring and the packages allowed its write paths
     (broker/core/core.txt); broker packages that handle a credential, gate
     an effect or approval, or parse owner-channel input, and any broker path
     no list names; supply chain, the image and its systemd units, the
     guest's build inputs, CI workflows and agent permissions: L3 review on the session's model with an explicit
     threat check, plus the batched lens screen with Security; a later
     security-relevant delta needs a re-sign.
  B  the broker packages in TIER_B_BROKER, other guest code, SPEC.md, and
     any path no rule names:
     L3 review plus one combined lens pass in the batched screen.
  C  the explicit list in TIER_C_*: docs, briefs, reviews, decisions, spikes,
     tests, tooling outside the tier-A prefixes: L3 review and CI only.

A change takes the highest tier of any path it touches. A path matching no
rule is B, so a new top-level directory gets a lens pass until it is classed.

Usage:
  tools/risk_tier.py PATH...            tier of the listed paths
  tools/risk_tier.py --git BASE [HEAD]  tier of `git diff --name-only BASE...HEAD`; with HEAD
                                        (the default) uncommitted and untracked paths count too;
                                        an empty diff prints no tier and exits 2
  --markdown                            print a short table (for a CI step summary)
  --pr-branch BRANCH --pr-title TITLE   lane gate: exit 1 if the PR belongs to a lane
                                        (docs/LANES.md) whose tier limit the change exceeds
"""
import argparse
import functools
import pathlib
import subprocess
import sys

# The trusted core (ARC-1, D-095): `core <pkg>`, `wiring <pkg>` and
# `allow <pkg> ...` lines name directories under broker/ that are tier A; a
# package an allow line lets call a core write path is itself a write path.
# broker/core/core_test.go keeps write paths into the core inside it, so the
# list and the check are one file.
CORE_LIST = pathlib.Path(__file__).resolve().parent.parent / "broker" / "core" / "core.txt"


@functools.lru_cache(maxsize=None)
def core_list(path=CORE_LIST):
    """Return (core, wiring, allowed) package sets from the core list; exit if unreadable."""
    try:
        text = path.read_text()
    except OSError as e:
        sys.exit(f"risk_tier: cannot read the core list: {e}")
    core, wiring, allowed = set(), set(), set()
    for n, line in enumerate(text.splitlines(), 1):
        w = line.split()
        if not w or w[0].startswith("#"):
            continue
        if w[0] in ("core", "wiring") and len(w) == 2:
            (core if w[0] == "core" else wiring).add(w[1])
        elif w[0] == "open" and len(w) == 2:
            pass
        elif w[0] == "allow" and len(w) > 4 and w[3] == "--":
            # The same grammar broker/core/core_test.go reads.
            allowed.add(w[1])
        else:
            sys.exit(f"risk_tier: {path}:{n}: unreadable line {line.strip()!r}")
    if not core:
        sys.exit(f"risk_tier: {path} names no core package")
    return core, wiring, allowed


# broker/ packages beyond the core and wiring lists that are tier A
# (Tier-A-narrow, #1698). A package is here only if it (a) holds or handles a
# credential or secret, (b) gates an effect or approval, or (c) parses
# owner-channel input. A package that meets several criteria is filed under
# one, with the others noted. Every other package is in TIER_B_BROKER,
# and a broker/ path in neither list is A, so a new package is A until it is
# classed. Packages core.txt names on a core or wiring line are A regardless
# and are not repeated here; a package on an allow line that meets a criterion
# by itself is listed too, so it stays A if its allow line goes. Keep in step
# with docs/OPERATING.md §3.
TIER_A_BROKER = {
    # (a) a credential or secret
    "apnet",                      # the Owner Card's Wi-Fi password
    "browser", "netjoin", "tpmseal",
    "durable",                    # writes keys, the vault file and root.json, and sets their mode
    "pageca",                     # the owner page's name-constrained authority and its sealed key (CH-9, #3153)
    # e2e/boxe2e, the G1 in-image run (#1714): holds the claim code, the Owner
    # Card's values and the code-generator seed, and its verdict proves G1.
    "e2e",
    # CRED-1 custody (#1654): recall's scrubber and the event bus that runs it
    # decide what authentication material reaches the recall index and event log.
    "events", "recall",
    "maintain",                   # also (b): attestor keys that gate security releases
    "probecmd",                   # also (b): CRED-1 child env; findings that pause grants
    "recovery",
    # (b) gates an effect or approval
    "apply", "card", "claim", "clock", "firstboot",
    "follow",                     # switches the update root of trust
    "mail", "netguard", "reversible", "route", "sendrules", "update", "workers",
    "provagent",                  # runs a provider agent on the owner's plan (CAP-11); also (a): seeds placeholders
    "attest",                     # bounds what public output may say (OSS-4)
    "hostdisk",                   # HW-8a second confirmation; udev host-disk isolation
    "infer",                      # INFER-SVC: its jail and reply checks keep private text on the box and untrusted output out of recall; covers infer/supervise
    "edgelink",                   # parses every frame and hello from the edge, and pins the link's TLS (HW-15, #3296)
    "camwire",                    # parses every camera frame and verifies the owner-signed settings and images a camera takes (NET-2, NET-4, #3513)
    "camnode",                    # the camera node's server: holds its device key in the secure element, admits only pinned keys, applies owner-signed bundles (NET-2, #3513)
    # (c) parses owner-channel input
    "bridgeclient", "bridgeproto", "control", "localapi", "localsrv", "localui",
    "boxname",                    # parses the owner's NAME text; the CH-21 check
    "modem", "modemlink", "owner",
    "photo",                      # owner photos; also (b): runs their decoder in a one-shot sandbox
    "question",                   # the owner's texted answers
    "sipsign", "smsapi",          # also (a)
    # wiring: every binary's main, and the core list itself
    "cmd", "core",
}
# broker/ packages that meet none of the three criteria: tier B.
TIER_B_BROKER = {
    "accel", "admission", "attention", "budget",
    # cgroup is B, but core vm kills machines through it: a change to Kill
    # or Freeze is reviewed with that caller.
    "cgroup",
    "corpus", "floor", "fold", "hostchange", "inflight",
    "machprobe", "quota", "routerule", "skill", "test", "voice",
}
TIER_A_FILES = {"broker/go.mod", "broker/go.sum"}
# Third-party source compiled into the broker: the code go.sum pins.
TIER_A_BROKER_PREFIXES = ("broker/vendor/", "broker/third_party/")
# risk_tier itself is A: CI runs the PR's own copy, so an edit to it decides its own tier.
# image/ builds what ships; .github/ builds the image,
# gates merges and pushes to main; .claude/ holds agent permissions; tools/ci_scope
# decides which CI jobs a change skips (CI-docs); tools/g1_scope and its lists decide
# which paths a PR may touch during the G1 freeze (G1-freeze); tools/ci_split decides
# which broker packages each race shard runs (CI-SHARD).
# tools/premerge decides which PRs need Mark and when an accepted head still holds; the
# tests that pin the merge gates and the lens READMEs (review rules) left its Mark-only
# list on Mark's "Narrow only" (2026-10-16), so they keep the full review instead.
# tools/vulncheck and its planted fixture decide which known vulnerabilities fail CI (EVL-5).
TIER_A_PREFIXES = (
    "assurance/", "tools/canary", "tools/depaudit", "tools/risk_tier", "tools/ci_scope",
    "tools/g1_scope", "tools/ci_split", "tools/premerge", "tools/vulncheck",
    "tests/fixtures/vulncheck/",
    "tests/test_premerge", "tests/test_risk_tier", "tests/test_ci_scope", "tests/test_g1_scope",
    "tests/test_workflows", "tests/test_merge_queue", "tests/test_lane",
    "image/", ".github/", ".claude/",
)
# guest/<name>/<file>: what the guest runs or installs.
TIER_A_GUEST_FILES = {"build-rootfs.sh", "package.json", "package-lock.json", "launch.json"}
# guest/codex: the Codex worker's tool sandbox and managed config (S8-W1).
TIER_A_GUEST_PATHS = {
    "guest/openclaw/openclaw.json5",
    "guest/codex/agentos-toolsh", "guest/codex/managed_config.toml",
    "guest/codex/requirements.toml",
}
UNIT_SUFFIXES = (".service", ".socket", ".timer")
TIER_B_FILES = {"SPEC.md"}
TIER_B_PREFIXES = ("guest/",)
# Explicit tier C. Top-level *.md other than SPEC.md and image/*.md are C by
# rule in tier_of; everything here is checked after the tier-A rules.
TIER_C_PREFIXES = ("docs/", "briefs/", "reviews/", "decisions/", "spikes/", "tests/", "tools/")

# Lane gate (CTRL-lane-gate, D-110): a lane that is not one of the peer Claude
# subscriptions is held to a tier limit in docs/LANES.md. A PR is in the lane when
# its head branch has the lane's stem or its title starts with the lane's row
# prefix. CI runs the base commit's copy of this file, so a PR cannot loosen the
# gate or the classifier it is judged by.
LANES = {
    # lane: (branch stem, title prefix, highest tier allowed)
    "codex": ("pkg/codex-", "CX-", "C"),
}


def lane_of(branch, title):
    """Return the lane a PR's head branch or title puts it in, or None."""
    for lane, (stem, prefix, _) in sorted(LANES.items()):
        if (branch or "").startswith(stem) or (title or "").lstrip().startswith(prefix):
            return lane
    return None


def lane_gate(branch, title, tier):
    """Return (ok, message) for a PR of the given tier."""
    lane = lane_of(branch, title)
    if lane is None:
        return True, "lane gate: not a lane PR"
    limit = LANES[lane][2]
    if tier >= limit:  # "A" < "B" < "C"
        return True, f"lane gate: {lane} PR at tier {tier}, within its limit {limit}"
    return False, (
        f"lane gate: the {lane} lane is limited to tier {limit} (docs/LANES.md), "
        f"and this change is tier {tier}. Drop the files listed above and send them "
        "to the peers as a lane:primary issue."
    )


REASONS = {
    "A": "credentials, effects and approvals, owner-channel input, the core, update or supply chain",
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
    for pre in TIER_A_BROKER_PREFIXES:
        if p.startswith(pre):
            return "A", pre
    if len(parts) == 3 and parts[0] == "reviews" and name.startswith("README"):
        return "A", "reviews/*/README*"
    if parts[0] == "broker" and len(parts) > 2 and parts[1] in TIER_A_BROKER:
        return "A", "broker/" + parts[1] + "/"
    if parts[0] == "broker":
        core, wiring, allowed = core_list()
        for pkg in sorted(core | wiring | allowed):
            if p.startswith("broker/" + pkg + "/"):
                return "A", "core list: broker/" + pkg + "/"
        # In no list: A until it is classed (Security #1700 f3).
        if len(parts) < 3 or parts[1] not in TIER_B_BROKER:
            return "A", "unlisted broker path"
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
    if parts[0] == "broker":
        return "B", "broker/" + parts[1] + "/"
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


def _git_paths(*args):
    out = subprocess.run(["git", *args], check=True, capture_output=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def changed_paths(base, head):
    # --no-renames lists a moved file under its old path too, so moving
    # image/build.sh to docs/ is still tier A. -z keeps git from quoting
    # names with non-ASCII bytes, quotes or newlines, which would match
    # no prefix. --no-relative keeps paths root-relative and whole-repo
    # under a user's diff.relative=true, wherever the tool runs (RT-3b).
    paths = _git_paths("diff", "--name-only", "-z", "--no-renames", "--no-relative", f"{base}...{head}")
    if head == "HEAD":
        # A run before commit (#2272): staged, unstaged and untracked paths
        # count too, against the same merge base the committed diff uses.
        mb = subprocess.run(["git", "merge-base", base, head], check=True,
                            capture_output=True, text=True).stdout.strip()
        paths += _git_paths("diff", "--name-only", "-z", "--no-renames", "--no-relative", mb)
        # The index too: a staged file since removed from the worktree still
        # goes into the next commit.
        paths += _git_paths("diff", "--cached", "--name-only", "-z", "--no-renames", "--no-relative", mb)
        # --full-name :/ lists the whole repo root-relative, as diff does,
        # whatever the cwd.
        paths += _git_paths("ls-files", "-z", "--others", "--exclude-standard", "--full-name", ":/")
    return list(dict.fromkeys(paths))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--git", nargs="+", metavar="REF")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--pr-branch")
    ap.add_argument("--pr-title")
    a = ap.parse_args(argv)
    gate = a.pr_branch is not None or a.pr_title is not None
    head = a.git[1] if a.git and len(a.git) > 1 else "HEAD"
    paths = changed_paths(a.git[0], head) if a.git else a.paths
    if a.git and not paths:
        # No tier for a diff it never saw: an empty diff used to print C.
        print(f"risk_tier: no changes between {a.git[0]} and {head} to tier", file=sys.stderr)
        return 2
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
    if gate:
        ok, msg = lane_gate(a.pr_branch, a.pr_title, tier)
        print(msg, file=sys.stdout if ok else sys.stderr)
        if not ok:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
