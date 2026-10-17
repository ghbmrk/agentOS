# NETJOIN-SCAN-BEST: pin the scan's best-strength rule against a later weaker duplicate (ONB-3)

Board row: issue #1284. Source: Potency on PR #1233 (mutation probe at 4ca8171). Class: later, recheck. Tier: see the PR (`tools/risk_tier.py`). Usage estimate: 15k tokens, checkpoint at 10k.

**Why (facts, verified at main 9338b37).** `Scanner.Scan` (`broker/netjoin/scan.go`) keeps each name at its best strength with `!ok || st > b`. The mutant `!ok || st != b` (keep the last strength seen) survives the suite, because `TestTheScanListsShowableNamesStrongestFirst` meets the weaker "Home Net" before the stronger one, and the last one seen is then also the best. Under the mutant a weaker duplicate seen later sinks a strong home network down the list, or past `MaxNetworks` off it.

## Requirement (from SPEC.md)

- **ONB-3** (SPEC.md:341): setup asks for the home network; the scan offers the networks in range, each once, strongest first.

Package IDs:
- **NETJOIN-SCAN-BEST-1** A name seen again at a weaker strength, later on the same device or on a later device, keeps its best strength and its place in the order.

**Acceptance test:** NETJOIN-SCAN-BEST-1: `TestTheScanKeepsABestStrengthOverALaterWeakerDuplicate` (`broker/netjoin/scan_test.go`). It fails under the `st != b` mutant.

## Scope

`broker/netjoin/scan_test.go`, `briefs/NETJOIN-SCAN-BEST.md`. Test only: `scan.go` already does the right thing.

## Done

CI green; NETJOIN-SCAN-BEST-1 covered by a passing test carrying `REQ:` with its ID, shown to fail under the mutant.
