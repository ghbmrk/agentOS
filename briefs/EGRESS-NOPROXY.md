# EGRESS-NOPROXY: pin that egress.DefaultTransport takes no proxy from the environment (DEV-2)

Board row: issue #1611 (P2-2w c4e3 s1-proxy). Source: Security 4a on #1584. Class: later (dispatched by the coordinator, dispatch 2026-10-17 00:22Z, S18). Tier: A (`tools/risk_tier.py`). Test-only. Usage estimate: 30k tokens, checkpoint at 20k.

**Why (facts, verified at main 9338b37).** `egress.DefaultTransport` (`broker/egress/holderapi.go:62`) sets no `Proxy`, so the guard resolves the provider's name (DEV-2). Setup's key check (`custody.setupKey`, `broker/cmd/agentos-egress/providers.go:116-125`) builds on it. No test pins either: `TestSetupKeyCheckSendsThroughTheGuard` catches `tr.Proxy = http.ProxyFromEnvironment` only where the runner has `HTTPS_PROXY` set, which CI does not.

## Requirement (from SPEC.md)

- **DEV-2** (SPEC.md:485): the home network is untrusted. The box reaches a provider only at an address netguard's policy resolved and allowed, which a proxy that resolves the name itself would bypass.

Package IDs:
- **EGRESS-NOPROXY-1** `egress.DefaultTransport(g).Proxy` is nil, with the proxy variables set.
- **EGRESS-NOPROXY-2** Setup's key check, run with `HTTPS_PROXY` set, still asks the guard for the provider's name; the test fails loudly if net/http read the environment before it, rather than passing blind.

**Acceptance tests:**
- EGRESS-NOPROXY-1: `TestDefaultTransportTakesNoProxyFromTheEnvironment` (`broker/egress/guard_test.go`). Mutant: `Proxy: http.ProxyFromEnvironment` in `DefaultTransport`.
- EGRESS-NOPROXY-2: `TestSetupKeyCheckSendsThroughTheGuard` (`broker/cmd/agentos-egress/keycheckguard_test.go`). Mutant: `tr.Proxy = http.ProxyFromEnvironment` in `setupKey`.

## Scope

`broker/egress/guard_test.go`, `broker/cmd/agentos-egress/keycheckguard_test.go`, `briefs/EGRESS-NOPROXY.md`.

## Done

CI green; both IDs covered by tests carrying `REQ:` with their IDs; both mutants fail.
