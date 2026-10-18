# SR3-mail-k18f: a global in-flight cap in the egress proxy

Board section: Security and architecture review (2026-10-08). Source: PR #1766 Security review, point r1. Row #1771, class release, tier A.

**Why it matters.** `agentos-egress.service` sets `MemoryMax=2G` from a legitimate peak that includes `PROXY_CALLS = 16` proxy requests, each holding up to `DefaultMaxBody` (8 MiB, read whole). The 16 is a constant in `tests/test_egress_memory.py`, not a bound in code: `Proxy.admit` caps in-flight requests per machine only (`DefaultMaxConcurrent` = 4). More than four machines, each with four maximal bodies in flight, on top of mail calls and an unlock, pass GOMEMLIMIT and MemoryHigh, and the cgroup kills the vault. It fails closed, but one set of callers costs every machine its model access.

**Requirements:** CRED-8 (a hostile caller costs one call, not the vault process). Also egress K18 (a row, not a SPEC ID).

**Fix.** Add a global in-flight counter to `egress.Proxy` next to the per-machine one, with a `DefaultMaxInFlight = 16` and a `Config` field to set it. `admit` refuses with `too many requests in flight` (the per-machine wording and status) when the total is at the cap, before it touches a machine's usage; `release` returns the slot. `tests/test_egress_memory.py` reads the constant from `proxy.go` the way it reads its other figures, so the memory derivation follows the code, not a copy of it. The per-machine cap stays.

**Acceptance tests:** CRED-8: `TestProxyGlobalInFlightCap` (`broker/egress/`) and the existing `tests/test_egress_memory.py`, changed to read the cap from source.

**Tests first.**
- T1 `TestProxyGlobalInFlightCap`: with a cap of N, N requests held open across more than N/4 machines are admitted; request N+1 from a fresh machine is refused with the in-flight refusal and is not charged to that machine's request or byte cap; after one finishes, the next is admitted.
- T2 a refused request leaves no slot taken (global or per-machine) and a panicking or cancelled request releases both.
- T3 `tests/test_egress_memory.py` fails if `PROXY_CALLS` differs from the code's cap (derive it, then assert the derivation still fits `MemoryMax`).
- Control: existing `broker/egress/...` tests stay green; the per-machine cap test is unchanged.

**Docs.** Extend egress K18's bound sentence with the global cap and what the memory figure rests on.

**Out of scope.** Lowering `DefaultMaxBody`, streaming bodies instead of reading them whole, and the SMTP/IMAP budgets (SR3-mail-k18d, k18b).

**Scope:** `broker/egress/proxy.go`, a new `broker/egress/inflight_test.go`, `tests/test_egress_memory.py`, `broker/egress/ASSUMPTIONS.md` (K18), this brief. `broker/cmd/agentos-egress/main.go` only if the proxy's constructor needs the new field passed (the default should make that unnecessary).

**Dependencies:** none. No open PR on these files at writing (D-111: check again at start).

**Usage estimate:** 50k tokens, checkpoint at 50k. Builder model: strongest (tier A: `broker/egress/proxy.go`).
