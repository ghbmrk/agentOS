# CRED-5f-mr-trailers: Forward scrubs non-canonical keys and request trailers

Board section: Phase 0: harness and risk spikes. Source: work item #815 (release; L3 point 1 and Security point 1 on #566). Tier A (credentials path, broker → vault process).

**Why.** `modelroute.Forward` drops the broker-only `Agentos-*` and `X-Agentos-*` headers before a guest's call reaches the vault process. Two gaps: `dropOurs` shadows the map key with its canonical form, so it deletes `Agentos-State` while `h["agentos-state"]` survives; and request trailers are never scrubbed, so a trailer a guest declares on the wire (`Trailer: Agentos-State`) reaches the vault process declared. Neither is reachable with a value today (the server canonicalizes wire keys, and `Request.Clone` leaves trailer values in the inbound request), so this is hardening that pins the boundary, not a live exploit.

**Requirements:** ARC-6 (the guest gets model access only through the broker's endpoint, holding only a placeholder), CRED-1 (no guest-supplied value is read as the broker's own).

**Change.**
- `dropOurs` deletes the key the map holds, matching on its canonical form.
- `Forward`'s `Rewrite` runs `dropOurs` on `pr.Out.Trailer` as well as on `pr.Out.Header`.

**Acceptance tests:**
- ARC-6, CRED-1: `TestRequestTrailersAreScrubbed` (raw wire: declared `agentos-state`, `Agentos-Machine` and `X-Agentos-Egress-Denied` trailers with values never reach the vault process, declared or valued; `X-Other` stays declared).
- CRED-1: `TestDropOursDeletesNonCanonicalKeys`.

**Scope:** `broker/modelroute/modelroute.go`, `broker/modelroute/modelroute_test.go`, this brief. `broker/modelroute/ASSUMPTIONS.md` is left out: #2044 holds it (D-111), and the change adds no assumption.

**Usage estimate:** 60k tokens. Builder model: Opus-class (tier A).
