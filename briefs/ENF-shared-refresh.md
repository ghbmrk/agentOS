# ENF-shared-refresh: a shared host's record lasts as long as conntrack keeps its connection

Board section: Devices, hardware and image (SPEC §13-14). Work item #4704 (L3 release finding on #4687, ENF-shared-src).

**Problem:** `bound_<segment>` refreshes a host record only on original-direction packets from the shared segment (`broker/enforcer/nft/compile.go`, the learn and bound rules), while conntrack refreshes a connection's idle timer on packets in either direction. `HostTimeout` (1 h) is justified in a comment and ASSUMPTIONS ENF-ct-bind-2 as longer than conntrack keeps any idle connection, which compares two different idle measures. A datagram flow that only receives for over an hour keeps its conntrack entry while the host's record expires, so the host's next packet on it is dropped. Fails closed; rare.

**Requirements:** NET-2 (device paths), NET-3.
1. Either (recommended) the comment and ENF-ct-bind-2 state the true bound ("longer than conntrack keeps a connection whose host is idle") and ASSUMPTIONS names the receive-only datagram residual and its fail-closed effect; or the record is refreshed on reply-direction packets through a second per-connection set keyed by `ct id`. Recommendation: the first, because the second adds a set per segment against the HostSize quota that #4701 is about, for a rare fail-closed cut.
2. Whichever is chosen, a test pins it.

**Scope:** `broker/enforcer/nft/compile.go` (comments, and rules only under the second option), `broker/enforcer/nft/sharedsrc_test.go` or `shared_test.go`, `broker/enforcer/nft/ASSUMPTIONS.md`, this brief.

**Acceptance tests:**
- First option: `broker/enforcer/nft`: `TestHostTimeoutBasisIsHostIdle` reads the compiled ruleset and checks the record refreshes only on original-direction packets and that ASSUMPTIONS ENF-ct-bind-2 names the residual; catches a later change that silently widens or narrows the refresh.
- Second option: a netns test (`netns_test.go` pattern) in which a host's UDP flow only receives for longer than a test-shortened `HostTimeout` and its next datagram still passes; catches the expiry.

**Guard files:** none.

**Dependencies:** none open. Runs before ENF-shared-quota (#4701) and ENF-shared-dos (#4703), which edit the same file.

**Tier / gate:** tier A (`broker/enforcer`): L3 on the strongest model, lens screen, separate Security accept.

**Usage estimate:** one session, under 80k (first option).
