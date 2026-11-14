# ENF-shared-nd-ll: a host's link-local address gets a neighbour hold on a shared segment

Board section: Devices, hardware and image (SPEC §13-14). Work item #5726, a release finding raised while building ENF-shared-nd-input (#5686). Tier A (enforcer ruleset).

**Problem:** the input-side claim (#5686) holds every IPv6 source a shared-segment host uses toward the enforcer except link-local and unspecified ones, since `claim` gives a hardware address one address (its DHCPv6 one). A host's link-local address therefore has no neighbour hold, and `nd_<segment>` passes any advertisement naming it. Failure path: guest A solicits DHCPv6 from its link-local address; guest B advertises A's link-local address with its own hardware address; the enforcer's DHCPv6 reply to A goes to B, and A gets no address.

**Requirements:** NET-3, NET-1; closes ENF-shared-nd-1's stated residual (`broker/enforcer/nft/ASSUMPTIONS.md`).

**Design:** a link-local source from a shared segment to the enforcer itself jumps to a new per-segment `ll_<segment>` chain (after neighbour discovery is judged and accepted, as the claim jump is). It keeps its holder's neighbour hold (`NeighSet`, `NeighAddrSet`, which `nd_<segment>` already enforces) or takes a free address's hold, separate from `ClaimSet`'s one-address rule; a new taker must be leased (`LeasedSet`) and hold no other link-local address (new `LinkLocalMACSet`, `llmac_<segment>_6`, `ClaimTimeout`), so the holds stay bounded by the segment's leases and no host fills `NeighSet` with forged hardware addresses. A packet from a held address of another hardware address passes with no hold. `Reload` carries the new set.

**Scope:** `broker/enforcer/nft/compile.go`, `keep.go`, `testdata/fixture.nft`, `ASSUMPTIONS.md`, `sharedsrc_test.go` (carry test), a new `llhold_test.go`, this brief.

**Guard files:** none.

**Acceptance tests:** `TestLinkLocalIsHeld` (netns, IPv6 in CI): on each shared segment an unleased sender, a sender of a held address and a second address of one hardware address take no hold; a hold is refreshed by its holder's packets; a second host's advertisement of the first host's link-local address leaves the enforcer's entry at the first host and its replies reach it; five mutants (no jump, and each line of the chain taken out) each fail their step. `TestReloadCarriesSharedRecords` (a link-local hold and its mark are carried), `TestGolden`.

**Tier / gate:** tier A: L3 and a separate Security accept if `premerge.py --needs-mark` prints `mark`. One session; estimate 80k tokens.
