# OSS-6s-b: Tor transport to Nostr relays, and the pull job

Board section: Backlog refill (2026-10-05). Split from OSS-6s on #325.

Part b of the publication sender. It implements OSS-6s-a's `Transport` over Tor, using Ubuntu `tor` through SOCKS, to third-party Nostr relays at onion addresses (D-062, SPEC OSS-6). There is no direct fallback: if Tor is unreachable, frames wait (OSS-6s-a a9). It also carries OSS-6i's test that two batches, or two signing keys, never share a circuit (isolation credentials per batch), and the repository's scheduled pull, verify and append job, once OSS-6j settles what that job is. Relay count, the delivery rule, the queue bound and the relay list source come from OSS-6p. Requirement IDs: OSS-6.

**Frame to events (release point from the #325 L3):** a 1 MiB frame is larger than common Nostr relay event-size limits. Part b maps one frame to a fixed number of equal-size events under the smallest limit among the listed relays, so every day still shows the same count and size, and the pull job reassembles a frame and verifies it whole. The mapping and the per-relay limit go in its ASSUMPTIONS, with values from OSS-6p.

**Tor client isolation (release point S1 from the #330 L3):** the Tor client runs as its own uncredentialed component. It has no access to the vault, the owner channel or broker credentials, and it receives only frames that pubid has already signed, so a compromised Tor client can learn nothing beyond what the relays already see.

**Release points carried from the #411 reviews (OSS-6s-a):**
- W6: the per-signer bound test. No production `Signer` is registered yet, so the package that registers the first one (for example a Nostr signer whose JSON escaping makes its overhead depend on the payload) carries it. Give an item over `SignerOverhead` its own reason, not the "could not be signed" count.
- SW1: a `Flush` timer, so waiting frames do not go out only on the next `Publish`. With it, a single caller or a mutex on `Sender` (`Flush` must not race `Release`).
- SW2: `Sender.Clear` (R1), so "stop sharing" also clears the batches held in pubsend's `Waiting`; the Clear path calls both it and `Publisher.Clear` (P6(b), OSS-7).
- a9: the drop-log wording. The line must be accurate and in owner terms, not internal ones.
- Transport.Send timeout (Security, #411 comment 6068975832): the Sender mutex is held during `Send`, so the Tor `Send` has a bounded timeout. Fold it into SW1/SW2.

**Needs:** OSS-6s-a, OSS-6p, OSS-6i (clause), OSS-6j

**Gate:** lenses (security, privacy); tier A
