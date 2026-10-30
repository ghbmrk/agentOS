# Enforcer Wake-on-LAN relay: assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change (briefs/ENF.md slice f, #3664).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| ENF-f-w1 | **The paired machines are an input, not yet a policy field.** The signed policy document (slice a) has no entry for a helper or compute host, so `New` takes the machines (hardware address and network) from its caller. Slice l must take them only from the owner-signed policy once it carries them; until then nothing on the enforcer wakes. Release finding on the PR: the document needs a paired-machine entry, signed as a loosening, which also gives the core its path to the helper (NET-2 Segments). | NET-2 Segments ("relays the core's Wake-on-LAN to a paired machine and to nothing else"), HW-11 | The relay reads the list from the document. |
| ENF-f-w2 | **Only an exact magic packet, only from the core, only to its machine's network.** The relay hears the core's interface only (`SO_BINDTODEVICE`; the ruleset also accepts port 9 from the core alone), takes exactly 102 bytes (or 108 with a SecureOn password) of sync and sixteen copies of one address on its list, and sends the same bytes as a broadcast on that machine's network only, at most once per 2 seconds per machine. A machine may be on Owner, Household or its own Devices VLAN, never on the core's, the edge's or the Guests' network, the admin port, the WAN or the access point's management interface. | NET-2 Segments, A18 | — |
| ENF-f-w3 | **IPv4 broadcast only.** Wake-on-LAN cards hear the broadcast on their own segment; the relay sends to 255.255.255.255:9 bound to that segment's interface. | HW-11 | — |
