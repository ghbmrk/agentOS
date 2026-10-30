# Enforcer mDNS pair relay: assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change (briefs/ENF.md slice f, #3664).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| ENF-f-m1 | **The relay's pairs are the ruleset's.** `NewPlan` takes `nft.Paths`, so the relay passes records on exactly the paths the firewall opens: an isolated or VLAN-less device's pair passes nothing, and Owner and Household are each one network (ENF-e-4). | NET-3 Casting | — |
| ENF-f-m2 | **One direction pair per pair.** From a person's network to a device, the network's queries go to the device and the device's responses come back; the device's own queries and the network's announcements are not passed. Between two devices both kinds pass both ways. A packet's side is the interface it arrived on (one socket per interface, `SO_BINDTODEVICE`, `IP_MULTICAST_ALL` off, own sends not looped back), never an address or a record in it. | NET-3 ("that device's mDNS records passed only across that pair") | A home device that must discover a person's device (AirPlay to a laptop) needs the other direction signed as its own pair. |
| ENF-f-m3 | **Packets pass whole, unparsed beyond the header.** The relay checks a DNS header, opcode 0 and source port 5353, and passes the bytes as they came, so the records a paired device announces reach its paired network even if they name other hosts. Anything a paired device says reaches only that network, at most 40 packets in a burst and 20 a second per interface. | NET-3 | Parsing and filtering records by the device's own name would need a DNS parser here. |
| ENF-f-m4 | **IPv4 only.** IPv6 mDNS (ff02::fb) is not relayed, so a paired device is found over IPv4. Unicast-response (QU) queries get their answer only if the querier re-asks by multicast, and legacy one-shot queries (not from port 5353) are not passed. | NET-3 | IPv6 parity needs a second socket per interface. |
