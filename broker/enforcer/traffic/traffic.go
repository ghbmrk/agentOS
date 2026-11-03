// Package traffic is the enforcer's per-device traffic summaries (SPEC
// NET-5; briefs/ENF.md slice i): for each Devices-network device, how many
// bytes it sent and received, the destinations it reached with the bytes
// to each, and how much it was refused and where. A summary is short: the
// Top destinations and refusals, the rest only counted, and nothing per
// packet (no port, time or content). Guests get no summary of their own,
// only the whole network's counters, and Owner and Household are not
// inspected (NET-1, NET-3).
//
// The sources are the firewall's own per-device counters and counting
// sets (broker/enforcer/nft, read through load.Loader.List), which count
// every packet: the kernel log's lines, which the firewall rate-bounds,
// are not a source. A summary is served only as the channel's
// traffic read (broker/enforcer/channel, Config.Traffic = Reader.Read).
// What it holds is untrusted input to whoever reads it, since devices
// choose the addresses and amounts it describes; it carries only numbers,
// addresses and the device's ID from the signed policy.
//
// It is enforcer code: it imports the standard library and
// broker/enforcer/policy, broker/enforcer/nft and broker/enforcer/wire only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package traffic

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Top is how many destinations and how many refused addresses a summary
// names; the rest are only counted.
const Top = 8

var (
	ErrUnknown      = errors.New("traffic: no such device in the signed policy")
	ErrNotInspected = errors.New("traffic: the Owner and Household networks are not inspected")
	ErrListing      = errors.New("traffic: the firewall's listing does not read")
)

// Summary is one Devices-network device's traffic. BytesOut and BytesIn
// count the connections the firewall accepted since the ruleset was last
// loaded; Destinations are the internet addresses it exchanged traffic
// with in the last day, by bytes; Blocked counts the packets it was refused
// since the ruleset was last loaded (nft.TrafficRefused), and BlockedTo
// the addresses it was refused at in the last day, by packets
// (nft.RefusedSet), each exactly however many it sent.
type Summary struct {
	Device           string `json:"device"`
	BytesOut         uint64 `json:"bytes_out"`
	BytesIn          uint64 `json:"bytes_in"`
	Destinations     []Dest `json:"destinations"`
	MoreDestinations int    `json:"more_destinations"`
	Blocked          uint64 `json:"blocked"`
	BlockedTo        []Dest `json:"blocked_to"`
	MoreBlocked      int    `json:"more_blocked"`
	// Truncated says a counting set was full, so addresses past its
	// size (nft.TrafficSize, nft.RefusedSize) may be missing.
	Truncated bool `json:"truncated"`
}

// Dest is one address and its count: bytes for a destination, packets for
// a refusal.
type Dest struct {
	Addr  string `json:"addr"`
	Count uint64 `json:"count"`
}

// Guests is the Guests network's only record: whole-network counters,
// never per device or per destination (NET-3).
type Guests struct {
	Network     string `json:"network"` // always policy.NetGuests
	BytesOut    uint64 `json:"bytes_out"`
	BytesIn     uint64 `json:"bytes_in"`
	Connections uint64 `json:"connections"`
}

// Reader answers the channel's traffic reads.
type Reader struct {
	// Policy is the policy in force (policy.Engine.Current).
	Policy func() policy.Document
	// List is the firewall table as nft's JSON (load.Loader.List with
	// nft.Table).
	List func() ([]byte, error)
}

// Read is device's summary as JSON, the body of the channel's traffic
// read: a Summary for a Devices-network device (all zero for one with no
// Wi-Fi identity, which has no IP path), Guests for a device on the Guests
// network, and an error for any other network or a device the signed
// policy does not name.
func (r *Reader) Read(device string) ([]byte, error) {
	dev := r.Policy().Device(device)
	if dev == nil {
		return nil, ErrUnknown
	}
	switch dev.Network {
	case policy.NetGuests:
		c, _, err := r.listing()
		if err != nil {
			return nil, err
		}
		return json.Marshal(Guests{Network: policy.NetGuests, BytesOut: c[nft.GuestsOut].Bytes, BytesIn: c[nft.GuestsIn].Bytes, Connections: c[nft.GuestsConns].Packets})
	case policy.NetDevices:
	default:
		return nil, ErrNotInspected
	}
	s := Summary{Device: dev.ID, Destinations: []Dest{}, BlockedTo: []Dest{}}
	vlan, ok := nft.VLAN(dev.WiFi)
	if !ok {
		return json.Marshal(s)
	}
	c, sets, err := r.listing()
	if err != nil {
		return nil, err
	}
	s.BytesOut, s.BytesIn, s.Blocked = c[nft.TrafficOut(vlan)].Bytes, c[nft.TrafficIn(vlan)].Bytes, c[nft.TrafficRefused(vlan)].Packets
	dests, refused := map[netip.Addr]uint64{}, map[netip.Addr]uint64{}
	for _, v6 := range []bool{false, true} {
		set := sets[nft.TrafficSet(vlan, v6)]
		s.Truncated = s.Truncated || len(set) >= nft.TrafficSize
		for a, n := range set {
			dests[a] += n.Bytes
		}
		set = sets[nft.RefusedSet(vlan, v6)]
		s.Truncated = s.Truncated || len(set) >= nft.RefusedSize
		for a, n := range set {
			refused[a] += n.Packets
		}
	}
	s.Destinations, s.MoreDestinations = top(dests)
	s.BlockedTo, s.MoreBlocked = top(refused)
	return json.Marshal(s)
}

// top is the Top largest counts, largest first (ties by address), and how
// many more there are.
func top(m map[netip.Addr]uint64) ([]Dest, int) {
	out := make([]Dest, 0, len(m))
	addrs := make([]netip.Addr, 0, len(m))
	for a := range m {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int {
		if c := cmp.Compare(m[b], m[a]); c != 0 {
			return c
		}
		return a.Compare(b)
	})
	for _, a := range addrs[:min(Top, len(addrs))] {
		out = append(out, Dest{Addr: a.String(), Count: m[a]})
	}
	return out, len(addrs) - len(out)
}

// count is one named counter's reading.
type count struct{ Packets, Bytes uint64 }

// listing reads the firewall table: its named counters, and
// each counting set's count by address. Anything outside the enforcer's
// table, and any element that is not an address, is skipped.
func (r *Reader) listing() (map[string]count, map[string]map[netip.Addr]count, error) {
	b, err := r.List()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrListing, err)
	}
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Family, Table, Name string
				count
			} `json:"counter"`
			Set *struct {
				Family, Table, Name string
				Elem                []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrListing, err)
	}
	counters := map[string]count{}
	sets := map[string]map[netip.Addr]count{}
	for _, o := range doc.Nftables {
		switch {
		case o.Counter != nil && o.Counter.Family == "inet" && o.Counter.Table == nft.Table:
			counters[o.Counter.Name] = o.Counter.count
		case o.Set != nil && o.Set.Family == "inet" && o.Set.Table == nft.Table:
			m := map[netip.Addr]count{}
			for _, raw := range o.Set.Elem {
				var e struct {
					Elem struct {
						Val     string `json:"val"`
						Counter count  `json:"counter"`
					} `json:"elem"`
				}
				if json.Unmarshal(raw, &e) != nil {
					continue // a bare address: no counter
				}
				if a, err := netip.ParseAddr(e.Elem.Val); err == nil {
					c := m[a.Unmap()]
					m[a.Unmap()] = count{c.Packets + e.Elem.Counter.Packets, c.Bytes + e.Elem.Counter.Bytes}
				}
			}
			sets[o.Set.Name] = m
		}
	}
	return counters, sets, nil
}
