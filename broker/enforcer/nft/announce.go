package nft

import (
	"slices"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Announces is, for each device's VLAN interface, the mDNS names the
// device pinned in the signed policy (policy.Device.MDNS, #4144): the only
// names slice f's pair relay passes from that interface (NET-3 Casting).
// An interface whose device pinned none is absent, so it announces nothing
// across its pairs. Owner and Household devices' names are held, not
// announced: their side of a pair never sends responses across it.
func Announces(d policy.Document, l Layout) (map[string][][]string, error) {
	devs, _, err := compiled(d, l)
	if err != nil {
		return nil, err
	}
	out := map[string][][]string{}
	for _, v := range devs {
		for _, n := range v.d.MDNS {
			out[v.iface] = append(out[v.iface], slices.Clone(n))
		}
	}
	return out, nil
}
