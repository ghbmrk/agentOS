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

// Hears is every interface slice f's mDNS relay listens on: each signed
// pair's ends, which it relays between, and every Devices-network
// device's VLAN, paired or not, where it only hears, so it knows which
// names each device proves its own (D-266). An isolated device's is not
// among them: it reaches nothing, the enforcer included. The ruleset
// admits mDNS from exactly these.
func Hears(d policy.Document, l Layout) ([]string, error) {
	devs, paths, err := compiled(d, l)
	if err != nil {
		return nil, err
	}
	return hears(devs, paths), nil
}

func hears(devs []device, paths []Path) []string {
	var out []string
	for _, v := range devs {
		if !v.d.Isolated {
			out = append(out, v.iface)
		}
	}
	for _, p := range paths {
		out = append(out, p.From, p.To)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
