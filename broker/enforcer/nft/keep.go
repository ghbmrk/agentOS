package nft

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Reload is Compile's ruleset followed, in the same transaction, by the
// answers the running ruleset holds for the names the new one still lists
// (ASSUMPTIONS ENF-set-keep-1). running is the running table as nft's JSON
// (load.Loader.List of Table); empty for none, as at the first load.
//
// The resolver puts each answer's addresses in its list's allow set and in
// the name's own set (AllowSet.Named). Reload copies each kept name's set
// into the new ruleset and fills each allow set with only the union of its
// kept names' sets; the old allow sets are never read. So a device keeps
// reaching what it already resolved for a name still listed (#4080), and
// an address only a dropped name answered leaves its allow set, which
// cuts the connections open to it (#4237; the live form checks the set).
// A name set is the holder's and the name's alone: a name dropped and
// listed again, or a device that takes over another's VLAN, starts empty.
func Reload(d policy.Document, l Layout, running []byte) (string, error) {
	text, devs, err := compile(d, l)
	if err != nil {
		return "", err
	}
	if len(running) == 0 {
		return text, nil
	}
	have, err := elements(running)
	if err != nil {
		return "", err
	}
	w := &writer{}
	for _, a := range allowSets(d, devs) {
		for _, v6 := range []bool{false, true} {
			var all []netip.Addr
			for _, n := range a.names() {
				ns := a.Named(n, v6)
				var kept []netip.Addr
				for _, e := range have[ns] {
					if e.Is6() == v6 {
						kept = append(kept, e)
					}
				}
				w.elements(ns, kept)
				all = append(all, kept...)
			}
			w.elements(a.set(v6), all)
		}
	}
	return text + w.b.String(), nil
}

// elements writes one add element line for set, with addrs each once in
// order; nothing for none.
func (w *writer) elements(set string, addrs []netip.Addr) {
	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, netip.Addr.Compare)
	addrs = slices.Compact(addrs)
	if len(addrs) == 0 {
		return
	}
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	w.line("add element inet " + Table + " " + set + " { " + strings.Join(s, ", ") + " }")
}

// elements is each set of Table in a JSON listing with its plain address
// elements. An element in any other form (an interval, or one with its own
// timeout, which no resolver here adds) is left out, so it is not kept.
func elements(listing []byte) (map[string][]netip.Addr, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Family string            `json:"family"`
				Table  string            `json:"table"`
				Name   string            `json:"name"`
				Elem   []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return nil, fmt.Errorf("nft: running table listing: %v", err)
	}
	out := map[string][]netip.Addr{}
	for _, o := range doc.Nftables {
		s := o.Set
		if s == nil || s.Family != "inet" || s.Table != Table {
			continue
		}
		for _, raw := range s.Elem {
			var str string
			if json.Unmarshal(raw, &str) != nil {
				continue
			}
			a, err := netip.ParseAddr(str)
			if err != nil || a.Zone() != "" || a.Is4In6() {
				continue
			}
			out[s.Name] = append(out[s.Name], a)
		}
	}
	return out, nil
}
