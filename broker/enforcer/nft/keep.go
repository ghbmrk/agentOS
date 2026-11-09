package nft

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Reload is Compile's ruleset followed, in the same transaction, by the
// answers the running ruleset holds for the names the new one still lists
// (ASSUMPTIONS ENF-set-keep-1), and by the shared segments' host records,
// holds and claims (records, ENF-shared-src-1). running is the running table as nft's JSON
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
//
// The fresh and recent sets (AllowSet) are carried for the kept addresses
// only, each recent one for the time it has left, so a load neither cuts
// a device that resolved a kept name a moment ago nor lets an answer it
// carries take new connections for longer than AnswerTimeout from its
// last Refresh (#4453).
func Reload(d policy.Document, l Layout, running []byte) (string, error) {
	text, devs, err := compile(d, l)
	if err != nil {
		return "", err
	}
	if len(running) == 0 {
		return text, nil
	}
	sets, err := listed(running)
	if err != nil {
		return "", err
	}
	have, left := elements(sets), recent(sets)
	w := &writer{}
	for _, a := range allowSets(d, devs) {
		for _, v6 := range []bool{false, true} {
			var all []netip.Addr
			for _, n := range a.names() {
				ns := a.Named(n, v6)
				kept := ofFamily(have[ns], v6)
				w.elements(ns, kept)
				all = append(all, kept...)
			}
			w.elements(a.set(v6), all)
			kept := map[netip.Addr]bool{}
			for _, e := range all {
				kept[e] = true
			}
			var fresh []netip.Addr
			for _, e := range ofFamily(have[a.Fresh(v6)], v6) {
				if kept[e] {
					fresh = append(fresh, e)
				}
			}
			w.elements(a.Fresh(v6), fresh)
			var rs []string
			for _, r := range left[a.Recent(v6)] {
				if a, err := netip.ParseAddr(r.addr); err == nil && kept[a] {
					rs = append(rs, a.String()+" expires "+secs(int(r.left)))
				}
			}
			if len(rs) > 0 {
				slices.Sort(rs)
				w.line("add element inet " + Table + " " + a.Recent(v6) + " { " + strings.Join(rs, ", ") + " }")
			}
		}
	}
	for _, r := range records(sets, l) {
		w.line("add element inet " + Table + " " + r.set + " { " + strings.Join(r.elems, ", ") + " }")
	}
	return text + w.b.String(), nil
}

// Refresh is the resolver's step (#4453): it moves every address in each
// fresh set of running (load.Loader.List of Table, the ruleset Compile or
// Reload made from d) into its recent set, each with a full AnswerTimeout,
// and takes it out of the fresh set, in one transaction. So an answer
// takes new connections from the moment the resolver adds it until
// AnswerTimeout after the next Refresh, and no longer: the daemon runs it
// on a fixed short interval, never while a load is under way, since a
// fresh answer never expires on its own. An address re-added to the
// recent set is deleted and added again: adding an element a set holds
// keeps its old expiry. An answer the resolver adds to the fresh set
// while Refresh runs either stays there for the next one or is refreshed
// by this one, from a later time than its answer; until then it takes
// new connections from the fresh set. Empty when no set has a fresh
// answer. The text holds only element changes to Table's sets (the
// loader's Update refuses anything else).
func Refresh(d policy.Document, l Layout, running []byte) (string, error) {
	devs, _, err := compiled(d, l)
	if err != nil {
		return "", err
	}
	sets, err := listed(running)
	if err != nil {
		return "", err
	}
	have := elements(sets)
	w := &writer{}
	for _, a := range allowSets(d, devs) {
		for _, v6 := range []bool{false, true} {
			fresh := ofFamily(have[a.Fresh(v6)], v6)
			if len(fresh) == 0 {
				continue
			}
			slices.SortFunc(fresh, netip.Addr.Compare)
			fresh = slices.Compact(fresh)
			s := make([]string, len(fresh))
			for i, e := range fresh {
				s[i] = e.String()
			}
			el := " { " + strings.Join(s, ", ") + " }"
			// Each delete follows an add, so it never names an element
			// the set lacks, which would refuse the whole transaction.
			for _, op := range []string{"add", "delete", "add"} {
				w.line(op + " element inet " + Table + " " + a.Recent(v6) + el)
			}
			for _, op := range []string{"add", "delete"} {
				w.line(op + " element inet " + Table + " " + a.Fresh(v6) + el)
			}
		}
	}
	return w.b.String(), nil
}

// ofFamily is the addresses of es of the family v6 picks.
func ofFamily(es []netip.Addr, v6 bool) []netip.Addr {
	var out []netip.Addr
	for _, e := range es {
		if e.Is6() == v6 {
			out = append(out, e)
		}
	}
	return out
}

// aging is one recent set's element: its value as nft printed it and the
// seconds it has left.
type aging struct {
	addr string
	left int64
}

// recent is each listed set's elements that are a value with an expiry
// and no timeout of their own, as a recent set holds them, each with the
// time it has left; one with more than AnswerTimeout left, or none, is
// left out, so it is not kept. Reload keeps only a value that parses as
// a kept address (nft and Go print some addresses differently, such as
// `::1.2.3.4` and `::102:304`), so a value in any other form is never
// carried.
func recent(sets []listedSet) map[string][]aging {
	out := map[string][]aging{}
	for _, s := range sets {
		for _, raw := range s.Elem {
			var e struct {
				Elem *struct {
					Val     string `json:"val"`
					Timeout *int64 `json:"timeout"`
					Expires int64  `json:"expires"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &e) != nil || e.Elem == nil || e.Elem.Timeout != nil || e.Elem.Expires <= 0 || e.Elem.Expires > AnswerTimeout {
				continue
			}
			out[s.Name] = append(out[s.Name], aging{e.Elem.Val, e.Elem.Expires})
		}
	}
	return out
}

// carried is one shared segment's set (HostSet, HeldSet, ClaimSet) with
// its elements as add element reads them, each with the time it has left.
type carried struct {
	set   string
	elems []string
}

// records is what the shared segments' sets hold in a JSON listing of the
// running table, so a load keeps every host record, hold and claim, each
// for the time it had left (#4480): a load then cuts no connection whose
// record it would drop, and frees no address a host holds for another
// host to take. Each element is read field by field and written again
// from the parsed values, never copied as text; one in any other form, or
// with no time left, is left out, which fails closed (bound, claim). The
// elements reach only the load's text, which goes to nft's input and
// nowhere else (the loader reports nft's first error line only, a
// position, not the text): a guest's or person's addresses are never
// logged or kept (NET-1, NET-3).
func records(sets []listedSet, l Layout) []carried {
	// Each set's element reader, its own timeout and the longest time an
	// element may have left, in seconds, by the set's name.
	read := map[string]func(json.RawMessage) (string, bool){}
	timeout, longest := map[string]int64{}, map[string]int64{}
	for _, sg := range segments(l) {
		for _, v6 := range []bool{false, true} {
			timeout[HostSet(sg.name, v6)], longest[HostSet(sg.name, v6)] = HostTimeout, HostTCPTimeout
			for _, s := range []string{HeldSet(sg.name, v6), ClaimSet(sg.name, v6)} {
				timeout[s], longest[s] = ClaimTimeout, ClaimTimeout
			}
			read[HostSet(sg.name, v6)] = func(raw json.RawMessage) (string, bool) {
				var c struct {
					Concat []json.RawMessage `json:"concat"`
				}
				if json.Unmarshal(raw, &c) != nil || len(c.Concat) != 4 {
					return "", false
				}
				var id uint32
				if json.Unmarshal(c.Concat[0], &id) != nil {
					return "", false
				}
				orig, ok1 := addrOf(c.Concat[1], v6)
				src, ok2 := addrOf(c.Concat[2], v6)
				hw, ok3 := hwOf(c.Concat[3])
				return fmt.Sprintf("%d . %s . %s . %s", id, orig, src, hw), ok1 && ok2 && ok3
			}
			read[HeldSet(sg.name, v6)] = func(raw json.RawMessage) (string, bool) {
				return addrOf(raw, v6)
			}
			read[ClaimSet(sg.name, v6)] = func(raw json.RawMessage) (string, bool) {
				var c struct {
					Concat []json.RawMessage `json:"concat"`
				}
				if json.Unmarshal(raw, &c) != nil || len(c.Concat) != 2 {
					return "", false
				}
				a, ok1 := addrOf(c.Concat[0], v6)
				hw, ok2 := hwOf(c.Concat[1])
				return a + " . " + hw, ok1 && ok2
			}
		}
	}
	var out []carried
	for _, s := range sets {
		if read[s.Name] == nil {
			continue
		}
		c := carried{set: s.Name}
		for _, raw := range s.Elem {
			var e struct {
				Elem *struct {
					Val     json.RawMessage `json:"val"`
					Expires int64           `json:"expires"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &e) != nil || e.Elem == nil || e.Elem.Expires <= 0 {
				continue
			}
			v, ok := read[s.Name](e.Elem.Val)
			if !ok || e.Elem.Expires > longest[s.Name] {
				continue
			}
			// An element refreshed for longer than its set's timeout (a TCP
			// connection's record, bound) needs a timeout of its own as long
			// as the time it has left.
			x := strconv.FormatInt(e.Elem.Expires, 10) + "s"
			if e.Elem.Expires > timeout[s.Name] {
				v += " timeout " + x
			}
			c.elems = append(c.elems, v+" expires "+x)
		}
		if len(c.elems) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// addrOf is a listed address of the family v6 picks, as nft reads it.
func addrOf(raw json.RawMessage, v6 bool) (string, bool) {
	var str string
	if json.Unmarshal(raw, &str) != nil {
		return "", false
	}
	a, err := netip.ParseAddr(str)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.Is6() != v6 {
		return "", false
	}
	return a.String(), true
}

// hwOf is a listed hardware (Ethernet) address, as nft reads it.
func hwOf(raw json.RawMessage) (string, bool) {
	var str string
	if json.Unmarshal(raw, &str) != nil {
		return "", false
	}
	hw, err := net.ParseMAC(str)
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return hw.String(), true
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

// listedSet is one set of Table in a JSON listing of it, its elements
// as nft printed them.
type listedSet struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Name   string            `json:"name"`
	Elem   []json.RawMessage `json:"elem"`
}

// listed is each set of Table (family inet) in a JSON listing.
func listed(listing []byte) ([]listedSet, error) {
	var doc struct {
		Nftables []struct {
			Set *listedSet `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return nil, fmt.Errorf("nft: running table listing: %v", err)
	}
	var out []listedSet
	for _, o := range doc.Nftables {
		if s := o.Set; s != nil && s.Family == "inet" && s.Table == Table {
			out = append(out, *s)
		}
	}
	return out, nil
}

// elements is each listed set with its plain address elements. An element
// in any other form (an interval, or one with its own timeout, which no
// resolver here adds) is left out, so it is not kept.
func elements(sets []listedSet) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for _, s := range sets {
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
	return out
}
