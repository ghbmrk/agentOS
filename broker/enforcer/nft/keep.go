package nft

import (
	"encoding/json"
	"fmt"
	"maps"
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
// leases and holds (records, ENF-shared-src-1). running is the running table as nft's JSON
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
// only, each for the time it has left, so a load neither cuts a device
// that resolved a kept name a moment ago nor lets an answer it carries
// take new connections for longer than AnswerTimeout from its last
// Refresh, or from its first add when no Refresh has moved it (#4453,
// #5116). A running table from before the sets were added, or whose
// fresh set had no timeout, carries none (ASSUMPTIONS ENF-set-ttl-2).
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
			for _, set := range []string{a.Fresh(v6), a.Recent(v6)} {
				var rs []string
				for _, r := range left[set] {
					if a, err := netip.ParseAddr(r.addr); err == nil && kept[a] {
						rs = append(rs, a.String()+" expires "+secs(int(r.left)))
					}
				}
				if len(rs) > 0 {
					slices.Sort(rs)
					w.line("add element inet " + Table + " " + set + " { " + strings.Join(rs, ", ") + " }")
				}
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
// on a fixed short interval, never while a load is under way. A fresh
// answer expires on its own only AnswerTimeout after its first add, which
// bounds it when the step keeps failing (#5116). An address re-added to the
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
	left := recent(sets)
	w := &writer{}
	for _, a := range allowSets(d, devs) {
		for _, v6 := range []bool{false, true} {
			var fresh []netip.Addr
			for _, r := range left[a.Fresh(v6)] {
				if e, err := netip.ParseAddr(r.addr); err == nil && e.Zone() == "" && !e.Is4In6() && e.Is6() == v6 {
					fresh = append(fresh, e)
				}
			}
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
// and no timeout of their own, as a fresh or recent set holds them, each with the
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

// carried is one shared segment's set (HostSet, LeaseSet, LeaseAddrSet,
// LeasedSet, HeldSet, ClaimSet, MACSet) with its elements as add element
// reads them, each with the time it has left.
type carried struct {
	set   string
	elems []string
}

// carry is how records reads the elements of one listed set: read parses
// an element's value into one element for each set of into, which lasts
// timeout unless given its own; an element with more than longest seconds
// left is left out.
type carry struct {
	into             []string
	read             func(json.RawMessage) ([]string, bool)
	timeout, longest int64
}

// records is what the shared segments' sets hold in a JSON listing of the
// running table, so a load keeps every host record, lease and hold, each
// for the time it had left (#4480): a load then cuts no connection whose
// record it would drop, drops no host that holds a lease, and frees no
// address a host holds for another host to take. A running table from
// before the leases (#5294) holds IPv4 claims instead: each becomes a lease
// for the time its claim had left, which is at most ClaimTimeout, half a
// lease, so it ends before the lease it stands for unless the client
// stopped renewing (ENF-shared-src-1). Each element is read field by field
// and written again from the parsed values, never copied as text; one in
// any other form, or with no time left, is left out, which fails closed
// (bound, claim). The elements reach only the load's text, which goes to
// nft's input and nowhere else (the loader reports nft's first error line
// only, a position, not the text): a guest's or person's addresses are
// never logged or kept (NET-1, NET-3).
func records(sets []listedSet, l Layout) []carried {
	by := map[string]carry{}
	for _, sg := range segments(l) {
		for _, v6 := range []bool{false, true} {
			by[HostSet(sg.name, v6)] = carry{[]string{HostSet(sg.name, v6)}, func(raw json.RawMessage) ([]string, bool) {
				c, ok := concat(raw, 4)
				if !ok {
					return nil, false
				}
				var id uint32
				if json.Unmarshal(c[0], &id) != nil {
					return nil, false
				}
				orig, ok1 := addrOf(c[1], v6)
				src, ok2 := addrOf(c[2], v6)
				hw, ok3 := hwOf(c[3])
				return []string{fmt.Sprintf("%d . %s . %s . %s", id, orig, src, hw)}, ok1 && ok2 && ok3
			}, HostTimeout, HostTCPTimeout}
		}
		// LeaseAddrSet is not read: each load writes it again from the
		// leases it carries, so it holds exactly their addresses.
		leases := []string{LeaseSet(sg.name), LeaseAddrSet(sg.name), LeasedSet(sg.name)}
		by[LeaseSet(sg.name)] = carry{leases[:2], func(raw json.RawMessage) ([]string, bool) {
			c, ok := concat(raw, 2)
			if !ok {
				return nil, false
			}
			var a uint32
			var hw uint64
			if json.Unmarshal(c[0], &a) != nil || a == 0 || json.Unmarshal(c[1], &hw) != nil || hw>>48 != 0 {
				return nil, false
			}
			return []string{leaseElem(a, hw), addrElem(a)}, true
		}, LeaseTimeout, LeaseTimeout}
		by[LeasedSet(sg.name)] = carry{leases[2:], rawHW, LeaseTimeout, LeaseTimeout}
		// The IPv4 claims of a running table from before the leases.
		by["claim_"+sg.name+"_4"] = carry{leases, func(raw json.RawMessage) ([]string, bool) {
			c, ok := concat(raw, 2)
			if !ok {
				return nil, false
			}
			var a, hw string
			if json.Unmarshal(c[0], &a) != nil || json.Unmarshal(c[1], &hw) != nil {
				return nil, false
			}
			ip, err1 := netip.ParseAddr(a)
			mac, err2 := net.ParseMAC(hw)
			if err1 != nil || err2 != nil || !ip.Is4() || ip.IsUnspecified() || len(mac) != 6 {
				return nil, false
			}
			v, x, h := lease(ip, mac)
			return []string{v, x, h}, true
		}, LeaseTimeout, ClaimTimeout}
		by[HeldSet(sg.name)] = carry{[]string{HeldSet(sg.name)}, func(raw json.RawMessage) ([]string, bool) {
			a, ok := addrOf(raw, true)
			return []string{a}, ok
		}, ClaimTimeout, ClaimTimeout}
		by[ClaimSet(sg.name)] = carry{[]string{ClaimSet(sg.name)}, func(raw json.RawMessage) ([]string, bool) {
			c, ok := concat(raw, 2)
			if !ok {
				return nil, false
			}
			a, ok1 := addrOf(c[0], true)
			hw, ok2 := hwOf(c[1])
			return []string{a + " . " + hw}, ok1 && ok2
		}, ClaimTimeout, ClaimTimeout}
		by[MACSet(sg.name)] = carry{[]string{MACSet(sg.name)}, rawHW, ClaimTimeout, ClaimTimeout}
	}
	w := elems{}
	for _, s := range sets {
		// A set records does not carry has the zero carry, whose longest
		// of 0 leaves every element out.
		r := by[s.Name]
		for _, raw := range s.Elem {
			var e struct {
				Elem *struct {
					Val     json.RawMessage `json:"val"`
					Expires int64           `json:"expires"`
				} `json:"elem"`
			}
			if json.Unmarshal(raw, &e) != nil || e.Elem == nil || e.Elem.Expires <= 0 || e.Elem.Expires > r.longest {
				continue
			}
			vs, ok := r.read(e.Elem.Val)
			if !ok {
				continue
			}
			for i, set := range r.into {
				w.add(set, vs[i], e.Elem.Expires, r.timeout)
			}
		}
	}
	return w.carried()
}

// elems gathers carried elements by set, in the order their sets come,
// each element once, with the longest time it was given.
type elems struct {
	order []string
	left  map[string]map[string]int64
	timed map[string]int64
}

// add adds element v of set, with left seconds left, to a set whose own
// timeout is timeout.
func (w *elems) add(set, v string, left, timeout int64) {
	if w.left == nil {
		w.left, w.timed = map[string]map[string]int64{}, map[string]int64{}
	}
	if w.left[set] == nil {
		w.order = append(w.order, set)
		w.left[set] = map[string]int64{}
		w.timed[set] = timeout
	}
	w.left[set][v] = max(w.left[set][v], left)
}

// carried is each set's elements as add element reads them, in the order
// they were first added. An element with more time left than its set's
// timeout (a TCP connection's record, bound) needs a timeout of its own
// as long as the time it has left.
func (w *elems) carried() []carried {
	var out []carried
	for _, set := range w.order {
		c := carried{set: set}
		for _, v := range slices.Sorted(maps.Keys(w.left[set])) {
			x := strconv.FormatInt(w.left[set][v], 10) + "s"
			if w.left[set][v] > w.timed[set] {
				v += " timeout " + x
			}
			c.elems = append(c.elems, v+" expires "+x)
		}
		out = append(out, c)
	}
	return out
}

// rawHW reads a listed raw hardware address (hwField) as one element.
func rawHW(raw json.RawMessage) ([]string, bool) {
	var hw uint64
	if json.Unmarshal(raw, &hw) != nil || hw>>48 != 0 {
		return nil, false
	}
	return []string{hwElem(hw)}, true
}

// concat is a listed concatenation of n fields.
func concat(raw json.RawMessage, n int) ([]json.RawMessage, bool) {
	var c struct {
		Concat []json.RawMessage `json:"concat"`
	}
	if json.Unmarshal(raw, &c) != nil || len(c.Concat) != n {
		return nil, false
	}
	return c.Concat, true
}

// Lease is an IPv4 lease the enforcer's DHCP server granted on a shared
// segment, as its lease file records it: the segment's interface (the
// Layout's Guests, Owner or Household), the leased address, the client's
// hardware address and the seconds the lease has left.
type Lease struct {
	Iface string
	Addr  netip.Addr
	HW    net.HardwareAddr
	Left  int64
}

// Seed is the text that puts leases in their segments' lease sets
// (LeaseSet, LeaseAddrSet, LeasedSet), each for the time it has left, so
// a load that follows it in the same transaction (after Compile's or
// Reload's text) passes every leased host at once, rather than only after
// its next renewal, up to half a lease later. A lease on no shared
// segment's interface, of no IPv4 address (or 0.0.0.0) or Ethernet
// hardware address, with no time left or with more than LeaseTimeout, is
// left out: its host waits for its next renewal (fails closed). Like
// records, the text goes only to nft's input (NET-1, NET-3). Empty for
// no leases.
func Seed(l Layout, leases []Lease) string {
	w := elems{}
	for _, sg := range segments(l) {
		for _, ls := range leases {
			if ls.Iface != sg.iface || !ls.Addr.Is4() || ls.Addr.IsUnspecified() || len(ls.HW) != 6 || ls.Left <= 0 || ls.Left > LeaseTimeout {
				continue
			}
			v, x, h := lease(ls.Addr, ls.HW)
			w.add(LeaseSet(sg.name), v, ls.Left, LeaseTimeout)
			w.add(LeaseAddrSet(sg.name), x, ls.Left, LeaseTimeout)
			w.add(LeasedSet(sg.name), h, ls.Left, LeaseTimeout)
		}
	}
	var b strings.Builder
	for _, c := range w.carried() {
		b.WriteString("add element inet " + Table + " " + c.set + " { " + strings.Join(c.elems, ", ") + " }\n")
	}
	return b.String()
}

// lease is a LeaseSet, a LeaseAddrSet and a LeasedSet element, as nft
// reads the sets' raw fields.
func lease(a netip.Addr, hw net.HardwareAddr) (string, string, string) {
	b := a.As4()
	v, h := uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]), hwInt(hw)
	return leaseElem(v, h), addrElem(v), hwElem(h)
}

// hwInt is hardware address hw as nft reads hwField.
func hwInt(hw net.HardwareAddr) uint64 {
	var h uint64
	for _, x := range hw {
		h = h<<8 | uint64(x)
	}
	return h
}

func leaseElem(a uint32, hw uint64) string { return fmt.Sprintf("0x%08x . %s", a, hwElem(hw)) }
func hwElem(hw uint64) string              { return fmt.Sprintf("0x%012x", hw) }
func addrElem(a uint32) string             { return fmt.Sprintf("0x%08x", a) }

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

// Held reads LeaseHeld in a JSON listing of the running table: table is
// the table's handle, which the kernel gives each new table, so each load
// (which starts the counter at 0) has its own, and held is how many of the
// address server's answers the snoop has held since. A table with no such
// counter (one loaded before it existed) holds none.
func Held(listing []byte) (table, held uint64, err error) {
	var doc struct {
		Nftables []struct {
			Table *struct {
				Family, Name string
				Handle       uint64
			} `json:"table"`
			Counter *struct {
				Family, Table, Name string
				Packets             uint64
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return 0, 0, fmt.Errorf("nft: running table listing: %v", err)
	}
	for _, o := range doc.Nftables {
		switch t, c := o.Table, o.Counter; {
		case t != nil && t.Family == "inet" && t.Name == Table:
			table = t.Handle
		case c != nil && c.Family == "inet" && c.Table == Table && c.Name == LeaseHeld:
			held = c.Packets
		}
	}
	return table, held, nil
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
