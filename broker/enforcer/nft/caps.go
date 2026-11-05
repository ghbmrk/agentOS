package nft

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// The byte caps in the kernel's own path (SPEC NET-2 Byte caps, D-248,
// D-255; ASSUMPTIONS ENF-cap-trip-c-*). The ruleset counts every byte the
// core sends to an internet address it may reach, per address, and every
// byte the edge sends to the internet, and drops what passes a cap before
// it leaves. The counts never restart within one ruleset load, so
// broker/enforcer/traffic reads them as one reading after another and
// trips on any cap passed; the drop stops the bytes past it from leaving
// in the meantime.
//
// The counting is fixed in the ruleset (Compile). The drop is the
// enforcer's day state, which the ruleset cannot know: which destinations
// share an address today and so share one cap, and how much each group
// has sent. That part is Drops' text, written from traffic.Counter.Drop
// after every reading and appended to every load; until it is, the core's
// and the edge's internet traffic is dropped, so a load without it fails
// closed.

// CapSet is the set that counts, per internet address, the IP bytes the
// core sent it since the ruleset was loaded: dynamic, at most CapSize
// addresses per family, and no element times out within a load. EdgeOut
// counts the edge's.
func CapSet(v6 bool) string { return "capc" + fam(v6) }

const (
	EdgeOut = "edge_out"
	CapDrop = "cap_drop" // packets a cap dropped, the core's and the edge's
	CapSize = 65535
	// MaxDropCap is the largest cap the kernel's quota can hold one byte
	// past (it takes at most 2^63-1). A larger cap, more than any link
	// carries in a day, has no drop; it still trips.
	MaxDropCap = 1<<63 - 2
)

// LogCap prefixes the kernel log line of a packet a cap dropped. A cap
// passed is a trip at the enforcer (KRN-12); the daemon makes it from the
// next reading, and the line says when the kernel first stopped bytes.
const LogCap = "enf cap "

// The cap chains. capChain counts the core's sends to its allow set, and
// edgeChain the edge's to the internet; each then goes to its drop chain,
// whose rules Drops writes. A packet past its cap goes to LogCap's logged
// chain: counted on CapDrop, logged within the cap's lines, dropped.
const (
	edgeChain     = "cap_edge"
	dropEdgeChain = "capd_edge"
)

func capChain(v6 bool) string     { return "cap" + fam(v6) }
func capDropChain(v6 bool) string { return "capd" + fam(v6) }

// DropHeader is the first line of every Drops text. The loader applies a
// text outside a full load only when it starts with it (load.Loader.Update).
const DropHeader = "flush chain inet " + Table + " capd_4"

// Drop is the drop's day state: each cap group, the edge's cap and the
// bytes each has sent today (traffic.Counter.Drop).
type Drop struct {
	Day       uint32
	Groups    []DropGroup
	EdgeCap   uint64
	EdgeCount uint64
	// Past is this kernel's quota edge (load.Loader.QuotaPast): true where
	// "over N" matches once the count is past N, false where it matches
	// once it reaches N. Each quota's N is the cap, or the cap plus one, so
	// the first byte past the cap is the first one dropped. Left false on
	// a kernel that matches past N, the drop lets one byte more through
	// than the cap, which the next reading still trips on.
	Past bool
	// Read is the listing the counter's last reading was taken from
	// (traffic.ReadingOf's), when the text is applied on its own after
	// that reading; nil otherwise. traffic.Counter.Drop fills it from the
	// reading it added last, so no caller sets it. A quota the text
	// starts in place of running ones (a merge, a new cap, a new day) is
	// loaded with the group's count plus what the running quotas it
	// replaces charged between Read and the running listing, so bytes
	// sent between the reading and the update are not let past its cap
	// uncharged.
	Read []byte
}

// DropGroup is one cap group: its destinations by their names on the
// signed list, sorted, each one's own cap, their one cap, the bytes the
// core sent them today, and the addresses the counter gives them today.
// An address in several groups is one the counter keeps them apart at,
// because it was neither resolved nor carried bytes today; its bytes are
// charged to each.
type DropGroup struct {
	Dests []string
	Caps  []uint64
	Cap   uint64
	Count uint64
	Addrs []netip.Addr
}

var ErrDrop = errors.New("nft: byte-cap drop state malformed")

// Drops is the text that sets the drop to p, in one transaction: every
// address p gives a group is charged to that group's quota, and any other
// address the core may reach to the group of the first destination,
// by name, whose resolver set holds it; anything else is dropped. A
// group's quota drops the first byte past its cap: it is loaded with the
// group's count and stops a packet once the count would pass the cap (N
// is the cap, or the cap plus one on a kernel whose quota matches at N;
// Drop.Past), agreeing with wire.PastCap to the byte.
//
// running is the running table's listing (load.Loader.List), taken after
// p.Read, when the text is applied on its own (load.Loader.Update), so the
// quotas of groups p no longer has are deleted and those it keeps go on
// counting in the kernel; nil when the text is appended to a full load
// (Compile or Reload), which starts with none. A quota the text starts
// while running ones are deleted carries what they charged since p.Read
// (gap): the edge's every deleted edge quota's, and a group's every
// deleted group quota's whose chain the running drop sent one of the
// group's destinations or addresses to.
func Drops(d policy.Document, l Layout, running []byte, p Drop) (string, error) {
	if _, _, err := compiled(d, l); err != nil {
		return "", err
	}
	if err := p.check(); err != nil {
		return "", err
	}
	core := allowSets(d, nil)[0]
	have := map[string]bool{}
	var gaps map[string]uint64
	var fed map[string]feed
	if running != nil {
		var err error
		if have, err = capObjects(running); err != nil {
			return "", err
		}
		if gaps, err = gap(p.Read, running); err != nil {
			return "", err
		}
		if fed, err = feeds(core, running); err != nil {
			return "", err
		}
	}
	w := &writer{}
	w.line(DropHeader)
	w.line("flush chain inet " + Table + " " + capDropChain(true))
	w.line("flush chain inet " + Table + " " + dropEdgeChain)

	want := map[string]bool{}
	byDest := map[string]string{}
	var adds []string
	edge := uint64(1)
	if p.Past {
		edge = 0
	}
	for _, g := range p.Groups {
		_, q := groupNames(p.Day, g)
		want[q] = true
	}
	qe := edgeQuota(p.Day, p.EdgeCap)
	want[qe] = true
	// carried is what the running quotas this text deletes charged since
	// the reading, of those pick takes.
	carried := func(pick func(old string) bool) uint64 {
		var n uint64
		for old, b := range gaps {
			if have[old] && !want[old] && pick(old) {
				n = sat(n, b)
			}
		}
		return n
	}
	quota := func(name string, limit, count uint64, pick func(old string) bool) {
		if !have[name] && limit <= MaxDropCap {
			n := limit + edge
			used := min(sat(count, carried(pick)), n)
			adds = append(adds, fmt.Sprintf("add quota inet %s %s { over %d bytes used %d bytes; }", Table, name, n, used))
		}
	}
	chains := map[string]string{} // group chain -> its quota
	for _, g := range p.Groups {
		c, q := groupNames(p.Day, g)
		quota(q, g.Cap, g.Count, func(old string) bool {
			f := fed["g_"+strings.TrimPrefix(old, "q_")]
			return strings.HasPrefix(old, "q_") && (slices.ContainsFunc(g.Dests, f.dest) || slices.ContainsFunc(g.Addrs, f.addr))
		})
		want[c], chains[c] = true, q
		for _, dest := range g.Dests {
			byDest[dest] = c
		}
	}
	quota(qe, p.EdgeCap, p.EdgeCount, func(old string) bool { return strings.HasPrefix(old, "qe_") })
	// An address the counter gives several groups (one their sets hold,
	// carrying nothing today, so the counter keeps them apart) is charged
	// to every one of their quotas, in a chain of its own per set of
	// groups.
	groupsOf := map[netip.Addr][]string{}
	for _, g := range p.Groups {
		c, _ := groupNames(p.Day, g)
		for _, a := range g.Addrs {
			groupsOf[a] = append(groupsOf[a], c)
		}
	}
	target := map[netip.Addr]string{}
	shared := map[string][]string{} // shared chain -> its groups' chains
	for a, cs := range groupsOf {
		if len(cs) == 1 {
			target[a] = cs[0]
			continue
		}
		slices.Sort(cs)
		m := sharedName(cs)
		target[a], shared[m], want[m] = m, cs, true
	}
	for name := range have {
		if !want[name] && isGroupChain(name) {
			w.line("delete chain inet " + Table + " " + name)
		}
	}
	for name := range have {
		if !want[name] && !isGroupChain(name) {
			w.line("delete quota inet " + Table + " " + name)
		}
	}
	for _, a := range adds {
		w.line(a)
	}
	for _, c := range slices.Sorted(maps.Keys(chains)) {
		if have[c] {
			continue
		}
		w.line("add chain inet " + Table + " " + c)
		for _, r := range capped(chains[c], capOf(p, c)) {
			w.line("add rule inet " + Table + " " + c + " " + r)
		}
	}
	for _, m := range slices.Sorted(maps.Keys(shared)) {
		if have[m] {
			continue
		}
		w.line("add chain inet " + Table + " " + m)
		for _, c := range shared[m] {
			for _, r := range capped(chains[c], capOf(p, c)) {
				w.line("add rule inet " + Table + " " + m + " " + r)
			}
		}
	}
	for _, v6 := range []bool{false, true} {
		ch := capDropChain(v6)
		var elems []string
		for a, c := range target {
			if a.Is6() == v6 {
				elems = append(elems, a.String()+" : goto "+c)
			}
		}
		if len(elems) > 0 {
			slices.Sort(elems)
			w.line("add rule inet " + Table + " " + ch + " " + family(v6) + " daddr vmap { " + strings.Join(elems, ", ") + " }")
		}
		for _, n := range core.names() {
			if c, ok := byDest[n]; ok {
				w.line("add rule inet " + Table + " " + ch + " " + family(v6) + " daddr @" + core.Named(n, v6) + " goto " + c)
			}
		}
		w.line("add rule inet " + Table + " " + ch + " drop")
	}
	for _, r := range capped(qe, p.EdgeCap) {
		w.line("add rule inet " + Table + " " + dropEdgeChain + " " + r)
	}
	return w.b.String(), nil
}

// capped is the rules of a chain that charges a packet to quota q of cap:
// past it, the packet goes to the drop; none for a cap the kernel's quota
// cannot hold, which then only trips.
func capped(q string, limit uint64) []string {
	if limit > MaxDropCap {
		return nil
	}
	return []string{"quota name " + strconv.Quote(q) + " goto " + logged(LogCap)}
}

// sharedName is the chain that charges an address to each of the groups
// whose chains are cs, sorted: one name per set of groups.
func sharedName(cs []string) string {
	h := sha256.Sum256([]byte(strings.Join(cs, "\x00")))
	return "m_" + hex.EncodeToString(h[:8])
}

// isGroupChain is whether a drop object's name is a chain's (a group's or a
// shared address's) rather than a quota's.
func isGroupChain(name string) bool {
	return strings.HasPrefix(name, "g_") || strings.HasPrefix(name, "m_")
}

func capOf(p Drop, chain string) uint64 {
	for _, g := range p.Groups {
		if c, _ := groupNames(p.Day, g); c == chain {
			return g.Cap
		}
	}
	return 0
}

// groupNames is a group's chain and quota: one name per day, destinations
// and caps, so a group that stays the same keeps its quota and its count
// in the kernel, and any change (a merge, a new cap, a new day) starts a
// new quota from the counter's count.
func groupNames(day uint32, g DropGroup) (chain, quota string) {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, day)
	for i, dest := range g.Dests {
		h.Write([]byte(dest + "\x00"))
		_ = binary.Write(h, binary.BigEndian, g.Caps[i])
	}
	s := hex.EncodeToString(h.Sum(nil)[:8])
	return "g_" + s, "q_" + s
}

func edgeQuota(day uint32, limit uint64) string {
	var b [12]byte
	binary.BigEndian.PutUint32(b[:4], day)
	binary.BigEndian.PutUint64(b[4:], limit)
	h := sha256.Sum256(append([]byte("edge\x00"), b[:]...))
	return "qe_" + hex.EncodeToString(h[:8])
}

// check refuses a state the text could not hold to the byte: a group
// without destinations, a destination in two groups, an address twice in
// one, or an address not in its plain form.
func (p Drop) check() error {
	dests := map[string]bool{}
	for _, g := range p.Groups {
		addrs := map[netip.Addr]bool{}
		if len(g.Dests) == 0 || len(g.Caps) != len(g.Dests) || !slices.IsSorted(g.Dests) {
			return fmt.Errorf("%w: group %v", ErrDrop, g.Dests)
		}
		for _, d := range g.Dests {
			if dests[d] {
				return fmt.Errorf("%w: %q in two groups", ErrDrop, d)
			}
			dests[d] = true
		}
		for _, a := range g.Addrs {
			if !a.IsValid() || a.Zone() != "" || a.Is4In6() || addrs[a] {
				return fmt.Errorf("%w: address %v", ErrDrop, a)
			}
			addrs[a] = true
		}
	}
	return nil
}

// sat is a + b, at most the largest uint64.
func sat(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// gap is, per quota in both listings, what it charged from read to
// running: nothing when read is nil.
func gap(read, running []byte) (map[string]uint64, error) {
	if read == nil {
		return nil, nil
	}
	before, err := quotasUsed(read)
	if err != nil {
		return nil, err
	}
	after, err := quotasUsed(running)
	if err != nil {
		return nil, err
	}
	out := map[string]uint64{}
	for q, n := range after {
		if b, ok := before[q]; ok && n > b {
			out[q] = n - b
		}
	}
	return out, nil
}

// quotasUsed is each quota's charged bytes in a listing.
func quotasUsed(listing []byte) (map[string]uint64, error) {
	var doc struct {
		Nftables []struct {
			Quota *struct {
				Family, Table, Name string
				Used                uint64
			} `json:"quota"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return nil, fmt.Errorf("nft: table listing: %v", err)
	}
	out := map[string]uint64{}
	for _, o := range doc.Nftables {
		if o.Quota != nil && o.Quota.Family == "inet" && o.Quota.Table == Table {
			out[o.Quota.Name] = o.Quota.Used
		}
	}
	return out, nil
}

// feed is what the running drop sends to one group chain: destinations by
// their resolver sets, and addresses by the verdict maps.
type feed struct {
	dests map[string]bool
	addrs map[netip.Addr]bool
}

func (f feed) dest(d string) bool     { return f.dests[d] }
func (f feed) addr(a netip.Addr) bool { return f.addrs[a] }

// feeds is, per group chain, what the running listing's drop chains send
// it.
func feeds(core AllowSet, listing []byte) (map[string]feed, error) {
	byset := map[string]string{}
	for _, n := range core.names() {
		byset[core.Named(n, false)], byset[core.Named(n, true)] = n, n
	}
	type target struct {
		Goto *struct{ Target string } `json:"goto"`
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Family, Table, Chain string
				Expr                 []struct {
					Match *struct{ Right json.RawMessage } `json:"match"`
					Vmap  *struct{ Data json.RawMessage }  `json:"vmap"`
					target
				}
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return nil, fmt.Errorf("nft: running table listing: %v", err)
	}
	out := map[string]feed{}
	at := func(chain string) feed {
		f, ok := out[chain]
		if !ok {
			f = feed{dests: map[string]bool{}, addrs: map[netip.Addr]bool{}}
			out[chain] = f
		}
		return f
	}
	for _, o := range doc.Nftables {
		r := o.Rule
		if r == nil || r.Family != "inet" || r.Table != Table || (r.Chain != capDropChain(false) && r.Chain != capDropChain(true)) {
			continue
		}
		var set string
		for _, e := range r.Expr {
			switch {
			case e.Match != nil:
				var right string
				if json.Unmarshal(e.Match.Right, &right) == nil {
					set = strings.TrimPrefix(right, "@")
				}
			case e.Vmap != nil:
				var data struct{ Set []json.RawMessage }
				if err := json.Unmarshal(e.Vmap.Data, &data); err != nil {
					return nil, fmt.Errorf("%w: running verdict map %s", ErrDrop, e.Vmap.Data)
				}
				for _, raw := range data.Set {
					var pair []json.RawMessage
					var addr string
					var v target
					if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 || json.Unmarshal(pair[0], &addr) != nil || json.Unmarshal(pair[1], &v) != nil || v.Goto == nil {
						return nil, fmt.Errorf("%w: running verdict map element %s", ErrDrop, raw)
					}
					a, err := netip.ParseAddr(addr)
					if err != nil {
						return nil, fmt.Errorf("%w: running verdict map address %q", ErrDrop, addr)
					}
					at(v.Goto.Target).addrs[a] = true
				}
			case e.Goto != nil && byset[set] != "":
				at(e.Goto.Target).dests[byset[set]] = true
			}
		}
	}
	return out, nil
}

// capObjects is the drop's chains and quotas in a running table's listing.
func capObjects(listing []byte) (map[string]bool, error) {
	var doc struct {
		Nftables []struct {
			Chain *struct{ Family, Table, Name string } `json:"chain"`
			Quota *struct{ Family, Table, Name string } `json:"quota"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(listing, &doc); err != nil {
		return nil, fmt.Errorf("nft: running table listing: %v", err)
	}
	out := map[string]bool{}
	for _, o := range doc.Nftables {
		switch {
		case o.Chain != nil && o.Chain.Family == "inet" && o.Chain.Table == Table && isGroupChain(o.Chain.Name):
			out[o.Chain.Name] = true
		case o.Quota != nil && o.Quota.Family == "inet" && o.Quota.Table == Table:
			out[o.Quota.Name] = true
		}
	}
	return out, nil
}

// capDecls declares the counting sets.
func capDecls(w *writer) {
	for _, v6 := range []bool{false, true} {
		w.open("set " + CapSet(v6))
		w.line("type " + map[bool]string{false: "ipv4_addr", true: "ipv6_addr"}[v6] + ";")
		w.line("size " + strconv.Itoa(CapSize) + ";")
		w.line("flags dynamic;")
		w.close()
	}
}

// capChains writes the counting chains, which hand each packet to its
// drop chain; those drop everything until Drops fills them. What the forward rules would
// refuse before an internet accept (the access point's admin, the ISP
// router, addresses that are not the internet) is not counted, so the
// count is exactly what the core or the edge may send. The core's sends
// count per address in its counting set; an address the full set cannot
// take is dropped, so no byte goes uncounted.
func capChains(w *writer) {
	q := strconv.Quote
	for _, v6 := range []bool{false, true} {
		f, s := family(v6), fam(v6)
		w.open("chain " + capChain(v6))
		w.line(f + " daddr @ap" + s + " return")
		w.line(f + " daddr @isp" + s + " return")
		w.line(f + " daddr @nonglobal" + s + " return")
		w.line("update @" + CapSet(v6) + " { " + f + " daddr counter }")
		w.line(f + " daddr != @" + CapSet(v6) + " drop")
		w.line("goto " + capDropChain(v6))
		w.close()
		w.open("chain " + capDropChain(v6))
		w.line("drop")
		w.close()
	}
	w.open("chain " + edgeChain)
	for _, v6 := range []bool{false, true} {
		f, s := family(v6), fam(v6)
		w.line(f + " daddr @ap" + s + " return")
		w.line(f + " daddr @isp" + s + " return")
		w.line(f + " daddr @nonglobal" + s + " return")
	}
	w.line("counter name " + q(EdgeOut))
	w.line("goto " + dropEdgeChain)
	w.close()
	w.open("chain " + dropEdgeChain)
	w.line("drop")
	w.close()
}

// capJumps is the forward chain's rules that send the core's packets to
// its allow set, and the edge's to the internet, through the cap chains,
// before any other rule decides them.
func capJumps(l Layout) []string {
	q := strconv.Quote
	core, edge, wan := q(l.Core), q(l.Edge), q(l.WAN)
	return []string{
		"iifname " + core + " oifname " + wan + " ip daddr @" + CoreSet(false) + " jump " + capChain(false),
		"iifname " + core + " oifname " + wan + " ip6 daddr @" + CoreSet(true) + " jump " + capChain(true),
		"iifname " + edge + " oifname " + wan + " jump " + edgeChain,
	}
}
