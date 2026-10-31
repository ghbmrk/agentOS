package mdns

// The record filter (#4069, NET-3 Casting): a relayed message is rebuilt
// from the parts of it the sender may say. A query keeps its questions
// for .local names only. A response keeps only the records that are its
// sender's own: host names whose addresses are on the sender's own link,
// service instances whose SRV targets are those hosts, and their TXT and
// PTR records. A name claimed on any other interface the relay hears is
// never the sender's, so a paired device cannot take over a name of its
// paired network or of another device.

import (
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// DNS record types the relay passes (RFC 1035, 2782, 3596).
const (
	typeA    = 1
	typePTR  = 12
	typeTXT  = 16
	typeAAAA = 28
	typeSRV  = 33
)

const classIN = 1

const (
	flagQR = 0x8000
	flagTC = 0x0200
)

// A name is its labels, without the root.
type name []string

type question struct {
	name       name
	typ, class uint16
}

type record struct {
	name       name
	typ, class uint16
	ttl        uint32
	// data is A's, AAAA's and TXT's rdata, and SRV's priority, weight and
	// port; target is PTR's and SRV's name.
	data   []byte
	target name
}

type message struct {
	id, flags  uint16
	questions  []question
	answers    []record
	authority  []record
	additional []record
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// parse reads a whole DNS message. It fails on anything malformed:
// truncated sections, bytes after the last record, forward or reserved
// name pointers, names over 255 bytes, or A, AAAA, PTR, SRV or TXT
// rdata of the wrong shape.
func parse(b []byte) (*message, bool) {
	if len(b) < 12 {
		return nil, false
	}
	m := &message{id: be16(b), flags: be16(b[2:])}
	off := 12
	for range be16(b[4:]) {
		n, next, ok := readName(b, off)
		if !ok || next+4 > len(b) {
			return nil, false
		}
		m.questions = append(m.questions, question{n, be16(b[next:]), be16(b[next+2:])})
		off = next + 4
	}
	for i, s := range []*[]record{&m.answers, &m.authority, &m.additional} {
		for range be16(b[6+2*i:]) {
			r, next, ok := readRecord(b, off)
			if !ok {
				return nil, false
			}
			*s = append(*s, r)
			off = next
		}
	}
	return m, off == len(b)
}

func readRecord(b []byte, off int) (record, int, bool) {
	n, off, ok := readName(b, off)
	if !ok || off+10 > len(b) {
		return record{}, 0, false
	}
	r := record{name: n, typ: be16(b[off:]), class: be16(b[off+2:]),
		ttl: uint32(be16(b[off+4:]))<<16 | uint32(be16(b[off+6:]))}
	start := off + 10
	end := start + int(be16(b[off+8:]))
	if end > len(b) {
		return record{}, 0, false
	}
	rdata := b[start:end]
	switch r.typ {
	case typeA, typeAAAA:
		ok = len(rdata) == 4 && r.typ == typeA || len(rdata) == 16 && r.typ == typeAAAA
		r.data = rdata
	case typeTXT:
		ok = txtValid(rdata)
		r.data = rdata
	case typePTR:
		r.target, off, ok = readName(b, start)
		ok = ok && off == end
	case typeSRV:
		ok = len(rdata) > 6
		if ok {
			r.data = rdata[:6]
			r.target, off, ok = readName(b, start+6)
			ok = ok && off == end
		}
	}
	return r, end, ok
}

// txtValid: TXT rdata is one or more length-prefixed strings that fill it
// exactly (RFC 6763 §6.1).
func txtValid(b []byte) bool {
	for len(b) > 0 {
		if int(b[0]) >= len(b) {
			return false
		}
		b = b[1+int(b[0]):]
	}
	return true
}

// readName reads the name at off and returns it with the offset after it.
// A pointer may only point back, before itself, so every pointer chain
// ends; the 255-byte bound ends a chain that keeps adding labels.
func readName(b []byte, off int) (name, int, bool) {
	var n name
	end, size := -1, 1
	for off < len(b) {
		c := int(b[off])
		switch {
		case c == 0:
			if end < 0 {
				end = off + 1
			}
			return n, end, true
		case c&0xC0 == 0xC0 && off+1 < len(b):
			p := (c&0x3F)<<8 | int(b[off+1])
			if p >= off {
				return nil, 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = p
		case c&0xC0 == 0 && off+1+c <= len(b):
			if size += 1 + c; size > 255 {
				return nil, 0, false
			}
			n = append(n, string(b[off+1:off+1+c]))
			off += 1 + c
		default:
			return nil, 0, false
		}
	}
	return nil, 0, false
}

// wire is n's labels on the wire, without the root.
func (n name) wire() string {
	var b strings.Builder
	for _, l := range n {
		b.WriteByte(byte(len(l)))
		b.WriteString(l)
	}
	return b.String()
}

// key is n's identity: its wire form with ASCII folded to lower case, as
// mDNS compares names (RFC 6762 §16).
func (n name) key() string {
	b := []byte(n.wire())
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// shown: every label of n is one a person can read as it is: valid UTF-8,
// not blank, with no control, format (bidi, zero-width, tag), separator
// other than a plain space, variation selector or invisible filler. A
// relayed name ends up in a person's device list, so a label that hides
// or reorders what it shows is refused.
func (n name) shown() bool {
	return !slices.ContainsFunc(n, func(l string) bool { return !labelNameOK(l) })
}

func labelNameOK(l string) bool {
	if !utf8.ValidString(l) || strings.TrimSpace(l) == "" {
		return false
	}
	for _, r := range l {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point) ||
			unicode.Is(unicode.Zs, r) && r != ' ' {
			return false
		}
	}
	return true
}

func (n name) local() bool { return len(n) > 1 && n.under("local") }

func (n name) under(l string) bool { return len(n) > 0 && strings.EqualFold(n[len(n)-1], l) }

// instance: <Instance>.<_service>.<_tcp or _udp>.local (RFC 6763 §4.1).
func (n name) instance() bool { return len(n) == 4 && n[1:].serviceType() }

// services is the service type enumeration name (RFC 6763 §9).
var services = name{"_services", "_dns-sd", "_udp", "local"}

// bytes is m on the wire, its names compressed.
func (m *message) bytes() []byte {
	w := writer{offsets: map[string]int{}}
	w.b = append(w.b, byte(m.id>>8), byte(m.id), byte(m.flags>>8), byte(m.flags))
	for _, n := range []int{len(m.questions), len(m.answers), len(m.authority), len(m.additional)} {
		w.b = append(w.b, byte(n>>8), byte(n))
	}
	for _, q := range m.questions {
		w.name(q.name)
		w.u16(q.typ)
		w.u16(q.class)
	}
	for _, r := range slices.Concat(m.answers, m.authority, m.additional) {
		w.name(r.name)
		w.u16(r.typ)
		w.u16(r.class)
		w.u16(uint16(r.ttl >> 16))
		w.u16(uint16(r.ttl))
		at := len(w.b)
		w.u16(0)
		w.b = append(w.b, r.data...)
		if r.typ == typePTR || r.typ == typeSRV {
			w.name(r.target)
		}
		n := len(w.b) - at - 2
		w.b[at], w.b[at+1] = byte(n>>8), byte(n)
	}
	return w.b
}

type writer struct {
	b       []byte
	offsets map[string]int
}

func (w *writer) u16(v uint16) { w.b = append(w.b, byte(v>>8), byte(v)) }

// name writes n, pointing at an earlier copy of its longest written
// suffix. Suffixes match byte for byte, so no label changes case.
func (w *writer) name(n name) {
	for i := range n {
		k := n[i:].wire()
		if o, ok := w.offsets[k]; ok {
			w.u16(0xC000 | uint16(o))
			return
		}
		if len(w.b) < 0x3FFF {
			w.offsets[k] = len(w.b)
		}
		w.b = append(w.b, byte(len(n[i])))
		w.b = append(w.b, n[i]...)
	}
	w.b = append(w.b, 0)
}

// How long the relay remembers names. A name claimed on an interface
// stays claimed for a day after it was last heard, whatever its TTL or a
// goodbye says, so a host that sleeps or leaves keeps its name from the
// devices. A device's own name lasts as long as its record does, at most
// mDNS's longest usual TTL (RFC 6762 §10).
const (
	claimHold = 24 * time.Hour
	ownHold   = 4500 * time.Second
	maxNames  = 256 // per interface and table; more are not learned
)

type names map[string]time.Time

// add notes k until until, unless the table is full of live names.
func (t names) add(k string, until, now time.Time) {
	if _, ok := t[k]; !ok && len(t) >= maxNames {
		for k, u := range t {
			if !u.After(now) {
				delete(t, k)
			}
		}
		if len(t) >= maxNames {
			return
		}
	}
	t[k] = until
}

func (t names) has(k string, now time.Time) bool { return t[k].After(now) }

// Filter is the relay's memory of names: for each interface, the names
// claimed by what was heard there, and the host and instance names its
// sender showed are its own.
type Filter struct {
	mu                  sync.Mutex
	claimed, hosts, ins map[string]names
}

func NewFilter() *Filter {
	return &Filter{claimed: map[string]names{}, hosts: map[string]names{}, ins: map[string]names{}}
}

func table(m map[string]names, iface string) names {
	if m[iface] == nil {
		m[iface] = names{}
	}
	return m[iface]
}

// Hear notes the names m, heard on iface, claims: every record's name in
// a response, a PTR's instance, and a probe's proposed records (a query's
// authority section). A query's known answers are what its sender
// cached, not what it owns, so they claim nothing.
func (f *Filter) Hear(iface string, m *message, now time.Time) {
	rs := m.authority
	if m.flags&flagQR != 0 {
		rs = slices.Concat(m.answers, m.authority, m.additional)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t := table(f.claimed, iface)
	for _, r := range rs {
		n := r.name
		if r.typ == typePTR {
			n = r.target
		}
		if r.typ != typePTR || n.instance() {
			t.add(n.key(), now.Add(claimHold), now)
		}
	}
}

// Pass is m as it may leave iface, whose own addresses are the hosts in
// link's prefixes other than the enforcer's own; nil if nothing is left.
func (f *Filter) Pass(iface string, link []netip.Prefix, m *message, now time.Time) []byte {
	out := &message{id: m.id, flags: m.flags &^ flagTC}
	if m.flags&flagQR == 0 {
		for _, q := range m.questions {
			if q.name.local() && q.name.shown() && q.class&0x7FFF == classIN {
				out.questions = append(out.questions, q)
			}
		}
		if len(out.questions) == 0 {
			return nil
		}
		return out.bytes()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	elsewhere := func(k string) bool {
		for i, t := range f.claimed {
			if i != iface && t.has(k, now) {
				return true
			}
		}
		return false
	}
	hosts, ins := table(f.hosts, iface), table(f.ins, iface)
	rs := slices.Concat(m.answers, m.additional)
	// The packet's own proof first: its hosts, then the instances on them;
	// then what earlier packets proved and no other interface has claimed.
	ph, pi := map[string]bool{}, map[string]bool{}
	for _, r := range rs {
		if (r.typ == typeA || r.typ == typeAAAA) && r.name.host() && mine(link, r.data) {
			ph[r.name.key()] = true
		}
	}
	isHost := func(n name) bool { return (ph[n.key()] || hosts.has(n.key(), now)) && !elsewhere(n.key()) }
	for _, r := range rs {
		if r.typ == typeSRV && r.name.instance() && isHost(r.target) {
			pi[r.name.key()] = true
		}
	}
	isIns := func(n name) bool {
		return n.instance() && (pi[n.key()] || ins.has(n.key(), now)) && !elsewhere(n.key())
	}
	keep := func(r record) bool {
		if r.class&0x7FFF != classIN || !r.name.shown() || !r.target.shown() {
			return false
		}
		switch r.typ {
		case typeA, typeAAAA:
			return mine(link, r.data) && isHost(r.name)
		case typeSRV:
			return isIns(r.name) && isHost(r.target)
		case typeTXT:
			return isIns(r.name)
		case typePTR:
			if r.name.key() == services.key() {
				// A service type, if the sender has an instance of it.
				return r.target.serviceType() && slices.ContainsFunc(slices.Concat(live(ins, now), slices.Collect(maps.Keys(pi))), func(k string) bool {
					return parentKey(k) == r.target.key() && !elsewhere(k)
				})
			}
			// An instance, from its type or a subtype of it.
			if !isIns(r.target) {
				return false
			}
			parent := r.target[1:].key()
			return r.name.key() == parent || len(r.name) == 5 && strings.EqualFold(r.name[1], "_sub") && r.name[2:].key() == parent
		}
		return false
	}
	var kept []record
	for _, s := range []struct{ in, out *[]record }{{&m.answers, &out.answers}, {&m.additional, &out.additional}} {
		for _, r := range *s.in {
			if keep(r) {
				*s.out = append(*s.out, r)
				kept = append(kept, r)
			}
		}
	}
	// Then the sender's names are what it just proved, until their TTL; a
	// goodbye (TTL 0) passes and ends the name.
	for _, r := range kept {
		t := map[uint16]names{typeA: hosts, typeAAAA: hosts, typeSRV: ins}[r.typ]
		switch {
		case t == nil:
		case r.ttl == 0:
			delete(t, r.name.key())
		default:
			t.add(r.name.key(), now.Add(min(time.Duration(r.ttl)*time.Second, ownHold)), now)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return out.bytes()
}

// host: <host>.local (RFC 6762 §3), not a service name.
func (n name) host() bool { return len(n) == 2 && n.local() && !strings.HasPrefix(n[0], "_") }

// serviceType: <_service>.<_tcp or _udp>.local.
func (n name) serviceType() bool {
	return len(n) == 3 && n.local() && strings.HasPrefix(n[0], "_") &&
		(strings.EqualFold(n[1], "_tcp") || strings.EqualFold(n[1], "_udp"))
}

// parentKey is the key of the name k's name is one label under.
func parentKey(k string) string { return k[1+int(k[0]):] }

func live(t names, now time.Time) []string {
	var out []string
	for k, u := range t {
		if u.After(now) {
			out = append(out, k)
		}
	}
	return out
}

// mine: a is a host address on the link, in one of its prefixes, never
// the enforcer's own address, a link-local one or a group.
func mine(link []netip.Prefix, b []byte) bool {
	a, _ := netip.AddrFromSlice(b)
	if !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range link {
		if p.Addr() != a && !p.Addr().IsLinkLocalUnicast() && p.Masked().Contains(a) {
			return true
		}
	}
	return false
}
