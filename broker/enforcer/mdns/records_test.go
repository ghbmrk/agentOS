package mdns

import (
	"bytes"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

func dn(s string) name { return name(strings.Split(s, ".")) }

func a(n, addr string, ttl uint32) record {
	ip := netip.MustParseAddr(addr)
	t := uint16(typeA)
	if ip.Is6() {
		t = typeAAAA
	}
	return record{name: dn(n), typ: t, class: 0x8001, ttl: ttl, data: ip.AsSlice()}
}

func srv(n, target string, ttl uint32) record {
	return record{name: dn(n), typ: typeSRV, class: 0x8001, ttl: ttl, data: []byte{0, 0, 0, 0, 0x02, 0x77}, target: dn(target)}
}

func txt(n string, ttl uint32) record {
	return record{name: dn(n), typ: typeTXT, class: 0x8001, ttl: ttl, data: []byte("\x08txtvers1")}
}

func ptr(n, target string, ttl uint32) record {
	return record{name: dn(n), typ: typePTR, class: 1, ttl: ttl, target: dn(target)}
}

func response(answers, additional []record) *message {
	return &message{flags: 0x8400, answers: answers, additional: additional}
}

// The printer's link: the enforcer is 10.13.0.1 and fd00:13::1 there.
var printerLink = []netip.Prefix{
	netip.MustParsePrefix("10.13.0.1/24"),
	netip.MustParsePrefix("fd00:13::1/64"),
	netip.MustParsePrefix("fe80::1/64"),
}

var t0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// passed is what of m Pass lets out of iface, as names and types.
func passed(t *testing.T, f *Filter, iface string, link []netip.Prefix, m *message, now time.Time) []string {
	t.Helper()
	b := f.Pass(iface, link, m, now)
	if b == nil {
		return nil
	}
	out, ok := parse(b)
	if !ok {
		t.Fatalf("Pass built a message parse refuses: %x", b)
	}
	var got []string
	for _, q := range out.questions {
		got = append(got, "?"+strings.Join(q.name, "."))
	}
	for i, s := range [][]record{out.answers, out.authority, out.additional} {
		for _, r := range s {
			got = append(got, describe(r, i))
		}
	}
	return got
}

func describe(r record, section int) string {
	s := []string{"an", "ns", "ar"}[section] + " " + strings.Join(r.name, ".")
	switch r.typ {
	case typeA, typeAAAA:
		ip, _ := netip.AddrFromSlice(r.data)
		s += " " + ip.String()
	case typeSRV, typePTR:
		s += " -> " + strings.Join(r.target, ".")
	case typeTXT:
		s += " txt"
	default:
		s += " type"
	}
	return s
}

// TestOwnRecordsOnly: a paired device's response keeps only its own
// records: hosts on its own link, instances on those hosts and their
// TXT and PTR records; every other record is dropped (#4069, NET-3).
func TestOwnRecordsOnly(t *testing.T) {
	m := response([]record{
		ptr("_ipp._tcp.local", "Printer._ipp._tcp.local", 4500),
		ptr("_universal._sub._ipp._tcp.local", "Printer._ipp._tcp.local", 4500),
		ptr("_services._dns-sd._udp.local", "_ipp._tcp.local", 4500),
		ptr("_services._dns-sd._udp.local", "_smb._tcp.local", 4500),        // no instance of its own
		ptr("_smb._tcp.local", "Printer._ipp._tcp.local", 4500),             // not the instance's type
		ptr("_x._sub._smb._tcp.local", "Printer._ipp._tcp.local", 4500),     // nor its subtype
		ptr("_x._dub._ipp._tcp.local", "Printer._ipp._tcp.local", 4500),     // not a subtype name
		ptr("_smb._tcp.local", "Laptop._smb._tcp.local", 4500),              // no SRV on its host
		ptr("2.0.13.10.in-addr.arpa", "printer.local", 120),                 // reverse names are not passed
		srv("Printer._ipp._tcp.local", "printer.local", 120),                //
		srv("Fake._smb._tcp.local", "laptop.local", 120),                    // a foreign host
		srv("printer._ipp.local", "printer.local", 120),                     // not an instance name
		srv("Printer._ipp._sctp.local", "printer.local", 120),               // nor this
		txt("Printer._ipp._tcp.local", 4500),                                //
		txt("Laptop._smb._tcp.local", 4500),                                 // not its instance
		txt("printer.local", 4500),                                          // a host, not an instance
		a("printer.local", "10.13.0.2", 120),                                //
		a("printer.local", "10.11.0.2", 120),                                // another link's address
		a("laptop.local", "10.11.0.2", 120),                                 // another link's host
		a("core.local", "10.13.0.1", 120),                                   // the enforcer's own address
		a("www.example", "10.13.0.2", 120),                                  // not .local
		a("a.b.local", "10.13.0.2", 120),                                    // not a host name
		a("_x.local", "10.13.0.2", 120),                                     // nor this
		a("group.local", "224.0.0.251", 120),                                // a group
		{name: dn("printer.local"), typ: 13, class: 1, ttl: 120, data: nil}, // HINFO
	}, []record{
		a("printer.local", "fd00:13::2", 120),
		a("printer.local", "fe80::2", 120), // link-local means nothing on another link
		a("printer.local", "fd00:11::2", 120),
	})
	m.questions = []question{{dn("printer.local"), typeA, 1}} // a response asks nothing
	m.authority = []record{a("printer.local", "10.13.0.2", 120)}
	got := passed(t, NewFilter(), "ap0.105", printerLink, m, t0)
	want := []string{
		"an _ipp._tcp.local -> Printer._ipp._tcp.local",
		"an _universal._sub._ipp._tcp.local -> Printer._ipp._tcp.local",
		"an _services._dns-sd._udp.local -> _ipp._tcp.local",
		"an Printer._ipp._tcp.local -> printer.local",
		"an Printer._ipp._tcp.local txt",
		"an printer.local 10.13.0.2",
		"ar printer.local fd00:13::2",
	}
	if !slices.Equal(got, want) {
		t.Errorf("passed\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Nothing of its own: nothing at all.
	if b := NewFilter().Pass("ap0.105", printerLink, response([]record{a("laptop.local", "10.11.0.2", 120)}, nil), t0); b != nil {
		t.Errorf("a response with no own record passed: %x", b)
	}
	// No link addresses known: nothing is the sender's own.
	if b := NewFilter().Pass("ap0.105", nil, m, t0); b != nil {
		t.Errorf("passed with no link addresses: %x", b)
	}
}

// TestQueriesCarryQuestionsOnly: a relayed query keeps its .local
// questions and nothing else, so the receiving side learns nothing of the
// asker's records, and a truncated query's continuation is not awaited.
func TestQueriesCarryQuestionsOnly(t *testing.T) {
	m := &message{id: 7, flags: flagTC,
		questions: []question{{dn("_ipp._tcp.local"), typePTR, 0x8001}, {dn("www.example"), typeA, 1}, {dn("printer.local"), typeA, 1}},
		answers:   []record{ptr("_ipp._tcp.local", "Printer._ipp._tcp.local", 4500)},
		authority: []record{a("laptop.local", "10.11.0.2", 120)},
	}
	b := NewFilter().Pass("hh0", nil, m, t0)
	out, ok := parse(b)
	if !ok {
		t.Fatalf("%x", b)
	}
	want := &message{id: 7, questions: []question{m.questions[0], m.questions[2]}}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got %+v, want %+v", out, want)
	}
	m.questions = m.questions[1:2]
	if b := NewFilter().Pass("hh0", nil, m, t0); b != nil {
		t.Errorf("a query with no .local question passed: %x", b)
	}
}

// TestClaimedNamesStayTheirs: a name heard claimed on another interface is
// never a device's own: not a host, so not the target of its instances,
// and not an instance. A claim lasts a day after it was last heard,
// whatever its TTL or a goodbye says. A query's known answers claim
// nothing; its probe records do.
func TestClaimedNamesStayTheirs(t *testing.T) {
	f := NewFilter()
	f.Hear("hh0", response([]record{a("laptop.local", "10.11.0.2", 0), ptr("_smb._tcp.local", "Laptop._smb._tcp.local", 0)}, nil), t0)
	f.Hear("hh0", &message{authority: []record{a("probe.local", "10.11.0.3", 120)},
		answers: []record{a("cached.local", "10.11.0.4", 120), ptr("_ipp._tcp.local", "Cached._ipp._tcp.local", 120)}}, t0)
	f.Hear("ap0.106", response(nil, []record{srv("Sensor._hap._tcp.local", "sensor.local", 120), ptr("_services._dns-sd._udp.local", "_ipp._tcp.local", 120)}), t0)
	f.Hear("ap0.105", response([]record{a("printer.local", "10.13.0.2", 120)}, nil), t0) // its own claims do not count against it
	m := response([]record{
		a("laptop.local", "10.13.0.2", 120),
		a("probe.local", "10.13.0.2", 120),
		a("cached.local", "10.13.0.2", 120),
		a("printer.local", "10.13.0.2", 120),
		srv("Laptop._smb._tcp.local", "printer.local", 120),
		srv("Sensor._hap._tcp.local", "printer.local", 120),
		srv("Cached._ipp._tcp.local", "printer.local", 120),
		srv("Mine._smb._tcp.local", "laptop.local", 120),
		ptr("_services._dns-sd._udp.local", "_ipp._tcp.local", 120),
	}, nil)
	want := []string{
		"an cached.local 10.13.0.2",
		"an printer.local 10.13.0.2",
		"an Cached._ipp._tcp.local -> printer.local",
		"an _services._dns-sd._udp.local -> _ipp._tcp.local",
	}
	for _, now := range []time.Time{t0, t0.Add(claimHold - time.Second)} {
		if got := passed(t, f, "ap0.105", printerLink, m, now); !slices.Equal(got, want) {
			t.Errorf("at %v passed\n%s\nwant\n%s", now.Sub(t0), strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	// A day after it was last heard, a claim ends.
	later := t0.Add(claimHold)
	if got := passed(t, f, "ap0.105", printerLink, response([]record{a("laptop.local", "10.13.0.2", 120)}, nil), later); len(got) != 1 {
		t.Errorf("a day later passed %v", got)
	}
	// Hearing a name again holds it a day from then.
	f.Hear("hh0", response([]record{a("laptop.local", "10.11.0.2", 120)}, nil), later)
	if got := passed(t, f, "ap0.105", printerLink, response([]record{a("laptop.local", "10.13.0.2", 120)}, nil), later.Add(claimHold-time.Second)); got != nil {
		t.Errorf("a renewed claim passed %v", got)
	}
}

// TestOwnNamesLearned: once a response proved a host and an instance are
// the device's, a later packet with only the instance's TXT or SRV
// passes, until the record's TTL (at most ownHold) runs out or a goodbye
// ends it. A name claimed elsewhere since stops passing.
func TestOwnNamesLearned(t *testing.T) {
	f := NewFilter()
	if got := passed(t, f, "ap0.105", printerLink, response([]record{txt("Printer._ipp._tcp.local", 4500)}, nil), t0); got != nil {
		t.Fatalf("an unproved instance's TXT passed: %v", got)
	}
	full := response([]record{srv("Printer._ipp._tcp.local", "printer.local", 9000), a("printer.local", "10.13.0.2", 120)}, nil)
	if got := passed(t, f, "ap0.105", printerLink, full, t0); len(got) != 2 {
		t.Fatalf("the announcement passed %v", got)
	}
	update := response([]record{txt("Printer._ipp._tcp.local", 4500), srv("Printer._ipp._tcp.local", "printer.local", 120)}, nil)
	for _, c := range []struct {
		at   time.Duration
		want int
	}{{0, 2}, {119 * time.Second, 2}, {120 * time.Second, 1}} {
		// The host lasts its A's 120 s: then an SRV on it no longer
		// passes, while the instance's TXT does until the instance ends.
		if got := passed(t, NewFilterFrom(f), "ap0.105", printerLink, update, t0.Add(c.at)); len(got) != c.want {
			t.Errorf("at %v passed %v, want %d records", c.at, got, c.want)
		}
	}
	// The instance lasts at most ownHold, though its SRV said 9000 s.
	f2 := NewFilter()
	passed(t, f2, "ap0.105", printerLink, full, t0)
	txtOnly := response([]record{txt("Printer._ipp._tcp.local", 4500)}, nil)
	if got := passed(t, f2, "ap0.105", printerLink, txtOnly, t0.Add(ownHold-time.Second)); len(got) != 1 {
		t.Errorf("before ownHold passed %v", got)
	}
	if got := passed(t, f2, "ap0.105", printerLink, txtOnly, t0.Add(ownHold)); got != nil {
		t.Errorf("at ownHold passed %v", got)
	}
	// A goodbye passes, then the name is no longer the device's.
	f3 := NewFilter()
	passed(t, f3, "ap0.105", printerLink, full, t0)
	bye := response([]record{srv("Printer._ipp._tcp.local", "printer.local", 0)}, nil)
	if got := passed(t, f3, "ap0.105", printerLink, bye, t0); len(got) != 1 {
		t.Errorf("the goodbye passed %v", got)
	}
	if got := passed(t, f3, "ap0.105", printerLink, txtOnly, t0); got != nil {
		t.Errorf("after the goodbye passed %v", got)
	}
	byeHost := response([]record{a("printer.local", "10.13.0.2", 0)}, nil)
	if got := passed(t, f3, "ap0.105", printerLink, byeHost, t0); len(got) != 1 {
		t.Errorf("the host's goodbye passed %v", got)
	}
	if got := passed(t, f3, "ap0.105", printerLink, response([]record{srv("Printer._ipp._tcp.local", "printer.local", 120)}, nil), t0); got != nil {
		t.Errorf("after the host's goodbye passed %v", got)
	}
	// Learned names are per interface.
	if got := passed(t, f, "ap0.106", printerLink, txtOnly, t0); got != nil {
		t.Errorf("another interface's names passed %v", got)
	}
	// Claimed elsewhere since: no longer the device's.
	f.Hear("hh0", response([]record{txt("Printer._ipp._tcp.local", 120)}, nil), t0)
	if got := passed(t, f, "ap0.105", printerLink, txtOnly, t0); got != nil {
		t.Errorf("a name claimed since passed %v", got)
	}
}

// NewFilterFrom copies f, so one learned state can be read at several
// times.
func NewFilterFrom(f *Filter) *Filter {
	g := NewFilter()
	for _, p := range []struct{ from, to map[string]names }{{f.claimed, g.claimed}, {f.hosts, g.hosts}, {f.ins, g.ins}} {
		for i, t := range p.from {
			p.to[i] = names{}
			for k, u := range t {
				p.to[i][k] = u
			}
		}
	}
	return g
}

// TestNamesBounded: an interface's tables hold at most maxNames live
// names; a full table learns nothing new until a name expires.
func TestNamesBounded(t *testing.T) {
	tb := names{}
	for i := range maxNames {
		tb.add(string(rune(i)), t0.Add(time.Duration(i+1)*time.Second), t0)
	}
	tb.add("new", t0.Add(time.Hour), t0)
	if tb.has("new", t0) || len(tb) != maxNames {
		t.Fatalf("a full table took a name (%d)", len(tb))
	}
	tb.add(string(rune(0)), t0.Add(time.Hour), t0) // a known name is renewed
	if !tb.has(string(rune(0)), t0.Add(time.Minute)) {
		t.Error("a known name was not renewed in a full table")
	}
	tb.add("new", t0.Add(time.Hour), t0.Add(2*time.Second)) // one has expired
	if !tb.has("new", t0.Add(2*time.Second)) || len(tb) != maxNames {
		t.Errorf("expired names were not dropped for a new one (%d)", len(tb))
	}
}

func TestMine(t *testing.T) {
	for _, c := range []struct {
		addr string
		want bool
	}{
		{"10.13.0.2", true}, {"fd00:13::abcd", true}, {"10.13.0.1", false}, {"fd00:13::1", false},
		{"10.14.0.2", false}, {"fe80::2", false}, {"224.0.0.251", false}, {"ff02::fb", false},
		{"0.0.0.0", false}, {"::ffff:10.13.0.2", false},
		{"10.13.0.0", false}, {"10.13.0.255", false}, {"10.13.0.254", true}, {"fd00:13::", true},
	} {
		if got := mine(printerLink, netip.MustParseAddr(c.addr).AsSlice()); got != c.want {
			t.Errorf("mine(%s) = %v", c.addr, got)
		}
	}
	if mine(printerLink, []byte{10, 13, 0}) {
		t.Error("a 3-byte address is mine")
	}
	// A /31 has no network or broadcast address.
	p31 := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/31")}
	if !mine(p31, netip.MustParseAddr("10.20.0.1").AsSlice()) {
		t.Error("a /31's other address is not mine")
	}
	if got := broadcast(netip.MustParsePrefix("10.13.0.1/22")); got != netip.MustParseAddr("10.13.3.255") {
		t.Errorf("broadcast of /22 = %v", got)
	}
	// A link-local prefix makes no address the device's.
	if mine([]netip.Prefix{netip.MustParsePrefix("fe80::1/10")}, netip.MustParseAddr("fe80::2").AsSlice()) {
		t.Error("link-local is mine")
	}
}

// A hand-built message: a PTR answer whose target and an SRV whose owner
// and target point back into earlier names.
var wireMsg = []byte{
	0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0,
	// _ipp._tcp.local PTR Printer.<12+0>
	4, '_', 'i', 'p', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0,
	0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 10,
	7, 'P', 'r', 'i', 'n', 't', 'e', 'r', 0xC0, 12,
	// <Printer...> SRV 0 0 631 printer.<local>
	0xC0, 39, 0, 33, 0x80, 1, 0, 0, 0, 120, 0, 16,
	0, 0, 0, 0, 0x02, 0x77, 7, 'p', 'r', 'i', 'n', 't', 'e', 'r', 0xC0, 22,
}

func TestParseCompressed(t *testing.T) {
	m, ok := parse(wireMsg)
	if !ok {
		t.Fatal("refused")
	}
	want := &message{flags: 0x8400, answers: []record{
		{name: dn("_ipp._tcp.local"), typ: typePTR, class: 1, ttl: 4500, target: dn("Printer._ipp._tcp.local")},
		{name: dn("Printer._ipp._tcp.local"), typ: typeSRV, class: 0x8001, ttl: 120, data: []byte{0, 0, 0, 0, 2, 0x77}, target: dn("printer.local")},
	}}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %+v\nwant %+v", m, want)
	}
	if b := m.bytes(); !bytes.Equal(b, wireMsg) {
		t.Errorf("rebuilt\n%x\nwant\n%x", b, wireMsg)
	}
	// Suffixes match byte for byte: a name differing in case is written
	// out, not pointed at.
	m.answers[1].name = dn("Printer._ipp._TCP.local")
	b := m.bytes()
	back, ok := parse(b)
	if !ok || !reflect.DeepEqual(back.answers[1].name, m.answers[1].name) {
		t.Errorf("case changed: %+v", back)
	}
	if len(b) <= len(wireMsg) {
		t.Errorf("a case-different name was compressed: %x", b)
	}
}

func TestParseRefuses(t *testing.T) {
	q := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	rr := func(typ byte, rdata ...byte) []byte {
		return append([]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 'a', 0, 0, typ, 0, 1, 0, 0, 0, 1, 0, byte(len(rdata))}, rdata...)
	}
	long := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for range 4 {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte{'x'}, 63)...)
	}
	long = append(long, 0, 0, 1, 0, 1)
	for name, b := range map[string][]byte{
		"short header":       q[:11],
		"truncated question": q[:len(q)-1],
		"question name":      q[:13],
		"trailing byte":      append(slices.Clone(q), 0),
		"forward pointer":    {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1},
		"pointer at end":     {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0},
		"reserved label":     {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x40, 0, 0, 1, 0, 1},
		"label past end":     {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a'},
		"name over 255":      long,
		"A of 5":             rr(typeA, 1, 2, 3, 4, 5),
		"AAAA of 4":          rr(typeAAAA, 1, 2, 3, 4),
		"A of 16":            rr(typeA, make([]byte, 16)...),
		"PTR with a tail":    rr(typePTR, 0, 0),
		"PTR unended":        rr(typePTR, 1, 'a'),
		"SRV of 6":           rr(typeSRV, 0, 0, 0, 0, 0, 0),
		"SRV with a tail":    rr(typeSRV, 0, 0, 0, 0, 0, 0, 0, 0),
		"TXT overrun":        rr(typeTXT, 3, 'a', 'b'),
		"rdata past end":     rr(typeA, 1, 2, 3, 4)[:28],
		"record header":      rr(typeA)[:24],
		"record name":        rr(typeA)[:13],
		"missing record":     rr(typeA, 1, 2, 3, 4)[:12],
	} {
		if _, ok := parse(b); ok {
			t.Errorf("%s: parsed %x", name, b)
		}
	}
	for name, b := range map[string][]byte{
		"name of 255": slices.Concat(long[:12+3*64], []byte{61}, bytes.Repeat([]byte{'x'}, 61), []byte{0, 0, 1, 0, 1}),
		"empty TXT":   rr(typeTXT),
		"TXT":         rr(typeTXT, 1, 'a', 0),
		"other type":  rr(99, 0xC0, 0xFF),
		"SRV":         rr(typeSRV, 0, 0, 0, 0, 0, 0, 0),
		"PTR":         rr(typePTR, 0xC0, 12),
	} {
		if _, ok := parse(b); !ok {
			t.Errorf("%s: refused %x", name, b)
		}
	}
}

// FuzzParse: parse never panics, and what it accepts rebuilds to a
// message it reads back the same.
func FuzzParse(f *testing.F) {
	f.Add(wireMsg)
	f.Add(response([]record{a("printer.local", "10.13.0.2", 120), txt("P._ipp._tcp.local", 1)}, nil).bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		m, ok := parse(b)
		if !ok {
			return
		}
		back, ok := parse(m.bytes())
		if !ok {
			t.Fatalf("rebuilt %x refused", m.bytes())
		}
		norm := func(m *message) {
			for _, s := range []*[]record{&m.answers, &m.authority, &m.additional} {
				for i := range *s {
					if r := &(*s)[i]; r.typ != typeA && r.typ != typeAAAA && r.typ != typeTXT && r.typ != typeSRV && r.typ != typePTR {
						r.data, r.target = nil, nil
					}
				}
			}
		}
		// The filter never fails on what parse accepts, and what it lets
		// out parses.
		fl := NewFilter()
		fl.Hear("hh0", m, t0)
		for _, link := range [][]netip.Prefix{printerLink, {netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}} {
			if out := fl.Pass("ap0.105", link, m, t0); out != nil {
				if _, ok := parse(out); !ok {
					t.Fatalf("Pass built %x", out)
				}
			}
		}
		norm(m)
		norm(back)
		if !reflect.DeepEqual(m, back) {
			t.Fatalf("%+v\n%+v", m, back)
		}
	})
}

// TestHostileLabelsRefused: a label that is blank, invisible or hides
// what it shows never passes, in a question or a record (hostiletext,
// #3901), so a paired device cannot show a person a spoofed service name.
func TestHostileLabelsRefused(t *testing.T) {
	hostiletext.Run(t, labelNameOK)
	for _, l := range []string{"My Printer", "Café", "Drucker-2", "o'clock.x"} {
		if !labelNameOK(l) {
			t.Errorf("refused %q", l)
		}
	}
	spoof := "\u202eMark's Laptop"
	m := response([]record{
		a("printer.local", "10.13.0.2", 120),
		srv(spoof+"._smb._tcp.local", "printer.local", 120),
		srv("Printer._ipp._tcp.local", "printer.local", 120),
		ptr("_ipp._tcp.local", "Printer._ipp._tcp.local", 120),
		ptr("_smb._tcp.local", spoof+"._smb._tcp.local", 120),
		a("print\u200ber.local", "10.13.0.2", 120),
	}, nil)
	want := []string{
		"an printer.local 10.13.0.2",
		"an Printer._ipp._tcp.local -> printer.local",
		"an _ipp._tcp.local -> Printer._ipp._tcp.local",
	}
	if got := passed(t, NewFilter(), "ap0.105", printerLink, m, t0); !slices.Equal(got, want) {
		t.Errorf("passed\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	q := &message{questions: []question{{dn(spoof + ".local"), typeA, 1}, {dn("printer.local"), typeA, 1}}}
	out, ok := parse(NewFilter().Pass("hh0", nil, q, t0))
	if !ok || len(out.questions) != 1 || out.questions[0].name[0] != "printer" {
		t.Errorf("query passed %+v", out)
	}
}

// worst is a message of n records, each an A record whose name is a
// pointer to one 255-byte name: the most name each record can cost.
func worst(n int) []byte {
	b := []byte{0, 0, 0x84, 0, 0, 0, byte(n >> 8), byte(n), 0, 0, 0, 0}
	first := len(b)
	for i := range 4 {
		l := 63
		if i == 3 {
			l = 61
		}
		b = append(b, byte(l))
		b = append(b, bytes.Repeat([]byte{'x'}, l)...)
	}
	b = append(b, 0, 0, typeA, 0, 1, 0, 0, 0, 120, 0, 4, 10, 13, 0, 2)
	for range n - 1 {
		b = append(b, 0xC0|byte(first>>8), byte(first), 0, typeA, 0, 1, 0, 0, 0, 120, 0, 4, 10, 13, 0, 2)
	}
	return b
}

// TestParseBounded: a message with more questions or records than the
// caps is refused before any is read, and the costliest message within
// them costs a bounded amount, so a flood of crafted packets cannot buy
// unbounded work per packet.
func TestParseBounded(t *testing.T) {
	if _, ok := parse(worst(maxRecords)); !ok {
		t.Fatal("refused a message at the record cap")
	}
	if _, ok := parse(worst(maxRecords + 1)); ok {
		t.Error("parsed a message over the record cap")
	}
	if b := worst(540); len(b) > maxPacket {
		t.Fatalf("the crafted packet is %d bytes", len(b))
	} else if _, ok := parse(b); ok {
		t.Error("parsed a 540-record packet")
	}
	q := func(n int) []byte {
		b := []byte{0, 0, 0, 0, byte(n >> 8), byte(n), 0, 0, 0, 0, 0, 0}
		for range n {
			b = append(b, 1, 'a', 0, 0, 1, 0, 1)
		}
		return b
	}
	if _, ok := parse(q(maxQuestions)); !ok {
		t.Error("refused a message at the question cap")
	}
	if _, ok := parse(q(maxQuestions + 1)); ok {
		t.Error("parsed a message over the question cap")
	}
	// Records split across sections count together.
	b := worst(maxRecords)
	b[7], b[9], b[11] = maxRecords-2, 1, 2
	if _, ok := parse(b); ok {
		t.Error("parsed a message over the record cap across sections")
	}
	b[11] = 1
	if _, ok := parse(b); !ok {
		t.Error("refused a message at the record cap across sections")
	}
	w := worst(maxRecords)
	if allocs := testing.AllocsPerRun(10, func() { parse(w) }); allocs > 8*maxRecords {
		t.Errorf("the worst message within the caps costs %v allocations", allocs)
	}
}

// TestFullClaimsFailClosed: while another interface's claimed names are
// full of live names, no name is a sender's own, since the name the full
// table would hold may be missing from it.
func TestFullClaimsFailClosed(t *testing.T) {
	f := NewFilter()
	var rs []record
	for i := range maxNames {
		rs = append(rs, a(fmt.Sprintf("h%d.local", i), "10.11.0.2", 120))
	}
	for i := 0; i < len(rs); i += 100 {
		f.Hear("hh0", response(rs[i:min(i+100, len(rs))], nil), t0)
	}
	own := response([]record{a("laptop.local", "10.13.0.2", 120)}, nil)
	if got := passed(t, f, "ap0.105", printerLink, own, t0); got != nil {
		t.Errorf("passed with Household's claims full: %v", got)
	}
	// Once one claim ends the table is not full.
	f.claimed["hh0"][dn("h0.local").key()] = t0
	if got := passed(t, f, "ap0.105", printerLink, own, t0); len(got) != 1 {
		t.Errorf("passed %v once a claim ended", got)
	}
	// A sender's own full table does not count against it.
	g := NewFilter()
	for i := 0; i < len(rs); i += 100 {
		g.Hear("ap0.105", response(rs[i:min(i+100, len(rs))], nil), t0)
	}
	if got := passed(t, g, "ap0.105", printerLink, own, t0); len(got) != 1 {
		t.Errorf("its own full claims blocked the sender: %v", got)
	}
}

// TestBucket: a bucket gives its size at once, then one token per 1/rate
// seconds.
func TestBucket(t *testing.T) {
	b := newBucket(3, 2, t0)
	for i := range 3 {
		if !b.take(t0) {
			t.Fatalf("token %d refused", i)
		}
	}
	if b.take(t0) || b.take(t0.Add(499*time.Millisecond)) {
		t.Error("a token past the size")
	}
	if !b.take(t0.Add(500 * time.Millisecond)) {
		t.Error("no token after 1/rate")
	}
	if b.take(t0.Add(500 * time.Millisecond)) {
		t.Error("two tokens after 1/rate")
	}
	// It never holds more than its size.
	for i := range 4 {
		if got := b.take(t0.Add(time.Hour)); got != (i < 3) {
			t.Errorf("after an hour, take %d = %v", i, got)
		}
	}
}
