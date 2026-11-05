package hostiletext

import (
	"fmt"
	"net/netip"
	"strconv"
	"testing"
)

// The address corpus (REV-PROOF-corpus, #4910): the ways an IPv6 address
// can name an IPv4 destination, so a check made on the IPv4 form (a decoy,
// a private range) cannot be passed by naming it another way (#4037,
// KRN-12, DEV-2), and near misses that name no IPv4 address, or another.

// Addr is one address text for a target IPv4 address: whether a
// connection to it reaches the target (Carries), and a name for the
// failure message. Text parses with netip.ParseAddr; it may hold a zone.
type Addr struct {
	Name, Text string
	Carries    bool
}

// Addrs is the corpus for target, an IPv4 address: every form that
// carries it (plain; IPv4-mapped, written four ways and zoned;
// IPv4-compatible; NAT64 at the well-known prefix and at the local-use
// /48's /96 and /48 positions, RFC 6052 and 8215; SIIT IPv4-translated
// ::ffff:0:0:0/96, RFC 6145; 6to4; ISATAP, link-local, global and inside
// 6to4; Teredo server and inverted client, RFC 4380), then near misses that
// carry no target: a neighbouring IPv4 address, each wrong prefix, a
// Teredo client not inverted, and a marker one bit off. Every IPv6 form is
// also fed zoned. It panics if target is not IPv4.
func Addrs(target netip.Addr) []Addr {
	if !target.Is4() {
		panic("hostiletext: Addrs needs an IPv4 target")
	}
	b := target.As4()
	q := target.String()
	hi, lo := fmt.Sprintf("%x", uint16(b[0])<<8|uint16(b[1])), fmt.Sprintf("%x", uint16(b[2])<<8|uint16(b[3]))
	ihi, ilo := fmt.Sprintf("%x", ^(uint16(b[0])<<8|uint16(b[1]))), fmt.Sprintf("%x", ^(uint16(b[2])<<8|uint16(b[3])))
	// local-use NAT64 at /48: octets 1-2 in bits 48-63, u-octet zero, 3-4 after it.
	l48 := fmt.Sprintf("64:ff9b:1:%s:%x:%x00::", hi, b[2], b[3])
	n := b
	n[0] ^= 0x80 // a neighbour no decoy, range or special registry shares
	other := netip.AddrFrom4(n).String()
	ohi := fmt.Sprintf("%x", uint16(n[0])<<8|uint16(n[1]))

	carries := []Addr{
		{"plain IPv4", q, true},
		{"IPv4-mapped dotted", "::ffff:" + q, true},
		{"IPv4-mapped hex", "::ffff:" + hi + ":" + lo, true},
		{"IPv4-mapped upper case", "::FFFF:" + q, true},
		{"IPv4-mapped expanded", "0000:0000:0000:0000:0000:ffff:" + hi + ":" + lo, true},
		{"IPv4-compatible dotted", "::" + q, true},
		{"IPv4-compatible hex", "::" + hi + ":" + lo, true},
		{"NAT64 well-known dotted", "64:ff9b::" + q, true},
		{"NAT64 well-known hex", "64:ff9b::" + hi + ":" + lo, true},
		{"NAT64 local-use /96", "64:ff9b:1::" + q, true},
		{"NAT64 local-use /48", l48, true},
		{"SIIT IPv4-translated", "::ffff:0:" + q, true},
		{"SIIT IPv4-translated hex", "::ffff:0:" + hi + ":" + lo, true},
		{"6to4", "2002:" + hi + ":" + lo + "::1", true},
		{"6to4 full", "2002:" + hi + ":" + lo + ":1:2:3:4:5", true},
		{"ISATAP link-local", "fe80::5efe:" + q, true},
		{"ISATAP link-local universal bit", "fe80::200:5efe:" + hi + ":" + lo, true},
		{"ISATAP global", "2001:db8:1::5efe:" + q, true},
		{"ISATAP inside 6to4", "2002:102:304::5efe:" + q, true},
		{"Teredo server", "2001:0:" + hi + ":" + lo + "::", true},
		{"Teredo client inverted", "2001:0:4136:e378:8000:63bf:" + ihi + ":" + ilo, true},
	}
	misses := []Addr{
		{"neighbour IPv4", other, false},
		{"neighbour IPv4-mapped", "::ffff:" + other, false},
		{"neighbour 6to4", "2002:" + ohi + ":" + lo + "::1", false},
		{"no ISATAP marker", "fe80::" + hi + ":" + lo, false},
		{"ISATAP marker one bit off", "fe80::100:5efe:" + hi + ":" + lo, false},
		{"ISATAP marker 5eff", "fe80::5eff:" + hi + ":" + lo, false},
		{"not 6to4 (2003::/16)", "2003:" + hi + ":" + lo + "::1", false},
		{"NAT64 outside the local-use /48", "64:ff9b:2::" + q, false},
		{"NAT64 well-known prefix plus one", "64:ff9b::1:" + hi + ":" + lo, false},
		{"not Teredo (2001:1::/32)", "2001:1:" + hi + ":" + lo + "::", false},
		{"Teredo client not inverted", "2001:0:4136:e378:8000:63bf:" + hi + ":" + lo, false},
		{"IPv4-mapped prefix one off", "::fffe:" + hi + ":" + lo, false},
		{"SIIT prefix one off", "::ffff:1:" + hi + ":" + lo, false},
		{"SIIT behind a prefix", "1::ffff:0:" + hi + ":" + lo, false},
		{"compatible behind a prefix", "1::" + hi + ":" + lo, false},
	}
	var out []Addr
	for _, a := range append(carries, misses...) {
		out = append(out, a)
		if netip.MustParseAddr(a.Text).Is6() {
			out = append(out, Addr{a.Name + " zoned", a.Text + "%eth0", a.Carries})
		}
	}
	return out
}

// AddrsWrong lists what reaches decides wrongly about Addrs(target): each
// entry that carries the target it says does not, and each that does not
// it says does. reaches is the check as its caller uses it, deciding
// whether the text names the target.
func AddrsWrong(target netip.Addr, reaches func(text string) bool) []string {
	var bad []string
	for _, a := range Addrs(target) {
		if got := reaches(a.Text); got != a.Carries {
			want := "misses"
			if !a.Carries {
				want = "wrongly finds"
			}
			bad = append(bad, want+" "+target.String()+" in "+a.Name+" "+strconv.Quote(a.Text))
		}
	}
	return bad
}

// RunAddrs fails t for each wrong decision AddrsWrong finds.
func RunAddrs(t testing.TB, target netip.Addr, reaches func(text string) bool) {
	t.Helper()
	for _, b := range AddrsWrong(target, reaches) {
		t.Errorf("hostiletext addrs: %s", b)
	}
}
