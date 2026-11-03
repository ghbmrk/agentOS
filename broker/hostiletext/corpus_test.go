package hostiletext

// REQ: KRN-12, DEV-2

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/ipform"
)

// The header corpus passes an exact list and fails each loosened copy of
// one: a case-blind match, a prefix denylist like the ones #2623 and its
// reviews kept widening, a list that accepts everything, and one that
// refuses everything (#4910 positive controls). Catches a corpus too weak
// to fail the checks it exists to fail.
func TestHeaderCorpusFailsLooseChecks(t *testing.T) {
	named := []string{"Authorization", "X-Api-Key"}
	exact := func(h string) bool { return slices.Contains(named, h) }
	if bad := HeadersAccepted(exact, named...); len(bad) != 0 {
		t.Fatalf("an exact list fails: %q", bad)
	}
	for name, loose := range map[string]func(string) bool{
		"case-blind": func(h string) bool {
			return slices.ContainsFunc(named, func(n string) bool { return strings.EqualFold(n, h) })
		},
		"prefix denylist": func(h string) bool {
			return !strings.HasPrefix(h, "X-Forwarded-") && h != "Cookie" && h != "Host"
		},
		"accepts all": func(string) bool { return true },
		"refuses all": func(string) bool { return false },
		"word denylist": func(h string) bool {
			l := strings.ToLower(h)
			return !strings.Contains(l, "auth") && !strings.Contains(l, "key") && !strings.Contains(l, "cookie")
		},
	} {
		if len(HeadersAccepted(loose, named...)) == 0 {
			t.Errorf("%s passes the header corpus", name)
		}
	}
	if len(HeadersAccepted(exact)) == 0 {
		t.Error("a check that names nothing it accepts passes")
	}
	// Each kind is in the corpus, in every case.
	names := HeaderNames()
	for _, want := range []string{"X-TOKEN", "x-csrf", "X-Http-Method-Override", "x-forwarded-for", "X-REAL-IP", "te", "Accept\r\nX-Injected"} {
		if !slices.ContainsFunc(names, func(e Entry) bool { return e.Text == want }) {
			t.Errorf("the corpus lacks %q", want)
		}
	}
}

// The value corpus passes a control-character check and fails a CR/LF-only
// one, which lets NUL and DEL through. Catches a corpus that only tests
// line breaks.
func TestValueCorpusFailsLooseChecks(t *testing.T) {
	plain := func(s string) bool {
		return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f })
	}
	if bad := ValuesAccepted(plain); len(bad) != 0 {
		t.Fatalf("a control-character check fails: %q", bad)
	}
	if len(ValuesAccepted(func(s string) bool { return !strings.ContainsAny(s, "\r\n") })) == 0 {
		t.Error("a CR/LF-only check passes the value corpus")
	}
	if len(ValuesAccepted(func(string) bool { return false })) == 0 {
		t.Error("a check refusing every value passes")
	}
}

// The address corpus passes ipform.Forms and fails each loosened copy: one
// that only unmaps and reads the well-known NAT64 prefix (as decoy/match
// Dest alone does), one without SIIT (the #4037 release item), one that
// reads a Teredo client without inverting it, and one that unmaps only.
// Catches a corpus too weak to fail the #4037 shapes.
func TestAddrCorpusFailsLooseForms(t *testing.T) {
	nat64 := netip.MustParsePrefix("64:ff9b::/96")
	siit := netip.MustParsePrefix("::ffff:0:0:0/96")
	teredo := netip.MustParsePrefix("2001::/32")
	via := func(forms func(netip.Addr) []netip.Addr) func(netip.Addr) func(string) bool {
		return func(target netip.Addr) func(string) bool {
			return func(s string) bool { return slices.Contains(forms(netip.MustParseAddr(s)), target) }
		}
	}
	for _, target := range []string{"169.254.169.254", "192.168.77.200", "10.0.0.1"} {
		target := netip.MustParseAddr(target)
		if bad := AddrsWrong(target, via(ipform.Forms)(target)); len(bad) != 0 {
			t.Fatalf("ipform.Forms fails the corpus for %s: %q", target, bad)
		}
		for name, forms := range map[string]func(netip.Addr) []netip.Addr{
			"unmap only": func(a netip.Addr) []netip.Addr { return []netip.Addr{a.WithZone("").Unmap()} },
			"unmap and NAT64": func(a netip.Addr) []netip.Addr {
				a = a.WithZone("").Unmap()
				if nat64.Contains(a) {
					b := a.As16()
					return []netip.Addr{netip.AddrFrom4([4]byte(b[12:]))}
				}
				return []netip.Addr{a}
			},
			"no SIIT": func(a netip.Addr) []netip.Addr {
				if siit.Contains(a.WithZone("")) {
					return []netip.Addr{a.WithZone("")}
				}
				return ipform.Forms(a)
			},
			"Teredo client read raw": func(a netip.Addr) []netip.Addr {
				out := ipform.Forms(a)
				if a = a.WithZone(""); teredo.Contains(a) {
					b := a.As16()
					out = append(out, netip.AddrFrom4([4]byte(b[12:])))
				}
				return out
			},
			"zone kept": func(a netip.Addr) []netip.Addr {
				if a.Zone() != "" {
					return []netip.Addr{a}
				}
				return ipform.Forms(a)
			},
		} {
			if len(AddrsWrong(target, via(forms)(target))) == 0 {
				t.Errorf("%s passes the address corpus for %s", name, target)
			}
		}
	}
}
