package enflist

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/dns"
)

// REQ: NET-2

// hostProbes are the host shapes the #6552 Security probe and #6553 name:
// each is a name dns.Generate refuses whole, so signing it would stop every
// resolver instance.
var hostProbes = []string{
	"",                                   // empty
	"ｔime.cloudflare.com",                // fullwidth Unicode letter
	"tïme.cloudflare.com",                // Latin-1 letter
	"time.cloudflare.com:4460",           // a port
	".time.cloudflare.com",               // leading dot: empty first label
	"time..cloudflare.com",               // doubled dot: empty label
	"time.cloudflare.com.",               // trailing dot
	"time.cloudflare.com..",              // two trailing dots
	"TIME.cloudflare.com",                // upper case
	"time_ntp.cloudflare.com",            // underscore
	"time.cloudflare.com\x00",            // NUL
	"time.cloud\tflare.com",              // tab
	"time.cloud flare.com",               // space
	"moc.\u202eevil",                     // a bidi override
	"time%2ecloudflare.com",              // %2e, a percent-escaped dot
	"localhost",                          // a single label
	"*.cloudflare.com",                   // a wildcard
	"192.0.2.1:53",                       // an IP literal with a port
	"[2001:db8::1]",                      // an IPv6 literal
	"2001:db8::1",                        // a bare IPv6 literal
	"-time.cloudflare.com",               // a label opening with a hyphen
	"time-.cloudflare.com",               // a label closing with a hyphen
	strings.Repeat("a", 64) + ".example", // a 64-byte label
	strings.Repeat(strings.Repeat("a", 63)+".", 4) + "example", // 260 bytes in all
}

// TestProposeRefusesEveryUnservableHostShape (#6553): each probe is
// ErrInput naming it, whatever its basis, and gives no link.
func TestProposeRefusesEveryUnservableHostShape(t *testing.T) {
	for _, h := range hostProbes {
		for _, b := range []Basis{Declared, Image, Backup} {
			n, err := Propose(cur(), Inputs{Dests: []Dest{{"time.cloudflare.com", Image, 2 << 20}, {h, b, 1}}, EdgeDeclaredBytes: 1})
			if !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), strconv.QuoteToASCII(h)) {
				t.Errorf("%q as %s: %v, want ErrInput naming it", h, b, err)
			}
			if n.doc != nil {
				t.Errorf("%q as %s: a document was drawn", h, b)
			}
		}
	}
}

// TestProposeNamesTheCanonicalSpellingAsTheFix (#6553 fold-in 3): a name
// whose canonical form is servable is refused with that form as the fix;
// one whose canonical form is not servable names no fix.
func TestProposeNamesTheCanonicalSpellingAsTheFix(t *testing.T) {
	for _, h := range []string{"TIME.cloudflare.com", "time.cloudflare.com.", "TIME.Cloudflare.COM."} {
		_, err := Propose(cur(), Inputs{Dests: []Dest{{h, Image, 1}}, EdgeDeclaredBytes: 1})
		if !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), `write it as "time.cloudflare.com"`) {
			t.Errorf("%q: %v, want the canonical spelling as the fix", h, err)
		}
	}
	for _, h := range []string{"time.cloudflare.com..", "TIME_ntp.example", "LOCALHOST"} {
		_, err := Propose(cur(), Inputs{Dests: []Dest{{h, Image, 1}}, EdgeDeclaredBytes: 1})
		if !errors.Is(err, ErrInput) || strings.Contains(err.Error(), "write it as") {
			t.Errorf("%q: %v, want ErrInput naming no fix", h, err)
		}
	}
}

// TestProposeSignsEveryShippedHost (#6553): an xn-- A-label, the bounds
// (a 63-byte label, 253 bytes in all) and every host the image's
// destinations and the known accounts ship still sign.
func TestProposeSignsEveryShippedHost(t *testing.T) {
	hosts := []string{
		"xn--bcher-kva.example",
		strings.Repeat("a", 63) + ".example",
		strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61),
		"2.debian.pool.ntp.org",
		"a-b.c-d.example",
	}
	if len(hosts[2]) != 253 {
		t.Fatalf("the 253-byte probe is %d bytes", len(hosts[2]))
	}
	var img struct {
		Destinations []struct{ Host string } `json:"destinations"`
	}
	readJSON(t, "../imagedest/dests.json", &img)
	for _, d := range img.Destinations {
		hosts = append(hosts, d.Host)
	}
	var known []struct{ Domains, SignIn []string }
	readJSON(t, "../accounts/known.json", &known)
	for _, e := range known {
		hosts = append(append(hosts, e.Domains...), e.SignIn...)
	}
	if len(hosts) < 10 {
		t.Fatalf("only %d hosts read: the shipped lists moved", len(hosts))
	}
	for _, h := range hosts {
		if _, err := Propose(cur(), Inputs{Dests: []Dest{{h, Declared, 1}}, EdgeDeclaredBytes: 1}); err != nil {
			t.Errorf("%q: %v, want it to sign", h, err)
		}
	}
}

// TestHostShapeAgreesWithTheEnforcer (#6553): enflist's restated check and
// dns.Hostname, the shape dns.Generate serves, agree on every probe, so a
// name Propose signs is one the enforcer's resolver can serve.
func TestHostShapeAgreesWithTheEnforcer(t *testing.T) {
	corpus := append([]string{"a.b", "a.b.", "0.0", "a-.b", "a.-b", "A.b", "a..b", "a.b-c", "xn--p1ai.xn--p1ai"}, hostProbes...)
	for _, h := range corpus {
		if got, want := hostShape(h), dns.Hostname(h); got != want {
			t.Errorf("hostShape(%q) = %v, dns.Hostname = %v", h, got, want)
		}
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}
