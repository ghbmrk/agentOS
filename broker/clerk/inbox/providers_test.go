package inbox

// REQ: VRB-2, D-154

import (
	"slices"
	"strings"
	"testing"
)

// The shipped file parses and every entry carries a source. Gmail's API
// account and a host under a listed suffix get mx.google.com; a lookalike
// suffix and an unknown host get "" and no security senders.
func TestProviderTables(t *testing.T) {
	for _, line := range strings.Split(string(providersTxt), "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "#") {
			if _, src, ok := strings.Cut(l, " -- "); !ok || strings.TrimSpace(src) == "" {
				t.Fatalf("shipped line has no source: %q", l)
			}
		}
	}
	if _, err := ParseProviders(providersTxt); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ api, host string }{{"gmail", ""}, {"", "imap.gmail.com"}, {"", "IMAP.Gmail.COM."}} {
		a, sec := Shipped.For(c.api, c.host)
		if a != "mx.google.com" || len(sec) == 0 {
			t.Fatalf("%q %q: authserv %q, security %q; want mx.google.com and Google's senders", c.api, c.host, a, sec)
		}
	}
	for _, c := range []struct{ api, host string }{
		{"", "evilgmail.com"}, {"", "imap.gmail.com.evil.test"}, {"", "imap.unknown.test"}, {"outlook", ""}, {"gmail.com", ""}, {"", "gmail"},
	} {
		if a, sec := Shipped.For(c.api, c.host); a != "" || sec != nil {
			t.Fatalf("%q %q matched: authserv %q, security %q", c.api, c.host, a, sec)
		}
	}
	for _, d := range Shipped.Table() {
		if strings.HasSuffix(d, ".test") {
			t.Fatalf("a test-only domain %q is in the shipped table", d)
		}
	}
	if strings.Contains(string(providersTxt), "mailhub.test") {
		t.Fatal("the eval's mailhub.test is in the shipped file")
	}

	for _, bad := range []string{
		"esp shop.test",    // no source
		"esp shop.test --", // empty source
		"authserv a.test mx.a.test -- x\nauthserv a.test mx.b.test -- y", // repeated key
		"security a.test sec.a.test -- x",                                // no authserv for its key
		"mx a.test -- x",                                                 // unknown kind
		"esp test -- x",                                                  // not a domain
	} {
		if _, err := ParseProviders([]byte(bad)); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	p, err := ParseProviders([]byte("esp mailhub.test -- test\nauthserv mailhub.test mx.mailhub.test -- test\nauthserv imap.mailhub.test mx2.mailhub.test -- test\nsecurity mailhub.test security@mailhub.test -- test"))
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := p.For("", "imap.mailhub.test:993"); a != "" {
		t.Fatalf("a host with a port matched %q; For takes the host alone", a)
	}
	if a, sec := p.For("", "imap.mailhub.test"); a != "mx2.mailhub.test" || sec != nil {
		t.Fatalf("the longest key did not win: %q %q", a, sec)
	}
	if a, sec := p.For("", "smtp.mailhub.test"); a != "mx.mailhub.test" || !slices.Equal(sec, []string{"security@mailhub.test"}) {
		t.Fatalf("suffix match: %q %q", a, sec)
	}
	if !slices.Equal(p.Table(), []string{"mailhub.test"}) {
		t.Fatalf("table %q", p.Table())
	}
}

// Indented and CR-ended lines are trimmed before they are read, a comment
// is skipped, and a key that is no domain or a security sender that is no
// address or domain fails the table; mustProviders panics on a bad table.
func TestParseProvidersTrimsAndRefuses(t *testing.T) {
	ok := "  # a comment\r\n\t\r\n authserv ex.test mx.ex.test -- s\r\n  security ex.test alerts@ex.test -- s \n"
	if p, err := ParseProviders([]byte(ok)); err != nil {
		t.Fatalf("%q: %v", ok, err)
	} else if a, sec := p.For("", "imap.ex.test"); a != "mx.ex.test" || !slices.Equal(sec, []string{"alerts@ex.test"}) {
		t.Fatalf("%q: authserv %q, security %v", ok, a, sec)
	}
	for _, bad := range []string{
		"authserv . mx.ex.test -- s",
		"authserv ex.test mx.ex.test -- s\nsecurity . alerts@ex.test -- s",
		"authserv ex.test mx.ex.test -- s\nsecurity ex.test nodot -- s",
	} {
		if _, err := ParseProviders([]byte(bad)); err == nil {
			t.Errorf("%q parsed, want an error", bad)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("mustProviders took a bad table")
		}
	}()
	mustProviders([]byte("nonsense"))
}
