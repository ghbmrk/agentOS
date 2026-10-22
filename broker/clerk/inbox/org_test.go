package inbox

// REQ: VRB-2 (assumption MIG-3-R1)

import "testing"

// Two senders align only under one organizational domain, by the Public
// Suffix List: two unrelated sites under a multi-label or private suffix are
// two organizations, and a suffix, an IP address or nothing aligns with
// nothing, so DKIM, URL-host and lookalike checks never pass for the wrong
// domain on live mail (#2600).
func TestAlignmentUsesThePublicSuffixList(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"a.co.uk", "b.co.uk", false},
		{"mail.a.co.uk", "A.CO.UK.", true},
		{"a.github.io", "b.github.io", false},
		{"news.shop.example", "shop.example", true},
		{"news.example.test", "example.test", true},
		{"a.test", "b.test", false},
		{"co.uk", "co.uk", false},
		{"192.0.2.1", "192.0.2.1", false},
		{"[192.0.2.1]", "[10.9.2.1]", false},
		{"", "", false},
	} {
		if got := aligned(c.a, c.b); got != c.want {
			t.Errorf("aligned(%q, %q) = %v, want %v (orgs %q, %q)", c.a, c.b, got, c.want, org(c.a), org(c.b))
		}
	}
}

// A sender reads as a lookalike when its whole domain, folded, is a known
// sender's or contact's organizational domain or a name under it, while it
// is another organization; its own organizational domain can stop short of
// the part that imitates (#2756).
func TestLookalikeFoldsTheWholeDomain(t *testing.T) {
	for _, c := range []struct {
		domain, known string
		want          bool
	}{
		{"paypa1.co.uk", "paypal.co.uk", true},
		{"news.paypa1.co.uk", "mail.paypal.co.uk", true},
		{"shop.rnyshopify.com", "shop.myshopify.com", true},
		{"barclays.c0.uk", "barclays.co.uk", true},
		{"rnail.example.test", "mail.example.test", false}, // one organization
		{"news.paypal.co.uk", "paypal.co.uk", false},
		{"other.co.uk", "paypal.co.uk", false},
		{"paypal.co.uk.", "paypa1.co.uk", true},
		{"anything.test", "co.uk", false}, // a suffix is no organization
	} {
		if got := lookalike(c.domain, c.known); got != c.want {
			t.Errorf("lookalike(%q, %q) = %v, want %v", c.domain, c.known, got, c.want)
		}
	}
}
