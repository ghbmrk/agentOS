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
		{"", "", false},
	} {
		if got := aligned(c.a, c.b); got != c.want {
			t.Errorf("aligned(%q, %q) = %v, want %v (orgs %q, %q)", c.a, c.b, got, c.want, org(c.a), org(c.b))
		}
	}
}
