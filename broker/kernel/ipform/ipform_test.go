package ipform

// REQ: KRN-12, DEV-2

import (
	"net/netip"
	"slices"
	"testing"
)

// Every form that carries 169.254.169.254 gives it, zoned or not; a
// neighbour of each form does not. Catches a decoy or private address named
// as IPv6 passing a check made on its IPv4 form.
func TestForms(t *testing.T) {
	meta := netip.MustParseAddr("169.254.169.254")
	for _, s := range []string{
		"169.254.169.254", "::ffff:169.254.169.254", "::ffff:169.254.169.254%1",
		"::169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b::a9fe:a9fe%eth0",
		"64:ff9b:1::a9fe:a9fe", "64:ff9b:1:a9fe:a9:fe00::", "2002:a9fe:a9fe::1",
		"fe80::5efe:a9fe:a9fe%eth0", "fe80::200:5efe:a9fe:a9fe",
		"2001:0:a9fe:a9fe::", "2001:0:4136:e378:8000:63bf:5601:5601",
	} {
		if !slices.Contains(Forms(netip.MustParseAddr(s)), meta) {
			t.Errorf("%s: %v lacks %s", s, Forms(netip.MustParseAddr(s)), meta)
		}
	}
	for _, s := range []string{
		"169.254.169.253", "fe80::a9fe:a9fe", "2003:a9fe:a9fe::1", "fe80::100:5efe:a9fe:a9fe",
		"64:ff9b:2::a9fe:a9fe", "2001:1:a9fe:a9fe::", "1::a9fe:a9fe", "::1",
	} {
		if slices.Contains(Forms(netip.MustParseAddr(s)), meta) {
			t.Errorf("%s gives %s", s, meta)
		}
	}
	if f := Forms(netip.MustParseAddr("fe80::1%eth0")); len(f) != 1 || f[0].Zone() != "" {
		t.Errorf("a zoned address keeps its zone: %v", f)
	}
}
