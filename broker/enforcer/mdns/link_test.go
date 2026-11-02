package mdns

// REQ: NET-3

import (
	"encoding/base64"
	"net/netip"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// TestCasterAddedThroughLink: a caster-class device added through the
// pair link with its announced names in Device.MDNS is discoverable
// across its pair once that document is signed (#4401): the names survive
// the link's encoding and the enforcer's decoding into the relay's pins,
// and its host and instance records reach the paired Owner network. The
// same link with MDNS omitted passes none of its records across the pair,
// which the pairing card says (page TestUnpinnedPairSaysSo).
func TestCasterAddedThroughLink(t *testing.T) {
	doc := func(names [][]string) policy.Document {
		return policy.Document{
			Version: 3,
			Devices: []policy.Device{
				{ID: "phone", Network: policy.NetOwner, Everyday: true},
				{ID: "caster", Network: policy.NetDevices, WiFi: "vlan109", Everyday: true, MDNS: names},
			},
			Pairs: []policy.Pair{{A: "phone", B: "caster"}},
		}
	}
	// The link carries the document as base64url of its canonical form;
	// the page decodes exactly that (page.draft).
	signed := func(d policy.Document) policy.Document {
		b, err := policy.Encode(d)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(base64.RawURLEncoding.EncodeToString(b))
		if err != nil {
			t.Fatal(err)
		}
		out, err := policy.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	relayer := func(d policy.Document) *relayer {
		paths, err := nft.Paths(d, fixtureLayout())
		if err != nil {
			t.Fatal(err)
		}
		announces, err := nft.Announces(d, fixtureLayout())
		if err != nil {
			t.Fatal(err)
		}
		return newRelayer(NewPlan(paths, announces), func(string) []netip.Prefix { return printerLink }, t0)
	}
	announce := response([]record{
		a("caster.local", "10.13.0.2", 120),
		srv("Living Room._cast._tcp.local", "caster.local", 120),
		txt("Living Room._cast._tcp.local", 120),
		ptr("_cast._tcp.local", "Living Room._cast._tcp.local", 120),
	}, nil).bytes()

	pinned := signed(doc([][]string{{"caster", "local"}, {"Living Room", "_cast", "_tcp", "local"}}))
	out, outs := relayer(pinned).handle("ap0.109", 5353, announce, t0)
	if out == nil || !slices.Equal(outs, []string{"own0"}) {
		t.Fatalf("the pinned caster went to %v", outs)
	}
	if back, ok := parse(out); !ok || len(back.answers) != 4 {
		t.Errorf("the pinned caster passed %x, not its 4 records", out)
	}

	if out, outs := relayer(signed(doc(nil))).handle("ap0.109", 5353, announce, t0); out != nil {
		t.Errorf("the unpinned caster passed %x to %v", out, outs)
	}
}
