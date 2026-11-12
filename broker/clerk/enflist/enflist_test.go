package enflist

// REQ: NET-2, CLK-14, KRN-12

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

func cur() policy.Document {
	return policy.Document{
		Version:      7,
		Destinations: []string{"old.example"},
		Caps:         map[string]uint64{"old.example": 5},
		EdgeCap:      9,
		Devices:      []policy.Device{{ID: "tv", Network: policy.NetDevices, Allow: []string{"a.example"}, Everyday: true}},
	}
}

// signed is the document a proposal link carries, as the enforcer's page
// reads it.
func signed(t *testing.T, link string) policy.Document {
	t.Helper()
	enc, ok := strings.CutPrefix(link, "https://enforcer.home.arpa/p?d=")
	if !ok {
		t.Fatalf("link %q", link)
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	d, err := policy.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestCapsAreTheStatedFigures (#4578 acceptance 1, 3, 4): each
// destination's signed cap equals the figure its source states, a
// declaration's daily bytes, the image's figure or the next full backup's
// size, with that basis signed beside it, and the edge's one cap is its
// declared total. No margin is added; the rest of the policy is kept.
func TestCapsAreTheStatedFigures(t *testing.T) {
	in := Inputs{Dests: []Dest{
		{Host: "mail.example", Basis: Declared, DailyBytes: 300 << 20},
		{Host: "backup.example", Basis: Backup, DailyBytes: 64 << 30},
		{Host: "updates.example", Basis: Image, DailyBytes: 1 << 20},
	}, EdgeDeclaredBytes: 2 << 30}
	n, err := Propose(cur(), in)
	if err != nil {
		t.Fatal(err)
	}
	link, err := n.Link("enforcer.home.arpa")
	if err != nil {
		t.Fatal(err)
	}
	d := signed(t, link)
	want := cur()
	want.Destinations = []string{"backup.example", "mail.example", "updates.example"}
	want.Caps = map[string]uint64{"mail.example": 300 << 20, "backup.example": 64 << 30, "updates.example": 1 << 20}
	want.Basis = map[string]string{"mail.example": "declared", "backup.example": "backup", "updates.example": "image"}
	want.EdgeCap = 2 << 30
	if canon, _ := policy.Encode(want); !reflect.DeepEqual(d, mustDecode(t, canon)) {
		t.Errorf("signed %+v, want %+v", d, want)
	}
	figs := []Figure{{"backup.example", 64 << 30, Backup}, {"mail.example", 300 << 20, Declared}, {"updates.example", 1 << 20, Image}, {"", 2 << 30, Declared}}
	if got := n.Figures(); !reflect.DeepEqual(got, figs) {
		t.Errorf("figures %+v, want %+v", got, figs)
	}
	n.Figures()[0].Bytes = 1
	if n.Figures()[0].Bytes != 64<<30 {
		t.Error("Figures shares its slice")
	}
	// An empty list drops every destination and keeps the edge's cap.
	n, err = Propose(cur(), Inputs{EdgeDeclaredBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	link, _ = n.Link("enforcer.home.arpa")
	if d := signed(t, link); len(d.Destinations) != 0 || d.Caps != nil || d.Basis != nil || d.EdgeCap != 1 || len(d.Devices) != 1 {
		t.Errorf("empty list: %+v", d)
	}
}

func mustDecode(t *testing.T, b []byte) policy.Document {
	t.Helper()
	d, err := policy.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestNoDailyBytesIsRefused (#4578 acceptance 2): a destination, or the
// edge, that states no daily bytes is refused with its name, in printable
// ASCII, and no document; never a default cap that would trip the core.
func TestNoDailyBytesIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		in   Inputs
		host string
		says string
	}{
		"a destination": {Inputs{Dests: []Dest{{Host: "ok.example", Basis: Declared, DailyBytes: 1}, {Host: "mail.example", Basis: Declared}}, EdgeDeclaredBytes: 1},
			"mail.example", `"mail.example" states no daily bytes, so agentOS cannot size its cap; declare its daily bytes, then sign.`},
		"a hostile name": {Inputs{Dests: []Dest{{Host: "moc.\u202eevil", Basis: Image}}, EdgeDeclaredBytes: 1},
			"moc.\u202eevil", `"moc.\u202eevil" states no daily bytes`},
		"the edge": {Inputs{Dests: []Dest{{Host: "ok.example", Basis: Backup, DailyBytes: 1}}},
			"", "The edge states no daily total, so agentOS cannot size its cap; declare the edge's daily total, then sign."},
	} {
		n, err := Propose(cur(), c.in)
		var e *NoDailyBytes
		if !errors.Is(err, ErrNoDailyBytes) || !errors.As(err, &e) || e.Host != c.host || !strings.HasPrefix(err.Error(), c.says) {
			t.Errorf("%s: %v, want *NoDailyBytes for %q saying %q", name, err, c.host, c.says)
		}
		if _, lerr := n.Link("enforcer.home.arpa"); lerr == nil {
			t.Errorf("%s: a refused proposal has a link", name)
		}
	}
	if errors.Is(&NoDailyBytes{}, ErrInput) {
		t.Error("NoDailyBytes is ErrInput")
	}
}

// TestBadListsAreRefused: a host listed twice, a basis off the policy's
// list, a name the policy refuses, or caps past 2^64-1 give ErrInput and
// no link; a link needs a plain enforcer name.
func TestBadListsAreRefused(t *testing.T) {
	for name, ds := range map[string][]Dest{
		"twice":        {{"a.example", Declared, 1}, {"a.example", Image, 2}},
		"no basis":     {{"a.example", "", 1}},
		"a guess":      {{"a.example", "guess", 1}},
		"a bad name":   {{"a example", Declared, 1}},
		"past 2^64-1":  {{"a.example", Declared, 1 << 63}, {"b.example", Declared, 1 << 63}},
		"no host name": {{"", Declared, 1}},
	} {
		if _, err := Propose(cur(), Inputs{Dests: ds, EdgeDeclaredBytes: 1}); !errors.Is(err, ErrInput) {
			t.Errorf("%s: %v, want ErrInput", name, err)
		}
	}
	n, err := Propose(cur(), Inputs{EdgeDeclaredBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "evil.example/x", "a?b", "a#b", "u@h", "h:1", "a b"} {
		if _, err := n.Link(name); !errors.Is(err, ErrInput) {
			t.Errorf("Link(%q): %v, want ErrInput", name, err)
		}
	}
}
