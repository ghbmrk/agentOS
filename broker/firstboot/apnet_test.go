package firstboot

// REQ: CH-7, HW-10, HW-1

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
)

func setupFile(t *testing.T) (*change.MemStore, claim.SetupNet) {
	t.Helper()
	n, err := claim.NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	st := &change.MemStore{}
	if err := st.Save(m); err != nil {
		t.Fatal(err)
	}
	return st, n
}

// The access point's loader serves the sticker's setup network until the
// card is confirmed (§8.1 step 4), and burns it once the latch says so
// (CTRL-claim-ap).
func TestSetupNetworkServesTheStickerNetworkBeforeTheCard(t *testing.T) {
	setup, want := setupFile(t)
	for name, latch := range map[string][]byte{
		"no latch":      nil,
		"preloaded":     []byte(`{"card_confirmed":false,"preloaded":true}`),
		"not confirmed": []byte(`{"card_confirmed":false}`),
	} {
		got, err := SetupNetwork(latch, false, setup)
		if err != nil || got == nil || *got != want {
			t.Fatalf("%s: SetupNetwork = %v, %v; want the sticker's network", name, got, err)
		}
	}
}

func TestSetupNetworkBurnsOnceTheCardIsConfirmed(t *testing.T) {
	setup, _ := setupFile(t)
	got, err := SetupNetwork([]byte(`{"card_confirmed":true,"preloaded":true}`), false, setup)
	if err != nil || got != nil {
		t.Fatalf("SetupNetwork = %v, %v; want nil, nil", got, err)
	}
	if b, _ := setup.Load(); len(b) != 0 {
		t.Fatal("the setup network was not burned")
	}
	// Burned stays burned, and a box with none serves none.
	if got, err := SetupNetwork(nil, false, setup); err != nil || got != nil {
		t.Fatalf("after the burn: %v, %v", got, err)
	}
	if got, err := SetupNetwork(nil, false, nil); err != nil || got != nil {
		t.Fatalf("no setup store: %v, %v", got, err)
	}
}

type failStore struct{ change.MemStore }

func (*failStore) Save([]byte) error { return errors.New("disk full") }

func TestSetupNetworkErrs(t *testing.T) {
	setup, _ := setupFile(t)
	if _, err := SetupNetwork([]byte(`{not json`), false, setup); err == nil {
		t.Error("a latch that does not parse returned nil")
	}
	if _, err := SetupNetwork(nil, false, &change.MemStore{}); err != nil {
		t.Errorf("an empty setup file: %v", err)
	}
	bad := &change.MemStore{}
	bad.Save([]byte(`{"ssid":""}`))
	if _, err := SetupNetwork(nil, false, bad); err == nil {
		t.Error("a setup file that does not parse returned nil")
	}
	fs := &failStore{}
	m, _ := setup.Load()
	fs.MemStore.Save(m)
	if n, err := SetupNetwork([]byte(`{"card_confirmed":true}`), false, fs); err == nil || n != nil {
		t.Errorf("a failed burn = %v, %v; want nil and an error", n, err)
	}
}

// Once setup has finished the seller's network is burned whatever the
// latch says: the page can write the latch, and a page that kept it
// unconfirmed must not keep the sticker's password working on an owned
// box (CTRL-claim-ap).
func TestSetupNetworkBurnsOnAnOwnedBox(t *testing.T) {
	for name, latch := range map[string][]byte{
		"unconfirmed latch": []byte(`{"card_confirmed":false,"preloaded":true}`),
		"no latch":          nil,
		"garbage latch":     []byte(`{not json`),
	} {
		setup, _ := setupFile(t)
		got, err := SetupNetwork(latch, true, setup)
		if err != nil || got != nil {
			t.Fatalf("%s: SetupNetwork = %v, %v; want nil, nil", name, got, err)
		}
		if b, _ := setup.Load(); len(b) != 0 {
			t.Fatalf("%s: the setup network was not burned", name)
		}
	}
	bad := &change.MemStore{}
	bad.Save([]byte(`{"ssid":""}`))
	if got, err := SetupNetwork(nil, true, bad); err != nil || got != nil {
		t.Fatalf("owned, unparsable setup file: %v, %v", got, err)
	}
	if b, _ := bad.Load(); len(b) != 0 {
		t.Fatal("an owned box kept an unparsable setup file")
	}
}

// CardConfirmed is the latch as agentos-ap reads it to serve the card's
// network (#1185).
func TestCardConfirmedReadsTheLatch(t *testing.T) {
	for _, c := range []struct {
		latch string
		want  bool
		err   bool
	}{
		{"", false, false},
		{`{"preloaded":true}`, false, false},
		{`{"card_confirmed":true}`, true, false},
		{`{"card_confirmed":true,"preloaded":true}`, true, false},
		{`not json`, false, true},
	} {
		got, err := CardConfirmed([]byte(c.latch))
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%q: got %v, %v", c.latch, got, err)
		}
	}
}
