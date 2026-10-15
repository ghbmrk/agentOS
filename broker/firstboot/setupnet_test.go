package firstboot

// REQ: HW-10, HW-1, CH-7, A1

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
)

// withSetupNet gives a box the seller's setup network.
func withSetupNet(t *testing.T, b *startBox) claim.SetupNet {
	t.Helper()
	n, err := claim.NewSetupNet(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := n.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.setup.Save(m); err != nil {
		t.Fatal(err)
	}
	return n
}

func network(t *testing.T, fb *FirstBoot) *claim.SetupNet {
	t.Helper()
	n, err := fb.Network()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The phone reaches a preloaded box on the sticker's setup network before
// the claim and until the card is confirmed (§8.1 step 4). At the confirm
// the setup network retires: the box answers with the card's network from
// then on and burns the setup file, so the seller's copy of the password
// opens nothing on a set-up box.
func TestTheSetupNetworkServesUntilTheConfirm(t *testing.T) {
	b, code := sealedBox(t)
	n := withSetupNet(t, b)
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := network(t, fb); got == nil || *got != n {
		t.Fatalf("before the claim: %v, want the sticker's", got)
	}
	if _, err := fb.Claim.Claim(code); err != nil {
		t.Fatal(err)
	}
	if got := network(t, fb); got == nil || *got != n {
		t.Fatalf("before the confirm: %v, want the sticker's", got)
	}
	// A restart before the confirm keeps it: the phone rejoins the same
	// network.
	if fb, err = b.begin(t); err != nil {
		t.Fatal(err)
	}
	if got := network(t, fb); got == nil || *got != n {
		t.Fatalf("restart before the confirm: %v", got)
	}
	b.confirm(t, fb.Card.Display())
	if got := network(t, fb); got != nil {
		t.Fatalf("after the confirm: %v, want the card's network", got)
	}
	if raw, _ := b.setup.Load(); len(raw) != 0 {
		t.Fatalf("setup file kept after the confirm: %s", raw)
	}
	if fb, err = b.begin(t); err != nil || network(t, fb) != nil {
		t.Fatalf("restart after the confirm: %v", err)
	}
}

// A confirmed box that still holds a setup file (a burn that failed, or
// a file put back) burns it at the start and never serves it.
func TestBeginBurnsAConfirmedBoxsSetupNetwork(t *testing.T) {
	b, code := sealedBox(t)
	fb, _ := b.begin(t)
	fb.Claim.Claim(code)
	b.confirm(t, fb.Card.Display())
	withSetupNet(t, b)
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := b.setup.Load(); len(raw) != 0 {
		t.Fatalf("setup file kept: %s", raw)
	}
	if network(t, fb) != nil {
		t.Fatal("served the setup network on a confirmed box")
	}
	// A burn that fails stops the start: a confirmed box never runs with
	// the seller's password on its disk unreported.
	withSetupNet(t, b)
	b.setup.Fail = errors.New("disk full")
	if _, err := b.begin(t); err == nil {
		t.Fatal("started with an unburnable setup file")
	}
}

// A sealed box that lost its claim state says "reinstall me" on the
// setup network, so the owner can read it; a box that holds a setup file
// but never held a claim state was sealed too, and goes the same way
// rather than to the download path's pairing.
func TestReinstallKeepsTheSetupNetwork(t *testing.T) {
	b, code := sealedBox(t)
	n := withSetupNet(t, b)
	fb, _ := b.begin(t)
	fb.Claim.Claim(code)
	b.claim = change.MemStore{}
	fb, err := b.begin(t)
	if err != nil || fb.Route != RouteReinstall {
		t.Fatalf("route %v %v", fb, err)
	}
	if got := network(t, fb); got == nil || *got != n {
		t.Fatalf("reinstall: %v", got)
	}

	b2 := &startBox{}
	n2 := withSetupNet(t, b2)
	fb, err = b2.begin(t)
	if err != nil || fb.Route != RouteReinstall {
		t.Fatalf("setup file without a claim state: %+v %v", fb, err)
	}
	if b2.resets != 0 || b2.shown.WiFiName != "" {
		t.Fatal("reset or drew a card")
	}
	if got := network(t, fb); got == nil || *got != n2 {
		t.Fatalf("reinstall without a claim state: %v", got)
	}
}

// A download box has no setup network: Network is nil (the flasher's
// path is a later row).
func TestADownloadBoxHasNoSetupNetwork(t *testing.T) {
	b := &startBox{download: true}
	fb, err := b.begin(t)
	if err != nil || fb.Route != RouteDownload {
		t.Fatalf("%+v %v", fb, err)
	}
	if network(t, fb) != nil {
		t.Fatal("a setup network on a download box")
	}
}

// A setup file that does not parse, or a store that cannot be read,
// stops the start: the box brings up no network nobody printed.
func TestABadSetupFileStopsTheStart(t *testing.T) {
	b, _ := sealedBox(t)
	b.setup.Save([]byte(`{"ssid":"AgentOS-Setup-ABCD","password":"open"}`))
	if _, err := b.begin(t); err == nil {
		t.Fatal("started with a bad setup file")
	}
	b2, _ := sealedBox(t)
	b2.setupStore = unreadable{}
	if _, err := b2.begin(t); err == nil {
		t.Fatal("started with an unreadable setup store")
	}
}

type unreadable struct{}

func (unreadable) Load() ([]byte, error) { return nil, errors.New("read error") }
func (unreadable) Save([]byte) error     { return nil }
