package firstboot

// REQ: HW-10, HW-1

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
)

// startBox is one box's stores across starts: the claim state the seller
// flow wrote (empty on a download box), the card latch and a vault that
// counts its resets.
type startBox struct {
	claim, latch change.MemStore
	setup        change.MemStore // the seller's setup network; empty on a download box
	setupStore   Store           // replaces setup when set
	download     bool            // the image is the download's (BoxConfig.Download)
	vault        bool
	resets       int
	shown        card.Card
}

func (b *startBox) begin(t *testing.T) (*FirstBoot, error) {
	t.Helper()
	var setup Store = &b.setup
	if b.setupStore != nil {
		setup = b.setupStore
	}
	return Begin(BoxConfig{
		Claim:    claim.Config{Store: &b.claim, BootID: func() (string, error) { return "boot-1", nil }},
		Latch:    &b.latch,
		SetupNet: setup,
		Download: b.download,
		Reset:    func() error { b.resets++; b.vault = false; return nil },
		Card: card.DisplayConfig{
			Generate: func(r io.Reader) (*card.Card, error) {
				c, err := card.Generate(r)
				if err == nil {
					b.shown = *c
				}
				return c, err
			},
			Provision: func(*card.Card) error { b.vault = true; return nil },
		},
	})
}

func (b *startBox) confirm(t *testing.T, d *card.Display) {
	t.Helper()
	if d == nil {
		t.Fatal("no card shown")
	}
	w, g := d.Asks()
	if err := d.Confirm(strings.Fields(b.shown.VaultPassphrase)[w-1], strings.Split(b.shown.RecoveryKey, "-")[g-1]); err != nil {
		t.Fatal(err)
	}
}

func sealedBox(t *testing.T) (*startBox, string) {
	t.Helper()
	b := &startBox{}
	code, err := claim.NewCode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim.Seal(&b.claim, code, nil, nil); err != nil {
		t.Fatal(err)
	}
	return b, code
}

// A sealed box takes the claim route: no card before the claim (Display
// nil, Hold says it waits to be claimed), the card after it.
func TestBeginRoutesASealedBoxToTheClaim(t *testing.T) {
	b, code := sealedBox(t)
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if fb.Route != RouteClaim || fb.Claim == nil {
		t.Fatalf("route %q claim %v", fb.Route, fb.Claim)
	}
	if fb.Card.Display() != nil || !errors.Is(fb.Card.Hold(), ErrUnclaimed) {
		t.Fatal("card step before the claim")
	}
	if b.resets != 1 {
		t.Fatalf("an unlatched start resets the vault first: %d", b.resets)
	}
	tok, err := fb.Claim.Claim(code)
	if err != nil || !fb.Claim.Claimant(tok) {
		t.Fatalf("claim %v", err)
	}
	if !errors.Is(fb.Card.Hold(), ErrCardPending) {
		t.Fatalf("hold after the claim: %v", fb.Card.Hold())
	}
	b.confirm(t, fb.Card.Display())
	if fb.Card.Hold() != nil || !b.vault {
		t.Fatal("card not confirmed")
	}
}

// A bare install (no claim state) of the download's image takes the
// download route: the card at once, no claim screen.
func TestBeginRoutesABareInstallToTheDownloadPath(t *testing.T) {
	b := &startBox{download: true}
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if fb.Route != RouteDownload || fb.Claim != nil {
		t.Fatalf("route %q claim %v", fb.Route, fb.Claim)
	}
	b.confirm(t, fb.Card.Display())
	if fb.Card.Hold() != nil {
		t.Fatal("held after the confirm")
	}
	// A restart of a confirmed download box is still the download path.
	fb, err = b.begin(t)
	if err != nil || fb.Route != RouteDownload || fb.Card.Hold() != nil {
		t.Fatalf("restart: %+v %v", fb, err)
	}
}

// #1270 (CTRL-card-sock s1): only an image configured as the download's
// takes the download route. On a preloaded image a claim state that is
// missing, or hidden from the page, routes to reinstall: no card, no
// reset, no setup step without the claim gate.
func TestBeginTakesTheDownloadRouteOnlyWhenConfigured(t *testing.T) {
	b := &startBox{}
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if fb.Route != RouteReinstall || fb.Claim == nil || fb.Card.Hold() != ErrReinstall || fb.Card.Display() != nil {
		t.Fatalf("route %q", fb.Route)
	}
	if _, err := fb.Claim.Claim("CANA-RYCL-AXMC-KDE2"); !errors.Is(err, claim.ErrAlreadyClaimed) {
		t.Fatalf("claim on a box with no claim state: %v", err)
	}
	if l, _ := b.latch.Load(); b.resets != 0 || b.shown.SetupSecret != "" || len(l) != 0 {
		t.Fatalf("resets %d, card drawn %v, latch %q", b.resets, b.shown.SetupSecret != "", l)
	}
}

// R4: a box that was ever sealed and lost its claim state routes to
// "already claimed, reinstall me": no card, no pairing, no claim, and the
// vault is never reset, whether the loss came before or after the confirm.
func TestBeginRoutesALostClaimStateToReinstall(t *testing.T) {
	for name, confirm := range map[string]bool{"after the confirm": true, "before the confirm": false} {
		b, code := sealedBox(t)
		fb, err := b.begin(t)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fb.Claim.Claim(code); err != nil {
			t.Fatal(err)
		}
		if confirm {
			b.confirm(t, fb.Card.Display())
		}
		resets := b.resets
		b.claim = change.MemStore{} // claim.json deleted
		fb, err = b.begin(t)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fb.Route != RouteReinstall {
			t.Fatalf("%s: route %q", name, fb.Route)
		}
		if b.resets != resets {
			t.Fatalf("%s: reset the vault", name)
		}
		if fb.Card.Display() != nil || fb.Card.Hold() == nil || !strings.Contains(fb.Card.Hold().Error(), "reinstall me") {
			t.Fatalf("%s: card %v", name, fb.Card.Hold())
		}
		if st := fb.Claim.Status(); !st.Claimed {
			t.Fatalf("%s: status %+v", name, st)
		}
		if _, err := fb.Claim.Claim(code); !errors.Is(err, claim.ErrAlreadyClaimed) {
			t.Fatalf("%s: claim %v", name, err)
		}
		if fb.Claim.Claimant(strings.Repeat("a", 64)) {
			t.Fatalf("%s: a claimant", name)
		}
	}
}

// The confirm keeps the sealed-box marker on the latch, and a latch the
// marker cannot be saved to stops the start before anything is shown.
func TestTheSealedMarkerSurvivesTheConfirm(t *testing.T) {
	b, code := sealedBox(t)
	fb, _ := b.begin(t)
	fb.Claim.Claim(code)
	b.confirm(t, fb.Card.Display())
	raw, _ := b.latch.Load()
	if !strings.Contains(string(raw), `"card_confirmed":true`) || !strings.Contains(string(raw), `"preloaded":true`) {
		t.Fatalf("latch %s", raw)
	}

	b2, _ := sealedBox(t)
	b2.latch.Fail = errors.New("disk full")
	if _, err := b2.begin(t); err == nil {
		t.Fatal("started without the marker")
	}
	// An unreadable latch stops the start on every route.
	b3 := &startBox{}
	b3.latch.Save([]byte("{"))
	if _, err := b3.begin(t); err == nil || b3.resets != 0 {
		t.Fatalf("corrupt latch: %v resets %d", err, b3.resets)
	}
}

// ClaimedCard's Display is its card step's: nil before the claim.
func TestClaimedCardDisplay(t *testing.T) {
	b, code := sealedBox(t)
	cl, err := claim.Open(claim.Config{Store: &b.claim, BootID: func() (string, error) { return "b", nil }})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := NewClaimedCard(cl, &b.latch, card.DisplayConfig{Provision: func(*card.Card) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if cc.Display() != nil {
		t.Fatal("display before the claim")
	}
	cc.Claim(code)
	if cc.Display() == nil || cc.Display() != cc.Card().Display() {
		t.Fatal("display after the claim")
	}
}
