package firstboot

// REQ: HW-1, F10

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
)

// After Again the step holds and shows a new card, the vault was reset
// once, and the disk latch still reads confirmed (agentos-ap keeps the
// card's network); the new card's confirm releases the hold.
func TestCardStepAgain(t *testing.T) {
	b := &startBox{download: true}
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	first := fb.Card.Display()
	b.confirm(t, first)
	resets := b.resets
	if err := fb.Again(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(fb.Card.Hold(), ErrCardPending) {
		t.Fatalf("hold %v", fb.Card.Hold())
	}
	if b.resets != resets+1 {
		t.Fatalf("resets %d, want %d", b.resets, resets+1)
	}
	d := fb.Card.Display()
	if d == nil || d == first || d.Confirmed() {
		t.Fatal("no new card shown")
	}
	raw, _ := b.latch.Load()
	if ok, err := CardConfirmed(raw); !ok || err != nil {
		t.Fatalf("latch %s: %v %v", raw, ok, err)
	}
	b.confirm(t, d)
	if fb.Card.Hold() != nil || !b.vault {
		t.Fatalf("hold %v, vault %v", fb.Card.Hold(), b.vault)
	}
}

// A start on a confirmed latch has no display; Again still makes one, and
// a failed reset shows no card and keeps the hold.
func TestCardStepAgainAfterRestart(t *testing.T) {
	b := &startBox{download: true}
	fb, _ := b.begin(t)
	b.confirm(t, fb.Card.Display())
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if fb.Card.Display() != nil || fb.Card.Hold() != nil {
		t.Fatal("restart did not find the card confirmed")
	}
	if err := fb.Again(); err != nil {
		t.Fatal(err)
	}
	if fb.Card.Display() == nil || fb.Card.Hold() == nil {
		t.Fatal("no card after the rerun")
	}
	b.confirm(t, fb.Card.Display())
	if fb.Card.Hold() != nil {
		t.Fatal(fb.Card.Hold())
	}

	st := &change.MemStore{}
	s, err := NewCardStep(st, card.DisplayConfig{Provision: func(*card.Card) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Again(func() error { return errors.New("vault busy") }); err == nil {
		t.Fatal("rerun past a failed reset")
	}
	if s.Display() != nil || s.Hold() == nil {
		t.Fatal("card shown after a failed reset")
	}
	if err := s.Again(func() error { return nil }); err != nil || s.Display() == nil {
		t.Fatalf("retry: %v", err)
	}
}

// The claim route reruns its step once claimed; before the claim, and on
// the reinstall route, there is no card step to rerun.
func TestClaimedCardAgain(t *testing.T) {
	b, code := sealedBox(t)
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := fb.Again(); !errors.Is(err, ErrUnclaimed) {
		t.Fatalf("before the claim: %v", err)
	}
	if _, err := fb.Claim.Claim(code); err != nil {
		t.Fatal(err)
	}
	first := fb.Card.Display()
	b.confirm(t, first)
	if err := fb.Again(); err != nil {
		t.Fatal(err)
	}
	if d := fb.Card.Display(); d == nil || d == first || fb.Card.Hold() == nil {
		t.Fatal("no new card")
	}
	b.confirm(t, fb.Card.Display())
	if fb.Card.Hold() != nil {
		t.Fatal(fb.Card.Hold())
	}
}

func TestFirstBootAgainOnReinstall(t *testing.T) {
	b := &startBox{}
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if fb.Route != RouteReinstall {
		t.Fatalf("route %q", fb.Route)
	}
	if err := fb.Again(); !errors.Is(err, ErrReinstall) || b.resets != 0 {
		t.Fatalf("reinstall: %v, resets %d", err, b.resets)
	}
}
