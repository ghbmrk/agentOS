package firstboot

// REQ: HW-1, F10

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
)

// After Again the step holds and shows a new card, the vault was reset
// once, and the disk latch still reads confirmed; the new card's confirm
// releases the hold.
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
	var cs cardState
	if err := json.Unmarshal(raw, &cs); err != nil || !cs.Confirmed {
		t.Fatalf("latch %s: %v", raw, err)
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
	s, err := NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t), Provision: func(*card.Card) error { return nil }})
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

// #2362: a rerun whose vault reset failed is retried by RetryRerun, with
// the same reset, until a new card is shown; with no failed rerun it does
// nothing. On the claim route it reaches the claimed card's step.
func TestRetryRerunAfterAFailedReset(t *testing.T) {
	st := &change.MemStore{}
	s, err := NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t), Provision: func(*card.Card) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if retried, err := RetryRerun(s); retried || err != nil {
		t.Fatalf("no failed rerun: retried %v, %v", retried, err)
	}
	fails, resets := 2, 0
	reset := func() error {
		resets++
		if resets <= fails {
			return errors.New("vault busy")
		}
		return nil
	}
	if err := s.Again(reset); err == nil {
		t.Fatal("rerun past a failed reset")
	}
	if retried, err := RetryRerun(s); !retried || err == nil || resets != 2 || s.Display() != nil {
		t.Fatalf("second failure: retried %v, %v, resets %d", retried, err, resets)
	}
	if retried, err := RetryRerun(s); !retried || err != nil || resets != 3 || s.Display() == nil || s.Hold() == nil {
		t.Fatalf("retry: retried %v, %v, resets %d", retried, err, resets)
	}
	if retried, err := RetryRerun(s); retried || err != nil || resets != 3 {
		t.Fatalf("after the new card: retried %v, %v, resets %d", retried, err, resets)
	}

	b, code := sealedBox(t)
	fb, err := b.begin(t)
	if err != nil {
		t.Fatal(err)
	}
	if retried, err := RetryRerun(fb.Card); retried || err != nil {
		t.Fatalf("before the claim: retried %v, %v", retried, err)
	}
	if _, err := fb.Claim.Claim(code); err != nil {
		t.Fatal(err)
	}
	b.confirm(t, fb.Card.Display())
	failed := false
	if err := fb.Card.(*ClaimedCard).Again(func() error {
		if !failed {
			failed = true
			return errors.New("vault busy")
		}
		return nil
	}); err == nil {
		t.Fatal("rerun past a failed reset")
	}
	if retried, err := RetryRerun(fb.Card); !retried || err != nil || fb.Card.Display() == nil || fb.Card.Hold() == nil {
		t.Fatalf("claimed card retry: retried %v, %v", retried, err)
	}
}

// #2397 (M13): a rerun whose reset works but whose new card cannot be
// made keeps the rerun: RetryRerun shows a card, and the hold is released
// only once that card is confirmed.
func TestRetryRerunAfterTheCardCannotBeMade(t *testing.T) {
	var shown card.Card
	fail := false
	s, err := NewCardStep(&change.MemStore{}, card.DisplayConfig{Authority: testAuthority(t),
		Generate: func(rd io.Reader) (*card.Card, error) {
			if fail {
				fail = false
				return nil, errors.New("no randomness")
			}
			c, err := card.Generate(rd)
			if err == nil {
				shown = *c
			}
			return c, err
		},
		Provision: func(*card.Card) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	confirm := func(d *card.Display) {
		t.Helper()
		if d == nil {
			t.Fatal("no card shown")
		}
		w, g := d.Asks()
		if err := d.Confirm(strings.Fields(shown.VaultPassphrase)[w-1], strings.Split(shown.RecoveryKey, "-")[g-1]); err != nil {
			t.Fatal(err)
		}
	}
	confirm(s.Display())
	first := shown.RecoveryKey
	resets := 0
	fail = true
	if err := s.Again(func() error { resets++; return nil }); err == nil {
		t.Fatal("rerun past a card that could not be made")
	}
	if s.Display() != nil || s.Hold() == nil || resets != 1 {
		t.Fatalf("display %v, hold %v, resets %d", s.Display(), s.Hold(), resets)
	}
	if retried, err := RetryRerun(s); !retried || err != nil || s.Display() == nil {
		t.Fatalf("retry: retried %v, %v", retried, err)
	}
	if !errors.Is(s.Hold(), ErrCardPending) || shown.RecoveryKey == first {
		t.Fatalf("hold %v before the new card's confirm", s.Hold())
	}
	confirm(s.Display())
	if s.Hold() != nil {
		t.Fatal(s.Hold())
	}
}
