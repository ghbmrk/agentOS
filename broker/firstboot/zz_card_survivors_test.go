package firstboot

// REQ: HW-1, F10, F18

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
)

// survivorStep is a card step over a memory latch whose provision calls are
// counted, with the card it shows kept for the test.
func survivorStep(t *testing.T, prov func(*card.Card) error) (*CardStep, *card.Card) {
	t.Helper()
	var shown card.Card
	s, err := NewCardStep(&change.MemStore{}, card.DisplayConfig{Authority: testAuthority(t),
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				shown = *c
			}
			return c, err
		},
		Provision: prov})
	if err != nil {
		t.Fatal(err)
	}
	return s, &shown
}

func confirmShown(d *card.Display, c *card.Card) error {
	w, g := d.Asks()
	return d.Confirm(strings.Fields(c.VaultPassphrase)[w-1], strings.Split(c.RecoveryKey, "-")[g-1])
}

func TestNewCardStepRefusesIncompleteOrUnreadable(t *testing.T) {
	cfg := card.DisplayConfig{Authority: testAuthority(t), Provision: func(*card.Card) error { return nil }}
	if _, err := NewCardStep(nil, cfg); err == nil {
		t.Fatal("no store accepted")
	}
	if _, err := NewCardStep(&change.MemStore{}, card.DisplayConfig{Authority: cfg.Authority}); err == nil {
		t.Fatal("no provision accepted")
	}
	if s, err := NewCardStep(loadFails{errors.New("unreadable")}, cfg); err == nil || s != nil {
		t.Fatalf("an unreadable latch gave a step: %v", err)
	}
}

func TestCardStepAgainWithoutResetKeepsTheCard(t *testing.T) {
	s, _ := survivorStep(t, func(*card.Card) error { return nil })
	first := s.Display()
	if err := s.Again(nil); err == nil {
		t.Fatal("a rerun without a reset ran")
	}
	if s.Display() != first {
		t.Fatal("a refused rerun moved the card")
	}
}

// A replaced card's confirm is refused without provisioning or latching.
func TestCardStepReplacedCardConfirmIsRefused(t *testing.T) {
	var provs int
	s, c := survivorStep(t, func(*card.Card) error { provs++; return nil })
	old, oldCard := s.Display(), *c
	if err := s.Again(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := confirmShown(old, &oldCard); err == nil {
		t.Fatal("the replaced card confirmed")
	}
	if provs != 0 || s.Hold() == nil {
		t.Fatalf("provisions %d, hold %v", provs, s.Hold())
	}
}

// A refusal's note does not outlive the next confirm, which has none.
func TestCardStepNoteClearedByNextConfirm(t *testing.T) {
	var answer error = Line("refused")
	s, c := survivorStep(t, func(*card.Card) error { return answer })
	if err := confirmShown(s.Display(), c); err == nil {
		t.Fatal("refusal confirmed")
	}
	answer = errors.New("plain")
	if err := confirmShown(s.Display(), c); err == nil {
		t.Fatal("plain error confirmed")
	}
	if n := TakeNote(s); n != "" {
		t.Fatalf("stale note %q", n)
	}
}

// A later rerun drops the earlier failed reset, so there is nothing to retry.
func TestCardStepAgainDropsAFailedReset(t *testing.T) {
	s, _ := survivorStep(t, func(*card.Card) error { return nil })
	if err := s.Again(func() error { return errors.New("no") }); err == nil {
		t.Fatal("failed reset passed")
	}
	if err := s.Again(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if ran, err := RetryRerun(s); ran || err != nil {
		t.Fatalf("retry ran %v, %v", ran, err)
	}
}

// An Again overtaken by a later one does not install its card.
func TestCardStepOvertakenAgainKeepsTheLaterCard(t *testing.T) {
	s, _ := survivorStep(t, func(*card.Card) error { return nil })
	inReset, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- s.Again(func() error { close(inReset); <-release; return nil })
	}()
	<-inReset
	if err := s.Again(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	later := s.Display()
	close(release)
	if err := <-done; err == nil {
		t.Fatal("the overtaken rerun reported success")
	}
	if s.Display() != later {
		t.Fatal("the overtaken rerun replaced the later card")
	}
}
