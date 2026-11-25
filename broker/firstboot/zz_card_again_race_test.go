package firstboot

// REQ: HW-1, F10, F18

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
)

// An Again that lands while a confirm's provision is running (#2083): the
// rerun's reset waits for that provision, so it never resets under it and
// the replaced card's confirm cannot release the hold the rerun took.
func TestCardStepAgainDuringProvision(t *testing.T) {
	var shown *card.Card
	entered, release := make(chan struct{}), make(chan struct{})
	var provs, provDone atomic.Int32
	st := &change.MemStore{}
	s, err := NewCardStep(st, card.DisplayConfig{Authority: testAuthority(t),
		Generate: func(r io.Reader) (*card.Card, error) {
			c, err := card.Generate(r)
			if err == nil {
				cp := *c
				shown = &cp
			}
			return c, err
		},
		Provision: func(*card.Card) error {
			if provs.Add(1) == 1 {
				close(entered)
				<-release
			}
			provDone.Add(1)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	first, c := s.Display(), *shown
	w, g := first.Asks()
	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, aerr error
	go func() {
		defer wg.Done()
		cerr = first.Confirm(strings.Fields(c.VaultPassphrase)[w-1], strings.Split(c.RecoveryKey, "-")[g-1])
	}()
	<-entered
	var resetUnder atomic.Bool
	resetRan := make(chan struct{})
	go func() {
		defer wg.Done()
		aerr = s.Again(func() error {
			resetUnder.Store(provDone.Load() == 0)
			close(resetRan)
			return nil
		})
	}()
	select {
	case <-resetRan:
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if cerr != nil || aerr != nil {
		t.Fatalf("confirm %v, again %v", cerr, aerr)
	}
	if resetUnder.Load() {
		t.Fatal("the rerun reset the vault while the replaced card was provisioning")
	}
	if !errors.Is(s.Hold(), ErrCardPending) {
		t.Fatalf("the replaced card released the hold: %v", s.Hold())
	}
	if d := s.Display(); d == nil || d == first || d.Confirmed() {
		t.Fatal("no new card after the rerun")
	}
	if provs.Load() != 1 {
		t.Fatalf("provisions %d, want 1", provs.Load())
	}
}
