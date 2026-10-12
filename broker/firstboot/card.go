package firstboot

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/ghbmrk/agentos/broker/card"
)

// ErrCardPending is what CardStep.Hold returns until the owner has saved
// the Owner Card and confirmed it (HW-1): setup does not finish before.
var ErrCardPending = errors.New("firstboot: I am waiting for you to save your Owner Card")

// cardState is the card step's latch, the only thing it keeps on disk.
type cardState struct {
	Confirmed bool `json:"card_confirmed"`
}

// CardStep is the first-boot Owner Card step (HW-1): on each start until
// the owner confirms, the box generates a card from its own randomness and
// shows it to the paired phone; nothing of it is written until the
// confirm, when the box provisions from it, latches, and erases its copy.
type CardStep struct {
	state Store
	mu    sync.Mutex
	done  bool
	d     *card.Display
}

// NewCardStep loads the latch and, if the card was not confirmed yet,
// generates a new card for display. cfg.Provision must accept a retry
// with the same card (ASSUMPTIONS.md F10).
func NewCardStep(st Store, cfg card.DisplayConfig) (*CardStep, error) {
	if st == nil || cfg.Provision == nil {
		return nil, errors.New("firstboot: incomplete card step config")
	}
	b, err := st.Load()
	if err != nil {
		return nil, err
	}
	var cs cardState
	if b != nil {
		if err := json.Unmarshal(b, &cs); err != nil {
			return nil, fmt.Errorf("firstboot: card state: %w", err)
		}
	}
	s := &CardStep{state: st, done: cs.Confirmed}
	if s.done {
		return s, nil
	}
	prov := cfg.Provision
	cfg.Provision = func(c *card.Card) error {
		if err := prov(c); err != nil {
			return err
		}
		b, err := json.Marshal(cardState{Confirmed: true})
		if err != nil {
			return err
		}
		if err := st.Save(b); err != nil {
			return err
		}
		s.mu.Lock()
		s.done = true
		s.mu.Unlock()
		return nil
	}
	if s.d, err = card.NewDisplay(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// ResetUnlatched runs reset unless st's latch says the card was
// confirmed. A start runs it before NewCardStep (or NewClaimedCard): a
// restart between provisioning and the latch left a vault made from a
// card nobody confirmed, and the new card this start shows must not meet
// it (ASSUMPTIONS.md F10). A latch it cannot read stops the start and
// resets nothing.
func ResetUnlatched(st Store, reset func() error) error {
	if st == nil || reset == nil {
		return errors.New("firstboot: incomplete card reset config")
	}
	b, err := st.Load()
	if err != nil {
		return err
	}
	var cs cardState
	if b != nil {
		if err := json.Unmarshal(b, &cs); err != nil {
			return fmt.Errorf("firstboot: card state: %w", err)
		}
	}
	if cs.Confirmed {
		return nil
	}
	if err := reset(); err != nil {
		return fmt.Errorf("firstboot: resetting an unconfirmed card's vault: %w", err)
	}
	return nil
}

// Display is the card's display for the local page: nil when the card was
// confirmed on an earlier start.
func (s *CardStep) Display() *card.Display { return s.d }

// Hold returns ErrCardPending, with the owner's next step, until the card
// is confirmed; nil after. The setup finish path calls it first.
func (s *CardStep) Hold() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil
	}
	return fmt.Errorf("%w: print or save your Owner Card, then type the word and group I ask for", ErrCardPending)
}
