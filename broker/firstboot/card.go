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
// Preloaded marks a box that held a claim code (Begin): it survives the
// confirm, so a box that loses its claim state never looks bare (R4).
type cardState struct {
	Confirmed bool `json:"card_confirmed"`
	Preloaded bool `json:"preloaded,omitempty"`
}

// CardStep is the first-boot Owner Card step (HW-1): on each start until
// the owner confirms, the box generates a card from its own randomness and
// shows it to the paired phone; nothing of it is written until the
// confirm, when the box provisions from it, latches, and erases its copy.
type CardStep struct {
	state     Store
	cfg       card.DisplayConfig
	preloaded bool

	mu   sync.Mutex
	done bool
	gen  int // the display whose confirm may latch; Again moves it on
	d    *card.Display
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
	s := &CardStep{state: st, cfg: cfg, preloaded: cs.Preloaded, done: cs.Confirmed}
	if s.done {
		return s, nil
	}
	if s.d, err = s.display(0); err != nil {
		return nil, err
	}
	return s, nil
}

// display builds generation gen's card display: its confirm provisions,
// latches and releases the hold, unless Again has moved on since.
func (s *CardStep) display(gen int) (*card.Display, error) {
	cfg := s.cfg
	prov := cfg.Provision
	cfg.Provision = func(c *card.Card) error {
		s.mu.Lock()
		stale := s.gen != gen
		s.mu.Unlock()
		if stale {
			return errors.New("firstboot: this Owner Card was replaced; use the new one")
		}
		if err := prov(c); err != nil {
			return err
		}
		b, err := json.Marshal(cardState{Confirmed: true, Preloaded: s.preloaded})
		if err != nil {
			return err
		}
		if err := s.state.Save(b); err != nil {
			return err
		}
		s.mu.Lock()
		s.done = true
		s.mu.Unlock()
		return nil
	}
	return card.NewDisplay(cfg)
}

// Again reruns the card step for a vault that holds no card although the
// latch says confirmed (#1330): the hold refuses at once, reset runs (the
// vault's card reset, a no-op on a vault remade empty), then a new card
// is shown whose confirm provisions and latches as before. The disk latch
// is kept until that confirm: agentos-ap serves the card's network while
// it reads confirmed, and the setup network is burned (ASSUMPTIONS.md).
// A failed reset shows no card; Again may be called again.
func (s *CardStep) Again(reset func() error) error {
	if reset == nil {
		return errors.New("firstboot: incomplete card reset config")
	}
	s.mu.Lock()
	s.done = false
	s.gen++
	gen := s.gen
	s.d = nil
	s.mu.Unlock()
	if err := reset(); err != nil {
		return fmt.Errorf("firstboot: resetting the vault for a new card: %w", err)
	}
	d, err := s.display(gen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return errors.New("firstboot: the card step was rerun again")
	}
	s.d = d
	return nil
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
// confirmed on an earlier start, and while Again resets the vault.
func (s *CardStep) Display() *card.Display {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.d
}

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
