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

// ErrNoAuthority is what CardStep.Hold returns, a fixed line for the page,
// while the card step has no page authority to print on the card (HW-1:
// the box makes every Owner Card after the core's page authority, and a
// card printed without its fingerprint can never get it). The step draws
// nothing and shows no card; setup's finish still answers card pending.
// The same line answers a keeper that does not know the card's page
// certificate (OWN-card-flow decision 10).
var ErrNoAuthority = errors.New("I can't make your Owner Card yet, because my page certificate isn't ready. Restart the box and open this page again. If you see this again, tell me in a text.")

// Line is a Provision error that is the page's fixed line for the owner
// (OWN-card-flow decision 10): the step keeps it for Note, so the setup page
// shows it in place of the card's own retry text. It never holds card text.
type Line string

func (l Line) Error() string { return string(l) }

// ErrKept, wrapped in a Provision error, says the keeper's store was made
// from an Owner Card the owner confirmed before the box restarted, and this
// card does not open it (OWN-card-flow decision 8): the step latches as
// confirmed, and the page shows this line once, so the owner keeps the
// earlier card.
var ErrKept = Line("This box already holds the keys of the Owner Card you confirmed before it restarted. Keep that card and throw this one away.")

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
	// noAuth: cfg.Authority is missing or not the page's authority
	// (card.CheckAuthority), so no card is ever drawn (ASSUMPTIONS OWN-card-ca-3).
	noAuth bool

	mu   sync.Mutex
	done bool
	gen  int // the display whose confirm may latch; Again moves it on
	d    *card.Display
	// failed is the reset of the latest rerun when that rerun showed no
	// card; RetryRerun runs it again (#2362).
	failed func() error
	// note is the latest confirm's Line, until Note takes it.
	note string
}

// NewCardStep loads the latch and, if the card was not confirmed yet,
// generates a new card for display. cfg.Provision must accept a retry
// with the same card (ASSUMPTIONS.md F10). Without a page authority
// (cfg.Authority) it builds no display and draws no randomness: Hold
// returns ErrNoAuthority, and the step never errors for it, so the page
// does not crash-loop (OWN-card-ca-3).
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
	s := &CardStep{state: st, cfg: cfg, preloaded: cs.Preloaded, done: cs.Confirmed,
		noAuth: card.CheckAuthority(cfg.Authority) != nil}
	if s.done || s.noAuth {
		return s, nil
	}
	if s.d, err = s.display(0); err != nil {
		return nil, err
	}
	return s, nil
}

// display builds generation gen's card display: its confirm provisions,
// latches and releases the hold, unless Again has moved on since. A
// provision error that is a Line is kept for Note; ErrKept latches.
func (s *CardStep) display(gen int) (*card.Display, error) {
	cfg := s.cfg
	prov := cfg.Provision
	cfg.Provision = func(c *card.Card) error {
		s.mu.Lock()
		stale := s.gen != gen
		s.note = ""
		s.mu.Unlock()
		if stale {
			return errors.New("firstboot: this Owner Card was replaced; use the new one")
		}
		if err := prov(c); err != nil {
			var l Line
			if errors.As(err, &l) {
				s.mu.Lock()
				s.note = string(l)
				s.mu.Unlock()
			}
			if !errors.Is(err, ErrKept) {
				return err
			}
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
// is kept until that confirm, so it still reads confirmed.
// A failed reset shows no card and keeps the hold; RetryRerun runs it
// again (#2362).
func (s *CardStep) Again(reset func() error) error {
	if reset == nil {
		return errors.New("firstboot: incomplete card reset config")
	}
	if s.noAuth {
		// No card could follow the reset, so the vault is left as it is.
		return ErrNoAuthority
	}
	s.mu.Lock()
	s.done = false
	s.gen++
	gen := s.gen
	s.d = nil
	s.failed = nil
	s.mu.Unlock()
	if err := reset(); err != nil {
		s.fail(gen, reset)
		return fmt.Errorf("firstboot: resetting the vault for a new card: %w", err)
	}
	d, err := s.display(gen)
	if err != nil {
		s.fail(gen, reset)
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

// fail keeps reset for RetryRerun unless a later rerun has started.
func (s *CardStep) fail(gen int, reset func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen == gen {
		s.failed = reset
	}
}

// RetryRerun reruns c's card step again when its latest rerun (Again)
// showed no card, with that rerun's reset, and reports whether it did.
// Without it setup stays held with no card to confirm until a restart
// (#2362, ASSUMPTIONS.md F18). c is a route's card step (FirstBoot.Card);
// a claimed card's step is retried, any other has none to retry.
func RetryRerun(c CardHold) (bool, error) {
	var s *CardStep
	switch v := c.(type) {
	case *CardStep:
		s = v
	case *ClaimedCard:
		s = v.Card()
	}
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	reset := s.failed
	s.failed = nil // one retry at a time; a failed one sets it again
	s.mu.Unlock()
	if reset == nil {
		return false, nil
	}
	return true, s.Again(reset)
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

// TakeNote returns the latest confirm's fixed line for the owner (a Line
// its provision returned), once, or "" when there is none. c is a route's
// card step (FirstBoot.Card), as for RetryRerun.
func TakeNote(c CardHold) string {
	var s *CardStep
	switch v := c.(type) {
	case *CardStep:
		s = v
	case *ClaimedCard:
		s = v.Card()
	}
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.note
	s.note = ""
	return n
}

// Hold returns ErrCardPending, with the owner's next step, until the card
// is confirmed; nil after. Without a page authority it returns
// ErrNoAuthority instead. The setup finish path calls it first.
func (s *CardStep) Hold() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil
	}
	if s.noAuth {
		return ErrNoAuthority
	}
	return fmt.Errorf("%w: print or save your Owner Card, then type the word and group I ask for", ErrCardPending)
}
