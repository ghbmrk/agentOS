package localui

import (
	"errors"
	"net/http"

	"github.com/ghbmrk/agentos/broker/card"
)

// OwnerCard is the first-boot Owner Card step as setup sees it
// (firstboot.CardStep, HW-1).
type OwnerCard interface {
	// Display is the card's display; nil once the card was confirmed on
	// an earlier start.
	Display() *card.Display
	// Hold refuses until the card is confirmed and provisioned.
	Hold() error
}

var errCardFirst = errors.New("Save your Owner Card and confirm it first.")

// cardHeld reports whether the Owner Card step still holds setup. It takes
// only the card step's own lock, so it may run under u.mu.
func (u *setup) cardHeld() bool {
	return u.s.cfg.Card != nil && u.s.cfg.Card.Hold() != nil
}

// card serves the Owner Card's display (card.Display.Handler) on this
// server, so the Host, same-origin, claim and subnet checks of ServeHTTP
// run first, and only to the phone that paired. The confirm returns the
// phone to setup.
func (u *setup) card(w http.ResponseWriter, r *http.Request) {
	d := u.s.cfg.Card.Display()
	if u.done() || d == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	d.Handler(u.paired, "/setup").ServeHTTP(w, r)
}

// paired reports whether r comes from the phone that paired, while setup
// is open.
func (u *setup) paired(r *http.Request) bool {
	key := u.phone(nil, r, false)
	u.mu.Lock()
	defer u.mu.Unlock()
	return key != "" && !u.st.Done && u.st.Owner != "" && u.st.Device != "" && key == u.st.Device
}
