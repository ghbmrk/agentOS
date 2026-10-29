package localui

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/firstboot"
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
	h := d.Handler(u.paired, "/setup")
	if r.Method != http.MethodPost {
		h.ServeHTTP(w, r)
		return
	}
	// A confirm whose provision voided the code generator (F10) goes
	// back to setup's codes step rather than the retry page; the display
	// keeps the card for the confirm after it.
	rec := &cardReply{h: http.Header{}, code: http.StatusOK}
	h.ServeHTTP(rec, r)
	if u.s.cfg.CodesVoid != nil && u.voidCodes() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	// A confirm the keeper refused, or answered kept, goes back to setup
	// with the step's fixed line (OWN-card-flow decision 10) rather than
	// the display's own retry text. Only the paired phone confirms.
	if line := firstboot.TakeNote(u.s.cfg.Card); line != "" {
		if key := u.phone(nil, r, false); u.paired(r) {
			u.mu.Lock()
			u.err[key] = line
			u.mu.Unlock()
		}
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	for k, v := range rec.h {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.code)
	w.Write(rec.body.Bytes())
}

// cardReply holds the card display's answer to a POST until setup knows
// whether the provision voided the code generator.
type cardReply struct {
	h    http.Header
	code int
	body bytes.Buffer
}

func (c *cardReply) Header() http.Header         { return c.h }
func (c *cardReply) WriteHeader(code int)        { c.code = code }
func (c *cardReply) Write(b []byte) (int, error) { return c.body.Write(b) }

// paired reports whether r comes from the phone that paired, while setup
// is open.
func (u *setup) paired(r *http.Request) bool {
	key := u.phone(nil, r, false)
	u.mu.Lock()
	defer u.mu.Unlock()
	return key != "" && !u.st.Done && u.st.Owner != "" && u.st.Device != "" && key == u.st.Device
}
