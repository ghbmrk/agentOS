package localui

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/card/words"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Recovery key page's lost-card route (REC-4; MIG-4-recovery-r4b, route
// B of D-201), for an owner who holds no card that opens the store: a
// hardware key's tap over the change agentosd names files a request for
// the next restart, the page offers the restart (the weekly reboot's
// unit, which waits out a call or accepted work), and after it the page
// shows the card the box made, through card.Display, on a second hardware
// key's tap over the card's ID (#4128), until the owner confirms it, when
// the kernel wipes its copy. The card is already in effect when shown
// (card.DisplayConfig.Made): the store changed at boot, its passphrase and
// recovery key replacing the old card's (#4130). The page names it
// by its mark, which the card prints, so after the kernel lets it go the
// page can still say which card is in effect (#4160). Each tap's
// challenge depends only on IDs agentosd names, so this page keeps
// nothing between the steps but the card's display.

func (a AgentosdPasskeys) RecoveryLostBegin(ctx context.Context, session string) (localapi.RecoveryLostBegun, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.RecoveryLostBegun
	err := a.Owner.Call(ctx, localapi.OpRecoveryLostBegin, localapi.RecoverySession{Token: session}, &out)
	return out, err
}

func (a AgentosdPasskeys) RecoveryLost(ctx context.Context, session string, authData, clientData, sig []byte) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, localapi.OpRecoveryLost, localapi.RecoveryLost{Token: session,
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}, nil)
}

func (a AgentosdPasskeys) RecoveryLostState(ctx context.Context, session string) (localapi.RecoveryLostState, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.RecoveryLostState
	err := a.Owner.Call(ctx, localapi.OpRecoveryLostState, localapi.RecoverySession{Token: session}, &out)
	return out, err
}

func (a AgentosdPasskeys) RecoveryLostWithdraw(ctx context.Context, session string) error {
	return a.sessionCall(ctx, localapi.OpRecoveryLostWithdraw, session)
}

func (a AgentosdPasskeys) RecoveryRestart(ctx context.Context, session string) error {
	return a.sessionCall(ctx, localapi.OpRecoveryRestart, session)
}

func (a AgentosdPasskeys) RecoveryLostCardBegin(ctx context.Context, session string) (localapi.RecoveryLostCardBegun, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.RecoveryLostCardBegun
	err := a.Owner.Call(ctx, localapi.OpRecoveryLostCardBegin, localapi.RecoverySession{Token: session}, &out)
	return out, err
}

func (a AgentosdPasskeys) RecoveryLostCard(ctx context.Context, session string, authData, clientData, sig []byte) (localapi.RecoveryLostCard, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.RecoveryLostCard
	err := a.Owner.Call(ctx, localapi.OpRecoveryLostCard, localapi.RecoveryLost{Token: session,
		AuthenticatorData: authData, ClientDataJSON: clientData, Signature: sig}, &out)
	return out, err
}

func (a AgentosdPasskeys) RecoveryLostDone(ctx context.Context, session string) error {
	return a.sessionCall(ctx, localapi.OpRecoveryLostDone, session)
}

func (a AgentosdPasskeys) sessionCall(ctx context.Context, op, session string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return a.Owner.Call(ctx, op, localapi.RecoverySession{Token: session}, nil)
}

// lostState is the one display of a card the box made, for the session
// that opened it, until RecoveryPendingFor passes.
type lostState struct {
	mu      sync.Mutex
	starter string
	until   time.Time
	display *card.Display
}

// The lost-card route's fixed lines. None names a value.
const (
	lostFiledText    = "Your request for a new card is filed. When I restart I make the new card, and this page shows it. Restart me now, or I carry it out at my next restart within a week."
	lostRestartText  = "I restart as soon as no call or task is running; once a month a check of my software runs first and takes a few minutes more. Then open this page again to see your new card."
	lostWithdrawText = "Your request for a new card is withdrawn: I make no new card at my next restart."
	lostDoneText     = "Done. Your new card is confirmed and I keep no copy of it. Keep it safe: its passphrase and recovery key are the only ones that open my store, and the backups I take from now on open with its recovery key. Your old card's passphrase and recovery key no longer open my store: so if you wrote the old passphrase down anywhere else, put the new card's passphrase there in its place, and destroy the old card if you find it."
	lostNoTapText    = "Nothing was filed. Tap again with one of your hardware keys."
	lostNoShowText   = "Nothing is shown. Tap again with one of your hardware keys."
	lostPhoneText    = "That tap was a phone passkey's. Only one of your hardware keys can show your new card. Tap again, and choose your hardware key."
)

// The lines for a card the kernel no longer holds, by what the last card a
// page showed is now (#4160); each names that card by its mark.
const (
	lostGoneText       = "I restarted before you confirmed your new card, so I no longer hold it. The card in effect is marked %s: if you printed or saved the card with that mark, keep it, as its passphrase and recovery key open my store; a card with another mark does not. If you hold none with that mark, ask for a new card again."
	lostConfirmedText  = "Your new card, marked %s, is confirmed and in effect, and I keep no copy of it: its passphrase and recovery key open my store, and a card with another mark does not."
	lostSupersededText = "The new card I showed you before, marked %s, is no longer in effect: neither its passphrase nor its recovery key opens my store. If no card you hold opens my store, ask for a new card."
	lostNoCardText     = "I hold no new card to show. If no card you hold opens my store, ask for a new card."
)

// cardMark is the mark of the card whose backup recipient ID is id: its
// first 32 bits, in two groups, printed on the card (card.DisplayConfig.Mark).
func cardMark(id string) string {
	if len(id) < 8 {
		return ""
	}
	return strings.ToUpper(id[:4] + "-" + id[4:8])
}

// lostNoCard is the line for a card the kernel no longer holds, from st.
func lostNoCard(st localapi.RecoveryLostState) string {
	switch m := cardMark(st.Shown); {
	case m == "":
		return lostNoCardText
	case !st.InEffect:
		return fmt.Sprintf(lostSupersededText, m)
	case st.Confirmed:
		return fmt.Sprintf(lostConfirmedText, m)
	default:
		return fmt.Sprintf(lostGoneText, m)
	}
}

// lostText is the owner's wording for each refusal on this route.
func lostText(err error) string {
	switch {
	case refused(err, localapi.ErrRecoveryNoCard):
		return lostNoCardText
	case refused(err, localapi.ErrRecoveryStale):
		return "Something changed since you started: the request was withdrawn, or the recovery key changed. Start again."
	}
	return recoveryText(err)
}

// lostCardText is lostText on the card's page: no card reads where the
// last card shown stands, and a missing page authority says so.
func (s *Server) lostCardText(ctx context.Context, tok string, err error) string {
	switch {
	case errors.Is(err, card.ErrNoAuthority):
		return firstboot.ErrNoAuthority.Error()
	case refused(err, localapi.ErrRecoveryNotAnchor):
		return lostPhoneText
	case refused(err, localapi.ErrRecoveryNoCard):
		if st, err := s.cfg.Recovery.RecoveryLostState(ctx, tok); err == nil {
			return lostNoCard(st)
		}
	}
	return lostText(err)
}

// lostView fills the first step's lost-card state; a failed read shows
// the first step as if none were filed.
func (s *Server) lostView(tok string, v *recoveryView) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	if st, err := s.cfg.Recovery.RecoveryLostState(ctx, tok); err == nil {
		v.Lost = st
		if st.Shown != "" && !st.Ready && !st.Filed {
			v.LostNote = lostNoCard(st)
		}
	}
}

// lostStep runs a posted lost-card step: the tap, a withdraw or the
// restart. It returns the page's error or done line.
func (s *Server) lostStep(r *http.Request, tok string) (errText, done string) {
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	f := r.PostForm
	switch f.Get("step") {
	case "lost":
		ad, ok1 := formBytes(f.Get("ad"), localapi.MaxPasskeyAssertion)
		cd, ok2 := formBytes(f.Get("cd"), localapi.MaxPasskeyAssertion)
		sig, ok3 := formBytes(f.Get("sig"), localapi.MaxPasskeyAssertion)
		if !ok1 || !ok2 || !ok3 {
			return lostNoTapText, ""
		}
		if err := s.cfg.Recovery.RecoveryLost(ctx, tok, ad, cd, sig); err != nil {
			return lostText(err), ""
		}
		return "", lostFiledText
	case "withdraw":
		if err := s.cfg.Recovery.RecoveryLostWithdraw(ctx, tok); err != nil {
			return lostText(err), ""
		}
		return "", lostWithdrawText
	}
	if err := s.cfg.Recovery.RecoveryRestart(ctx, tok); err != nil {
		return lostText(err), ""
	}
	return "", lostRestartText
}

// lostTapPage serves /recovery/lost: the hardware key's tap over the
// change agentosd names.
func (s *Server) lostTapPage(w http.ResponseWriter, r *http.Request, tok string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	v := recoveryView{RP: s.cfg.PasskeyRPID}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	b, err := s.cfg.Recovery.RecoveryLostBegin(ctx, tok)
	if err != nil {
		w.Header().Set("Content-Security-Policy", vaultCSP)
		v.Err = lostText(err)
		s.render(w, "recovery", v)
		return
	}
	w.Header().Set("Content-Security-Policy", passkeyCSP)
	v.Step, v.Old, v.Challenge = "lost", b.Old, base64.StdEncoding.EncodeToString(b.Challenge)
	s.render(w, "recovery", v)
}

// lostCardPage serves /recovery/new: the card the box made, to the session
// that opened it, until it is confirmed. A session with no display of it
// is asked for a hardware key's tap over the card's ID first (#4128), and
// the tap's post opens its display; a display for another session, or
// past its time, goes.
func (s *Server) lostCardPage(w http.ResponseWriter, r *http.Request, tok string) {
	if tok == "" {
		http.Redirect(w, r, "/recovery/", http.StatusSeeOther)
		return
	}
	if d := s.lostDisplay(tok); d != nil {
		mine := func(r *http.Request) bool {
			s.lost.mu.Lock()
			defer s.lost.mu.Unlock()
			return s.lost.display == d && s.lost.starter == tokenKey(cookieToken(r))
		}
		d.Handler(mine, "/recovery/?lost=done").ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", vaultCSP)
	v := recoveryView{RP: s.cfg.PasskeyRPID}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		err := s.lostShow(ctx, tok, r.PostForm)
		if err == nil {
			http.Redirect(w, r, "/recovery/new", http.StatusSeeOther)
			return
		}
		v.Err = lostNoShowText
		if !errors.Is(err, errNoTap) {
			v.Err = s.lostCardText(ctx, tok, err)
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := s.cfg.Recovery.RecoveryLostCardBegin(ctx, tok)
	if err != nil {
		if v.Err == "" {
			v.Err = s.lostCardText(ctx, tok, err)
		}
		s.render(w, "recovery", v)
		return
	}
	w.Header().Set("Content-Security-Policy", passkeyCSP)
	v.Step, v.Mark, v.Challenge = "show", cardMark(b.ID), base64.StdEncoding.EncodeToString(b.Challenge)
	s.render(w, "recovery", v)
}

// errNoTap: the post carried no tap.
var errNoTap = errors.New("localui: no tap")

// lostDisplay is tok's display of the made card, or nil; a display for
// another session, or past its time, goes.
func (s *Server) lostDisplay(tok string) *card.Display {
	s.lost.mu.Lock()
	d, mine := s.lost.display, s.lost.starter == tokenKey(tok) && s.cfg.Now().Before(s.lost.until)
	if d != nil && !mine {
		s.lost.display = nil
	}
	s.lost.mu.Unlock()
	if d != nil && !mine {
		d.Discard()
		return nil
	}
	return d
}

// lostShow reads the card on the posted hardware key's tap and makes it
// tok's display, printing its mark.
func (s *Server) lostShow(ctx context.Context, tok string, f url.Values) error {
	ad, ok1 := formBytes(f.Get("ad"), localapi.MaxPasskeyAssertion)
	cd, ok2 := formBytes(f.Get("cd"), localapi.MaxPasskeyAssertion)
	sig, ok3 := formBytes(f.Get("sig"), localapi.MaxPasskeyAssertion)
	if f.Get("step") != "show" || !ok1 || !ok2 || !ok3 {
		return errNoTap
	}
	c, err := s.cfg.Recovery.RecoveryLostCard(ctx, tok, ad, cd, sig)
	defer clear(c.Card)
	if err != nil {
		return err
	}
	if len(c.Card) != localapi.RecoveryCardLen || len(c.ID) != localapi.RecoveryIDLen {
		return Refused(localapi.ErrRecoveryUnavailable)
	}
	text := card.RecoveryKeyText([localapi.RecoveryCardKeyLen]byte(c.Card[:localapi.RecoveryCardKeyLen]))
	// The passphrase the unlock step put in the store's passphrase slot
	// with the key (MIG-4-recovery-r4d), from the seed after the key's bits.
	pass, err := words.FromSeed(c.Card[localapi.RecoveryCardKeyLen:])
	if err != nil {
		return Refused(localapi.ErrRecoveryUnavailable)
	}
	phrase := string(pass)
	clear(pass)
	var auth []byte
	if s.cfg.PageAuthority != nil {
		auth = s.cfg.PageAuthority()
	}
	gen := s.cfg.RecoveryCard
	if gen == nil {
		gen = card.Generate
	}
	d, err := card.NewDisplay(card.DisplayConfig{Rotate: &card.Parts{Passphrase: true, Recovery: true}, Made: true, Authority: auth, Mark: cardMark(c.ID),
		// The card's other parts are drawn only to fill the card the
		// display checks whole; it keeps the passphrase and recovery key.
		Generate: func(rd io.Reader) (*card.Card, error) {
			c, err := gen(rd)
			if err == nil {
				c.VaultPassphrase, c.RecoveryKey = phrase, text
			}
			return c, err
		},
		Provision: func(*card.Card) error { return s.lostConfirmed(tok) }})
	if err != nil {
		return err
	}
	s.lost.mu.Lock()
	old := s.lost.display
	s.lost.starter, s.lost.until, s.lost.display = tokenKey(tok), s.cfg.Now().Add(RecoveryPendingFor), d
	s.lost.mu.Unlock()
	if old != nil {
		old.Discard()
	}
	return nil
}

// lostConfirmed is the display's provision: the kernel wipes its copy. A
// kernel that restarted meanwhile holds none, and the card the owner just
// confirmed is still the one that opens the store, so that is done too.
func (s *Server) lostConfirmed(tok string) error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	if err := s.cfg.Recovery.RecoveryLostDone(ctx, tok); err != nil && !refused(err, localapi.ErrRecoveryNoCard) {
		return err
	}
	s.lost.mu.Lock()
	s.lost.display = nil
	s.lost.mu.Unlock()
	return nil
}
