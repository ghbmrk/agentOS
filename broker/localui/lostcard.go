package localui

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// The Recovery key page's lost-card route (REC-4; MIG-4-recovery-r4b, route
// B of D-201), for an owner who holds no card that opens the store: a
// hardware key's tap over the change agentosd names files a request for
// the next restart, the page offers the restart (the weekly reboot's
// unit, which waits out a call or accepted work), and after it the page
// shows the card the box made, through card.Display, until the owner
// confirms it, when the kernel wipes its copy. The card is already in
// effect when shown (card.DisplayConfig.Made): the store changed at boot.
// The tap's challenge depends only on the recipient agentosd names, so
// this page keeps nothing between the steps but the card's display.

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

func (a AgentosdPasskeys) RecoveryLostCard(ctx context.Context, session string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var out localapi.RecoveryLostCard
	err := a.Owner.Call(ctx, localapi.OpRecoveryLostCard, localapi.RecoverySession{Token: session}, &out)
	return out.Card, err
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
	lostWithdrawText = "Your request for a new card is withdrawn. Your current card stays in effect."
	lostDoneText     = "Done. Your new card is confirmed and I keep no copy of it. Keep it safe: its recovery key is the only one that opens my store, and the backups I take from now on open with it. Your old card's passphrase still opens my store."
	lostGoneText     = "I no longer hold your new card: I restarted before you confirmed it. My store already takes the new recovery key, so nobody holds a recovery key that opens it. Ask for a new card again."
	lostNoTapText    = "Nothing was filed. Tap again with one of your hardware keys."
)

// lostText is the owner's wording for each refusal on this route.
func lostText(err error) string {
	switch {
	case refused(err, localapi.ErrRecoveryNoCard):
		return lostGoneText
	case refused(err, localapi.ErrRecoveryStale):
		return "Something changed since you started: the request was withdrawn, or the recovery key changed. Start again."
	}
	return recoveryText(err)
}

// lostView fills the first step's lost-card state; a failed read shows
// the first step as if none were filed.
func (s *Server) lostView(tok string, v *recoveryView) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	if st, err := s.cfg.Recovery.RecoveryLostState(ctx, tok); err == nil {
		v.Lost = st
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
// that opened it, until it is confirmed. A display for another session, or
// past its time, goes; the kernel still holds the card, so it is read
// again for this one.
func (s *Server) lostCardPage(w http.ResponseWriter, r *http.Request, tok string) {
	if tok == "" {
		http.Redirect(w, r, "/recovery/", http.StatusSeeOther)
		return
	}
	d, err := s.lostDisplay(r.Context(), tok)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", vaultCSP)
		v := recoveryView{RP: s.cfg.PasskeyRPID, Err: lostText(err)}
		if errors.Is(err, card.ErrNoAuthority) {
			v.Err = firstboot.ErrNoAuthority.Error()
		}
		s.render(w, "recovery", v)
		return
	}
	mine := func(r *http.Request) bool {
		s.lost.mu.Lock()
		defer s.lost.mu.Unlock()
		return s.lost.display == d && s.lost.starter == tokenKey(cookieToken(r))
	}
	d.Handler(mine, "/recovery/?lost=done").ServeHTTP(w, r)
}

// lostDisplay is tok's display of the made card, made from the kernel's
// copy when there is none.
func (s *Server) lostDisplay(ctx context.Context, tok string) (*card.Display, error) {
	s.lost.mu.Lock()
	d, mine := s.lost.display, s.lost.starter == tokenKey(tok) && s.cfg.Now().Before(s.lost.until)
	if d != nil && !mine {
		s.lost.display = nil
	}
	s.lost.mu.Unlock()
	if d != nil {
		if mine {
			return d, nil
		}
		d.Discard()
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	bits, err := s.cfg.Recovery.RecoveryLostCard(ctx, tok)
	defer clear(bits)
	if err != nil {
		return nil, err
	}
	if len(bits) != localapi.RecoveryCardLen {
		return nil, Refused(localapi.ErrRecoveryUnavailable)
	}
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	var auth []byte
	if s.cfg.PageAuthority != nil {
		auth = s.cfg.PageAuthority()
	}
	gen := s.cfg.RecoveryCard
	if gen == nil {
		gen = card.Generate
	}
	d, err = card.NewDisplay(card.DisplayConfig{Rotate: &card.Parts{Recovery: true}, Made: true, Authority: auth,
		// The card's other parts are drawn only to fill the card the
		// display checks whole; it keeps the recovery key alone.
		Generate: func(rd io.Reader) (*card.Card, error) {
			c, err := gen(rd)
			if err == nil {
				c.RecoveryKey = text
			}
			return c, err
		},
		Provision: func(*card.Card) error { return s.lostConfirmed(tok) }})
	if err != nil {
		return nil, err
	}
	s.lost.mu.Lock()
	old := s.lost.display
	s.lost.starter, s.lost.until, s.lost.display = tokenKey(tok), s.cfg.Now().Add(RecoveryPendingFor), d
	s.lost.mu.Unlock()
	if old != nil {
		old.Discard()
	}
	return d, nil
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
