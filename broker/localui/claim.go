package localui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ghbmrk/agentos/broker/claim"
)

// BoxClaim is the box's claim (HW-10, firstboot.ClaimedCard): until the
// claim code from the box's sticker is typed here, setup does not start,
// and afterwards only the phone that claimed the box may continue it.
type BoxClaim interface {
	Status() claim.Status
	// Claim tries a code and returns the claimant token on success.
	Claim(code string) (string, error)
	// Claimant reports whether tok is the claimant's token.
	Claimant(tok string) bool
}

// claimCookie carries the claimant token. It lasts as long as a setup
// cookie: setup continues only on the phone that holds it.
const claimCookie = "agentos_claim"

type claimView struct {
	// Code prefills the form from the sticker's QR link (/claim?code=…);
	// only the POST tries it.
	Code      string
	Err       string
	TriesLeft int
	Locked    bool
	Claimed   bool
	// Reserve is the sticker holder's tries left this boot: while above
	// 0 a locked page still takes the sticker's code (claim.ReserveTries).
	Reserve int
	// Reinstall drops "setup continues on the phone that claimed me":
	// the box lost its claim state, so no phone holds its setup.
	Reinstall bool
}

// claimGate keeps setup behind the box's claim: before it every setup
// page sends the phone to /claim, after it a phone without the claimant
// cookie is told setup continues elsewhere. It reports whether it
// answered the request.
func (s *Server) claimGate(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.Claim == nil {
		return false
	}
	p := r.URL.Path
	if p != "/" && p != "/setup" && !strings.HasPrefix(p, "/setup/") {
		return false
	}
	if !s.cfg.Claim.Status().Claimed {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Claim me first: type the claim code from my sticker.", http.StatusForbidden)
			return true
		}
		http.Redirect(w, r, "/claim", http.StatusSeeOther)
		return true
	}
	if p == "/" {
		return false
	}
	if s.isClaimant(r) {
		return s.claimWiFiGate(w, r)
	}
	w.WriteHeader(http.StatusForbidden)
	s.render(w, "claimbox", claimView{Claimed: true, Reinstall: s.cfg.Claim.Status().Reinstall})
	return true
}

func (s *Server) isClaimant(r *http.Request) bool {
	c, err := readCookie(r, claimCookie)
	return err == nil && s.cfg.Claim.Claimant(c.Value)
}

// claimPage shows and takes the claim code (HW-10). A wrong code is
// counted by the box; enough of them lock this page until the box
// restarts.
func (s *Server) claimPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		typed := r.PostFormValue("code")
		release, ok := s.claimTurn(r)
		if !ok {
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
			v := s.claimView()
			v.Err = claimBusy
			s.render(w, "claimbox", v)
			return
		}
		tok, err := s.cfg.Claim.Claim(typed)
		release()
		if tok != "" {
			setCookie(w, r, &http.Cookie{Name: claimCookie, Value: tok, Path: "/", MaxAge: int(SetupCookieFor.Seconds()),
				HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		if err == nil && s.cfg.SetupWiFi != nil {
			// The claim's answer is the new setup Wi-Fi password and its
			// QR (HW-10, #1692).
			http.Redirect(w, r, "/claim/wifi", http.StatusSeeOther)
			return
		}
		if err == nil {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		if tok != "" {
			// Claimed, but the card step did not start: setup shows it.
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		v := s.claimView()
		code := http.StatusUnprocessableEntity
		switch {
		case errors.Is(err, claim.ErrAlreadyClaimed):
			code = http.StatusConflict
		case errors.Is(err, claim.ErrLocked):
			code = http.StatusLocked
		case errors.Is(err, claim.ErrWrongCode):
			v.Err = "That code did not match my sticker. Check it and type it again."
		default:
			code = http.StatusInternalServerError
			v.Err = "I could not check that code. Try again."
		}
		w.WriteHeader(code)
		s.render(w, "claimbox", v)
		return
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Claim.Status().Claimed && s.isClaimant(r) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	v := s.claimView()
	if c := r.URL.Query().Get("code"); len(c) <= 32 {
		v.Code = c
	}
	s.render(w, "claimbox", v)
}

// claimQueue is how many claim posts may wait while one runs: each try
// is an Argon2id derivation (claim K9), so a flood of posts beyond it is
// answered busy at once rather than queued behind the owner's.
const claimQueue = 4

const claimBusy = "I am busy checking codes. Try again in a moment."

// claimTurn waits for this post's turn to run Claim. It refuses at once
// when claimQueue posts already wait, and refuses a post whose request
// ended before its turn came, so Claim never runs for a phone that left.
func (s *Server) claimTurn(r *http.Request) (release func(), ok bool) {
	select {
	case s.claimWait <- struct{}{}:
	default:
		return nil, false
	}
	select {
	case s.claimRun <- struct{}{}:
	case <-r.Context().Done():
		<-s.claimWait
		return nil, false
	}
	if r.Context().Err() != nil {
		<-s.claimRun
		<-s.claimWait
		return nil, false
	}
	return func() { <-s.claimRun; <-s.claimWait }, true
}

func (s *Server) claimView() claimView {
	st := s.cfg.Claim.Status()
	return claimView{TriesLeft: st.TriesLeft, Locked: st.Locked, Claimed: st.Claimed, Reserve: st.Reserve, Reinstall: st.Reinstall}
}
