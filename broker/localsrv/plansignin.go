package localsrv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// PlanSignIn is agentosd's sign-in of the owner's plan after setup (ONB-3,
// ONB-9, #1264), through the same runner as setup's.
type PlanSignIn interface {
	// Ready reports whether the plan is signed out and its sign-in can
	// start: the route declares one and its gate is open.
	Ready() bool
	// Waiting reports whether a sign-in of the plan still waits for the
	// owner to approve its code, whoever started it.
	Waiting() bool
	// Start starts the sign-in and returns the provider's link and code,
	// and who issues the code. SignInBusy: the last sign-in still waits.
	Start(ctx context.Context) (link, code, from string, err error)
}

// planKept is the link and code of the sign-in the page started, kept
// while it waits for the session that last proved the owner for it
// (#1945): the page shows them again rather than a busy text.
type planKept struct {
	dc localapi.DeviceCode
	by [sha256.Size]byte // the session's token digest
}

// kept returns the started sign-in's link and code while it waits, and
// forgets them once it does not. waiting is whether any sign-in of the
// plan waits, this one or another.
func (s *Server) kept() (k planKept, ok, waiting bool) {
	waiting = s.cfg.PlanSignIn != nil && s.cfg.PlanSignIn.Ready() && s.cfg.PlanSignIn.Waiting()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !waiting {
		s.plan = planKept{}
	}
	return s.plan, s.plan.dc.Link != "", waiting
}

// keep keeps dc for the session tok, in place of what was kept.
func (s *Server) keep(dc localapi.DeviceCode, tok string) {
	s.mu.Lock()
	s.plan = planKept{dc, sha256.Sum256([]byte(tok))}
	s.mu.Unlock()
}

// planSignInReady says whether the page offers the plan's sign-in and, to
// the session it is kept for only, the waiting sign-in's link and code.
// Whoever approves that code becomes the plan's login (CRED-5), so a
// session that has not proved the owner for it never reads it.
func (s *Server) planSignInReady(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Auth
	if decode(args, &in) != nil || !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	out := localapi.PlanSignIn{Ready: s.cfg.PlanSignIn != nil && s.cfg.PlanSignIn.Ready()}
	if k, ok, _ := s.kept(); ok && k.by == sha256.Sum256([]byte(in.Token)) {
		out.DeviceCode = k.dc
	}
	return out, nil
}

// planSignIn starts the plan's sign-in. Whoever approves the code becomes
// the plan's login (CRED-5), so, as for a SIM, a session is not enough: it
// always takes a code-generator code, counted as any code is. Starts are
// bounded per minute, as setup's are: each one starts a provider worker.
//
// While the sign-in it started waits, the session it is kept for gets the
// same link and code back with no code; another session gets them after a
// good code, and they are then kept for that session (#1945). A start that
// would be refused, busy or past the bound, is refused before the code is
// checked, so no code is spent on it (#1941 Security 1). One runs at a
// time, so two pages cannot both spend a code on a start.
func (s *Server) planSignIn(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.PlanSignInStart
	err := decode(args, &in)
	ses, ok := s.live(in.Token)
	if !ok {
		return nil, errUnauthorized
	}
	if err != nil || len(in.Code) > localapi.MaxCode || strings.HasPrefix(in.Code, owner.UnlockProofPrefix) ||
		s.cfg.PlanSignIn == nil || !s.cfg.PlanSignIn.Ready() {
		return nil, errBadArgs
	}
	s.planMu.Lock()
	defer s.planMu.Unlock()
	k, ok, waiting := s.kept()
	switch {
	case ok && k.by == sha256.Sum256([]byte(in.Token)):
		// This session was shown them already: nothing is spent or started.
		return localapi.PlanSignInStarted{DeviceCode: k.dc}, nil
	case waiting && !ok:
		// A sign-in this page did not start (setup's) waits: no code
		// would start another.
		return nil, errSignInBusy
	}
	if in.Code == "" {
		return localapi.PlanSignInStarted{Refusal: localapi.RefusedCodeNeeded}, nil
	}
	at, ok := s.allowSignIn()
	if !ok {
		return nil, errLimited
	}
	started := false
	defer func() {
		if !started {
			s.unspend(at)
		}
	}()
	if !s.takeTry() {
		return nil, errLimited
	}
	_, locks, err := s.cfg.Owner.LocalSignIn(in.Code)
	s.endTry(err != nil && !errors.Is(err, owner.ErrTooMany))
	switch {
	case errors.Is(err, owner.ErrWrongCode), errors.Is(err, owner.ErrTooMany):
		r, t := s.triesLeft(err)
		return localapi.PlanSignInStarted{Refusal: r, Text: t}, nil
	case err != nil:
		return nil, errFailed
	case locks != ses.locks:
		// As for a SIM: a lock between the token check and the code kills
		// the session, and the code alone does not revive it (SR3-1).
		s.drop(in.Token)
		return nil, errUnauthorized
	}
	s.refresh(in.Token)
	if k, ok, _ := s.kept(); ok {
		// Another session started it: the code proves the owner here.
		s.keep(k.dc, in.Token)
		return localapi.PlanSignInStarted{DeviceCode: k.dc}, nil
	}
	link, code, from, err := s.cfg.PlanSignIn.Start(ctx)
	// A busy provider started no worker, so the start is not counted.
	started = !errors.Is(err, SignInBusy)
	switch {
	case errors.Is(err, SignInBusy):
		return nil, errSignInBusy
	case err != nil, !issued(link, code, from):
		return nil, errFailed
	}
	dc := localapi.DeviceCode{Link: link, Code: code, From: from}
	s.keep(dc, in.Token)
	return localapi.PlanSignInStarted{DeviceCode: dc}, nil
}

// allowSignIn counts one start at the returned time unless
// localapi.DeviceCodesPerMinute were made in the last minute.
func (s *Server) allowSignIn() (time.Time, bool) {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.signins[:0]
	for _, t := range s.signins {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	s.signins = kept
	if len(kept) >= localapi.DeviceCodesPerMinute {
		return time.Time{}, false
	}
	s.signins = append(kept, now)
	return now, true
}

// unspend takes back the start allowSignIn counted at at: it never reached
// the provider.
func (s *Server) unspend(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.signins) - 1; i >= 0; i-- {
		if s.signins[i].Equal(at) {
			s.signins = append(s.signins[:i], s.signins[i+1:]...)
			return
		}
	}
}
