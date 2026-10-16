package localsrv

import (
	"context"
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
	// Start starts the sign-in and returns the provider's link and code,
	// and who issues the code. SignInBusy: the last sign-in still waits.
	Start(ctx context.Context) (link, code, from string, err error)
}

func (s *Server) planSignInReady(context.Context) (any, error) {
	return localapi.PlanSignIn{Ready: s.cfg.PlanSignIn != nil && s.cfg.PlanSignIn.Ready()}, nil
}

// planSignIn starts the plan's sign-in. Whoever approves the code becomes
// the plan's login (CRED-5), so, as for a SIM, a session is not enough: it
// always takes a code-generator code, counted as any code is. Starts are
// bounded per minute, as setup's are: each one starts a provider worker.
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
	if in.Code == "" {
		return localapi.PlanSignInStarted{Refusal: localapi.RefusedCodeNeeded}, nil
	}
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
	if !s.allowSignIn() {
		return nil, errLimited
	}
	link, code, from, err := s.cfg.PlanSignIn.Start(ctx)
	switch {
	case errors.Is(err, SignInBusy):
		return nil, errSignInBusy
	case err != nil, !issued(link, code, from):
		return nil, errFailed
	}
	return localapi.PlanSignInStarted{DeviceCode: localapi.DeviceCode{Link: link, Code: code, From: from}}, nil
}

// allowSignIn counts one start unless localapi.DeviceCodesPerMinute were
// made in the last minute.
func (s *Server) allowSignIn() bool {
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
		return false
	}
	s.signins = append(kept, now)
	return true
}
