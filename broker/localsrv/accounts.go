package localsrv

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// AccountSignIn is one account clerk's installed-app sign-in as agentosd
// reaches it across the keeper boundary (#3006, D-154 rule 1): one typed
// frame each way. The verifier, the code's answer, the tokens and the
// client secret once given stay in the clerk; agentosd relays only the
// consent address, the pasted address and the clerk's typed details.
type AccountSignIn interface {
	// Begin starts a sign-in for one declared use and returns the consent
	// address, or a detail. reg nil signs in again with the sealed client.
	Begin(ctx context.Context, use string, reg *localapi.AccountRegistration) (consent, detail string, err error)
	// Finish hands the clerk the pasted address and the use the owner
	// confirmed, and returns its detail.
	Finish(ctx context.Context, use, pasted string) (detail string, err error)
}

// accountBegin needs a session; the page's form is bounded again here,
// since the page is treated as compromised (Security L1).
func (s *Server) accountBegin(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.AccountBegin
	err := decode(args, &in)
	if _, ok := s.live(in.Token); !ok {
		return nil, errUnauthorized
	}
	a := s.cfg.Accounts[in.Account]
	if err != nil || a == nil || !plainID(in.Use) {
		return nil, errBadArgs
	}
	if r := in.Registration; r != nil && (!clientField(r.ID) || !clientField(r.Secret)) {
		return nil, errBadArgs
	}
	consent, detail, err := a.Begin(ctx, in.Use, in.Registration)
	if err != nil {
		return nil, errFailed
	}
	return localapi.AccountBegun{Consent: consent, Detail: detail}, nil
}

func (s *Server) accountFinish(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.AccountFinish
	err := decode(args, &in)
	if _, ok := s.live(in.Token); !ok {
		return nil, errUnauthorized
	}
	a := s.cfg.Accounts[in.Account]
	if err != nil || a == nil || !plainID(in.Use) || in.Pasted == "" || len(in.Pasted) > localapi.MaxPasted {
		return nil, errBadArgs
	}
	detail, err := a.Finish(ctx, in.Use, in.Pasted)
	if err != nil {
		return nil, errFailed
	}
	return localapi.AccountFinished{Detail: detail}, nil
}

// plainID is a declared account's or use's ID: lowercase letters, digits
// and dashes, within MaxID.
func plainID(v string) bool {
	return v != "" && len(v) <= localapi.MaxID && strings.Trim(v, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func clientField(v string) bool { return v != "" && len(v) <= localapi.MaxClientField }
