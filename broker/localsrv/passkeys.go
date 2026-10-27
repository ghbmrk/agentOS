package localsrv

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Passkeys is the owner side's passkey ops (cmd/agentosd, #2779a) in raw
// bytes, so localsrv links no kernel/key. session names the page's session
// by its token's digest, never the token. Every error is a sockets.Code
// from localapi.PasskeyCodes, or ErrBadArgs; any other reaches the page as
// ErrPasskeyUnavailable, so no kernel text does.
type Passkeys interface {
	List(ctx context.Context) (localapi.PasskeyList, error)
	// Begin keeps point for session and returns the challenge a hardware
	// key signs to enrol it.
	Begin(ctx context.Context, session string, point []byte) (challenge []byte, err error)
	// Finish enrols session's kept point under the hardware key whose
	// get() assertion this is.
	Finish(ctx context.Context, session string, authData, clientData, sig []byte) error
	// CutOff cuts the listed key id off under the hardware key whose
	// get() assertion over its CutChallenge this is (#3209); with none,
	// only an anchor's ErrPasskeyAnchor or an already cut key's nil.
	CutOff(ctx context.Context, id string, authData, clientData, sig []byte) error
}

// PasskeyBeginsPerMinute bounds enrolment starts on the socket, as
// EnrollsPerMinute bounds setup's: each verifies a point and keeps it.
const PasskeyBeginsPerMinute = 6

// passkeyOps are the passkey ops, served only with Config.Passkeys.
func (s *Server) passkeyOps() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpPasskeys:      s.passkeys,
		localapi.OpPasskeyBegin:  s.passkeyBegin,
		localapi.OpPasskeyFinish: s.passkeyFinish,
		localapi.OpPasskeyCutOff: s.passkeyCutOff,
	}
}

// passkeyErr is err as one of the closed set of codes.
func passkeyErr(err error) error {
	var c sockets.Code
	if errors.As(err, &c) && (slices.Contains(localapi.PasskeyCodes, string(c)) || c == errBadArgs) {
		return c
	}
	return sockets.Code(localapi.ErrPasskeyUnavailable)
}

// sessionID names tok's session to the owner side.
func sessionID(tok string) string {
	d := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(d[:])
}

func (s *Server) passkeys(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Auth
	if decode(args, &in) != nil || !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	l, err := s.cfg.Passkeys.List(ctx)
	if err != nil {
		return nil, passkeyErr(err)
	}
	return l, nil
}

func (s *Server) passkeyBegin(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.PasskeyBegin
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || len(in.Point) != localapi.PasskeyPoint {
		return nil, errBadArgs
	}
	if !s.allowPasskeyBegin() {
		return nil, errLimited
	}
	c, err := s.cfg.Passkeys.Begin(ctx, sessionID(in.Token), in.Point)
	if err != nil {
		return nil, passkeyErr(err)
	}
	if len(c) != localapi.PasskeyChallenge {
		return nil, sockets.Code(localapi.ErrPasskeyUnavailable)
	}
	return localapi.PasskeyBegun{Challenge: c}, nil
}

func (s *Server) passkeyFinish(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.PasskeyFinish
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	if err := s.cfg.Passkeys.Finish(ctx, sessionID(in.Token), in.AuthenticatorData, in.ClientDataJSON, in.Signature); err != nil {
		return nil, passkeyErr(err)
	}
	return localapi.Text{}, nil
}

func (s *Server) passkeyCutOff(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.PasskeyCutOff
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	none := len(in.AuthenticatorData) == 0 && len(in.ClientDataJSON) == 0 && len(in.Signature) == 0
	all := assertionPart(in.AuthenticatorData) && assertionPart(in.ClientDataJSON) && assertionPart(in.Signature)
	if err != nil || !passkeyID(in.ID) || !(none || all) {
		return nil, errBadArgs
	}
	if err := s.cfg.Passkeys.CutOff(ctx, in.ID, in.AuthenticatorData, in.ClientDataJSON, in.Signature); err != nil {
		return nil, passkeyErr(err)
	}
	return localapi.Text{}, nil
}

func assertionPart(b []byte) bool { return len(b) > 0 && len(b) <= localapi.MaxPasskeyAssertion }

// passkeyID is a listed key's ID: lowercase hex of PasskeyIDLen.
func passkeyID(id string) bool {
	return len(id) == localapi.PasskeyIDLen && strings.Trim(id, "0123456789abcdef") == ""
}

// allowPasskeyBegin counts one begin unless PasskeyBeginsPerMinute were
// made in the last minute.
func (s *Server) allowPasskeyBegin() bool {
	return s.allowPerMinute(&s.passkeyBegins, PasskeyBeginsPerMinute)
}

// allowPerMinute counts one try in *ts unless n were made in the last
// minute.
func (s *Server) allowPerMinute(ts *[]time.Time, n int) bool {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := (*ts)[:0]
	for _, t := range *ts {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	if len(kept) >= n {
		*ts = kept
		return false
	}
	*ts = append(kept, now)
	return true
}
