package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Recovery is the owner side's recovery-key ops (cmd/agentosd, REC-4
// r4a), so localsrv links no kernel. Every error is a sockets.Code from
// localapi.RecoveryCodes, or ErrBadArgs; any other reaches the page as
// ErrRecoveryUnavailable, so no kernel or keeper text does.
type Recovery interface {
	// Begin returns the challenge a hardware key signs to make next the
	// recovery key.
	Begin(ctx context.Context, next []byte) (localapi.RecoveryBegun, error)
	// Rotate makes next the recovery key, opening the store with the
	// factor, under the hardware key whose get() assertion over Begin's
	// challenge this is.
	Rotate(ctx context.Context, factor string, secret, next, authData, clientData, sig []byte) (localapi.RecoveryDone, error)
}

// RecoveryRotatesPerMinute bounds rotations on the socket: each opens the
// store with the factor it carries, so the bound also slows a page that
// guesses factors (the keeper's key stretch slows it more).
const RecoveryRotatesPerMinute = 3

func (s *Server) recoveryOps() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpRecoveryBegin:  s.recoveryBegin,
		localapi.OpRecoveryRotate: s.recoveryRotate,
	}
}

// recoveryErr is err as one of the closed set of codes.
func recoveryErr(err error) error {
	var c sockets.Code
	if errors.As(err, &c) && (slices.Contains(localapi.RecoveryCodes, string(c)) || c == errBadArgs) {
		return c
	}
	return sockets.Code(localapi.ErrRecoveryUnavailable)
}

// recoveryFactor reports whether factor and secret are in the frame's
// bounds; the keeper checks that they open the store.
func recoveryFactor(factor string, secret []byte) bool {
	switch factor {
	case localapi.RecoveryFactorPassphrase:
		return len(secret) > 0 && len(secret) <= localapi.MaxRecoveryPassphrase
	case localapi.RecoveryFactorRecovery:
		return len(secret) == localapi.RecoveryKeyLen
	}
	return false
}

func (s *Server) recoveryBegin(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.RecoveryBegin
	err := decode(args, &in)
	defer clear(in.Next)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || len(in.Next) != localapi.RecoveryKeyLen {
		return nil, errBadArgs
	}
	b, err := s.cfg.Recovery.Begin(ctx, in.Next)
	if err != nil {
		return nil, recoveryErr(err)
	}
	if len(b.Challenge) != localapi.PasskeyChallenge || len(b.Next) != localapi.RecoveryIDLen ||
		b.Old != "" && len(b.Old) != localapi.RecoveryIDLen {
		return nil, sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	return b, nil
}

func (s *Server) recoveryRotate(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.RecoveryRotate
	err := decode(args, &in)
	defer func() { clear(in.Secret); clear(in.Next) }()
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !recoveryFactor(in.Factor, in.Secret) || len(in.Next) != localapi.RecoveryKeyLen ||
		!assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	if !s.allowPerMinute(&s.recoveryRotates, RecoveryRotatesPerMinute) {
		return nil, errLimited
	}
	d, err := s.cfg.Recovery.Rotate(ctx, in.Factor, in.Secret, in.Next, in.AuthenticatorData, in.ClientDataJSON, in.Signature)
	if err != nil {
		return nil, recoveryErr(err)
	}
	return d, nil
}
