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
// r4a and r4b), so localsrv links no kernel. Every error is a
// sockets.Code from localapi.RecoveryCodes, ErrBadArgs or ErrLimited; any
// other reaches the page as ErrRecoveryUnavailable, so no kernel or keeper
// text does.
type Recovery interface {
	// Begin returns the challenge a hardware key signs to make next the
	// recovery key.
	Begin(ctx context.Context, next []byte) (localapi.RecoveryBegun, error)
	// Rotate makes next the recovery key, opening the store with the
	// factor, under the hardware key whose get() assertion over Begin's
	// challenge this is.
	Rotate(ctx context.Context, factor string, secret, next, authData, clientData, sig []byte) (localapi.RecoveryDone, error)
	// LostBegin returns the challenge a hardware key signs to ask for a
	// new card at the next restart (r4b).
	LostBegin(ctx context.Context) (localapi.RecoveryLostBegun, error)
	// Lost files the kernel's approval for the next restart, under the
	// hardware key whose get() assertion over LostBegin's challenge this
	// is.
	Lost(ctx context.Context, authData, clientData, sig []byte) error
	// LostState is where a lost-card request stands.
	LostState(ctx context.Context) (localapi.RecoveryLostState, error)
	// LostWithdraw removes a filed request.
	LostWithdraw(ctx context.Context) error
	// Restart restarts the box.
	Restart(ctx context.Context) error
	// LostCardBegin returns the challenge a hardware key signs to see the
	// new card the kernel holds, and the card's ID (#4128).
	LostCardBegin(ctx context.Context) (localapi.RecoveryLostCardBegun, error)
	// LostCard is the new card's bits the kernel holds, under the hardware
	// key whose get() assertion over LostCardBegin's challenge this is.
	LostCard(ctx context.Context, authData, clientData, sig []byte) (localapi.RecoveryLostCard, error)
	// LostDone has the kernel wipe them.
	LostDone(ctx context.Context) error
}

// RecoveryRotatesPerMinute bounds rotations on the socket: each opens the
// store with the factor it carries, so the bound also slows a page that
// guesses factors (the keeper's key stretch slows it more).
const RecoveryRotatesPerMinute = 3

func (s *Server) recoveryOps() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpRecoveryBegin:  s.recoveryBegin,
		localapi.OpRecoveryRotate: s.recoveryRotate,
		localapi.OpRecoveryLostBegin: func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			return s.recoverySession(args, func() (any, error) {
				b, err := s.cfg.Recovery.LostBegin(ctx)
				if err == nil && (len(b.Challenge) != localapi.PasskeyChallenge || b.Old != "" && len(b.Old) != localapi.RecoveryIDLen) {
					err = sockets.Code(localapi.ErrRecoveryUnavailable)
				}
				return b, err
			})
		},
		localapi.OpRecoveryLost: s.recoveryLost,
		localapi.OpRecoveryLostState: func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			return s.recoverySession(args, func() (any, error) { return s.cfg.Recovery.LostState(ctx) })
		},
		localapi.OpRecoveryLostWithdraw: func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			return s.recoverySession(args, func() (any, error) { return nil, s.cfg.Recovery.LostWithdraw(ctx) })
		},
		localapi.OpRecoveryRestart: func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			return s.recoverySession(args, func() (any, error) {
				if !s.allowPerMinute(&s.recoveryRotates, RecoveryRotatesPerMinute) {
					return nil, errLimited
				}
				return nil, s.cfg.Recovery.Restart(ctx)
			})
		},
		localapi.OpRecoveryLostCardBegin: func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			return s.recoverySession(args, func() (any, error) {
				b, err := s.cfg.Recovery.LostCardBegin(ctx)
				if err == nil && (len(b.Challenge) != localapi.PasskeyChallenge || len(b.ID) != localapi.RecoveryIDLen) {
					err = sockets.Code(localapi.ErrRecoveryUnavailable)
				}
				return b, err
			})
		},
		localapi.OpRecoveryLostCard: s.recoveryLostCard,
		localapi.OpRecoveryLostDone: func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
			return s.recoverySession(args, func() (any, error) { return nil, s.cfg.Recovery.LostDone(ctx) })
		},
	}
}

// recoveryErr is err as one of the closed set of codes.
func recoveryErr(err error) error {
	var c sockets.Code
	if errors.As(err, &c) && (slices.Contains(localapi.RecoveryCodes, string(c)) || c == errBadArgs || c == errLimited) {
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

// recoverySession runs op for a frame that carries a valid session alone,
// answering its error as one of the closed set of codes.
func (s *Server) recoverySession(args json.RawMessage, op func() (any, error)) (any, error) {
	var in localapi.RecoverySession
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil {
		return nil, errBadArgs
	}
	v, err := op()
	if err != nil {
		return nil, recoveryErr(err)
	}
	return v, nil
}

func (s *Server) recoveryLost(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.RecoveryLost
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	if !s.allowPerMinute(&s.recoveryRotates, RecoveryRotatesPerMinute) {
		return nil, errLimited
	}
	if err := s.cfg.Recovery.Lost(ctx, in.AuthenticatorData, in.ClientDataJSON, in.Signature); err != nil {
		return nil, recoveryErr(err)
	}
	return nil, nil
}

func (s *Server) recoveryLostCard(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.RecoveryLost
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	if !s.allowPerMinute(&s.recoveryRotates, RecoveryRotatesPerMinute) {
		return nil, errLimited
	}
	c, err := s.cfg.Recovery.LostCard(ctx, in.AuthenticatorData, in.ClientDataJSON, in.Signature)
	if err == nil && (len(c.Card) != localapi.RecoveryCardLen || len(c.ID) != localapi.RecoveryIDLen) {
		err = sockets.Code(localapi.ErrRecoveryUnavailable)
	}
	if err != nil {
		clear(c.Card)
		return nil, recoveryErr(err)
	}
	return wipedCard(c), nil
}

// wipedCard encodes as a localapi.RecoveryLostCard and clears the card's
// bits once encoded, so agentosd keeps no copy after the frame (#4128).
type wipedCard localapi.RecoveryLostCard

func (c wipedCard) MarshalJSON() ([]byte, error) {
	defer clear(c.Card)
	return json.Marshal(localapi.RecoveryLostCard(c))
}
