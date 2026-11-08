package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Erase is the owner side's erase ops (cmd/agentosd, KRN-forget c,
// #3414, D-284), so localsrv links no kernel. session names the page's
// session by its token's digest, never the token: the challenge is bound
// to it. Every error is a sockets.Code from localapi.EraseCodes, or
// ErrBadArgs; any other reaches the page as ErrEraseUnavailable, so no
// kernel text does.
type Erase interface {
	// Find looks name up and answers the readback, with a handle and the
	// challenge a passkey signs over exactly what was found.
	Find(ctx context.Context, session, name string) (localapi.EraseFound, error)
	// Confirm erases what handle's find showed on a passkey's get()
	// assertion over its challenge, and answers the result's text.
	Confirm(ctx context.Context, session, handle string, authData, clientData, sig []byte) (string, error)
}

// EraseFindsPerMinute bounds finds on the socket: each asks the kernel to
// look a name up across every sealed label.
const EraseFindsPerMinute = 10

func (s *Server) eraseOps() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpEraseFind:    s.eraseFind,
		localapi.OpEraseConfirm: s.eraseConfirm,
	}
}

// eraseErr is err as one of the closed set of codes.
func eraseErr(err error) error {
	var c sockets.Code
	if errors.As(err, &c) && (slices.Contains(localapi.EraseCodes, string(c)) || c == errBadArgs) {
		return c
	}
	return sockets.Code(localapi.ErrEraseUnavailable)
}

// eraseName is a name the kernel can look up: some text in its bound,
// with no control characters.
func eraseName(n string) bool {
	return strings.TrimSpace(n) != "" && len(n) <= localapi.MaxEraseName && utf8.ValidString(n) &&
		strings.IndexFunc(n, unicode.IsControl) < 0
}

// eraseHandle is a find's handle: lowercase hex of EraseHandle.
func eraseHandle(h string) bool {
	return len(h) == localapi.EraseHandle && strings.Trim(h, "0123456789abcdef") == ""
}

func (s *Server) eraseFind(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.EraseFind
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !eraseName(in.Name) {
		return nil, errBadArgs
	}
	if !s.allowPerMinute(&s.eraseFinds, EraseFindsPerMinute) {
		return nil, errLimited
	}
	f, err := s.cfg.Erase.Find(ctx, sessionID(in.Token), in.Name)
	if err != nil {
		return nil, eraseErr(err)
	}
	if f.Handle != "" && (!eraseHandle(f.Handle) || len(f.Challenge) != localapi.PasskeyChallenge) {
		return nil, sockets.Code(localapi.ErrEraseUnavailable)
	}
	return f, nil
}

func (s *Server) eraseConfirm(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.EraseConfirm
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !eraseHandle(in.Handle) ||
		!assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	text, err := s.cfg.Erase.Confirm(ctx, sessionID(in.Token), in.Handle, in.AuthenticatorData, in.ClientDataJSON, in.Signature)
	if err != nil {
		return nil, eraseErr(err)
	}
	return localapi.Text{Text: text}, nil
}
