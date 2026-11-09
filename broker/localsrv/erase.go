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
	// assertion over its challenge, and answers the result.
	Confirm(ctx context.Context, session, handle string, authData, clientData, sig []byte) (localapi.EraseDone, error)
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

// eraseName is a name the kernel can look up: in its bound, with no
// space at either end, starting with no mark, and only letters, combining
// marks (Devanagari, Tamil, Thai names, a decomposed accent), digits,
// spaces and plain punctuation (an address's '@' and a typographic
// apostrophe among it). Default-ignorable marks, variation selectors and
// fillers are refused, so no invisible character can pass, so what the
// page shows is what is looked up (the hostile-text corpus, #3901). The
// page sends it in NFC (localui); agentosd links no x/text (ARC-2), and a
// name in another form only fails to match.
func eraseName(n string) bool {
	if n == "" || len(n) > localapi.MaxEraseName || !utf8.ValidString(n) || strings.TrimSpace(n) != n {
		return false
	}
	if first, _ := utf8.DecodeRuneInString(n); unicode.IsMark(first) {
		return false
	}
	for _, r := range n {
		if unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Variation_Selector, r) || r == khitanFiller ||
			!(unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsDigit(r) || r == ' ' || strings.ContainsRune("-_.,()'’/+&@", r)) {
			return false
		}
	}
	return true
}

// khitanFiller (U+16FE4) is a mark that shows nothing, outside the
// default-ignorable set.
const khitanFiller = '\U00016FE4'

// eraseLive is tok's session if it may reach the erase ops: signed in
// since the last STOP, and not stopped now. STOP ends every older
// session's erase ops, so the owner's STOP after a page erase they did not
// make stops a hacked page's next one (KRN-forget-c-fu).
func (s *Server) eraseLive(tok string) error {
	gen := s.cfg.Owner.StopGen()
	ses, st, ok := s.liveStatus(tok)
	switch {
	case !ok:
		return errUnauthorized
	case st.Stopped || ses.stops != gen:
		return sockets.Code(localapi.ErrEraseStopped)
	}
	return nil
}

// eraseHandle is a find's handle: lowercase hex of EraseHandle.
func eraseHandle(h string) bool {
	return len(h) == localapi.EraseHandle && strings.Trim(h, "0123456789abcdef") == ""
}

func (s *Server) eraseFind(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.EraseFind
	err := decode(args, &in)
	if live := s.eraseLive(in.Token); live != nil {
		return nil, live
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
	if live := s.eraseLive(in.Token); live != nil {
		return nil, live
	}
	if err != nil || !eraseHandle(in.Handle) ||
		!assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	done, err := s.cfg.Erase.Confirm(ctx, sessionID(in.Token), in.Handle, in.AuthenticatorData, in.ClientDataJSON, in.Signature)
	if err != nil {
		return nil, eraseErr(err)
	}
	return done, nil
}
