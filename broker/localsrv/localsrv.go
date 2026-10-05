// Package localsrv serves localui.sock in agentosd (P2-2w step a): the
// local UI's ops on the owner channel (localapi). The local UI decodes
// untrusted input, so it is treated as compromised (Security L1 on the
// P2-2w plan): agentosd mints the session token on a good sign-in, checks
// it on every op that acts or reads the owner's requests, ends it at its
// time, on sign-out and on a session lock, and counts wrong codes for the
// socket itself (L2). Errors are fixed codes (L3).
package localsrv

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Owner is the owner channel as the socket serves it (*owner.Channel).
type Owner interface {
	LocalStatus() owner.LocalStatus
	LocalGridCell() string
	LocalSignIn(code string) (time.Time, error)
	LocalStop(ctx context.Context) error
	LocalResume() (string, error)
	LocalRequests() []owner.LocalRequest
	LocalAnswer(id, sum string, approve bool, code string) (string, error)
	LocalWaiting() string
	// LocalStatusLines is STATUS's text, as the owner's phone gets it.
	LocalStatusLines() string
	// UnlockPeriod is CH-14's N: how long a sign-in lasts.
	UnlockPeriod() time.Duration
}

// Config configures a Server.
type Config struct {
	Owner Owner
	// LineNote is the owner line's note (modemlink.Link.OwnerLineNote);
	// nil when there is no modem bridge.
	LineNote func() string
	Now      func() time.Time
	Rand     io.Reader
}

// WrongPerMinute bounds wrong codes on the socket in any minute, tries in
// flight included: the page's own per-phone bound (localui
// PageWrongPerMinute), so a compromised page gains nothing by spraying.
const WrongPerMinute = 5

// MaxSessions bounds the signed-in sessions; a new one evicts the oldest.
const MaxSessions = 16

type session struct {
	until time.Time
	at    time.Time // the last sign-in: minting, or a code since
	locks uint64
	n     uint64
}

// Server serves localui.sock's ops.
type Server struct {
	cfg Config

	mu       sync.Mutex
	sessions map[[sha256.Size]byte]session // by the token's digest
	minted   uint64
	wrong    []time.Time
	inFlight int
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	return &Server{cfg: cfg, sessions: map[[sha256.Size]byte]session{}}
}

// Ops are localui.sock's ops, one for each of localapi.Ops.
func (s *Server) Ops() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpStatus:   s.status,
		localapi.OpStop:     s.stop,
		localapi.OpGridCell: s.gridCell,
		localapi.OpSignIn:   s.signIn,
		localapi.OpSignOut:  s.signOut,
		localapi.OpSession:  s.session,
		localapi.OpLines:    s.authed(s.lines),
		localapi.OpResume:   s.resume,
		localapi.OpRequests: s.authed(s.requests),
		localapi.OpWaiting:  s.authed(s.waiting),
		localapi.OpAnswer:   s.answer,
	}
}

var (
	errUnauthorized = sockets.Code(localapi.ErrUnauthorized)
	errBadArgs      = sockets.Code(localapi.ErrBadArgs)
	errLimited      = sockets.Code(localapi.ErrLimited)
	errFailed       = sockets.Code(localapi.ErrFailed)
)

// decode reads args strictly: unknown fields and trailing data refused.
func decode(args json.RawMessage, v any) error {
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	d := json.NewDecoder(bytes.NewReader(args))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.More() {
		return errBadArgs
	}
	return nil
}

func (s *Server) status(context.Context, sockets.Peer, json.RawMessage) (any, error) {
	st := s.cfg.Owner.LocalStatus()
	out := localapi.Status{Stopped: st.Stopped, Unlocked: st.Unlocked, UnlockedUntil: st.UnlockedUntil,
		LowLocked: st.LowLocked, Challenged: st.Challenged, UnlockDays: int(s.cfg.Owner.UnlockPeriod() / (24 * time.Hour))}
	if s.cfg.LineNote != nil {
		out.LineNote = s.cfg.LineNote()
	}
	return out, nil
}

func (s *Server) stop(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
	if s.cfg.Owner.LocalStop(ctx) != nil {
		return nil, errFailed
	}
	return localapi.Text{Text: "Stopped."}, nil
}

func (s *Server) gridCell(context.Context, sockets.Peer, json.RawMessage) (any, error) {
	return localapi.Text{Text: s.cfg.Owner.LocalGridCell()}, nil
}

func (s *Server) signIn(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.SignIn
	if err := decode(args, &in); err != nil || in.Code == "" || len(in.Code) > localapi.MaxCode {
		return nil, errBadArgs
	}
	if !s.takeTry() {
		return nil, errLimited
	}
	until, err := s.cfg.Owner.LocalSignIn(in.Code)
	// Every refused sign-in counts, a refused unlock proof included, which
	// the channel leaves to the vault process (Security S1 on step a);
	// only the day's spent bound does not, since nothing was tried.
	s.endTry(err != nil && !errors.Is(err, owner.ErrTooMany))
	switch {
	case errors.Is(err, owner.ErrWrongCode):
		return nil, sockets.Code(localapi.RefusedWrongCode)
	case errors.Is(err, owner.ErrTooMany):
		return nil, sockets.Code(localapi.RefusedTooMany)
	case err != nil:
		return nil, errFailed
	}
	tok := s.mint(until, s.cfg.Owner.LocalStatus().Locks)
	if tok == "" {
		return nil, errFailed
	}
	return localapi.Session{Token: tok, Until: until}, nil
}

func (s *Server) signOut(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Auth
	if decode(args, &in) != nil {
		return nil, errUnauthorized
	}
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	s.mu.Lock()
	delete(s.sessions, sha256.Sum256([]byte(in.Token)))
	s.mu.Unlock()
	return localapi.Text{}, nil
}

// session reports a live token's session; a dead one is unauthorized.
func (s *Server) session(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Auth
	if decode(args, &in) != nil || !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return localapi.Session{Token: in.Token, Until: s.sessions[sha256.Sum256([]byte(in.Token))].until}, nil
}

// authed wraps an op that takes only a token.
func (s *Server) authed(op func(context.Context) (any, error)) sockets.Handler {
	return func(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
		var in localapi.Auth
		if decode(args, &in) != nil || !s.valid(in.Token) {
			return nil, errUnauthorized
		}
		return op(ctx)
	}
}

func (s *Server) lines(context.Context) (any, error) {
	return localapi.Lines{Status: s.cfg.Owner.LocalStatusLines()}, nil
}

func (s *Server) resume(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Resume
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || len(in.Code) > localapi.MaxCode {
		return nil, errBadArgs
	}
	if !s.fresh(in.Token) {
		if in.Code == "" {
			return localapi.Answered{Refusal: localapi.RefusedCodeNeeded}, nil
		}
		if !s.takeTry() {
			return nil, errLimited
		}
		_, err := s.cfg.Owner.LocalSignIn(in.Code)
		s.endTry(err != nil && !errors.Is(err, owner.ErrTooMany))
		switch {
		case errors.Is(err, owner.ErrWrongCode):
			return localapi.Answered{Refusal: localapi.RefusedWrongCode}, nil
		case errors.Is(err, owner.ErrTooMany):
			return localapi.Answered{Refusal: localapi.RefusedTooMany}, nil
		case err != nil:
			return nil, errFailed
		}
		s.refresh(in.Token)
	}
	t, err := s.cfg.Owner.LocalResume()
	if err != nil {
		return nil, errFailed
	}
	return localapi.Answered{Text: t}, nil
}

func (s *Server) requests(context.Context) (any, error) {
	return localapi.Requests{Requests: s.cfg.Owner.LocalRequests()}, nil
}

func (s *Server) waiting(context.Context) (any, error) {
	return localapi.Text{Text: s.cfg.Owner.LocalWaiting()}, nil
}

func (s *Server) answer(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Answer
	err := decode(args, &in)
	// The token first, so no field check answers an unsigned-in client.
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	switch {
	case err != nil, in.ID == "", len(in.ID) > localapi.MaxID, in.Sum == "", len(in.Sum) > localapi.MaxSum,
		len(in.Code) > localapi.MaxCode, in.Approve && in.Code == "":
		return nil, errBadArgs
	}
	if in.Approve {
		if !s.takeTry() {
			return nil, errLimited
		}
	}
	msg, err := s.cfg.Owner.LocalAnswer(in.ID, in.Sum, in.Approve, in.Code)
	if in.Approve {
		s.endTry(errors.Is(err, owner.ErrWrongCode) || errors.Is(err, owner.ErrTextedCode))
	}
	switch {
	case err == nil:
		return localapi.Answered{Text: msg}, nil
	case errors.Is(err, owner.ErrWrongCode):
		return localapi.Answered{Text: msg, Refusal: localapi.RefusedWrongCode}, nil
	case errors.Is(err, owner.ErrTooMany):
		return localapi.Answered{Refusal: localapi.RefusedTooMany}, nil
	case errors.Is(err, owner.ErrNoRequest):
		return localapi.Answered{Refusal: localapi.RefusedNoRequest}, nil
	case errors.Is(err, owner.ErrChanged):
		return localapi.Answered{Refusal: localapi.RefusedChanged}, nil
	case errors.Is(err, owner.ErrTextedCode):
		return localapi.Answered{Text: owner.ErrTextedCode.Error(), Refusal: localapi.RefusedTextedCode}, nil
	case msg != "":
		// Nothing settled; msg is the channel's own reply (expired,
		// already answered), as the owner's phone would get it.
		return localapi.Answered{Text: msg, Refusal: localapi.RefusedNotSettled}, nil
	}
	return nil, errFailed
}

// mint records a session until until, signed in under locks, and returns
// its token ("" if no randomness).
func (s *Server) mint(until time.Time, locks uint64) string {
	var b [localapi.TokenBytes]byte
	if _, err := io.ReadFull(s.cfg.Rand, b[:]); err != nil {
		return ""
	}
	tok := hex.EncodeToString(b[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.minted++
	s.sessions[sha256.Sum256([]byte(tok))] = session{until: until, at: s.cfg.Now(), locks: locks, n: s.minted}
	for len(s.sessions) > MaxSessions {
		var oldest [sha256.Size]byte
		var n uint64
		for k, v := range s.sessions {
			if n == 0 || v.n < n {
				oldest, n = k, v.n
			}
		}
		delete(s.sessions, oldest)
	}
	return tok
}

// valid says tok names a live session: minted here, before its time, and
// with no session lock since. A dead one is dropped.
func (s *Server) valid(tok string) bool {
	if len(tok) != 2*localapi.TokenBytes {
		return false
	}
	locks := s.cfg.Owner.LocalStatus().Locks
	k := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	ses, ok := s.sessions[k]
	if !ok {
		return false
	}
	if !s.cfg.Now().Before(ses.until) || locks != ses.locks {
		delete(s.sessions, k)
		return false
	}
	return true
}

// fresh says tok's session signed in within FreshFor.
func (s *Server) fresh(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ses, ok := s.sessions[sha256.Sum256([]byte(tok))]
	return ok && s.cfg.Now().Sub(ses.at) < localapi.FreshFor
}

// refresh marks tok's session as just signed in.
func (s *Server) refresh(tok string) {
	k := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	if ses, ok := s.sessions[k]; ok {
		ses.at = s.cfg.Now()
		s.sessions[k] = ses
	}
}

// takeTry holds a slot for a code try, refused when the minute's wrong
// codes and the tries in flight reach WrongPerMinute.
func (s *Server) takeTry() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.cfg.Now().Add(-time.Minute)
	i := 0
	for i < len(s.wrong) && !s.wrong[i].After(cut) {
		i++
	}
	s.wrong = s.wrong[i:]
	if len(s.wrong)+s.inFlight >= WrongPerMinute {
		return false
	}
	s.inFlight++
	return true
}

// endTry gives the slot back, keeping it a minute when the code was wrong.
func (s *Server) endTry(wrong bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight--
	if wrong {
		s.wrong = append(s.wrong, s.cfg.Now())
	}
}
