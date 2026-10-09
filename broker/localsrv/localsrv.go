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
	"fmt"
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
	// Line is the owner line's note, last outage and counts (the modem
	// link's); nil when there is no modem bridge. Status carries only its
	// note (Security D1).
	Line func() localapi.Line
	Now  func() time.Time
	Rand io.Reader
	// DescribeRoot verifies a root to follow and holds it, with the root
	// files brought with it, for approval (follow.Executor.Describe); on an error, only the summary's Reason
	// is kept, and only if it is a coarse cause the page words. Follow
	// submits the owner's request to follow a held root
	// (grants.FollowIntent) and returns the channel's reply. Either nil
	// refuses its op.
	DescribeRoot func(ctx context.Context, root []byte, chain [][]byte) (localapi.RootSummary, error)
	Follow       func(ctx context.Context, name, digest string) (string, error)
	// Paused lists the paused grants (grants.Gate.Paused); AskResume asks
	// the owner, on the page, to resume one from the pause the page
	// showed (grants.Gate.AskResume) and returns the reply to show
	// (W5a-resume). Either nil refuses its op.
	Paused    func() []localapi.PausedGrant
	AskResume func(ctx context.Context, grant, pause string) (string, error)
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
		localapi.OpLine:     s.authed(s.line),
		localapi.OpResume:   s.resume,
		localapi.OpRequests: s.authed(s.requests),
		localapi.OpWaiting:  s.authed(s.waiting),
		localapi.OpAnswer:   s.answer,
		// Changing where updates come from needs a session (WF3).
		localapi.OpFollowRoot: s.followRoot,
		localapi.OpFollow:     s.follow,
		// Resuming a paused grant needs a session, then a code (W5a-resume).
		localapi.OpPaused:    s.authed(s.paused),
		localapi.OpAskResume: s.askResume,
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
	if s.cfg.Line != nil {
		out.LineNote = s.cfg.Line().Note
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
	case errors.Is(err, owner.ErrWrongCode), errors.Is(err, owner.ErrTooMany):
		// Fixed refusal only: page_sign_in is untokened, so what is left
		// of the day's tries is told only on a signed-in RESUME (D1).
		r, _ := s.triesLeft(err)
		return localapi.Session{Refusal: r}, nil
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
	if decode(args, &in) != nil {
		return nil, errUnauthorized
	}
	ses, ok := s.live(in.Token)
	if !ok {
		return nil, errUnauthorized
	}
	return localapi.Session{Token: in.Token, Until: ses.until}, nil
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

// line is the owner line's counts, for a signed-in page only (Security D1).
func (s *Server) line(context.Context) (any, error) {
	if s.cfg.Line == nil {
		return localapi.Line{}, nil
	}
	return s.cfg.Line(), nil
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
		case errors.Is(err, owner.ErrWrongCode), errors.Is(err, owner.ErrTooMany):
			r, t := s.triesLeft(err)
			return localapi.Answered{Refusal: r, Text: t}, nil
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

func (s *Server) followRoot(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.FollowRoot
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || len(in.Root) == 0 || len(in.Root) > localapi.MaxRoot || len(in.Chain) > localapi.MaxRootChain {
		return nil, errBadArgs
	}
	for _, c := range in.Chain {
		if len(c) == 0 || len(c) > localapi.MaxRoot {
			return nil, errBadArgs
		}
	}
	if s.cfg.DescribeRoot == nil {
		return nil, errFailed
	}
	sum, err := s.cfg.DescribeRoot(ctx, in.Root, in.Chain)
	if err != nil {
		return localapi.RootSummary{Refusal: localapi.RefusedRoot, Reason: rootReason(sum.Reason)}, nil
	}
	sum.Refusal, sum.Reason = "", ""
	return sum, nil
}

// rootReason keeps a refused root's coarse cause only if it is one the
// page words, never other text (agentosd maps the updater's errors).
func rootReason(r string) string {
	switch r {
	case localapi.RootExpired, localapi.RootSignatures, localapi.RootThreshold:
		return r
	}
	return ""
}

func (s *Server) follow(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Follow
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || len(in.Name) > localapi.MaxFollowName || !lowerHex(in.Digest, localapi.DigestLen) {
		return nil, errBadArgs
	}
	if s.cfg.Follow == nil {
		return nil, errFailed
	}
	t, err := s.cfg.Follow(ctx, in.Name, in.Digest)
	if err != nil {
		return nil, errFailed
	}
	return localapi.Text{Text: t}, nil
}

func (s *Server) paused(context.Context) (any, error) {
	if s.cfg.Paused == nil {
		return nil, errFailed
	}
	return localapi.Paused{Grants: s.cfg.Paused()}, nil
}

func (s *Server) askResume(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.AskResume
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || in.Grant == "" || in.Pause == "" || len(in.Grant) > localapi.MaxID || len(in.Pause) > localapi.MaxPause {
		return nil, errBadArgs
	}
	if s.cfg.AskResume == nil {
		return nil, errFailed
	}
	t, err := s.cfg.AskResume(ctx, in.Grant, in.Pause)
	if err != nil {
		return nil, errFailed
	}
	return localapi.Text{Text: t}, nil
}

func lowerHex(v string, n int) bool {
	if len(v) != n {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// triesLeft is the refusal of a wrong or unchecked code and what the day's
// local tries have left, told only in a signed-in response to the code
// just tried (Security D1, UX-2wb-2): a count once 2 or fewer remain, and once none
// remain, the bound's fixed reset.
func (s *Server) triesLeft(err error) (refusal, text string) {
	st := s.cfg.Owner.LocalStatus()
	switch {
	case errors.Is(err, owner.ErrTooMany), st.LocalLeft <= 0:
		return localapi.RefusedTooMany, "No more codes can be tried today. Try again after " + st.LocalReset + ", or use your recovery key."
	case st.LocalLeft <= 2:
		return localapi.RefusedWrongCode, fmt.Sprintf("%d %s left today.", st.LocalLeft, map[bool]string{true: "try", false: "tries"}[st.LocalLeft == 1])
	}
	return localapi.RefusedWrongCode, ""
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
	_, ok := s.live(tok)
	return ok
}

// live is tok's session, read in the same critical section that checks it
// (Security S2 on step b).
func (s *Server) live(tok string) (session, bool) {
	if len(tok) != 2*localapi.TokenBytes {
		return session{}, false
	}
	locks := s.cfg.Owner.LocalStatus().Locks
	k := sha256.Sum256([]byte(tok))
	s.mu.Lock()
	defer s.mu.Unlock()
	ses, ok := s.sessions[k]
	if !ok {
		return session{}, false
	}
	if !s.cfg.Now().Before(ses.until) || locks != ses.locks {
		delete(s.sessions, k)
		return session{}, false
	}
	return ses, true
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
