package modemlink

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// SetupLine is agentosd's end of the modem bridge while the box has no
// owner yet (P2-2w c4c; §8.1 pairing, CH-1, CH-12). Setup reads the box's
// number from it, sends its fixed texts through it and takes the PAIR
// texts that reach the box. It serves the same owner.sock ops as a Link,
// to the bridge's uid only, and only until setup finishes.
//
// There is no owner yet, so no number is trusted: only texts that start
// with PAIR are passed on (anyone else's never reach the page), at most
// SetupInboundPerMinute a minute and MaxSetupInbound waiting. The SIM the
// bridge finds while setup runs is recorded as the owner line's (Record),
// once: it is the box's own SIM, and the owner pairs with its number.
type SetupLine struct {
	cfg SetupConfig

	mu       sync.Mutex
	ready    chan struct{} // closed and replaced when an item is queued
	queue    []*item
	out      map[string]*item
	state    string
	number   string
	seen     time.Time
	recorded bool
	inIDs    map[string]time.Time
	inTimes  []time.Time
	inbox    chan setupText
	okSince  time.Time
}

// SetupConfig configures a SetupLine.
type SetupConfig struct {
	// Record records iccid as the owner line's SIM, where the bridge reads
	// it at its next open (agentos-modem's roles file); nil records none,
	// and an unbound line stays unbound.
	Record func(iccid string) error
	Now    func() time.Time
	// SendWait and PollWait override localapi.SetupSendWait's 40 s and
	// bridgeproto.OutboxWait (tests).
	SendWait, PollWait time.Duration
}

// MaxSetupInbound caps the PAIR texts waiting for the page.
const MaxSetupInbound = 8

// SetupInboundPerMinute caps the PAIR texts setup keeps a minute (ST2):
// a pairing needs one, so a flood from anyone cannot fill the page.
const SetupInboundPerMinute = 5

// ErrNotSent is a setup text that did not go: no usable line, the bridge
// reported a failure, or no result came within SendWait.
var ErrNotSent = errors.New("modemlink: the setup text was not sent")

type setupText struct{ from, text string }

// NewSetup returns a SetupLine. Until the bridge reports the line ok, it
// is not ready.
func NewSetup(cfg SetupConfig) *SetupLine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SendWait == 0 {
		cfg.SendWait = 40 * time.Second
	}
	if cfg.PollWait == 0 {
		cfg.PollWait = bridgeproto.OutboxWait
	}
	return &SetupLine{cfg: cfg, ready: make(chan struct{}), out: map[string]*item{}, state: bridgeproto.StateDown,
		inbox: make(chan setupText, MaxSetupInbound)}
}

// usableLocked says the bridge reported the line ok within Silent.
func (s *SetupLine) usableLocked(now time.Time) bool {
	return s.state == bridgeproto.StateOK && now.Sub(s.seen) <= Silent
}

// Ready says setup can text now.
func (s *SetupLine) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usableLocked(s.cfg.Now())
}

// Number is the box's own number, E.164, while the line is usable and the
// bridge knows it; "" otherwise.
func (s *SetupLine) Number() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.usableLocked(s.cfg.Now()) {
		return ""
	}
	return s.number
}

// Send has the bridge text to the number and waits for its result. The
// caller checks the number and the text (localsrv).
func (s *SetupLine) Send(ctx context.Context, to, text string) error {
	it := &item{Item: bridgeproto.Item{ID: newID(), Line: bridgeproto.LineOwner, To: to, Text: text}, result: make(chan string, 1)}
	s.mu.Lock()
	if !s.usableLocked(s.cfg.Now()) || len(s.queue) >= MaxQueued {
		s.mu.Unlock()
		return ErrNotSent
	}
	s.queue = append(s.queue, it)
	close(s.ready)
	s.ready = make(chan struct{})
	s.mu.Unlock()
	t := time.NewTimer(s.cfg.SendWait)
	defer t.Stop()
	select {
	case code := <-it.result:
		if code == bridgeproto.CodeOK {
			return nil
		}
	case <-t.C:
	case <-ctx.Done():
	}
	s.mu.Lock()
	if i := slices.Index(s.queue, it); i >= 0 {
		s.queue = slices.Delete(s.queue, i, i+1)
	}
	delete(s.out, it.ID)
	s.mu.Unlock()
	return ErrNotSent
}

// Next waits for a PAIR text that reached the box, until ctx ends.
func (s *SetupLine) Next(ctx context.Context) (from, text string, ok bool) {
	select {
	case in := <-s.inbox:
		return in.from, in.text, true
	case <-ctx.Done():
		return "", "", false
	}
}

// Ops are owner.sock's bridge ops while setup runs.
func (s *SetupLine) Ops() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		bridgeproto.OpInbound: s.inbound,
		bridgeproto.OpOutbox:  s.outbox,
		bridgeproto.OpSent:    s.sent,
		bridgeproto.OpState:   s.setState,
	}
}

// pairText says text asks to pair: its first word is PAIR.
func pairText(text string) bool {
	f := strings.Fields(text)
	return len(f) > 0 && strings.EqualFold(f[0], "pair")
}

func (s *SetupLine) inbound(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in bridgeproto.Inbound
	if json.Unmarshal(args, &in) != nil || !in.Valid() {
		return nil, errBadInbound
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = maxTime(s.seen, now)
	if in.Line != bridgeproto.LineOwner {
		return nil, errSecond
	}
	if s.state != bridgeproto.StateOK {
		return nil, errPaused
	}
	for id, t := range s.inIDs {
		if now.Sub(t) > IDTTL {
			delete(s.inIDs, id)
		}
	}
	if _, again := s.inIDs[in.ID]; again && in.ID != "" {
		return struct{}{}, nil
	}
	if in.ID != "" {
		if s.inIDs == nil {
			s.inIDs = map[string]time.Time{}
		}
		s.inIDs[in.ID] = now
	}
	// A sender name is never a number to pair, and only PAIR texts reach
	// the page; anything else is taken and dropped.
	if in.Named || !bridgeproto.ValidNumber(in.From) || !pairText(in.Text) {
		return struct{}{}, nil
	}
	kept := s.inTimes[:0]
	for _, t := range s.inTimes {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	s.inTimes = kept
	if len(kept) >= SetupInboundPerMinute {
		return struct{}{}, nil // taken and dropped: no one waits on it
	}
	select {
	case s.inbox <- setupText{from: in.From, text: in.Text}:
		s.inTimes = append(s.inTimes, now)
	default:
	}
	return struct{}{}, nil
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (s *SetupLine) outbox(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
	wait := time.NewTimer(s.cfg.PollWait)
	defer wait.Stop()
	began := s.cfg.Now()
	for {
		s.mu.Lock()
		now := s.cfg.Now()
		s.seen = maxTime(s.seen, now)
		if ctx.Err() == nil && s.usableLocked(now) && len(s.queue) > 0 && !began.Before(s.okSince) {
			it := s.queue[0]
			s.queue = s.queue[1:]
			s.out[it.ID] = it
			s.mu.Unlock()
			return map[string]any{"item": it.Item}, nil
		}
		ready := s.ready
		s.mu.Unlock()
		select {
		case <-ready:
		case <-wait.C:
			return map[string]any{"item": nil}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *SetupLine) sent(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var r bridgeproto.Sent
	if json.Unmarshal(args, &r) != nil {
		return nil, errBadSent
	}
	switch r.Code {
	case bridgeproto.CodeOK, bridgeproto.CodeDown, bridgeproto.CodeRecipient, bridgeproto.CodeLimited,
		bridgeproto.CodeRefused, bridgeproto.CodeUnreachable, bridgeproto.CodeTooLong:
	default:
		return nil, errBadSent
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = maxTime(s.seen, s.cfg.Now())
	if it, ok := s.out[r.ID]; ok {
		delete(s.out, r.ID)
		it.result <- r.Code
	}
	return struct{}{}, nil
}

func (s *SetupLine) setState(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var st bridgeproto.State
	if json.Unmarshal(args, &st) != nil || !bridgeproto.ValidOwnerLine(st.OwnerLine) ||
		st.ICCID != "" && !bridgeproto.ValidICCID(st.ICCID) || st.Number != "" && !bridgeproto.ValidNumber(st.Number) {
		return nil, errBadState
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if st.OwnerLine == bridgeproto.StateOK && !s.usableLocked(now) {
		s.okSince = now
	}
	s.state, s.seen = st.OwnerLine, now
	s.number = ""
	if st.OwnerLine == bridgeproto.StateOK {
		s.number = st.Number
	}
	if st.OwnerLine != bridgeproto.StateOK {
		// Nothing more goes until the line is ok again; what waits fails.
		for _, it := range s.queue {
			it.result <- bridgeproto.CodeDown
		}
		s.queue = nil
	}
	if st.OwnerLine == bridgeproto.StateUnbound && st.ICCID != "" && !s.recorded && s.cfg.Record != nil {
		// The box's own SIM, found with no SIM recorded: setup binds it,
		// once, and the bridge opens it at its next try.
		if err := s.cfg.Record(st.ICCID); err == nil {
			s.recorded = true
		}
	}
	return struct{}{}, nil
}
