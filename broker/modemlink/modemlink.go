// Package modemlink is agentosd's side of the modem bridge (P2-3w part 1;
// CH-1, CH-2, ADP-12). A Link is the owner channel's modem.Modem: Send
// queues a text for the bridge to pull from owner.sock's outbox and waits
// for its result, and Inbox carries the owner-line texts the bridge hands
// in. Ops are owner.sock's bridge ops (bridgeproto).
//
// The bridge is the less-trusted side (it parses any sender's PDUs), so
// nothing it says widens authority: agentosd addresses every text to the
// owner itself, stamps its own receive time, takes only the owner line's
// texts for the owner channel, and stops the owner channel while the
// owner line is swapped or unbound (security S-B1, S-B4, S-B8 on the
// P2-3w design).
package modemlink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Defaults and limits.
const (
	// SendWait bounds how long Send waits for the bridge's result: past
	// the slowest send that can still succeed, a poll's wait and three
	// segments (owner.MaxSegments) at the modem's 60 s each, plus a margin,
	// so a text still going out is not reported down (L3 on #170).
	SendWait = bridgeproto.OutboxWait + 3*60*time.Second + 15*time.Second
	// Silent is how long the bridge may say nothing before the owner line
	// reads as down: two missed state reports and a margin.
	Silent = 2*bridgeproto.StateEvery + 30*time.Second
	// IDTTL is how long a taken inbound ID is remembered: past a bridge
	// restart, after which the modem gives up an untaken text again.
	IDTTL = 10 * time.Minute
	// MaxQueued caps the texts waiting for the bridge.
	MaxQueued = 64
	// InboundPerMinute caps texts handed in per minute (security S-B4).
	InboundPerMinute = 20
)

// ErrRecipient is a Send to anyone but the owner: the owner channel texts
// only the owner (CH-1).
var ErrRecipient = errors.New("modemlink: the owner channel texts only the owner")

// Refusals on owner.sock, as fixed codes.
const (
	errBadInbound = sockets.Code(bridgeproto.RefusedBad)
	errPaused     = sockets.Code(bridgeproto.RefusedPaused)
	errSecond     = sockets.Code(bridgeproto.RefusedSecond)
	errLimited    = sockets.Code(bridgeproto.RefusedLimited)
	errBadSent    = sockets.Code("bad result")
	errBadState   = sockets.Code("bad state")
)

// Config configures a Link.
type Config struct {
	// Owner is the owner's number, the only recipient.
	Owner string
	Now   func() time.Time
	// SendWait and PollWait override SendWait and bridgeproto.OutboxWait
	// (tests).
	SendWait, PollWait time.Duration
	// Location is the time zone of the recovery text's times: the box's
	// (default time.Local).
	Location *time.Location
}

// Outage is a stretch when the owner line could not be used, and how many
// texts to the owner could not go in it.
type Outage struct {
	From, To time.Time
	// Missed counts every text that could not go; Requests, the approval
	// requests among them.
	Missed, Requests int
}

type item struct {
	bridgeproto.Item
	result chan string   // nil: nobody waits (the recovery text)
	handed chan struct{} // closed when a poll takes it; nil with result
	// bump hears each SendFirst that went ahead of it while queued, so
	// its wait grows by one SendWait; nil with result.
	bump chan struct{}
	// first: queued by SendFirst; later replies queue behind it.
	first bool
}

// Link is agentosd's end of the modem bridge.
type Link struct {
	cfg   Config
	inbox chan modem.SMS

	mu          sync.Mutex
	ready       chan struct{} // closed and replaced when an item is queued
	queue       []*item
	out         map[string]*item
	state       string
	seen        time.Time
	outage      *Outage
	last        Outage
	stray       int
	dropped     bool
	others      int
	timedOut    int
	inboundIDs  map[string]time.Time // taken inbound IDs, kept for IDTTL
	inboundTime []time.Time
	// okSince is when the owner line last became usable. A poll that
	// began before it may be a dead bridge's connection, so it is handed
	// nothing (its item would be lost).
	okSince time.Time
}

// New returns a Link. Until the bridge reports the owner line's state, it
// reads as down.
func New(cfg Config) *Link {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SendWait == 0 {
		cfg.SendWait = SendWait
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.PollWait == 0 {
		cfg.PollWait = bridgeproto.OutboxWait
	}
	return &Link{cfg: cfg, inbox: make(chan modem.SMS, 64), ready: make(chan struct{}), out: map[string]*item{}, state: bridgeproto.StateDown}
}

// Number is unused by the owner channel; the box's number is the bridge's.
func (l *Link) Number() string { return "" }

// Inbox carries the owner line's texts.
func (l *Link) Inbox() <-chan modem.SMS { return l.inbox }

// usableLocked says the owner line can carry texts now, and opens an
// outage when it cannot. Caller holds mu.
func (l *Link) usableLocked(now time.Time) bool {
	ok := l.state == bridgeproto.StateOK && now.Sub(l.seen) <= Silent
	if !ok && l.outage == nil {
		from := now
		if l.state == bridgeproto.StateOK { // silent: down since last heard
			from = l.seen
		}
		l.outage = &Outage{From: from}
	}
	return ok
}

// heardLocked notes the bridge spoke at now, and closes an outage the line
// has recovered from: one text with its times and count, ahead of
// anything queued; nothing missed is replayed (UX U-B1, U-B2). Caller
// holds mu.
func (l *Link) heardLocked(now time.Time) {
	l.seen = now
	if l.outage == nil || !l.usableLocked(now) {
		return
	}
	o := *l.outage
	o.To = now
	l.outage, l.last, l.okSince = nil, o, now
	if o.Missed == 0 {
		return
	}
	it := &item{Item: bridgeproto.Item{ID: newID(), Line: bridgeproto.LineOwner, To: l.cfg.Owner, Text: recoveryText(o, l.cfg.Location)}}
	l.queue = append([]*item{it}, l.queue...)
	l.wakeLocked()
}

// recoveryText counts what did not reach the owner. A dropped approval
// request is never re-sent, but the agent was told it can ask again
// (grants), so the text says so (UX on #170).
func recoveryText(o Outage, loc *time.Location) string {
	o.From, o.To = o.From.In(loc), o.To.In(loc)
	layout := "15:04"
	if o.To.Sub(o.From) >= 24*time.Hour || o.From.Day() != o.To.Day() {
		layout = "Jan 2 15:04"
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %s", n, many)
	}
	what := plural(o.Missed, "text", "texts")
	if r := o.Requests; r > 0 {
		what = plural(r, "approval request", "approval requests")
		if other := o.Missed - r; other > 0 {
			what += " and " + plural(other, "other text", "other texts")
		}
	}
	end := "."
	if o.Requests > 0 {
		end = "; your agent can ask again."
	}
	return fmt.Sprintf("I couldn't text you from %s to %s. %s didn't reach you%s", o.From.Format(layout), o.To.Format(layout), what, end)
}

func (l *Link) wakeLocked() {
	close(l.ready)
	l.ready = make(chan struct{})
}

func newID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Send texts the owner through the bridge and waits for the result: nil,
// or modem.ErrDown when the owner line is down, swapped or unbound, the
// bridge is silent or full, or the text did not go. A text that could not
// go while the line was unusable is counted for the recovery text.
func (l *Link) Send(to, text string) error { return l.send(to, text, false, false) }

// SendRequest is Send for an approval request (owner.RequestSender), so
// the recovery text can count requests apart.
func (l *Link) SendRequest(to, text string) error { return l.send(to, text, true, false) }

func (l *Link) send(to, text string, request, first bool) error {
	if to != l.cfg.Owner {
		return ErrRecipient
	}
	now := l.cfg.Now()
	l.mu.Lock()
	limit := MaxQueued
	if first {
		limit += FirstSlack
	}
	if !l.usableLocked(now) || len(l.queue)+len(l.out) >= limit {
		if l.outage != nil {
			l.outage.Missed++
			if request {
				l.outage.Requests++
			}
		}
		l.mu.Unlock()
		return modem.ErrDown
	}
	it := &item{Item: bridgeproto.Item{ID: newID(), Line: bridgeproto.LineOwner, To: l.cfg.Owner, Text: text},
		result: make(chan string, 1), handed: make(chan struct{}), bump: make(chan struct{}, MaxQueued+FirstSlack)}
	ahead := len(l.queue) + len(l.out)
	if first {
		ahead = len(l.out)
		l.aheadLocked(it)
	} else {
		l.queue = append(l.queue, it)
	}
	l.wakeLocked()
	l.mu.Unlock()
	// SendWait runs from when the bridge takes the text: the bridge sends
	// one at a time, so the texts ahead may each take up to SendWait (L3
	// on #170). A reply that went ahead adds one more.
	deadline := time.Now().Add(time.Duration(ahead+1) * l.cfg.SendWait)
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
wait:
	for {
		select {
		case <-it.handed:
			t.Reset(l.cfg.SendWait)
			break wait
		case <-it.bump:
			// Go 1.23+ timers: Reset drops any expiry not yet received.
			deadline = deadline.Add(l.cfg.SendWait)
			t.Reset(time.Until(deadline))
		case <-t.C:
			l.mu.Lock()
			l.dropLocked(it)
			l.timedOut++
			l.mu.Unlock()
			return modem.ErrDown
		}
	}
	select {
	case code := <-it.result:
		if code == bridgeproto.CodeOK {
			return nil
		}
		return modem.ErrDown
	case <-t.C:
		l.mu.Lock()
		l.dropLocked(it)
		l.timedOut++
		l.mu.Unlock()
		return modem.ErrDown
	}
}

// dropLocked forgets it, queued or handed out; a late result for it is
// stray. Caller holds mu.
func (l *Link) dropLocked(it *item) {
	delete(l.out, it.ID)
	for i, q := range l.queue {
		if q == it {
			l.queue = append(l.queue[:i], l.queue[i+1:]...)
			return
		}
	}
}

// Stray counts results for unknown or finished IDs (security S-B3).
func (l *Link) Stray() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stray
}

// TimedOut counts sends the bridge gave no result for within SendWait,
// reported down to the owner channel though they may still have gone.
func (l *Link) TimedOut() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.timedOut
}

// Others counts texts on the owner line from anyone but the owner, set
// aside unread: the owner channel acts only on the owner's.
func (l *Link) Others() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.others
}

// Dropped says inbound texts were dropped past the rate limit.
func (l *Link) Dropped() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// LastOutage is the last outage the owner line recovered from.
func (l *Link) LastOutage() Outage {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// OwnerLineNote is the owner line's state for the box's local page, in
// fixed words; empty while the line is fine (UX U-B1, U-B3, U-B4: the
// owner line's states are shown there and in the recovery text, not in
// STATUS, which could not reach the owner anyway).
func (l *Link) OwnerLineNote() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.state
	if st == bridgeproto.StateOK && l.cfg.Now().Sub(l.seen) > Silent {
		st = bridgeproto.StateDown
	}
	switch st {
	case bridgeproto.StateOK:
		return ""
	case bridgeproto.StateSwapped:
		return "The SIM in my phone modem changed. Texts to and from you are paused until you confirm it on my Wi-Fi page."
	case bridgeproto.StateUnbound:
		return "My phone modem has no SIM, or its number isn't set up. Set it up on my Wi-Fi page."
	}
	return "I can't reach my phone modem. Check it's plugged in."
}

// Ops are owner.sock's bridge ops.
func (l *Link) Ops() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		bridgeproto.OpInbound: l.inbound,
		bridgeproto.OpOutbox:  l.outbox,
		bridgeproto.OpSent:    l.sent,
		bridgeproto.OpState:   l.setState,
	}
}

func (l *Link) inbound(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in bridgeproto.Inbound
	if json.Unmarshal(args, &in) != nil || !in.Valid() {
		return nil, errBadInbound
	}
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.heardLocked(now)
	if in.Line != bridgeproto.LineOwner {
		// The second line's texts are never the owner's, whoever they
		// claim to be from (S-B8); the agent's path for them is part 2.
		return nil, errSecond
	}
	if l.state != bridgeproto.StateOK {
		return nil, errPaused // swapped or unbound: not the owner's SIM
	}
	for id, t := range l.inboundIDs {
		if now.Sub(t) > IDTTL {
			delete(l.inboundIDs, id)
		}
	}
	if _, again := l.inboundIDs[in.ID]; again && in.ID != "" {
		return struct{}{}, nil // a try whose answer was lost
	}
	if in.Named || in.From != l.cfg.Owner {
		// Set aside before the rate limit and the inbox, so no one else's
		// texts can crowd out the owner's (L3 on #170). Taken, so the
		// bridge does not retry it.
		l.others++
		return struct{}{}, nil
	}
	kept := l.inboundTime[:0]
	for _, t := range l.inboundTime {
		if now.Sub(t) < time.Minute {
			kept = append(kept, t)
		}
	}
	l.inboundTime = kept
	if len(kept) >= InboundPerMinute {
		l.dropped = true
		return nil, errLimited
	}
	m := modem.SMS{From: in.From, To: l.cfg.Owner, Text: in.Text, At: now, Alphanumeric: in.Named}
	select {
	case l.inbox <- m:
	default:
		l.dropped = true
		return nil, errLimited
	}
	l.inboundTime = append(l.inboundTime, now)
	if in.ID != "" {
		if l.inboundIDs == nil {
			l.inboundIDs = map[string]time.Time{}
		}
		l.inboundIDs[in.ID] = now
	}
	return struct{}{}, nil
}

func (l *Link) outbox(ctx context.Context, _ sockets.Peer, _ json.RawMessage) (any, error) {
	wait := time.NewTimer(l.cfg.PollWait)
	defer wait.Stop()
	began := l.cfg.Now()
	for {
		l.mu.Lock()
		now := l.cfg.Now()
		l.heardLocked(now)
		// A poll whose bridge hung up (its context ended) is handed
		// nothing, nor one that began before the line last recovered.
		if ctx.Err() == nil && l.usableLocked(now) && len(l.queue) > 0 && !began.Before(l.okSince) {
			it := l.queue[0]
			l.queue = l.queue[1:]
			l.out[it.ID] = it
			if it.handed != nil {
				close(it.handed)
			}
			l.mu.Unlock()
			return map[string]any{"item": it.Item}, nil
		}
		ready := l.ready
		l.mu.Unlock()
		select {
		case <-ready:
		case <-wait.C:
			return map[string]any{"item": nil}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (l *Link) sent(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var s bridgeproto.Sent
	if json.Unmarshal(args, &s) != nil {
		return nil, errBadSent
	}
	switch s.Code {
	case bridgeproto.CodeOK, bridgeproto.CodeDown, bridgeproto.CodeRecipient, bridgeproto.CodeLimited,
		bridgeproto.CodeRefused, bridgeproto.CodeUnreachable, bridgeproto.CodeTooLong:
	default:
		return nil, errBadSent
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.heardLocked(l.cfg.Now())
	it, ok := l.out[s.ID]
	if !ok {
		l.stray++
		return struct{}{}, nil
	}
	delete(l.out, s.ID)
	if it.result != nil {
		it.result <- s.Code
	}
	return struct{}{}, nil
}

func (l *Link) setState(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var st bridgeproto.State
	if json.Unmarshal(args, &st) != nil || !bridgeproto.ValidOwnerLine(st.OwnerLine) {
		return nil, errBadState
	}
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state = st.OwnerLine
	if st.OwnerLine != bridgeproto.StateOK {
		// Swapped or unbound: what was handed out may be on the wrong
		// SIM's line; nothing more goes (S-B8).
		l.usableLocked(now)
	}
	l.heardLocked(now)
	return struct{}{}, nil
}
