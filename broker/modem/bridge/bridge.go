// Package bridge is the modem bridge's core (agentos-modem, P2-3w part 1;
// CH-1, CH-2, ADP-12): it opens the owner line's modem, checks its SIM is
// the one recorded at setup, and carries texts between the modem and
// agentosd's owner socket (bridgeproto). The bridge is always the client:
// agentosd serves owner.sock to the bridge's uid only.
//
// The owner line's state is reported as a closed enum: ok; down while the
// modem does not open or answer; swapped while its SIM is not the recorded
// one; unbound while no SIM is recorded or the modem has none. Only an ok
// line carries texts (security S-B8).
package bridge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
)

// Caller is agentosd's owner socket (bridgeclient.Client).
type Caller interface {
	Call(ctx context.Context, op string, args, out any) error
}

// Owner is the owner line's modem (*at.Modem).
type Owner interface {
	modem.Modem
	ICCID() string
	// Ack deletes a text agentosd has taken (at.Config.KeepUntilAck).
	Ack(ref string) error
	Done() <-chan struct{}
	Close() error
}

// Config configures Run.
type Config struct {
	Agentosd Caller
	// OpenOwner opens the owner line's modem; an *at.SIMError means no
	// usable SIM. It passes check to at.Config.CheckSIM, so a SIM that is
	// not the recorded one is turned away before any stored text is read
	// off it (L3 on #170).
	OpenOwner func(ctx context.Context, check func(iccid string) error) (Owner, error)
	// OwnerICCID is the owner line's SIM serial recorded at setup ("": none
	// yet). It is read again at each open, so a SIM the owner confirms on
	// the local page is taken without a restart.
	OwnerICCID func() string
	// Retry is how long to wait before opening the modem again (default
	// 10 s); StateEvery is how often the state is sent unchanged (default
	// bridgeproto.StateEvery); InboundRetry is the first wait before a
	// refused inbound text is sent again, doubling each time (default 1 s).
	Retry, StateEvery, InboundRetry time.Duration
	// Logf logs counts and states, never numbers, texts or serials.
	Logf func(format string, args ...any)
}

// Run serves the owner line until ctx is done.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Agentosd == nil || cfg.OpenOwner == nil || cfg.OwnerICCID == nil {
		return errors.New("bridge: agentosd, OpenOwner and OwnerICCID are required")
	}
	if cfg.Retry == 0 {
		cfg.Retry = 10 * time.Second
	}
	if cfg.StateEvery == 0 {
		cfg.StateEvery = bridgeproto.StateEvery
	}
	if cfg.InboundRetry == 0 {
		cfg.InboundRetry = time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	b := &runner{cfg: cfg, state: bridgeproto.StateDown}
	go b.report(ctx)
	for ctx.Err() == nil {
		m, st := b.open(ctx)
		b.set(st)
		if m != nil {
			b.serve(ctx, m)
			m.Close()
			b.set(bridgeproto.StateDown)
		}
		select {
		case <-ctx.Done():
		case <-time.After(cfg.Retry):
		}
	}
	return ctx.Err()
}

type runner struct {
	cfg     Config
	mu      sync.Mutex
	state   string
	changed chan struct{}
}

var (
	errUnbound = errors.New("bridge: no SIM recorded for the owner line")
	errSwapped = errors.New("bridge: not the owner line's recorded SIM")
)

// open opens the modem and checks its SIM: the modem only when ok.
func (b *runner) open(ctx context.Context) (Owner, string) {
	want := b.cfg.OwnerICCID()
	m, err := b.cfg.OpenOwner(ctx, func(iccid string) error {
		switch {
		case want == "":
			return errUnbound
		case iccid == "" || !sameICCID(iccid, want):
			return errSwapped
		}
		return nil
	})
	var simErr *at.SIMError
	switch {
	case errors.As(err, &simErr), errors.Is(err, errUnbound):
		return nil, bridgeproto.StateUnbound
	case errors.Is(err, errSwapped):
		return nil, bridgeproto.StateSwapped
	case err != nil:
		b.cfg.Logf("bridge: owner modem not open")
		return nil, bridgeproto.StateDown
	case want == "":
		m.Close()
		return nil, bridgeproto.StateUnbound
	case m.ICCID() == "" || !sameICCID(m.ICCID(), want):
		m.Close()
		return nil, bridgeproto.StateSwapped
	}
	return m, bridgeproto.StateOK
}

func sameICCID(a, b string) bool {
	norm := func(s string) string {
		out := make([]byte, 0, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			if c != ' ' {
				out = append(out, c)
			}
		}
		return string(out)
	}
	return norm(a) == norm(b)
}

func (b *runner) set(st string) {
	b.mu.Lock()
	changed := b.state != st
	b.state = st
	ch := b.changed
	b.mu.Unlock()
	if changed {
		b.cfg.Logf("bridge: owner line %s", st)
		if ch != nil {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// report sends the state on each change and every StateEvery.
func (b *runner) report(ctx context.Context) {
	changed := make(chan struct{}, 1)
	b.mu.Lock()
	b.changed = changed
	b.mu.Unlock()
	t := time.NewTicker(b.cfg.StateEvery)
	defer t.Stop()
	for {
		b.mu.Lock()
		st := b.state
		b.mu.Unlock()
		// A report agentosd did not hear is sent again soon, not at the
		// next StateEvery: agentosd may have restarted and read the line
		// as down meanwhile.
		var again <-chan time.Time
		if err := b.cfg.Agentosd.Call(ctx, bridgeproto.OpState, bridgeproto.State{OwnerLine: st}, nil); err != nil && ctx.Err() == nil {
			b.cfg.Logf("bridge: state not reported")
			again = time.After(min(b.cfg.Retry, b.cfg.StateEvery))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-changed:
		case <-again:
		}
	}
}

// serve carries texts while the modem answers.
//
// The modem keeps each text stored until agentosd has taken it
// (at.Config.KeepUntilAck), so a text is never lost to the bridge, the
// modem or agentosd going away: it is read again at the next open, with
// the same ID, and agentosd takes an ID once (L3 on #170).
func (b *runner) serve(runCtx context.Context, m Owner) {
	ctx, cancel := context.WithCancel(runCtx)
	defer cancel()
	go func() {
		select {
		case <-m.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.outbox(ctx, m)
	}()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sms := <-m.Inbox():
			b.inbound(ctx, m, sms)
		}
	}
}

// reportOK tells agentosd the owner line is ok, again until it is heard;
// false once ctx is done.
func (b *runner) reportOK(ctx context.Context) bool {
	for wait := b.cfg.InboundRetry; ; wait = min(2*wait, b.cfg.Retry) {
		if b.cfg.Agentosd.Call(ctx, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK}, nil) == nil {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

// inbound offers one text to agentosd. A text the modem keeps (the
// owner's: it has a Ref) is offered while the modem answers, again while
// the refusal can pass, and deleted once agentosd has it or can never take
// it; before each new offer agentosd is told again that the line is ok,
// since a paused refusal or a lost connection may mean agentosd restarted
// and reads the line as down. Anyone else's text was deleted as it was
// read and is offered once, so it can never hold up the owner's (L3 on
// #170). A text agentosd would refuse as malformed (too long, a bad
// sender) is never offered: its request could exceed what agentosd reads.
func (b *runner) inbound(ctx context.Context, m Owner, sms modem.SMS) {
	id := sms.Ref
	if id == "" {
		var r [16]byte
		rand.Read(r[:])
		id = hex.EncodeToString(r[:])
	}
	in := bridgeproto.Inbound{Line: bridgeproto.LineOwner, From: sms.From, Text: sms.Text, Named: sms.Alphanumeric, ID: id}
	if !in.Valid() {
		b.cfg.Logf("bridge: a malformed text was dropped")
		if sms.Ref != "" && m.Ack(sms.Ref) != nil {
			b.cfg.Logf("bridge: a dropped text was not deleted")
		}
		return
	}
	for wait := b.cfg.InboundRetry; ; wait = min(2*wait, b.cfg.Retry) {
		err := b.cfg.Agentosd.Call(ctx, bridgeproto.OpInbound, in, nil)
		if ctx.Err() != nil {
			return // still stored: read again at the next open
		}
		if err == nil || !bridgeproto.Retryable(err) || sms.Ref == "" {
			if err != nil {
				b.cfg.Logf("bridge: an inbound text was refused")
			}
			if sms.Ref != "" && m.Ack(sms.Ref) != nil {
				b.cfg.Logf("bridge: a taken text was not deleted")
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if !b.reportOK(ctx) {
			return
		}
	}
}

// outbox pulls agentosd's texts and sends them on the owner line.
func (b *runner) outbox(ctx context.Context, m Owner) {
	for ctx.Err() == nil {
		var out struct {
			Item *bridgeproto.Item `json:"item"`
		}
		if err := b.cfg.Agentosd.Call(ctx, bridgeproto.OpOutbox, struct{}{}, &out); err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
			continue
		}
		if out.Item == nil {
			continue
		}
		code := bridgeproto.CodeRecipient
		if out.Item.Line == bridgeproto.LineOwner {
			code = codeOf(m.Send(out.Item.To, out.Item.Text))
		}
		if err := b.cfg.Agentosd.Call(ctx, bridgeproto.OpSent, bridgeproto.Sent{ID: out.Item.ID, Code: code}, nil); err != nil && ctx.Err() == nil {
			b.cfg.Logf("bridge: a result was not reported")
		}
	}
}

func codeOf(err error) string {
	switch {
	case err == nil:
		return bridgeproto.CodeOK
	case errors.Is(err, at.ErrNumber):
		return bridgeproto.CodeRecipient
	case errors.Is(err, modem.ErrDown):
		return bridgeproto.CodeDown
	}
	return bridgeproto.CodeUnreachable
}
