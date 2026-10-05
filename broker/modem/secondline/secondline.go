// Package secondline is ADP-12's second line: texts and calls to third
// parties, never from the owner-channel number (CH-1). The line is an
// optional dependency (DEP-3): without one the tool reports itself
// unavailable and nothing is sent at all, so third-party traffic can never
// fall back to the owner's channel.
//
// What arrives on the second line is untrusted data. It comes out of
// Inbound as Untrusted, a type the owner channel does not accept, so it can
// never become a control word, task chat, or part of an approval.
//
// Recipient verification, third-party rate limits and transcript
// journaling belong to the adapter that calls this tool (the send verb);
// see broker/modem/at/ASSUMPTIONS.md.
package secondline

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
)

// Call is a voice call on the second line.
type Call interface {
	Active() <-chan struct{}
	Ended() <-chan struct{}
	Say(ctx context.Context, pcm []byte) error
	Hangup(ctx context.Context) error
}

// Line is a SIM that can text and call.
type Line interface {
	modem.Modem
	Dial(ctx context.Context, number string) (Call, error)
}

// FromAT adapts the real driver.
func FromAT(m *at.Modem) Line { return atLine{m} }

type atLine struct{ *at.Modem }

func (l atLine) Dial(ctx context.Context, number string) (Call, error) {
	c, err := l.Modem.Dial(ctx, number)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Config configures the tool.
type Config struct {
	// Owner is the owner channel's line (CH-1). It is only compared
	// against, never used.
	Owner modem.Modem
	// Second is the second line; nil leaves the tool unavailable.
	Second Line
	// Disclosure is the broker-rendered audio (8 kHz S16_LE mono) that
	// opens every call: an automated assistant is calling for the owner.
	Disclosure []byte
	// AnswerWait bounds how long a call may ring (default 60 s).
	AnswerWait time.Duration
}

// Untrusted is a text that reached the second line: data for the agent,
// never owner input.
type Untrusted struct {
	From, Text string
	At         time.Time
}

// Errors.
var (
	ErrUnavailable = errors.New("secondline: no second line configured")
	ErrOwnerLine   = errors.New("secondline: the second line is the owner-channel line")
	ErrNoAnswer    = errors.New("secondline: call not answered")
)

// Tool is the second-line tool.
type Tool struct {
	cfg     Config
	inbound chan Untrusted
}

// New checks the configuration. A second line that is the owner's line, by
// identity or by number, or whose number is unknown, is refused, as is a
// second line with no disclosure audio.
func New(cfg Config) (*Tool, error) {
	if cfg.AnswerWait == 0 {
		cfg.AnswerWait = 60 * time.Second
	}
	t := &Tool{cfg: cfg, inbound: make(chan Untrusted, 64)}
	if cfg.Second == nil {
		close(t.inbound)
		return t, nil
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	if len(cfg.Disclosure) == 0 {
		return nil, errors.New("secondline: calls need disclosure audio")
	}
	go t.pump()
	return t, nil
}

// check holds the second line apart from the owner's, at setup and again
// before every use.
func (t *Tool) check() error {
	s, o := t.cfg.Second, t.cfg.Owner
	if o != nil {
		if same(s, o) {
			return ErrOwnerLine
		}
		if digits(s.Number()) != "" && digits(s.Number()) == digits(o.Number()) {
			return ErrOwnerLine
		}
	}
	if digits(s.Number()) == "" {
		return errors.New("secondline: the second line's number is unknown, so it cannot be told apart")
	}
	return nil
}

func same(s Line, o modem.Modem) bool {
	if a, ok := s.(atLine); ok {
		if b, ok := o.(*at.Modem); ok {
			return a.Modem == b
		}
	}
	return any(s) == any(o)
}

func digits(n string) string {
	var sb strings.Builder
	for _, c := range n {
		if c >= '0' && c <= '9' {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// Available reports whether third-party texts and calls can be made.
func (t *Tool) Available() bool { return t.cfg.Second != nil }

// Text sends a text to a third party from the second line.
func (t *Tool) Text(to, text string) error {
	if t.cfg.Second == nil {
		return ErrUnavailable
	}
	if err := t.check(); err != nil {
		return err
	}
	return t.cfg.Second.Send(to, text)
}

// Call calls a third party from the second line. It returns once the call
// is answered and the disclosure has been played in full; only then may
// anything else be said.
func (t *Tool) Call(ctx context.Context, to string) (Call, error) {
	if t.cfg.Second == nil {
		return nil, ErrUnavailable
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	c, err := t.cfg.Second.Dial(ctx, to)
	if err != nil {
		return nil, err
	}
	w := time.NewTimer(t.cfg.AnswerWait)
	defer w.Stop()
	select {
	case <-c.Active():
	case <-c.Ended():
		return nil, ErrNoAnswer
	case <-w.C:
		_ = c.Hangup(context.Background())
		return nil, ErrNoAnswer
	case <-ctx.Done():
		_ = c.Hangup(context.Background())
		return nil, ctx.Err()
	}
	if err := c.Say(ctx, t.cfg.Disclosure); err != nil {
		// A call that cannot carry the disclosure carries nothing.
		_ = c.Hangup(context.Background())
		return nil, err
	}
	return c, nil
}

// Inbound delivers texts received on the second line, as untrusted data.
// It is closed when there is no second line.
func (t *Tool) Inbound() <-chan Untrusted { return t.inbound }

func (t *Tool) pump() {
	for m := range t.cfg.Second.Inbox() {
		select {
		case t.inbound <- Untrusted{From: m.From, Text: m.Text, At: m.At}:
		default: // unread third-party texts are dropped, never queued unbounded
		}
	}
}
