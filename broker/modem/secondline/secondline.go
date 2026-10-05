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
// The second line is a second SIM (FromAT) or an owner-held calling
// account (package sipline); either way its role is bound at setup (Roles).
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

// SIM is a modem line that knows its SIM's serial number (ICCID).
type SIM interface {
	modem.Modem
	ICCID() string
	// Done is closed when the modem has gone away.
	Done() <-chan struct{}
}

// Line is a second line that can text and call: a second SIM (FromAT), or
// an owner-held calling account (an Account, package sipline).
type Line interface {
	modem.Modem
	// Done is closed when the line has gone away.
	Done() <-chan struct{}
	Dial(ctx context.Context, number string) (Call, error)
}

// Account is a second line that is a calling account rather than a SIM. Its
// role is bound to its address of record (user@domain), which the owner
// gives at setup, the way a SIM's role is bound to its serial.
type Account interface {
	Line
	AOR() string
}

var _ SIM = (*at.Modem)(nil)

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
	// against, never used, and it is required.
	Owner SIM
	// Second is the second line; nil leaves the tool unavailable.
	Second Line
	// Roles are the SIM serial numbers recorded when the owner assigned
	// each line at setup. Roles follow the SIM, not the USB port: modems
	// moved to each other's ports are caught as swapped.
	Roles Roles
	// OwnerPhone is the owner's own number. Third-party traffic never goes
	// to it or to either of the box's numbers, so the agent cannot use the
	// second line to ask the owner for a code and read the answer as
	// untrusted data (CH-19).
	OwnerPhone string
	// CountryCode is the home country code, for comparing numbers.
	CountryCode string
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

// Roles binds each line to its SIM, or the second line to its account.
type Roles struct {
	OwnerICCID, SecondICCID string
	// SecondAccount is the second line's address of record when it is a
	// calling account. At most one of SecondICCID and SecondAccount is set.
	SecondAccount string
}

// Errors.
var (
	ErrUnavailable = errors.New("secondline: no second line configured")
	ErrOwnerLine   = errors.New("secondline: the second line is the owner-channel line")
	ErrSwapped     = errors.New("secondline: the owner and second lines are swapped; move the modems back or set the lines up again")
	ErrUnbound     = errors.New("secondline: a line's SIM is unknown or not the one set up for it")
	ErrRecipient   = errors.New("secondline: not a third-party number")
	ErrNoAnswer    = errors.New("secondline: call not answered")
	ErrOwnerPhone  = errors.New("secondline: the owner's number and home country code are required")
)

// Check verifies that owner and second are the SIMs recorded for their
// roles. It fails closed: an unreadable or unrecorded serial, one SIM in
// both roles, or a missing owner line is refused. The supervisor runs it
// again after reopening either modem.
func (r Roles) Check(owner, second SIM) error {
	if owner == nil || second == nil {
		return ErrUnbound
	}
	o, s := norm(owner.ICCID()), norm(second.ICCID())
	ro, rs := norm(r.OwnerICCID), norm(r.SecondICCID)
	switch {
	case o == "" || s == "" || ro == "" || rs == "":
		return ErrUnbound
	case o == s || ro == rs:
		return ErrOwnerLine
	case o == rs && s == ro:
		return ErrSwapped
	case o != ro || s != rs:
		return ErrUnbound
	}
	return nil
}

func norm(iccid string) string { return strings.ToUpper(strings.TrimSpace(iccid)) }

// CheckAccount verifies that owner is the SIM recorded for the owner role
// and second is the account recorded for the second role. It fails closed
// like Check: an unread or unrecorded serial or address, or roles recorded
// for both a second SIM and an account, are refused.
func (r Roles) CheckAccount(owner SIM, second Account) error {
	if owner == nil || second == nil {
		return ErrUnbound
	}
	o, ro := norm(owner.ICCID()), norm(r.OwnerICCID)
	a, ra := normAOR(second.AOR()), normAOR(r.SecondAccount)
	switch {
	case o == "" || ro == "" || a == "" || ra == "" || norm(r.SecondICCID) != "":
		return ErrUnbound
	case o != ro || a != ra:
		return ErrUnbound
	}
	return nil
}

// normAOR compares addresses of record without their scheme and with the
// domain's case folded; the user part is case-sensitive (RFC 3261 19.1.4).
func normAOR(aor string) string {
	aor = strings.TrimSpace(aor)
	for _, p := range []string{"sip:", "sips:"} {
		if len(aor) >= len(p) && strings.EqualFold(aor[:len(p)], p) {
			aor = aor[len(p):]
		}
	}
	user, host, ok := strings.Cut(aor, "@")
	if !ok || user == "" || host == "" {
		return ""
	}
	return user + "@" + strings.ToLower(host)
}

// Tool is the second-line tool.
type Tool struct {
	cfg     Config
	inbound chan Untrusted
}

// New checks the configuration. Without a second line the tool is
// unavailable and nothing more is checked. With one, the owner line, the
// owner's own number and the home country code are required (without them
// the owner-number guards would pass everything), both lines must be the
// SIMs recorded for their roles, their numbers must differ, and calls need
// disclosure audio.
func New(cfg Config) (*Tool, error) {
	if cfg.AnswerWait == 0 {
		cfg.AnswerWait = 60 * time.Second
	}
	t := &Tool{cfg: cfg, inbound: make(chan Untrusted, 64)}
	if cfg.Second == nil {
		close(t.inbound)
		return t, nil
	}
	if cfg.CountryCode == "" || cfg.OwnerPhone == "" || strings.HasPrefix(cfg.OwnerPhone, "alpha:") {
		return nil, ErrOwnerPhone
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
	if o == nil {
		return ErrUnbound
	}
	if same(s, o) {
		return ErrOwnerLine
	}
	switch s := s.(type) {
	case Account:
		if err := t.cfg.Roles.CheckAccount(o, s); err != nil {
			return err
		}
	case SIM:
		if err := t.cfg.Roles.Check(o, s); err != nil {
			return err
		}
	default:
		return ErrUnbound
	}
	if at.SameNumber(s.Number(), o.Number(), t.cfg.CountryCode) {
		return ErrOwnerLine
	}
	return nil
}

func same(s Line, o SIM) bool {
	if a, ok := s.(atLine); ok {
		if b, ok := o.(*at.Modem); ok {
			return a.Modem == b
		}
	}
	return any(s) == any(o)
}

// recipient refuses the owner's own phone and the box's two numbers.
func (t *Tool) recipient(to string) error {
	for _, n := range []string{t.cfg.OwnerPhone, t.cfg.Owner.Number(), t.cfg.Second.Number()} {
		if at.SameNumber(to, n, t.cfg.CountryCode) {
			return ErrRecipient
		}
	}
	return nil
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
	if err := t.recipient(to); err != nil {
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
	if err := t.recipient(to); err != nil {
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

// MainNumberText answers the owner when they text the second line.
const MainNumberText = "This is your box's second line. Text your box on its main number."

// pump runs until the second line's modem goes away. A text from the
// owner's own number never reaches an agent: the second line is not an
// owner channel, so codes and instructions sent to it are not read. The
// owner gets the fixed MainNumberText, at most once an hour.
func (t *Tool) pump() {
	in, done := t.cfg.Second.Inbox(), t.cfg.Second.Done()
	var told time.Time
	for {
		select {
		case <-done:
			return
		case m := <-in:
			if t.cfg.OwnerPhone != "" && !m.Alphanumeric && at.SameNumber(m.From, t.cfg.OwnerPhone, t.cfg.CountryCode) {
				if now := time.Now(); told.IsZero() || now.Sub(told) >= time.Hour {
					told = now
					_ = t.cfg.Second.Send(t.cfg.OwnerPhone, MainNumberText)
				}
				continue
			}
			select {
			case t.inbound <- Untrusted{From: m.From, Text: m.Text, At: m.At}:
			default: // unread third-party texts are dropped, never queued unbounded
			}
		}
	}
}
