package radio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// Device is one device a stack serves, as the signed policy names it: the
// stack that reaches it, and the characteristics an op may name (BLE).
type Device struct {
	Name  string
	Stack Stack
	Chars []string
}

// Notification is a notification from a subscribed characteristic.
type Notification struct {
	Device, Char string
	Data         []byte
}

// Config is what a Host serves.
type Config struct {
	Devices []Device
	// Notify takes each notification; it runs on the stack's read loop, so
	// it must not call back into Host.
	Notify func(Notification)
	// Log takes one line per refusal and per link that ended.
	Log func(string)
	// Timeout bounds the wait for one answer (default 10 s).
	Timeout time.Duration
}

var (
	ErrUnknownDevice = errors.New("radio: device not in the policy")
	ErrNoStack       = errors.New("radio: stack not running")
	ErrTimeout       = errors.New("radio: no answer in time")
	ErrRefused       = errors.New("radio: the stack refused")
	ErrFailed        = errors.New("radio: the radio failed")
	ErrUnreachable   = errors.New("radio: the device did not answer")
)

// Host is the enforcer's end of every stack's command interface. It
// implements channel.Radio.
type Host struct {
	cfg     Config
	devices map[string]Device

	mu    sync.Mutex
	links map[Stack]*link
	next  uint64
}

// Conn is a stack's link: a socket the host can put a write deadline on,
// so a stack that stops reading cannot hold a caller past Config.Timeout.
// The *os.File confine.Start returns and a net.Conn both are.
type Conn interface {
	io.ReadWriteCloser
	SetWriteDeadline(time.Time) error
}

// maxExpired bounds the requests a link may leave unanswered past their
// timeout; past it the stack is treated as dead.
const maxExpired = 64

type link struct {
	stack   Stack
	conn    Conn
	wmu     sync.Mutex
	pending map[uint64]pending // under Host.mu
	expired map[uint64]string  // timed-out requests' devices, under Host.mu
	dead    bool               // under Host.mu
}

type pending struct {
	device string
	answer chan Up
}

// NewHost serves cfg's devices. A device on a stack nothing declares, or
// named twice, is refused.
func NewHost(cfg Config) (*Host, error) {
	if cfg.Notify == nil || cfg.Log == nil {
		return nil, errors.New("radio: config incomplete")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	h := &Host{cfg: cfg, devices: map[string]Device{}, links: map[Stack]*link{}}
	for _, d := range cfg.Devices {
		if _, dup := h.devices[d.Name]; dup || !name(d.Name) || Declared[d.Stack] == nil {
			return nil, fmt.Errorf("radio: device %q refused", d.Name)
		}
		for _, c := range d.Chars {
			if !name(c) {
				return nil, fmt.Errorf("radio: device %q characteristic refused", d.Name)
			}
		}
		h.devices[d.Name] = d
	}
	return h, nil
}

// Attach makes conn stack s's command interface, replacing any earlier
// link (a restarted process), and reads its answers until it ends.
func (h *Host) Attach(s Stack, conn Conn) error {
	if Declared[s] == nil {
		return fmt.Errorf("radio: stack %q not declared", s)
	}
	l := &link{stack: s, conn: conn, pending: map[uint64]pending{}, expired: map[uint64]string{}}
	h.mu.Lock()
	old := h.links[s]
	h.links[s] = l
	h.mu.Unlock()
	if old != nil {
		h.fail(old, "replaced")
	}
	go h.readLoop(l)
	return nil
}

// Call sends r to the stack that serves r.Device and waits for its answer.
// The op must be declared for that stack, and a characteristic must be one
// the policy lists for the device; otherwise nothing is sent.
func (h *Host) Call(r Request) ([]byte, error) { return h.Send(context.Background(), r) }

// Send is Call for a caller with a deadline of its own (an asserted
// action, action.Actuator): it checks ctx under the lock that orders the
// link's writes, in the same step as the write, so it never starts a send
// once ctx has ended, and a send it did start is ordered before every
// later one on the link (a relock). It stops waiting for the answer when
// ctx ends, as at Config.Timeout.
func (h *Host) Send(ctx context.Context, r Request) ([]byte, error) {
	d, ok := h.devices[r.Device]
	if !ok {
		h.cfg.Log(fmt.Sprintf("radio: refused %s for unknown device", r.Op))
		return nil, ErrUnknownDevice
	}
	h.mu.Lock()
	h.next++
	r.ID = h.next
	h.mu.Unlock()
	if err := r.Check(d.Stack); err != nil {
		h.cfg.Log(fmt.Sprintf("radio: refused %s on %s: %v", r.Op, d.Stack, err))
		return nil, err
	}
	if r.Char != "" && !slices.Contains(d.Chars, r.Char) {
		h.cfg.Log(fmt.Sprintf("radio: refused %s on an undeclared characteristic", r.Op))
		return nil, ErrNotDeclared
	}
	h.mu.Lock()
	l := h.links[d.Stack]
	if l == nil || l.dead {
		h.mu.Unlock()
		return nil, ErrNoStack
	}
	answer := make(chan Up, 1)
	l.pending[r.ID] = pending{device: r.Device, answer: answer}
	h.mu.Unlock()

	// One deadline bounds the write and the answer together.
	deadline := time.Now().Add(h.cfg.Timeout)
	timer := time.NewTimer(h.cfg.Timeout)
	defer timer.Stop()
	l.wmu.Lock()
	if err := ctx.Err(); err != nil {
		l.wmu.Unlock()
		h.mu.Lock()
		delete(l.pending, r.ID)
		h.mu.Unlock()
		return nil, err
	}
	err := l.conn.SetWriteDeadline(deadline)
	if err == nil {
		err = write(l.conn, r)
	}
	l.wmu.Unlock()
	if err != nil {
		h.fail(l, "write: "+err.Error())
		return nil, ErrNoStack
	}
	select {
	case u, ok := <-answer:
		if !ok {
			return nil, ErrNoStack
		}
		switch u.Code {
		case CodeOK:
			return u.Data, nil
		case CodeRefused:
			return nil, ErrRefused
		case CodeUnreachable:
			return nil, ErrUnreachable
		}
		return nil, ErrFailed
	case <-timer.C:
		return nil, h.expire(l, r)
	case <-ctx.Done():
		return nil, h.expire(l, r)
	}
}

// expire gives up waiting for r's answer. A late answer is dropped, not
// taken as unasked; a stack that leaves too many unanswered is dead.
func (h *Host) expire(l *link, r Request) error {
	h.mu.Lock()
	_, still := l.pending[r.ID]
	delete(l.pending, r.ID)
	if still {
		l.expired[r.ID] = r.Device
	}
	dead := len(l.expired) > maxExpired
	h.mu.Unlock()
	if dead {
		h.fail(l, "too many requests unanswered")
	}
	return ErrTimeout
}

// verbs maps the channel's device verbs to ops.
var verbs = map[wire.Verb]Op{
	wire.VerbOn: OpOn, wire.VerbOff: OpOff, wire.VerbLevel: OpLevel, wire.VerbLock: OpLock,
	wire.VerbShut: OpShut, wire.VerbClose: OpClose, wire.VerbReturnToDock: OpReturnToDock,
}

// Do carries out one channel device command (channel.Radio).
func (h *Host) Do(device string, v wire.Verb, level uint8) error {
	op, ok := verbs[v]
	if !ok {
		return ErrNotDeclared
	}
	_, err := h.Call(Request{Op: op, Device: device, Level: level})
	return err
}

// State reads a device (channel.Radio).
func (h *Host) State(device string) ([]byte, error) {
	return h.Call(Request{Op: OpRead, Device: device})
}

// readLoop takes the stack's messages until the link ends. Anything that
// does not decode, answers no outstanding request, or names a device or
// characteristic the stack does not serve ends the link: the process is
// untrusted, so it gets no second parse.
func (h *Host) readLoop(l *link) {
	for {
		var u Up
		if err := read(l.conn, &u); err != nil {
			h.fail(l, "read: "+err.Error())
			return
		}
		if err := u.check(); err != nil {
			h.fail(l, "malformed message")
			return
		}
		if u.ID == 0 {
			d, ok := h.devices[u.Device]
			if !ok || d.Stack != l.stack || !slices.Contains(d.Chars, u.Char) {
				h.fail(l, "notification for an undeclared device or characteristic")
				return
			}
			h.cfg.Notify(Notification{Device: u.Device, Char: u.Char, Data: u.Data})
			continue
		}
		h.mu.Lock()
		p, ok := l.pending[u.ID]
		delete(l.pending, u.ID)
		late, expired := l.expired[u.ID]
		delete(l.expired, u.ID)
		h.mu.Unlock()
		switch {
		case ok && p.device == u.Device:
			p.answer <- u
		case !ok && expired && late == u.Device:
			// the answer to a request that already timed out
		default:
			if ok {
				close(p.answer)
			}
			h.fail(l, "answer to no outstanding request")
			return
		}
	}
}

// fail ends a link once: it closes the connection and fails every waiter.
func (h *Host) fail(l *link, why string) {
	h.mu.Lock()
	if l.dead {
		h.mu.Unlock()
		return
	}
	l.dead = true
	waiters := l.pending
	l.pending = map[uint64]pending{}
	if h.links[l.stack] == l {
		delete(h.links, l.stack)
	}
	h.mu.Unlock()
	h.cfg.Log(fmt.Sprintf("radio: %s link ended: %s", l.stack, why))
	l.conn.Close()
	for _, p := range waiters {
		close(p.answer)
	}
}
