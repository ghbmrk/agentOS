// Package action is the enforcer's asserted actions on safety-list devices
// (SPEC NET-4 Tightening, NET-6; briefs/ENF.md slice s). Every turn-on or
// open of a safety-list device, every unlock or disarm, and the device
// commands NET-4 puts beside the asserted tightenings (turning a camera
// off, arming an alarm) run only on the owner's passkey assertion over a
// challenge that names the device, the action and a short window, and each
// challenge works once. The page (slice b) serves the challenge, only at
// home; the channel has no path here at all, so a channel request for one
// of these becomes a texted link (Link), never an action.
//
// The asserted tightenings that change the policy (cutting a safety-list
// device's vendor cloud, isolating or removing it) are policy versions:
// TighteningLink is their link, and the page applies them through
// policy.Engine.Propose at once, with no wait.
//
// It is enforcer code: it imports the standard library, broker/kernel/key
// and broker/enforcer/policy only (broker/daemon/arc2_test.go). Its
// assumptions are in ASSUMPTIONS.md.
package action

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Act is one asserted action, from the closed list below.
type Act string

const (
	On     Act = "on"     // turn on: a heater, primary heating, an oven, a plug, a relay, a camera, a microphone
	Open   Act = "open"   // a valve, a feeding valve, a garage door
	Fly    Act = "fly"    // a drone, on one named route
	Unlock Act = "unlock" // a lock (slice q's rules sit on top)
	Disarm Act = "disarm" // an alarm (slice q's rules sit on top)
	Off    Act = "off"    // a camera or a microphone: stops what it records and its alerts
	Arm    Act = "arm"    // an alarm
)

// table is which acts each safety class takes. A class it does not name
// (a siren, a sensor, a device of unknown type) takes none, and an everyday
// device takes none here: its commands are the channel's.
var table = map[string][]Act{
	policy.ClassHeater:         {On},
	policy.ClassPrimaryHeating: {On},
	policy.ClassOven:           {On},
	policy.ClassPlug:           {On},
	policy.ClassRelay:          {On},
	policy.ClassValve:          {Open},
	policy.ClassFeedValve:      {Open},
	policy.ClassGarageDoor:     {Open},
	policy.ClassDrone:          {Fly},
	policy.ClassLock:           {Unlock},
	policy.ClassAlarm:          {Arm, Disarm},
	policy.ClassCamera:         {On, Off},
	policy.ClassMicrophone:     {On, Off},
}

// Takes reports whether dev takes act a through a challenge: dev is on the
// safety list, not isolated, and its class takes a.
func Takes(dev policy.Device, a Act) bool {
	return !dev.Everyday && !dev.Isolated && slices.Contains(table[dev.Class], a)
}

// Acts is the closed list, for the page and the tests.
func Acts() []Act { return []Act{On, Open, Fly, Unlock, Disarm, Off, Arm} }

// Actuator carries out one verified action: the radio host (slice k), or a
// driver behind it (slice q, a camera's settings channel), wired by the
// daemon (slice l). route is empty except for Fly.
//
// Act must return within Timeout. The book stops waiting then and reports
// ErrTimeout, so a hung call cannot hold the policy lock the page takes
// around Redeem, which the channel's relocks share. An act already sent
// when the book stops waiting must stay ordered before every later command
// to the same device (the radio host sends a stack's commands in order on
// one link), so a relock that lands after a timeout still wins.
type Actuator interface {
	Act(device string, a Act, route string) error
}

// Window is how long a challenge lasts: the short window NET-6 names.
// MaxLive bounds the challenges held at once, so the Owner network cannot
// fill the enforcer's memory. Timeout bounds one Actuator call, as the
// radio host bounds one answer.
const (
	Window  = 2 * time.Minute
	MaxLive = 16
	Timeout = 10 * time.Second
	maxName = 64
)

// Domain prefixes what the passkey signs for an action, so an assertion
// for a policy version or a page action can never be one here.
const Domain = "agentos.enforcer.action.v1\x00"

var (
	ErrRefused   = errors.New("this device does not take that action")
	ErrMalformed = errors.New("this link is malformed")
	ErrLimited   = errors.New("too many approvals waiting; wait a minute")
	ErrGone      = errors.New("this approval has expired or was already used; open the link again")
	ErrNotOwner  = errors.New("your passkey did not approve this action; open the link again and approve with your passkey")
	ErrMoved     = errors.New("the device changed since this page was drawn; open the link again")
	ErrTimeout   = errors.New("the device did not answer in time and may still do it; check the device before you open the link again")
)

var errPanicked = errors.New("action: the actuator failed")

// Challenge is one tap the owner is asked for: one act on one device, good
// once, until ExpiresMS.
type Challenge struct {
	ID        string
	Device    string
	Class     string // the device's class when drawn; it must be unchanged
	Act       Act
	Route     string // Fly only
	ExpiresMS int64
	Msg       []byte // what the passkey signs (its SHA-256 is the WebAuthn challenge)
}

// Book holds the live challenges and does each action once, after the
// owner's assertion. It is safe for concurrent use.
type Book struct {
	owner   key.PublicKey
	act     Actuator
	timeout time.Duration
	mu      sync.Mutex
	live    map[string]Challenge
}

// NewBook returns a book whose actions owner approves and act carries out,
// waiting at most timeout for each: zero means Timeout, and a longer or
// negative one is refused, so the bound can only be tightened.
func NewBook(owner key.PublicKey, act Actuator, timeout time.Duration) (*Book, error) {
	if timeout == 0 {
		timeout = Timeout
	}
	if owner.Alg() != key.AlgES256 || act == nil || timeout < 0 || timeout > Timeout {
		return nil, errors.New("action: bad config")
	}
	return &Book{owner: owner, act: act, timeout: timeout, live: map[string]Challenge{}}, nil
}

// Issue draws a challenge for act a on device in doc, the policy in force.
// Only Fly names a route.
func (b *Book) Issue(doc policy.Document, device string, a Act, route string, nowMS int64) (Challenge, error) {
	if !text(device) || (a == Fly) != (route != "") || (route != "" && !text(route)) {
		return Challenge{}, ErrMalformed
	}
	dev := doc.Device(device)
	if dev == nil || !Takes(*dev, a) {
		return Challenge{}, ErrRefused
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, c := range b.live {
		if c.ExpiresMS <= nowMS {
			delete(b.live, id)
		}
	}
	if len(b.live) >= MaxLive {
		return Challenge{}, ErrLimited
	}
	c := Challenge{ID: newID(), Device: device, Class: dev.Class, Act: a, Route: route, ExpiresMS: nowMS + Window.Milliseconds()}
	c.Msg = msg(c)
	b.live[c.ID] = c
	return c, nil
}

// Redeem spends challenge id, whether or not sig verifies, and, if sig is
// the owner's assertion over it (key.AssertionSig form), the window has
// not passed and the device in doc, the policy in force, still takes the
// act with the class it had, carries the act out at once. It waits for the
// actuator at most the book's timeout and then returns ErrTimeout.
func (b *Book) Redeem(doc policy.Document, id string, sig []byte, nowMS int64) (Challenge, error) {
	b.mu.Lock()
	c, ok := b.live[id]
	delete(b.live, id)
	b.mu.Unlock()
	if !ok || c.ExpiresMS <= nowMS {
		return Challenge{}, ErrGone
	}
	if len(sig) == 0 || !b.owner.Verify(c.Msg, sig) {
		return Challenge{}, ErrNotOwner
	}
	dev := doc.Device(c.Device)
	if dev == nil || dev.Class != c.Class || !Takes(*dev, c.Act) {
		return Challenge{}, ErrMoved
	}
	if err := b.call(c); err != nil {
		return Challenge{}, err
	}
	return c, nil
}

// call runs the actuator for c and waits for it at most the book's
// timeout. A call still running then is left to finish on its own; its
// result is dropped. A panicking actuator is a failed act, not a crash of
// the enforcer.
func (b *Book) call(c Challenge) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- errPanicked
			}
		}()
		done <- b.act.Act(c.Device, c.Act, c.Route)
	}()
	t := time.NewTimer(b.timeout)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		return ErrTimeout
	}
}

// msg is what the passkey signs: the domain, then the device, its class,
// the act, the route, the challenge's own ID and its expiry, so one tap
// does one named act on one device once, inside its window.
func msg(c Challenge) []byte {
	s := Domain + c.Device + "\x00" + c.Class + "\x00" + string(c.Act) + "\x00" + c.Route + "\x00" + c.ID + "\x00" + strconv.FormatInt(c.ExpiresMS, 10)
	return []byte(s)
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// text is a device or route name a challenge may carry: short, printable
// ASCII with no separator, so a name cannot forge another field of msg.
func text(s string) bool {
	if s == "" || len(s) > maxName {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// Link is the page link for act a on device: what the enforcer texts the
// owner when the channel asks for one of these, since the channel never
// carries them out (NET-4, NET-6). name is the enforcer's own name.
func Link(name, device string, a Act, route string) string {
	q := url.Values{"d": {device}, "a": {string(a)}}
	if route != "" {
		q.Set("r", route)
	}
	return "https://" + name + "/a?" + q.Encode()
}

// TighteningLink is the page link for an asserted tightening the channel
// asked for and the policy refused without the owner (policy.ErrNeedsOwner):
// the policy in force with op applied, as a proposal link the page renders
// itself and applies at once on the owner's tap.
func TighteningLink(name string, cur policy.Document, op policy.Op) (string, error) {
	next, ok := policy.Apply(cur, op)
	if !ok {
		return "", ErrRefused
	}
	b, err := policy.Encode(next)
	if err != nil {
		return "", err
	}
	return "https://" + name + "/p?d=" + base64.RawURLEncoding.EncodeToString(b), nil
}
