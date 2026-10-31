// Package locks is the enforcer's rules for locks and alarms on its radios
// (SPEC NET-6, NET-4 Standing rules, NET-2 Texts and calls; briefs/ENF.md
// slice q). It sits between slice s's once-only challenges and the radio:
//
//   - An unlock or disarm runs only as the Actuator of an action.Book, so
//     only after the owner's passkey tap at home on a challenge naming the
//     device, the act and a short window. At an unusual time (Unusual) it
//     also needs a second passkey assertion over a challenge of its own
//     (Second, Confirm); a text reply never stands in for one, since only
//     the owner's passkey signs one.
//   - Every unlock it does or sees is logged; one at an unusual time is
//     texted (alert.UnusualUnlock, alert.UnusualDisarm). A lock relocks
//     RelockAfter after any unlock, whoever unlocked it.
//   - A visitor's keypad code is a signed standing rule (policy.StandingRule
//     with Action ActionCode). The enforcer sets it on the lock's own
//     PIN-code schedule, with the rule's window, only while the window is
//     open, and removes it when the window ends. A keypad unlock the lock
//     reports for a rule that is not open on that lock is refused: the lock
//     relocks at the next Tick.
//
// The radio is untrusted (radio.Host): what the lock reports (Seen) only
// ever adds a log line, a text or an earlier relock, never removes one.
//
// It is enforcer code: it imports the standard library, broker/kernel/key,
// broker/enforcer/policy, broker/enforcer/action and broker/enforcer/alert
// only (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package locks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// ActionCode is a standing rule's action for a visitor's keypad code on a
// lock: the code (a device secret, Config.Codes) works only inside the
// rule's window.
const ActionCode = "code"

const (
	// RelockAfter is how long a lock stays unlocked before the enforcer
	// relocks it (ASSUMPTIONS.md ENF-q-2).
	RelockAfter = time.Minute
	// UsualFrom and UsualTo bound the usual hours in the enforcer's zone,
	// [07:00, 22:00): any other time is unusual (ENF-q-3).
	UsualFrom = 7
	UsualTo   = 22
	// MaxRules bounds the distinct keypad rules kept for one device's
	// unlock reports between ticks; past it the lock relocks at once
	// (ENF-q-6).
	MaxRules = 4
	// expectFor is how long a report of the enforcer's own act counts as
	// that act, so it is not logged twice.
	expectFor = action.Timeout + 5*time.Second
	// retryAfter is how long a failed relock or code push waits before the
	// next try.
	retryAfter = 5 * time.Second
	// MinPIN and MaxPIN bound a keypad code's digits.
	MinPIN = 4
	MaxPIN = 12
)

// Domain prefixes what the passkey signs for a second assertion, so a tap
// on an action.Book challenge (action.Domain) can never be one.
const Domain = "agentos.enforcer.locks.second.v1\x00"

var (
	ErrNotLock   = errors.New("locks: only an unlock or a disarm goes through here")
	ErrSecond    = errors.New("at this hour an unlock or disarm also needs a second passkey tap on this page; open the link again and tap twice")
	ErrRefused   = errors.New("this device does not take that action")
	ErrLimited   = errors.New("too many approvals waiting; wait a minute")
	ErrGone      = errors.New("this approval has expired or was already used; open the link again")
	ErrNotOwner  = errors.New("your passkey did not approve this; open the link again and approve with your passkey")
	ErrMalformed = errors.New("locks: malformed")
)

// Code is one keypad code on a lock's own PIN-code schedule: it works only
// from FromMS until ToMS (exclusive), the window of the rule it serves.
type Code struct {
	Rule   string
	PIN    []byte
	FromMS int64
	ToMS   int64
}

// Driver is a lock's or alarm's stack, behind slice k's radio interface
// (slice t's adapters build it over radio.Host). Act carries out an unlock
// or a disarm under action.Actuator's contract. Lock locks a lock (its
// secure direction). SetCodes makes the enforcer's keypad codes on device
// exactly codes, each on the lock's own schedule, removing any other code
// the enforcer set before.
type Driver interface {
	action.Actuator
	Lock(ctx context.Context, device string) error
	SetCodes(ctx context.Context, device string, codes []Code) error
}

// Alerts is the enforcer's alert log, texts and calls (alert.Alerts).
type Alerts interface {
	Raise(k alert.Kind, device string) (alert.Record, error)
}

// Config is what a Gate needs. Every field but Now is required.
type Config struct {
	Owner  key.PublicKey // the owner's passkey (ES256, the enforcer's RP ID)
	Driver Driver
	Alerts Alerts
	// Codes returns rule's keypad code on device, from the enforcer's
	// device-secret store (slice r). It is never logged.
	Codes func(device, rule string) ([]byte, error)
	Zone  *time.Location // the enforcer's zone: what "unusual" is read in
	Now   func() time.Time
	Log   func(string)
}

// Report is what a lock or alarm reports it did.
type Report uint8

const (
	Unlocked Report = iota + 1
	Locked
	Disarmed
)

// Event is one report from a device's stack. Rule names the standing rule
// whose keypad code was used, or is empty.
type Event struct {
	Device string
	Report Report
	Rule   string
}

// Second is a second-assertion challenge: one unlock or disarm of one
// device at an unusual time, good once, until ExpiresMS.
type Second struct {
	ID        string
	Device    string
	Act       action.Act
	ExpiresMS int64
	Msg       []byte // what the passkey signs
}

// Gate holds the lock rules. It is the action.Actuator for every unlock
// and disarm (Act), and is safe for concurrent use. Close stops it.
type Gate struct {
	cfg Config

	mu      sync.Mutex
	seconds map[string]Second    // issued, not yet confirmed
	permits map[string]int64     // device+act -> confirmed until (ms)
	due     map[string]time.Time // lock -> when to relock
	// pend is the earliest relock deadline of the unlocks since that
	// lock's last relock began, so a relock in flight cannot clear one.
	pend   map[string]time.Time
	failed map[string]bool      // lock -> a relock failed (logged once)
	expect map[string]time.Time // device+report -> own act counts until
	sent   map[string][]Code    // lock -> codes last pushed (PINs dropped)
	retry  map[string]time.Time // lock -> next code push try
	busy   map[string]bool      // lock -> its relock or code push is running

	// The radio's reports since the last Tick, one entry per device and
	// report, for the locks and alarms the last Tick's policy holds.
	known   map[string]policy.Device
	reports map[string]*seenReport
	dropped int

	// Alerts wait here for the teller, one entry per kind and device, so
	// neither Act nor Tick waits on the alert log, whose texts the core
	// carries (ENF-q-11).
	tells   map[tell]bool
	telling bool
	wake    chan struct{}
	done    chan struct{}
}

type seenReport struct {
	n     int
	rules []string // the distinct keypad rules named, at most MaxRules
	over  bool     // more than MaxRules were named
}

type tell struct {
	kind   alert.Kind
	device string
}

// New returns a gate over cfg and starts its teller.
func New(cfg Config) (*Gate, error) {
	if cfg.Owner.Alg() != key.AlgES256 || cfg.Driver == nil || cfg.Alerts == nil || cfg.Codes == nil || cfg.Zone == nil || cfg.Log == nil {
		return nil, errors.New("locks: config incomplete")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g := &Gate{
		cfg: cfg, seconds: map[string]Second{}, permits: map[string]int64{},
		due: map[string]time.Time{}, pend: map[string]time.Time{}, failed: map[string]bool{}, expect: map[string]time.Time{},
		sent: map[string][]Code{}, retry: map[string]time.Time{}, busy: map[string]bool{},
		known: map[string]policy.Device{}, reports: map[string]*seenReport{},
		tells: map[tell]bool{}, wake: make(chan struct{}, 1), done: make(chan struct{}),
	}
	go g.teller()
	return g, nil
}

// Close stops the teller. Alerts still waiting are dropped.
func (g *Gate) Close() { close(g.done) }

// Unusual reports whether t is an unusual time in zone: outside
// [UsualFrom, UsualTo) by the zone's own clock.
func Unusual(t time.Time, zone *time.Location) bool {
	h := t.In(zone).Hour()
	return h < UsualFrom || h >= UsualTo
}

// Unusual reports whether now is an unusual time, so the page knows to ask
// for a second tap.
func (g *Gate) Unusual() bool { return Unusual(g.cfg.Now(), g.cfg.Zone) }

func gated(a action.Act) bool { return a == action.Unlock || a == action.Disarm }

// Act carries out an unlock or a disarm the owner's tap on an action.Book
// challenge approved. At an unusual time it also spends the second
// assertion Confirm took for that device and act, and without one refuses
// with ErrSecond before anything reaches the device. A lock is due to
// relock RelockAfter from now before the unlock is sent, so even an unlock
// whose answer never comes is relocked. The unlock or disarm is logged,
// and texted at an unusual time.
func (g *Gate) Act(ctx context.Context, device string, a action.Act, route string) error {
	if !gated(a) || route != "" {
		return ErrNotLock
	}
	now := g.cfg.Now()
	unusual := Unusual(now, g.cfg.Zone)
	g.mu.Lock()
	if unusual {
		k := device + "\x00" + string(a)
		until, ok := g.permits[k]
		delete(g.permits, k)
		if !ok || until <= now.UnixMilli() {
			g.mu.Unlock()
			return ErrSecond
		}
	}
	report := Disarmed
	if a == action.Unlock {
		report = Unlocked
		g.unlockAt(device, now.Add(RelockAfter))
	}
	g.expect[device+"\x00"+strconv.Itoa(int(report))] = now.Add(expectFor)
	g.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := g.cfg.Driver.Act(ctx, device, a, ""); err != nil {
		// The act may still have reached the device (action.Actuator), so
		// the lock's own report of it must be told, not taken as ours.
		g.mu.Lock()
		delete(g.expect, device+"\x00"+strconv.Itoa(int(report)))
		g.mu.Unlock()
		return err
	}
	g.told(device, report, unusual)
	return nil
}

// told logs an unlock, disarm or relock of device, and texts an unlock or
// disarm at an unusual time. It never waits on the alert log: the teller
// raises the alert, once for repeats of one kind on one device, which the
// alert log folds anyway.
func (g *Gate) told(device string, r Report, unusual bool) {
	var k alert.Kind
	switch {
	case r == Unlocked && unusual:
		k = alert.UnusualUnlock
	case r == Unlocked:
		k = alert.RoutineUnlock
	case r == Disarmed && unusual:
		k = alert.UnusualDisarm
	case r == Disarmed:
		g.cfg.Log(device + " disarmed.")
		return
	case r == Locked:
		k = alert.RoutineLock
	}
	g.mu.Lock()
	g.tells[tell{k, device}] = true
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

// teller raises the waiting alerts, one at a time.
// A raise the core holds up holds up only the alerts behind it.
func (g *Gate) teller() {
	for {
		select {
		case <-g.done:
			return
		case <-g.wake:
		}
		for {
			g.mu.Lock()
			batch := g.tells
			g.telling = len(batch) > 0
			if !g.telling {
				g.mu.Unlock()
				break
			}
			g.tells = map[tell]bool{}
			g.mu.Unlock()
			for t := range batch {
				if _, err := g.cfg.Alerts.Raise(t.kind, t.device); err != nil {
					g.cfg.Log(fmt.Sprintf("locks: alert for %s not raised: %v", t.device, err))
				}
			}
		}
	}
}

// unlockAt records an unlock of lock that must relock by at. Under g.mu.
func (g *Gate) unlockAt(lock string, at time.Time) {
	g.relockBy(lock, at)
	if p, ok := g.pend[lock]; !ok || at.Before(p) {
		g.pend[lock] = at
	}
}

// relockBy makes lock due to relock no later than at. Under g.mu.
func (g *Gate) relockBy(lock string, at time.Time) {
	if d, ok := g.due[lock]; !ok || at.Before(d) {
		g.due[lock] = at
	}
}

// Second draws a second-assertion challenge for an unlock or disarm of
// device in doc, the policy in force. A device ID is a policy name, which
// holds no control character, so it cannot forge another field of Msg.
func (g *Gate) Second(doc policy.Document, device string, a action.Act) (Second, error) {
	if !gated(a) {
		return Second{}, ErrMalformed
	}
	dev := doc.Device(device)
	if dev == nil || !action.Takes(*dev, a) {
		return Second{}, ErrRefused
	}
	now := g.cfg.Now().UnixMilli()
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, s := range g.seconds {
		if s.ExpiresMS <= now {
			delete(g.seconds, id)
		}
	}
	if len(g.seconds) >= action.MaxLive {
		return Second{}, ErrLimited
	}
	s := Second{ID: newID(), Device: device, Act: a, ExpiresMS: now + action.Window.Milliseconds()}
	s.Msg = []byte(Domain + s.Device + "\x00" + string(s.Act) + "\x00unusual-time\x00" + s.ID + "\x00" + strconv.FormatInt(s.ExpiresMS, 10))
	g.seconds[s.ID] = s
	return s, nil
}

// Confirm spends second challenge id, whether or not sig verifies, and,
// if sig is the owner's assertion over it (key.AssertionSig form) inside
// its window, lets one unlock or disarm of that device go ahead at an
// unusual time until the window ends.
func (g *Gate) Confirm(id string, sig []byte) error {
	now := g.cfg.Now().UnixMilli()
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.seconds[id]
	delete(g.seconds, id)
	if !ok || s.ExpiresMS <= now {
		return ErrGone
	}
	if len(sig) == 0 || !g.cfg.Owner.Verify(s.Msg, sig) {
		return ErrNotOwner
	}
	g.permits[s.Device+"\x00"+string(s.Act)] = s.ExpiresMS
	return nil
}

// Seen takes one report from a device's stack. It never blocks and never
// calls the driver, so the radio host's read loop may call it; Tick acts
// on it. Reports are kept per device and report, and only for the locks
// and alarms the last Tick's policy holds, so a stack that floods cannot
// crowd out another device's report (ENF-q-6). The daemon ticks once
// before it attaches any stack.
func (g *Gate) Seen(e Event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	dev, ok := g.known[e.Device]
	if !ok || !fits(dev, e.Report) {
		g.dropped++
		return
	}
	k := e.Device + "\x00" + strconv.Itoa(int(e.Report))
	p := g.reports[k]
	if p == nil {
		p = &seenReport{}
		g.reports[k] = p
	}
	p.n++
	if e.Rule != "" && !p.over && !slices.Contains(p.rules, e.Rule) {
		if len(p.rules) >= MaxRules {
			p.over = true
		} else {
			p.rules = append(p.rules, e.Rule)
		}
	}
}

// fits reports whether dev can make report r: a lock locks and unlocks,
// an alarm disarms.
func fits(dev policy.Device, r Report) bool {
	switch r {
	case Unlocked, Locked:
		return lock(dev)
	case Disarmed:
		return !dev.Everyday && dev.Class == policy.ClassAlarm
	}
	return false
}

// Tick applies doc, the policy in force, at now: it acts on the reports
// since the last tick, then starts, for each lock whose last one has
// ended, its relock when due and its keypad-code push when the codes
// changed. It does not wait for them, so one stack that hangs delays no
// other lock. The daemon calls it about once a second, never under the
// policy lock the page holds around a redeem.
func (g *Gate) Tick(doc policy.Document) {
	now := g.cfg.Now()
	known := map[string]policy.Device{}
	for _, dev := range doc.Devices {
		if fits(dev, Unlocked) || fits(dev, Disarmed) {
			known[dev.ID] = dev
		}
	}
	g.mu.Lock()
	reports, dropped := g.reports, g.dropped
	g.known, g.reports, g.dropped = known, map[string]*seenReport{}, 0
	for l := range g.due {
		if _, ok := known[l]; !ok || !lock(known[l]) {
			delete(g.due, l)
		}
	}
	g.mu.Unlock()
	if dropped > 0 {
		g.cfg.Log(fmt.Sprintf("locks: %d reports for devices that cannot make them, dropped", dropped))
	}
	keys := make([]string, 0, len(reports))
	for k := range reports {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		device, r, _ := strings.Cut(k, "\x00")
		n, _ := strconv.Atoi(r)
		g.seen(doc, device, Report(n), reports[k], now)
	}
	for _, dev := range doc.Devices {
		if !lock(dev) {
			continue
		}
		g.mu.Lock()
		run := !g.busy[dev.ID]
		g.busy[dev.ID] = true
		g.mu.Unlock()
		if run {
			go g.work(doc, dev.ID, now)
		}
	}
}

// lock reports whether dev is a lock on the safety list.
func lock(dev policy.Device) bool { return !dev.Everyday && dev.Class == policy.ClassLock }

// seen acts on one device's reports of one kind: one may be the enforcer's
// own act, already told; the rest are logged, an unlock or disarm at an
// unusual time texted. An unlock relocks after RelockAfter, or at once
// when it named a keypad rule that is not an open code rule on that lock,
// or more rules than MaxRules.
func (g *Gate) seen(doc policy.Document, device string, r Report, p *seenReport, now time.Time) {
	if dev := doc.Device(device); dev == nil || !fits(*dev, r) {
		return
	}
	g.mu.Lock()
	k := device + "\x00" + strconv.Itoa(int(r))
	n := p.n
	if now.Before(g.expect[k]) {
		n--
	}
	delete(g.expect, k)
	refused := false
	if r == Unlocked {
		refused = p.over
		for _, rule := range p.rules {
			if !open(doc, device, rule, now) {
				refused = true
			}
		}
		at := now.Add(RelockAfter)
		if refused {
			at = now
		}
		g.unlockAt(device, at)
	}
	g.mu.Unlock()
	if refused {
		g.cfg.Log("locks: " + device + " was unlocked with a keypad code outside its signed window; relocking it now")
	}
	if n > 0 {
		g.told(device, r, Unusual(now, g.cfg.Zone))
	}
}

// open reports whether rule is a keypad-code rule on device whose window
// is open at now.
func open(doc policy.Document, device, rule string, now time.Time) bool {
	for _, r := range doc.Active(device, now.UnixMilli()) {
		if r.ID == rule && r.Action == ActionCode {
			return true
		}
	}
	return false
}

// work relocks lock if it is due, then pushes its keypad codes.
func (g *Gate) work(doc policy.Document, lock string, now time.Time) {
	defer func() {
		g.mu.Lock()
		delete(g.busy, lock)
		g.mu.Unlock()
	}()
	g.relock(lock, now)
	g.codes(doc, lock, now)
}

// codes pushes lock's keypad codes when the set open now differs from what
// was last pushed, and on the first tick, so a code left from before a
// restart is removed.
func (g *Gate) codes(doc policy.Document, lock string, now time.Time) {
	var want []Code
	for _, r := range doc.Active(lock, now.UnixMilli()) {
		if r.Action == ActionCode {
			want = append(want, Code{Rule: r.ID, FromMS: r.FromMS, ToMS: r.ToMS})
		}
	}
	g.mu.Lock()
	last, pushed := g.sent[lock]
	wait := now.Before(g.retry[lock])
	g.mu.Unlock()
	if (pushed && slices.EqualFunc(last, want, sameCode)) || wait {
		return
	}
	out := make([]Code, 0, len(want))
	for _, c := range want {
		pin, err := g.cfg.Codes(lock, c.Rule)
		if err != nil || !digits(pin) {
			g.cfg.Log("locks: no usable keypad code held for rule " + c.Rule + " on " + lock + "; it is not set")
			continue
		}
		c.PIN = pin
		out = append(out, c)
	}
	ctx, cancel := context.WithTimeout(context.Background(), action.Timeout)
	err := g.cfg.Driver.SetCodes(ctx, lock, out)
	cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		delete(g.sent, lock)
		g.retry[lock] = now.Add(retryAfter)
		g.cfg.Log(fmt.Sprintf("locks: keypad codes on %s not set: %v", lock, err))
		return
	}
	delete(g.retry, lock)
	g.sent[lock] = want
}

func sameCode(a, b Code) bool { return a.Rule == b.Rule && a.FromMS == b.FromMS && a.ToMS == b.ToMS }

// relock locks l if it is due. A relock that fails is tried again after
// retryAfter, logged once until one succeeds.
func (g *Gate) relock(l string, now time.Time) {
	g.mu.Lock()
	at, ok := g.due[l]
	if !ok || now.Before(at) {
		g.mu.Unlock()
		return
	}
	g.expect[l+"\x00"+strconv.Itoa(int(Locked))] = now.Add(expectFor)
	delete(g.pend, l)
	g.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), action.Timeout)
	err := g.cfg.Driver.Lock(ctx, l)
	cancel()
	g.mu.Lock()
	if err != nil {
		delete(g.expect, l+"\x00"+strconv.Itoa(int(Locked)))
		g.due[l] = now.Add(retryAfter)
		first := !g.failed[l]
		g.failed[l] = true
		g.mu.Unlock()
		if first {
			g.cfg.Log(fmt.Sprintf("locks: relocking %s failed, trying again: %v", l, err))
		}
		return
	}
	// An unlock while this relock ran needs its own relock, even when it
	// came after the lock command did.
	if p, ok := g.pend[l]; ok {
		g.due[l] = p
	} else {
		delete(g.due, l)
	}
	delete(g.failed, l)
	g.mu.Unlock()
	g.told(l, Locked, false)
}

// digits is a keypad code: MinPIN to MaxPIN ASCII digits.
func digits(b []byte) bool {
	if len(b) < MinPIN || len(b) > MaxPIN {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
