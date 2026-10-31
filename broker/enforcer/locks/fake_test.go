package locks_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/locks"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const rp = "enforcer.home.arpa"

// zone is the enforcer's zone in every test: a fixed offset, so a test's
// clock times read the same on any machine.
var zone = time.FixedZone("test", -5*60*60)

// at is a time on 2026-11-03 in zone.
func at(hour, min int) time.Time { return time.Date(2026, 11, 3, hour, min, 0, 0, zone) }

// phone is the owner's passkey.
type phone struct {
	t    *testing.T
	priv *ecdsa.PrivateKey
}

func newPhone(t *testing.T) *phone {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &phone{t: t, priv: p}
}

func (p *phone) public() key.PublicKey {
	point, _ := p.priv.PublicKey.Bytes()
	pk, err := key.ES256(rp, point)
	if err != nil {
		p.t.Fatal(err)
	}
	return pk
}

// sign is a tap over msg, with user verification, in key.AssertionSig's
// form, as a browser on the enforcer's origin returns it.
func (p *phone) sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]), "origin": "https://" + rp, "crossOrigin": false})
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, m[:])
	if err != nil {
		p.t.Fatal(err)
	}
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		p.t.Fatal(err)
	}
	return b
}

// clock is the tests' time.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) set(t time.Time)     { c.mu.Lock(); c.now = t; c.mu.Unlock() }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

// radio is the fake radio: one stack serving Door Lock and alarm devices
// as the Door Lock cluster does. Each lock keeps its own state and its own
// PIN-code users, each with a schedule; a keypad entry works only for a
// code on the lock inside its schedule, by the lock's own clock.
type radio struct {
	clock *clock
	mu    sync.Mutex
	locks map[string]*fakeLock
	calls []string // every command, in order
	fail  error    // when set, every command fails
}

type fakeLock struct {
	unlocked bool
	disarmed bool
	codes    []locks.Code
}

func newRadio(c *clock, devices ...string) *radio {
	r := &radio{clock: c, locks: map[string]*fakeLock{}}
	for _, d := range devices {
		r.locks[d] = &fakeLock{}
	}
	return r
}

func (r *radio) dev(device string) (*fakeLock, error) {
	if r.fail != nil {
		return nil, r.fail
	}
	l, ok := r.locks[device]
	if !ok {
		return nil, errors.New("radio: no such device")
	}
	return l, nil
}

func (r *radio) Act(ctx context.Context, device string, a action.Act, route string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	r.calls = append(r.calls, fmt.Sprintf("%s %s", a, device))
	l, err := r.dev(device)
	if err != nil {
		return err
	}
	switch a {
	case action.Unlock:
		l.unlocked = true
	case action.Disarm:
		l.disarmed = true
	default:
		return errors.New("radio: not declared")
	}
	return nil
}

func (r *radio) Lock(ctx context.Context, device string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, "lock "+device)
	l, err := r.dev(device)
	if err != nil {
		return err
	}
	l.unlocked = false
	return nil
}

func (r *radio) SetCodes(ctx context.Context, device string, codes []locks.Code) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("codes %s %d", device, len(codes)))
	l, err := r.dev(device)
	if err != nil {
		return err
	}
	l.codes = slices.Clone(codes)
	return nil
}

// keypad is someone typing pin on device's keypad now: the lock unlocks
// only for a code it holds inside that code's own schedule, and reports
// the rule it was set for.
func (r *radio) keypad(device, pin string) (locks.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.clock.Now().UnixMilli()
	for _, c := range r.locks[device].codes {
		if string(c.PIN) == pin && c.FromMS <= now && now < c.ToMS {
			r.locks[device].unlocked = true
			return locks.Event{Device: device, Report: locks.Unlocked, Rule: c.Rule}, true
		}
	}
	return locks.Event{}, false
}

func (r *radio) unlocked(device string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.locks[device].unlocked
}

func (r *radio) did() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

func (r *radio) codesOn(device string) []locks.Code {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.locks[device].codes)
}

// alerts records what was raised.
type alerts struct {
	mu    sync.Mutex
	kinds []alert.Kind
	fail  error
}

func (a *alerts) Raise(k alert.Kind, device string) (alert.Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return alert.Record{}, a.fail
	}
	if _, err := alert.Words(k, device); err != nil {
		return alert.Record{}, err
	}
	a.kinds = append(a.kinds, k)
	return alert.Record{}, nil
}

// texts is how many raised alerts reach the owner by text or call.
func (a *alerts) texts() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, k := range a.kinds {
		if d, _ := k.Delivery(); d != alert.LogOnly {
			n++
		}
	}
	return n
}

func (a *alerts) has(k alert.Kind) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.kinds, k)
}

// The fixture: a front door lock with the plumber's code on Tuesday
// 09:00-12:00, a back door lock, an alarm, a plug and a TV.
const (
	plumberPIN = "482915"
	walkerPIN  = "771203"
)

func fixture() policy.Document {
	return policy.Document{
		Version: 3,
		Devices: []policy.Device{
			{ID: "front", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"},
			{ID: "back", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"},
			{ID: "alarm", Network: policy.NetDevices, Class: policy.ClassAlarm},
			{ID: "plug", Network: policy.NetDevices, Class: policy.ClassPlug, Secure: "off"},
			{ID: "tv", Network: policy.NetDevices, Everyday: true},
		},
		Standing: []policy.StandingRule{
			{ID: "plumber", Device: "front", Action: locks.ActionCode, FromMS: at(9, 0).UnixMilli(), ToMS: at(12, 0).UnixMilli()},
			{ID: "walker", Device: "back", Action: locks.ActionCode, FromMS: at(13, 0).UnixMilli(), ToMS: at(14, 0).UnixMilli()},
		},
	}
}

// rig is one enforcer's lock rules over the fake radio, with the page's
// book wired to the gate as its actuator for unlocks and disarms.
type rig struct {
	t      *testing.T
	clock  *clock
	phone  *phone
	radio  *radio
	alerts *alerts
	gate   *locks.Gate
	book   *action.Book
	doc    policy.Document
	log    []string
	mu     sync.Mutex
}

func newRig(t *testing.T, now time.Time) *rig {
	r := &rig{t: t, clock: &clock{now: now}, phone: newPhone(t), alerts: &alerts{}, doc: fixture()}
	r.radio = newRadio(r.clock, "front", "back", "alarm", "plug")
	pins := map[string]string{"front/plumber": plumberPIN, "back/walker": walkerPIN}
	g, err := locks.New(locks.Config{
		Owner: r.phone.public(), Driver: r.radio, Alerts: r.alerts, Zone: zone, Now: r.clock.Now,
		Codes: func(device, rule string) ([]byte, error) {
			p, ok := pins[device+"/"+rule]
			if !ok {
				return nil, errors.New("no code")
			}
			return []byte(p), nil
		},
		Log: func(s string) { r.mu.Lock(); r.log = append(r.log, s); r.mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.gate = g
	b, err := action.NewBook(r.phone.public(), g, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.book = b
	return r
}

func (r *rig) now() int64 { return r.clock.Now().UnixMilli() }

// tap draws an action challenge for a on device and redeems it with the
// owner's tap, as the page does.
func (r *rig) tap(device string, a action.Act) error {
	c, err := r.book.Issue(r.doc, device, a, "", r.now())
	if err != nil {
		return err
	}
	_, err = r.book.Redeem(r.doc, c.ID, r.phone.sign(c.Msg), r.now())
	return err
}

// second is the owner's second tap for a on device.
func (r *rig) second(device string, a action.Act) error {
	s, err := r.gate.Second(r.doc, device, a)
	if err != nil {
		return err
	}
	return r.gate.Confirm(s.ID, r.phone.sign(s.Msg))
}

func (r *rig) tick() { r.gate.Tick(r.doc) }

func (r *rig) logged(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.log {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
