// Package alert is the enforcer's texts, calls, light and alert log (SPEC
// NET-2 Texts and calls; briefs/ENF.md slice h).
//
// The enforcer reaches the owner only by text and call, and only when the
// owner must act: a text for an ask or an alert that needs action, a call
// for an urgent safety event. Everything else, routine unlocks included,
// is only logged; there is no digest. Each text and call is the enforcer's
// own fixed wording (Kind's closed list), sent as a channel message to the
// kernel for the owner line (channel.Alert). The core can drop, delay,
// forge or falsely confirm any of them, so nothing it sends resolves an
// alert: the enforcer's own log, page and light are the record. The light,
// a Thread bulb only the enforcer drives, shows red for every unresolved
// alert and any recovery pending, whatever happened to the text.
//
// It is enforcer code: it imports the standard library and
// broker/enforcer/wire only (broker/daemon/arc2_test.go). Its assumptions
// are in ASSUMPTIONS.md.
package alert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// Kind is one event on the closed list. Its Delivery and wording are
// fixed here; a slice that needs another kind adds it here.
type Kind uint8

const (
	// Texts: the owner needs to act (NET-2 Texts and calls).
	UnusualUnlock Kind = iota + 1
	UnusualDisarm
	RecoveryCodeUsed
	Enrolment
	ChannelPaused
	SafetyOff  // a channel command turned a heater off
	SafetyShut // a channel command shut a valve
	HeadFork   // the kernel's log forked from the head copies (STO-1)
	// Calls: an urgent safety event.
	AlarmTriggered
	DoorForced
	FailedUnlocks
	// Logged only.
	RoutineUnlock
	RoutineLock
)

// Delivery is how a kind reaches the owner.
type Delivery uint8

const (
	LogOnly Delivery = iota
	Text
	Call
)

type spec struct {
	delivery Delivery
	device   bool   // the wording names a device
	words    string // fixed wording; %s is the device
}

var kinds = map[Kind]spec{
	UnusualUnlock:    {Text, true, "Enforcer: %s was unlocked at an unusual time. Clear it on the enforcer's page at home; its light stays red until you do."},
	UnusualDisarm:    {Text, true, "Enforcer: %s was disarmed at an unusual time. Clear it on the enforcer's page at home; its light stays red until you do."},
	RecoveryCodeUsed: {Text, false, "Enforcer: the recovery code was used to enrol a new passkey. If it was not you, cancel it on the enforcer's page at home now. Clear this there too; its light stays red until you do."},
	Enrolment:        {Text, false, "Enforcer: a passkey was enrolled on the enforcer. Clear it on the enforcer's page at home; its light stays red until you do."},
	ChannelPaused:    {Text, false, "Enforcer: the core's channel sent too much and is paused. Home devices keep their last rules. Resume it on the enforcer's page at home; its light stays red until you do."},
	SafetyOff:        {Text, true, "Enforcer: %s was switched off by the core. Turning it back on needs the enforcer's page at home. Clear this there too; its light stays red until you do."},
	SafetyShut:       {Text, true, "Enforcer: %s was shut by the core. Opening it again needs the enforcer's page at home. Clear this there too; its light stays red until you do."},
	HeadFork:         {Text, false, "Enforcer: the core's log does not match the copy the enforcer keeps. The core may have been rolled back. Choose what to do on the enforcer's page at home; its light stays red until you do."},
	AlarmTriggered:   {Call, true, "Enforcer: the alarm %s was triggered."},
	DoorForced:       {Call, true, "Enforcer: %s was forced open."},
	FailedUnlocks:    {Call, true, "Enforcer: repeated failed attempts to unlock %s."},
	RoutineUnlock:    {LogOnly, true, "%s unlocked."},
	RoutineLock:      {LogOnly, true, "%s locked."},
}

// Fold windows: a repeat of an open alert within its delivery's window
// after the owner was last told counts on it and sends nothing; a repeat
// after the window tells the owner again (NET-2: every urgent event calls,
// a burst costs one).
const (
	FoldCall = 10 * time.Minute
	FoldText = time.Hour
)

func (d Delivery) fold() time.Duration {
	if d == Call {
		return FoldCall
	}
	return FoldText
}

// Delivery is k's delivery; ok is false for a kind not on the list.
func (k Kind) Delivery() (d Delivery, ok bool) {
	s, ok := kinds[k]
	return s.delivery, ok
}

// Words is the fixed text for k about device.
func Words(k Kind, device string) (string, error) {
	s, ok := kinds[k]
	switch {
	case !ok:
		return "", ErrKind
	case s.device != (device != ""), s.device && !wire.Name(device):
		return "", ErrDevice
	case s.device:
		return fmt.Sprintf(s.words, device), nil
	}
	return s.words, nil
}

// Colour is what the light shows.
type Colour uint8

const (
	Off   Colour = iota // nothing unresolved, the core up
	Amber               // the core down or silent, nothing unresolved
	Red                 // an unresolved alert or a recovery pending
)

// Light is the enforcer-only Thread bulb, driven through the radio host
// (slice k).
type Light interface {
	Show(Colour) error
}

// Journal is the alert log's durable record: one line per change,
// appended. Append must be durable when it returns; Load returns every
// byte appended, a torn last line included; Truncate cuts the record to n
// bytes.
type Journal interface {
	Load() ([]byte, error)
	Append([]byte) error
	Truncate(n int) error
}

// Record is one alert log line, as its latest state.
type Record struct {
	ID       uint64    `json:"id"`
	Kind     Kind      `json:"kind"`
	Device   string    `json:"device,omitempty"`
	Text     string    `json:"text"`
	At       time.Time `json:"at"`
	Last     time.Time `json:"last"`
	Count    int       `json:"count"`          // times raised while open
	Told     time.Time `json:"told,omitzero"`  // when the text or call was last offered to the kernel
	Sent     bool      `json:"sent,omitempty"` // the kernel took the last offer; never proof it arrived
	Open     bool      `json:"open,omitempty"`
	Resolved time.Time `json:"resolved,omitzero"`
}

// Status is the light's inputs and what it shows.
type Status struct {
	Open     []Record
	Recovery bool
	CoreDown bool
	Colour   Colour
}

// Config is what the alerts are built from. Send, Light and Journal are
// required.
type Config struct {
	// Send hands a text or call to the kernel for the owner line:
	// channel.Channel.Alert.
	Send func(wire.Alert) error
	// Light is the bulb.
	Light   Light
	Journal Journal
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Errors.
var (
	ErrConfig   = errors.New("alert: config incomplete")
	ErrKind     = errors.New("alert: not a kind on the list")
	ErrDevice   = errors.New("alert: device name missing, unexpected or not a name")
	ErrUnknown  = errors.New("alert: no open alert with that id")
	ErrResolved = errors.New("alert: a channel-paused alert resolves only when the channel resumes")
	ErrCorrupt  = errors.New("alert: journal corrupt")
)

// Alerts is the enforcer's alert log, light and owner-line sender. It is
// the channel's Alerts and is safe for concurrent use.
type Alerts struct {
	cfg Config

	mu       sync.Mutex
	log      []Record
	byID     map[uint64]int
	next     uint64
	recovery bool
	coreDown bool

	// size is the journal's length after its last good append, so a
	// failed append is cut back and leaves no fragment.
	size int

	// lightMu orders light updates so a stale colour never lands last.
	lightMu sync.Mutex
}

// New builds the alerts from the journal and shows the light. The core
// counts as down until the daemon says it is up (Core).
func New(cfg Config) (*Alerts, error) {
	if cfg.Send == nil || cfg.Light == nil || cfg.Journal == nil {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &Alerts{cfg: cfg, byID: map[uint64]int{}, coreDown: true}
	raw, err := cfg.Journal.Load()
	if err != nil {
		return nil, err
	}
	raw, err = whole(cfg.Journal, raw)
	if err != nil {
		return nil, err
	}
	a.size = len(raw)
	for i, ln := range bytes.Split(raw, []byte{'\n'}) {
		if len(ln) == 0 {
			continue
		}
		var r Record
		d := json.NewDecoder(bytes.NewReader(ln))
		d.DisallowUnknownFields()
		if err := d.Decode(&r); err != nil || r.ID == 0 {
			return nil, fmt.Errorf("%w: line %d", ErrCorrupt, i+1)
		}
		a.put(r)
	}
	a.show()
	return a, nil
}

func (a *Alerts) put(r Record) {
	if i, ok := a.byID[r.ID]; ok {
		a.log[i] = r
	} else {
		a.byID[r.ID] = len(a.log)
		a.log = append(a.log, r)
	}
	a.next = max(a.next, r.ID)
}

func (a *Alerts) write(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := a.cfg.Journal.Append(b); err != nil {
		_ = a.cfg.Journal.Truncate(a.size) // a short write leaves no fragment
		return err
	}
	a.size += len(b)
	return nil
}

// Raise logs one event, and for a text or call keeps it open, turns the
// light red and sends it. The log line and the light come first, so a
// dropped or refused text still shows (P6); a journal error is returned
// after the light and the send. An event of a kind already open for the
// same device counts on that alert; it sends nothing more within the
// delivery's fold window after the owner was last told, so a burst costs
// one text or call, and sends again after it, so a later event is never
// silenced by an earlier one left open.
func (a *Alerts) Raise(k Kind, device string) (Record, error) {
	text, err := Words(k, device)
	if err != nil {
		return Record{}, err
	}
	d, _ := k.Delivery()
	now := a.cfg.Now().UTC()
	a.mu.Lock()
	r, tell := Record{}, d != LogOnly
	if i := a.open(k, device); d != LogOnly && i >= 0 {
		r = a.log[i]
		r.Count++
		r.Last = now
		tell = now.Sub(r.Told) >= d.fold()
	} else {
		r = Record{ID: a.next + 1, Kind: k, Device: device, Text: text, At: now, Last: now, Count: 1, Open: d != LogOnly}
	}
	if tell {
		r.Told, r.Sent = now, false
	}
	// A record the journal refused is still shown and sent: the light
	// must not depend on the disk either (P6).
	werr := a.write(r)
	a.put(r)
	a.mu.Unlock()
	if d != LogOnly {
		a.show()
		if tell {
			r = a.send(r)
		}
	}
	return r, werr
}

func (a *Alerts) open(k Kind, device string) int {
	for i := len(a.log) - 1; i >= 0; i-- {
		if r := a.log[i]; r.Open && r.Kind == k && r.Device == device {
			return i
		}
	}
	return -1
}

// send offers r to the kernel and records whether it took it. A refusal
// changes nothing else: the alert stays open and the light red, and Core
// offers it again when the core is back.
func (a *Alerts) send(r Record) Record {
	d, _ := r.Kind.Delivery()
	w := wire.Alert{Kind: wire.AlertText, Text: r.Text}
	if d == Call {
		w.Kind = wire.AlertCall
	}
	if a.cfg.Send(w) != nil {
		return r
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	i, ok := a.byID[r.ID]
	if !ok {
		return r
	}
	if a.log[i].Sent || !a.log[i].Told.Equal(r.Told) {
		return a.log[i] // already taken, or a newer telling owns the flag
	}
	s := a.log[i]
	s.Sent = true
	if a.write(s) == nil {
		a.put(s)
	}
	return a.log[a.byID[r.ID]]
}

// SafetyOff is the channel's hook: a channel command turned a heater off
// or shut a valve (NET-2 Channel).
func (a *Alerts) SafetyOff(device string, v wire.Verb) {
	k := SafetyOff
	if v == wire.VerbShut {
		k = SafetyShut
	}
	_, _ = a.Raise(k, device)
}

// Paused is the channel's hook: a burst paused the channel.
func (a *Alerts) Paused() { _, _ = a.Raise(ChannelPaused, "") }

// Resumed resolves the channel-paused alert; the page calls it after the
// owner resumed the channel there (slice b).
func (a *Alerts) Resumed() error {
	a.mu.Lock()
	i := a.open(ChannelPaused, "")
	var err error
	if i >= 0 {
		err = a.resolve(i)
	}
	a.mu.Unlock()
	a.show()
	return err
}

// Resolve closes open alert id. Only the enforcer's page calls it, after
// the owner acted there; nothing on the channel resolves an alert. A
// paused channel resolves only by resuming it (Resumed).
func (a *Alerts) Resolve(id uint64) error {
	a.mu.Lock()
	i, ok := a.byID[id]
	var err error
	switch {
	case !ok || !a.log[i].Open:
		err = ErrUnknown
	case a.log[i].Kind == ChannelPaused:
		err = ErrResolved
	default:
		err = a.resolve(i)
	}
	a.mu.Unlock()
	a.show()
	return err
}

func (a *Alerts) resolve(i int) error {
	r := a.log[i]
	r.Open, r.Resolved = false, a.cfg.Now().UTC()
	if err := a.write(r); err != nil {
		return err
	}
	a.put(r)
	return nil
}

// Recovery sets whether a recovery is pending (slice c): red until it
// ends.
func (a *Alerts) Recovery(pending bool) {
	a.mu.Lock()
	a.recovery = pending
	a.mu.Unlock()
	a.show()
}

// Core sets whether the core is up (slice l, from the channel and the
// heartbeat). Coming up, every open alert the kernel never took is offered
// again.
func (a *Alerts) Core(up bool) {
	a.mu.Lock()
	a.coreDown = !up
	var unsent []Record
	if up {
		for _, r := range a.log {
			if r.Open && !r.Sent {
				unsent = append(unsent, r)
			}
		}
	}
	a.mu.Unlock()
	a.show()
	for _, r := range unsent {
		a.send(r)
	}
}

// Status is the light's inputs and colour, for the page.
func (a *Alerts) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Status{Recovery: a.recovery, CoreDown: a.coreDown}
	for _, r := range a.log {
		if r.Open {
			s.Open = append(s.Open, r)
		}
	}
	switch {
	case len(s.Open) > 0 || s.Recovery:
		s.Colour = Red
	case s.CoreDown:
		s.Colour = Amber
	}
	return s
}

// Log is every alert log line, oldest first.
func (a *Alerts) Log() []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.log)
}

// Refresh shows the light again; the daemon calls it on a timer so a bulb
// that missed a change, or was power-cycled, catches up.
func (a *Alerts) Refresh() error { return a.show() }

func (a *Alerts) show() error {
	a.lightMu.Lock()
	defer a.lightMu.Unlock()
	return a.cfg.Light.Show(a.Status().Colour)
}

// whole cuts a torn last append, a line with no newline, from the journal
// and returns the rest. Append writes a record and its newline in one
// call, so a line without one was never acknowledged, and cutting it
// keeps the next Append from landing on the fragment.
func whole(j Journal, raw []byte) ([]byte, error) {
	n := bytes.LastIndexByte(raw, '\n') + 1
	if n == len(raw) {
		return raw, nil
	}
	if err := j.Truncate(n); err != nil {
		return nil, err
	}
	return raw[:n], nil
}
