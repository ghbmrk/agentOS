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
// alert: the enforcer's own log and page are the record. The light, a
// Thread bulb only the enforcer drives, is saved for a known attack
// (D-254): it shows red only while a trip at the enforcer (KRN-12) is
// unresolved, whatever happened to its text. Every other alert and a
// silent core show on the page.
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
	// A trip at the enforcer (KRN-12): traffic to a decoy address, a byte
	// cap passed, a malformed or excessive channel message. The only kind
	// that lights the bulb. Appended, so journalled kinds keep their numbers.
	Trip
	// A factory reset by the case code dropped the passkey (NET-2
	// Hardening): a text, never the light (D-254). Appended after Trip.
	FactoryReset
	// The enforcer's record of a box's cut is missing or does not read
	// back (#5399): provisioning wrote it and nothing removes it, so its
	// loss means root on the enforcer or lost state. The box stays cut;
	// like Trip it lights the bulb until the cut lifts. Appended after
	// FactoryReset.
	RecordMissing
	// The passkey in force made a new recovery code, spending the written
	// one (ENF-c-f4, #5042): a holder of a synced passkey on the Owner
	// Wi-Fi cannot do it unseen. Appended last.
	RecoveryCodeChanged
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
	UnusualUnlock:       {Text, true, "Enforcer: %s was unlocked at an unusual time. Clear it on the enforcer's page at home."},
	UnusualDisarm:       {Text, true, "Enforcer: %s was disarmed at an unusual time. Clear it on the enforcer's page at home."},
	RecoveryCodeUsed:    {Text, false, "Enforcer: the recovery code was used to enrol a new passkey. If it was not you, open the enforcer's page at home within 10 minutes and cancel the replacement there if one is waiting; if none is waiting, make a new recovery code there. After 10 minutes a waiting replacement is in force and only a factory reset with the code inside the enforcer's case takes it back. Clear this there too."},
	RecoveryCodeChanged: {Text, false, "Enforcer: a new recovery code was made with your passkey, so the code you wrote down no longer works. If it was not you, someone else can use your passkey: make a new recovery code on the enforcer's page at home and keep it safe. Clear this there too."},
	Enrolment:           {Text, false, "Enforcer: a passkey was enrolled on the enforcer. Clear it on the enforcer's page at home."},
	ChannelPaused:       {Text, false, "Enforcer: the core's channel sent too much and is paused. Home devices keep their last rules. Resume it on the enforcer's page at home."},
	SafetyOff:           {Text, true, "Enforcer: %s was switched off by the core. Turning it back on needs the enforcer's page at home. Clear this there too."},
	SafetyShut:          {Text, true, "Enforcer: %s was shut by the core. Opening it again needs the enforcer's page at home. Clear this there too."},
	HeadFork:            {Text, false, "Enforcer: the core's log does not match the copy the enforcer keeps. The core may have been rolled back. Choose what to do on the enforcer's page at home."},
	AlarmTriggered:      {Call, true, "Enforcer: the alarm %s was triggered."},
	DoorForced:          {Call, true, "Enforcer: %s was forced open."},
	FailedUnlocks:       {Call, true, "Enforcer: repeated failed attempts to unlock %s."},
	RoutineUnlock:       {LogOnly, true, "%s unlocked."},
	RoutineLock:         {LogOnly, true, "%s locked."},
	Trip:                {Text, true, "Enforcer: %s touched a decoy or broke a limit, a known attack. The enforcer's page at home shows whether it was cut off or needs your passkey there to isolate it; its light stays red until the cut lifts or you clear this there."},
	FactoryReset:        {Text, false, "Enforcer: a factory reset was run with the code inside its case, which drops its passkey and recovery code. Anyone who opened the case has that code, so someone else may have run it. Nothing can loosen its rules until a new passkey enrols. Enrol one and clear this on the enforcer's page at home. Until a passkey enrols, the page says \"This enforcer was factory reset.\" If it does not say so and you have not enrolled a passkey since, the reset did not finish: run it again there."},
	RecordMissing:       {Text, true, "Enforcer: its record of %[1]s's cut is missing or unreadable, so %[1]s stays cut. Someone may have tampered with the enforcer: check it before you let %[1]s back on the enforcer's page at home. Its light stays red until you do or you clear this there."},
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

// lights reports whether an open alert of kind k turns the light red: a
// known attack (D-254), which only lifting its cut resolves (Lifted).
func (k Kind) lights() bool { return k == Trip || k == RecordMissing }

// Words is the fixed text for k about device.
func Words(k Kind, device string) (string, error) {
	s, ok := kinds[k]
	switch {
	case !ok:
		return "", ErrKind
	case s.device != (device != ""), s.device && !wire.Name(device):
		return "", ErrDevice
	case k == RecordMissing:
		return fmt.Sprintf(s.words, boxName(device)), nil
	case s.device:
		return fmt.Sprintf(s.words, device), nil
	}
	return s.words, nil
}

// boxName is a box as the page names it, so the owner reads no device
// ID: the edge box and the core (#5445 item 5).
func boxName(device string) string {
	switch device {
	case "edge":
		return "the edge box"
	case "core":
		return "the core"
	}
	return device
}

// Colour is what the light shows.
type Colour uint8

const (
	Off Colour = iota // no trip unresolved
	Red               // a trip at the enforcer unresolved (D-254)
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

// Status is the page's view and what the light shows.
type Status struct {
	Open     []Record
	CoreDown bool
	Colour   Colour
}

// Config is what the alerts are built from. Send, Light and Journal are
// required.
type Config struct {
	// Send hands a text or call to the kernel for the owner line:
	// channel.Channel.Alert. It is called under the offer lock, so it
	// must not raise a text or call itself.
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
	coreDown bool

	// size is the journal's length after its last good append, so a
	// failed append is cut back and leaves no fragment. dirty is set
	// while a failed append's cut-back failed too, so the journal may be
	// longer than size: no record is appended until a cut-back succeeds,
	// so none sits glued to a fragment or past size, where a later
	// cut-back would remove it.
	size  int
	dirty bool

	// lightMu orders light updates so a stale colour never lands last.
	lightMu sync.Mutex

	// offerMu makes reading whether an alert is unsent and offering it
	// one step: held from that read until the kernel's answer is
	// recorded, so two callers (Raise, Core) never offer the same
	// telling twice (#4903). It is taken before mu, never under it.
	offerMu sync.Mutex
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
	if a.dirty {
		if err := a.cfg.Journal.Truncate(a.size); err != nil {
			return fmt.Errorf("journal not cut back after a failed append: %w", err)
		}
		a.dirty = false
	}
	if err := a.cfg.Journal.Append(b); err != nil {
		// A short write leaves no fragment; a cut-back that fails too
		// is tried again before the next append.
		a.dirty = a.cfg.Journal.Truncate(a.size) != nil
		return err
	}
	a.size += len(b)
	return nil
}

// Raise logs one event, and for a text or call keeps it open, shows the
// light (red for a trip) and sends it. The log line and the light come
// first, so a dropped or refused text still shows (P6); a journal error is returned
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
			a.offerMu.Lock()
			r = a.offer(r.ID)
			a.offerMu.Unlock()
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

// offer offers alert id to the kernel, unless it is resolved or the
// kernel took its latest telling already, records whether it took it, and returns the alert's latest
// state. A refusal changes nothing else: the alert
// stays open (a trip's light red), and Core offers it again when the core
// is back. The caller holds offerMu, so the unsent state it reads stays
// unsent until the kernel's answer is recorded.
func (a *Alerts) offer(id uint64) Record {
	a.mu.Lock()
	r := a.log[a.byID[id]]
	a.mu.Unlock()
	if !r.Open || r.Sent {
		return r
	}
	d, _ := r.Kind.Delivery()
	w := wire.Alert{Kind: wire.AlertText, Text: r.Text}
	if d == Call {
		w.Kind = wire.AlertCall
	}
	err := a.cfg.Send(w)
	a.mu.Lock()
	defer a.mu.Unlock()
	i := a.byID[id]
	if err != nil || !a.log[i].Told.Equal(r.Told) {
		return a.log[i] // refused, or a Raise's newer telling owns the flag
	}
	s := a.log[i]
	s.Sent = true
	if a.write(s) == nil {
		a.put(s)
	}
	return a.log[i]
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

// Lifted resolves every open trip and missing record from device; the
// page calls it once the owner's passkey has lifted that cut in full
// (NET-4). The light goes off when none is left open.
func (a *Alerts) Lifted(device string) error {
	a.mu.Lock()
	var err error
	for i := range a.log {
		if r := a.log[i]; r.Open && r.Kind.lights() && r.Device == device {
			err = errors.Join(err, a.resolve(i))
		}
	}
	a.mu.Unlock()
	a.show()
	return err
}

// Core sets whether the core is up (slice l, from the channel and the
// heartbeat), for the page; the light does not show it (D-254). Coming
// up, every open alert the kernel never took is offered again, under the
// offer lock, so one a concurrent Raise or Core is offering is not
// offered twice.
func (a *Alerts) Core(up bool) {
	a.mu.Lock()
	a.coreDown = !up
	a.mu.Unlock()
	a.show()
	if !up {
		return
	}
	a.offerMu.Lock()
	defer a.offerMu.Unlock()
	a.mu.Lock()
	var unsent []uint64
	for _, r := range a.log {
		if r.Open && !r.Sent {
			unsent = append(unsent, r.ID)
		}
	}
	a.mu.Unlock()
	for _, id := range unsent {
		a.offer(id)
	}
}

// Status is what the page shows: open alerts, the core down, and the
// light's colour.
func (a *Alerts) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Status{CoreDown: a.coreDown}
	for _, r := range a.log {
		if r.Open {
			s.Open = append(s.Open, r)
		}
	}
	if slices.ContainsFunc(s.Open, func(r Record) bool { return r.Kind.lights() }) {
		s.Colour = Red
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
