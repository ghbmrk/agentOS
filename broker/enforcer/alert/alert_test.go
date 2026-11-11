package alert

// REQ: NET-2, KRN-12

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/channel"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// The channel's Alerts hook is this package.
var _ channel.Alerts = (*Alerts)(nil)

type journal struct{ b []byte }

func (j *journal) Load() ([]byte, error) { return j.b, nil }
func (j *journal) Append(b []byte) error { j.b = append(j.b, b...); return nil }
func (j *journal) Truncate(n int) error  { j.b = j.b[:n]; return nil }

type bulb struct {
	mu    sync.Mutex
	shown []Colour
	// hook, if set, runs after each Show is recorded, with the count of
	// colours shown so far, outside mu.
	hook func(n int)
}

func (b *bulb) Show(c Colour) error {
	b.mu.Lock()
	b.shown = append(b.shown, c)
	n, hook := len(b.shown), b.hook
	b.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return nil
}

func (b *bulb) now() Colour {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.shown[len(b.shown)-1]
}

// core is the kernel's end of the owner line: it may refuse, or take and
// silently drop, every text.
type core struct {
	mu     sync.Mutex
	refuse bool
	got    []wire.Alert
}

func (c *core) Send(a wire.Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refuse {
		return channel.ErrNoSession
	}
	c.got = append(c.got, a)
	return nil
}

type rig struct {
	a    *Alerts
	core *core
	bulb *bulb
	j    *journal
}

func newRig(t *testing.T, j *journal) *rig { return newRigCore(t, j, &core{}) }

// newRigCore starts the alerts, as after a restart, with the core up.
func newRigCore(t *testing.T, j *journal, c *core) *rig {
	t.Helper()
	r := &rig{core: c, bulb: &bulb{}, j: j}
	a, err := New(Config{Send: r.core.Send, Light: r.bulb, Journal: j,
		Now: func() time.Time { return time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	r.a = a
	r.a.Core(true)
	return r
}

// TestDroppedTripStillOnLight (NET-2 Texts and calls, KRN-12): a trip
// whose text the core refuses, and a call it takes and drops, stay open on
// the page and in the log across a restart; the trip keeps the light red
// until the page resolves it, and only the page resolves either. Catches
// reliance on the core.
func TestDroppedTripStillOnLight(t *testing.T) {
	j := &journal{}
	r := newRig(t, j)
	if c := r.bulb.now(); c != Off {
		t.Fatalf("light %v before any alert", c)
	}
	r.core.refuse = true
	refused, err := r.a.Raise(Trip, "edge")
	if err != nil {
		t.Fatal(err)
	}
	r.core.refuse = false
	dropped, err := r.a.Raise(DoorForced, "back-door") // the core takes it and drops it
	if err != nil {
		t.Fatal(err)
	}
	if refused.Sent || !dropped.Sent {
		t.Fatalf("sent flags %v %v", refused.Sent, dropped.Sent)
	}
	if len(r.core.got) != 1 || r.core.got[0].Kind != wire.AlertCall {
		t.Fatalf("the kernel got %v, want the one call", r.core.got)
	}
	for _, r := range []*rig{r, newRigCore(t, j, &core{refuse: true})} {
		if c := r.bulb.now(); c != Red {
			t.Fatalf("light %v with a trip unresolved", c)
		}
		st := r.a.Status()
		if len(st.Open) != 2 || st.Open[0].Device != "edge" || st.Open[1].Device != "back-door" {
			t.Fatalf("open on the page: %v", st.Open)
		}
		if len(r.a.Log()) != 2 {
			t.Fatalf("log %v", r.a.Log())
		}
	}

	// The core coming back is offered the refused text again; taking it
	// resolves nothing.
	r2 := newRig(t, j)
	if len(r2.core.got) != 1 || !strings.Contains(r2.core.got[0].Text, "edge") {
		t.Fatalf("resent on the core's return: %v", r2.core.got)
	}
	if c := r2.bulb.now(); c != Red {
		t.Fatalf("light %v after the core took the text", c)
	}
	if err := r2.a.Resolve(dropped.ID); err != nil {
		t.Fatal(err)
	}
	if c := r2.bulb.now(); c != Red {
		t.Fatalf("light %v with the trip still open", c)
	}
	if err := r2.a.Resolve(refused.ID); err != nil {
		t.Fatal(err)
	}
	if c := r2.bulb.now(); c != Off {
		t.Fatalf("light %v once the owner resolved the trip", c)
	}
	if err := r2.a.Resolve(dropped.ID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("resolving twice: %v", err)
	}
}

// TestDroppedTextStillOnPage (NET-2 Texts and calls): a text the core
// refuses and a call it drops stay open on the page across a restart with
// the light off, and only the page resolves them. Catches reliance on the
// core, and a routine alert read as an attack (D-254).
func TestDroppedTextStillOnPage(t *testing.T) {
	j := &journal{}
	r := newRig(t, j)
	r.core.refuse = true
	refused, err := r.a.Raise(UnusualUnlock, "front-door")
	if err != nil {
		t.Fatal(err)
	}
	r.core.refuse = false
	if _, err := r.a.Raise(DoorForced, "back-door"); err != nil {
		t.Fatal(err)
	}
	r2 := newRig(t, j)
	if st := r2.a.Status(); len(st.Open) != 2 || st.Colour != Off || r2.bulb.now() != Off {
		t.Fatalf("after a restart: %+v, light %v", st, r2.bulb.now())
	}
	if err := r2.a.Resolve(refused.ID); err != nil || len(r2.a.Status().Open) != 1 {
		t.Fatalf("resolve on the page: %v %+v", err, r2.a.Status().Open)
	}
}

// TestFactoryResetTexts (NET-2 Texts and calls, NET-2 Hardening, NET-4;
// #4292): a factory reset is a text that sends the owner to the page with
// no "if it was not you", since either answer needs the owner there; a
// text the core refuses still leaves it open on the page and in the log
// across a restart, offered again when the core is back; and it never
// lights the bulb (D-254). Its number follows Trip's, so journalled kinds
// keep their meaning. Its text is raised before anything is dropped, so
// it also tells the owner how to tell a reset cut short, where "enrol
// one" cannot be done, by the reset screen's own line, which no enrolled
// page shows, so a reset followed by an enrolment does not read as cut
// short (#4929 R-UX1; the page's TestEnrolAnswerFollowsState pins the
// line in the screen). Catches a reset by whoever opened the case going unseen until
// the next enrolment.
func TestFactoryResetTexts(t *testing.T) {
	if FactoryReset != Trip+1 {
		t.Fatalf("FactoryReset is %d, want %d: journalled kinds would change meaning", FactoryReset, Trip+1)
	}
	if d, ok := FactoryReset.Delivery(); !ok || d != Text {
		t.Fatalf("delivery %d %v", d, ok)
	}
	w, err := Words(FactoryReset, "")
	if err != nil || !strings.Contains(w, "enforcer's page at home") || !strings.Contains(w, "factory reset") ||
		!strings.Contains(w, `the page says "This enforcer was factory reset."`) ||
		!strings.Contains(w, "not enrolled a passkey since, the reset did not finish") ||
		strings.Contains(strings.ToLower(w), "not you") {
		t.Fatalf("words %q %v", w, err)
	}
	j := &journal{}
	r := newRig(t, j)
	r.core.refuse = true
	rec, err := r.a.Raise(FactoryReset, "")
	if err != nil || !rec.Open || rec.Sent {
		t.Fatalf("raised %+v %v", rec, err)
	}
	if r.bulb.now() != Off {
		t.Fatal("a factory reset lit the bulb")
	}
	r2 := newRigCore(t, j, &core{})
	st := r2.a.Status()
	if len(st.Open) != 1 || st.Open[0].Kind != FactoryReset || st.Colour != Off {
		t.Fatalf("after a restart: %+v", st)
	}
	if got := r2.core.got; len(got) != 1 || got[0].Kind != wire.AlertText || got[0].Text != w {
		t.Fatalf("not offered again when the core came back: %+v", got)
	}
}

// TestRoutineUnlockLoggedNotTexted (NET-2 Texts and calls): a routine
// unlock or lock is logged and nothing else: no text, no call, no open
// alert, no change of light; and a burst of one kind on one device costs
// the owner one text. Catches noise the owner pays for.
func TestRoutineUnlockLoggedNotTexted(t *testing.T) {
	r := newRig(t, &journal{})
	for range 3 {
		if _, err := r.a.Raise(RoutineUnlock, "front-door"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.a.Raise(RoutineLock, "front-door"); err != nil {
		t.Fatal(err)
	}
	if len(r.core.got) != 0 {
		t.Fatalf("routine events sent %v", r.core.got)
	}
	if st := r.a.Status(); len(st.Open) != 0 || st.Colour != Off || r.bulb.now() != Off {
		t.Fatalf("routine events changed the light: %+v", st)
	}
	if n := len(r.a.Log()); n != 4 {
		t.Fatalf("%d log lines, want 4", n)
	}

	for range 5 {
		if _, err := r.a.Raise(FailedUnlocks, "front-door"); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.core.got) != 1 {
		t.Fatalf("a burst sent %d calls, want 1", len(r.core.got))
	}
	if st := r.a.Status(); len(st.Open) != 1 || st.Open[0].Count != 5 {
		t.Fatalf("burst: %+v", st.Open)
	}
}

// Every kind has fixed wording the wire carries, and the closed list
// decides delivery: SPEC's urgent safety events call, every other alert
// texts.
func TestWordsFixed(t *testing.T) {
	calls := []Kind{AlarmTriggered, DoorForced, FailedUnlocks}
	logged := []Kind{RoutineUnlock, RoutineLock}
	for k, s := range kinds {
		dev := ""
		if s.device {
			dev = "boiler"
		}
		w, err := Words(k, dev)
		if err != nil || len(w) > wire.MaxAlert {
			t.Fatalf("kind %d: %q %v", k, w, err)
		}
		if _, err := wire.Encode(wire.ToCore, wire.Alert{Kind: wire.AlertText, Text: w}); err != nil {
			t.Fatalf("kind %d's words do not cross the wire: %v", k, err)
		}
		// Every text opens an alert only the page clears, so every text
		// sends the owner there, with no condition on it (UX fix-lists on
		// #3909); only a trip's text names the light, which shows only
		// trips (D-254).
		if s.delivery == Text && !strings.Contains(w, "enforcer's page at home") {
			t.Fatalf("kind %d's text does not send the owner to the page: %q", k, w)
		}
		if strings.Contains(w, "light") != k.lights() {
			t.Fatalf("kind %d's text and the light: %q", k, w)
		}
		want := Text
		switch {
		case slices.Contains(calls, k):
			want = Call
		case slices.Contains(logged, k):
			want = LogOnly
		}
		if s.delivery != want {
			t.Fatalf("kind %d delivers %d, want %d", k, s.delivery, want)
		}
	}
	for _, bad := range []struct {
		k   Kind
		dev string
	}{{UnusualUnlock, ""}, {UnusualUnlock, "a b"}, {UnusualUnlock, "a/b"}, {Enrolment, "x"}, {0, ""}, {99, "x"}} {
		if _, err := Words(bad.k, bad.dev); err == nil {
			t.Fatalf("Words(%d, %q) accepted", bad.k, bad.dev)
		}
	}
}

// TestOnlyTripsLight (NET-2 Texts and calls, KRN-12, D-254): an
// unusual-time unlock, a recovery-code use, an enrolment, a factory reset, a paused
// channel, a pending recovery and a silent core each leave the light off
// and show on the page; a trip at the enforcer, from any box or device,
// turns it red until its cut lifts or the owner resolves it on the page.
// Catches routine alerts keeping the light red, so a real trip is read as
// routine.
func TestOnlyTripsLight(t *testing.T) {
	r := newRig(t, &journal{})
	off := func(what string) {
		t.Helper()
		if c, st := r.bulb.now(), r.a.Status(); c != Off || st.Colour != Off {
			t.Fatalf("%s: light %v, status %v", what, c, st.Colour)
		}
	}
	for _, e := range []struct {
		k   Kind
		dev string
	}{{UnusualUnlock, "front-door"}, {UnusualDisarm, "hall"}, {RecoveryCodeUsed, ""}, {Enrolment, ""}, {FactoryReset, ""},
		{SafetyOff, "boiler"}, {SafetyShut, "main-valve"}, {HeadFork, ""},
		{AlarmTriggered, "hall"}, {DoorForced, "back-door"}, {FailedUnlocks, "front-door"}} {
		if _, err := r.a.Raise(e.k, e.dev); err != nil {
			t.Fatal(err)
		}
		off(fmt.Sprintf("kind %d", e.k))
	}
	r.a.Paused()
	off("paused channel")
	r.a.Core(false)
	off("core silent")
	st := r.a.Status()
	if len(st.Open) != 12 || !st.CoreDown {
		t.Fatalf("not on the page: %d open, core down %v", len(st.Open), st.CoreDown)
	}
	r.a.Core(true)

	red := func(what string) {
		t.Helper()
		if c, st := r.bulb.now(), r.a.Status(); c != Red || st.Colour != Red {
			t.Fatalf("%s: light %v, status %v", what, c, st.Colour)
		}
	}
	// A trip from the edge and one from a device: lifting one cut leaves
	// the other's light; lifting a cut with no trip changes nothing.
	edge, err := r.a.Raise(Trip, "edge")
	if err != nil {
		t.Fatal(err)
	}
	red("edge trip")
	if !strings.Contains(r.core.got[len(r.core.got)-1].Text, "edge touched a decoy") {
		t.Fatalf("trip text: %v", r.core.got[len(r.core.got)-1])
	}
	cam, err := r.a.Raise(Trip, "camera-3")
	if err != nil {
		t.Fatal(err)
	}
	// Another alert on the tripped box is not a trip: lifting the cut
	// leaves it open on the page.
	edgeFault, err := r.a.Raise(SafetyOff, "edge")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.a.Lifted("core"); err != nil {
		t.Fatal(err)
	}
	red("no core trip to lift")
	if err := r.a.Lifted("edge"); err != nil {
		t.Fatal(err)
	}
	red("device trip still open")
	if got := r.a.Log()[r.a.byID[edgeFault.ID]]; !got.Open {
		t.Fatalf("lifting a cut closed a non-trip alert: %+v", got)
	}
	if err := r.a.Resolve(edgeFault.ID); err != nil {
		t.Fatal(err)
	}
	if got := r.a.Log()[r.a.byID[edge.ID]]; got.Open || got.Resolved.IsZero() {
		t.Fatalf("lifted trip still open: %+v", got)
	}
	if err := r.a.Resolve(cam.ID); err != nil {
		t.Fatal(err)
	}
	off("both trips resolved")
	// A repeat trip from the core after its cut lifted is a new alert.
	if _, err := r.a.Raise(Trip, "core"); err != nil {
		t.Fatal(err)
	}
	red("core trip")
	if err := r.a.Lifted("core"); err != nil {
		t.Fatal(err)
	}
	off("core cut lifted")

	// #5399: a box's missing cut record is a known attack too: it lights
	// the bulb, and lifting that box's cut resolves it.
	if RecordMissing != FactoryReset+1 {
		t.Fatalf("RecordMissing is %d, want %d: journalled kinds would change meaning", RecordMissing, FactoryReset+1)
	}
	if d, ok := RecordMissing.Delivery(); !ok || d != Text {
		t.Fatalf("RecordMissing's delivery %d %v", d, ok)
	}
	if _, err := r.a.Raise(RecordMissing, "edge"); err != nil {
		t.Fatal(err)
	}
	red("edge record missing")
	if w := r.core.got[len(r.core.got)-1].Text; w != "Enforcer: its record of edge's cut is missing or unreadable, so edge stays cut. Someone may have tampered with the enforcer: check it before you let edge back on the enforcer's page at home. Its light stays red until you do or you clear this there." {
		t.Fatalf("missing record text: %q", w)
	}
	if err := r.a.Lifted("core"); err != nil {
		t.Fatal(err)
	}
	red("another box's cut lifted")
	if err := r.a.Lifted("edge"); err != nil {
		t.Fatal(err)
	}
	off("edge cut lifted")

	// A paused channel still resolves only by resuming it.
	p := r.a.Status().Open
	i := slices.IndexFunc(p, func(r Record) bool { return r.Kind == ChannelPaused })
	if err := r.a.Resolve(p[i].ID); !errors.Is(err, ErrResolved) {
		t.Fatalf("resolving a pause without resuming: %v", err)
	}
	if err := r.a.Resumed(); err != nil || len(r.a.Status().Open) != 11 {
		t.Fatalf("resumed: %v %d", err, len(r.a.Status().Open))
	}
}

// The channel's sink may call back into the channel: Alerts calls Send
// without holding its lock, so a Send that raises again does not deadlock.
func TestSendMayReenter(t *testing.T) {
	r := &rig{bulb: &bulb{}, j: &journal{}}
	var a *Alerts
	n := 0
	send := func(wire.Alert) error {
		if n++; n == 1 {
			a.Status()
			_, _ = a.Raise(RoutineLock, "front-door")
		}
		return nil
	}
	a, err := New(Config{Send: send, Light: r.bulb, Journal: r.j})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = a.Raise(DoorForced, "front-door"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock")
	}
}

// A failed journal write raises nothing; a torn last line is dropped.
func TestJournal(t *testing.T) {
	if _, err := New(Config{Send: (&core{}).Send, Light: &bulb{}}); !errors.Is(err, ErrConfig) {
		t.Fatalf("no journal: %v", err)
	}
	j := &journal{}
	r := newRig(t, j)
	if _, err := r.a.Raise(Enrolment, ""); err != nil {
		t.Fatal(err)
	}
	j.b = append(j.b, `{"id":2,"kin`...) // a power cut mid-append
	r = newRig(t, j)
	if got := r.a.Log(); len(got) != 1 {
		t.Fatalf("after a torn line: %v", got)
	}
	if _, err := r.a.Raise(Enrolment, ""); err != nil { // the next append is clean
		t.Fatal(err)
	}
	if got := newRig(t, j).a.Log(); len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("append after a torn line, reopened: %v", got)
	}
	j.b = append(j.b, "{\"id\":3,\"x\":1}\n"...)
	if _, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: j}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt journal: %v", err)
	}
}

// TestLaterEventTellsAgain (NET-2 Texts and calls): an open alert folds a
// burst, but not a later event: an alarm three days after one the owner,
// away from home, could not clear calls again, and so does an unusual
// unlock a week later. Within the window a repeat still sends nothing.
// Catches one unresolved alert silencing every later one (Potency and UX
// fix-lists on #3909).
func TestLaterEventTellsAgain(t *testing.T) {
	c := &core{}
	now := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	a, err := New(Config{Send: c.Send, Light: &bulb{}, Journal: &journal{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a.Core(true)
	raise := func(k Kind, dev string) {
		t.Helper()
		if _, err := a.Raise(k, dev); err != nil {
			t.Fatal(err)
		}
	}
	raise(AlarmTriggered, "hall")
	now = now.Add(FoldCall - time.Second)
	raise(AlarmTriggered, "hall") // the same burst
	now = now.Add(72 * time.Hour)
	raise(AlarmTriggered, "hall")
	raise(DoorForced, "front")
	now = now.Add(48 * time.Hour)
	raise(DoorForced, "front")
	raise(UnusualUnlock, "front")
	now = now.Add(7 * 24 * time.Hour)
	raise(UnusualUnlock, "front")
	var calls, texts int
	for _, g := range c.got {
		if g.Kind == wire.AlertCall {
			calls++
		} else {
			texts++
		}
	}
	if calls != 4 || texts != 2 {
		t.Fatalf("%d calls and %d texts, want 4 and 2", calls, texts)
	}
	if st := a.Status(); len(st.Open) != 3 || st.Open[0].Count != 3 {
		t.Fatalf("open: %+v", st.Open)
	}
}

// A valve shut and a heater off each name what happened.
func TestSafetyOffNamesVerb(t *testing.T) {
	r := newRig(t, &journal{})
	r.a.SafetyOff("boiler", wire.VerbOff)
	r.a.SafetyOff("main-valve", wire.VerbShut)
	if len(r.core.got) != 2 || !strings.Contains(r.core.got[0].Text, "boiler was switched off") ||
		!strings.Contains(r.core.got[1].Text, "main-valve was shut") {
		t.Fatalf("texts %v", r.core.got)
	}
}

type short struct {
	journal
	fail bool
}

func (s *short) Append(b []byte) error {
	if s.fail {
		s.journal.b = append(s.journal.b, b[:len(b)/2]...)
		return errors.New("disk full")
	}
	return s.journal.Append(b)
}

// A failed append that wrote part of its line is cut back, so the next
// append and the next open see no fragment (delta L3 on #3909).
func TestShortWriteLeavesNoFragment(t *testing.T) {
	j := &short{}
	a, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: j})
	if err != nil {
		t.Fatal(err)
	}
	j.fail = true
	if _, err := a.Raise(Enrolment, ""); err == nil {
		t.Fatal("short write not reported")
	}
	j.fail = false
	if _, err := a.Raise(RoutineLock, "front-door"); err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: &j.journal})
	if err != nil {
		t.Fatalf("reopen after a short write: %v", err)
	}
	if n := len(b.Log()); n != 1 {
		t.Fatalf("%d lines after reopen, want the one written whole", n)
	}
}

// TestLiftKeepsClosedTripTime (KRN-12, ENF-h-a2): lifting a cut again
// later leaves a trip it already closed as it was: its Resolved time, in
// the log and in the journal after a restart, stays the first lift's, so
// the page never shows a wrong lift time for a standing record. Catches
// Lifted rewriting closed trips (dropping its Open test).
func TestLiftKeepsClosedTripTime(t *testing.T) {
	j := &journal{}
	now := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	a, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: j,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	trip, err := a.Raise(Trip, "edge")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	first := now
	if err := a.Lifted("edge"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := a.Lifted("edge"); err != nil {
		t.Fatal(err)
	}
	check := func(what string, log []Record) {
		t.Helper()
		i := slices.IndexFunc(log, func(r Record) bool { return r.ID == trip.ID })
		if i < 0 || log[i].Open || !log[i].Resolved.Equal(first) {
			t.Fatalf("%s: closed trip %+v, want resolved at %v", what, log, first)
		}
	}
	check("log", a.Log())
	b, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: j})
	if err != nil {
		t.Fatal(err)
	}
	check("after restart", b.Log())
}

// torn is a journal whose append writes half its line while short is
// set, and whose cut-back fails while noCut is.
type torn struct {
	journal
	short, noCut bool
}

func (j *torn) Append(b []byte) error {
	if j.short {
		j.journal.b = append(j.journal.b, b[:len(b)/2]...)
		return errors.New("disk full")
	}
	return j.journal.Append(b)
}

func (j *torn) Truncate(n int) error {
	if j.noCut {
		return errors.New("disk: truncate failed")
	}
	return j.journal.Truncate(n)
}

// A failed append whose cut-back fails too leaves a fragment: no record
// is appended after it until a cut-back succeeds, so a saved record never
// sits glued to the fragment, and a later failed append's cut-back never
// removes it (Security 6722859700 on #5101).
func TestFailedCutBackKeepsSavedRecord(t *testing.T) {
	j := &torn{}
	a, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: j})
	if err != nil {
		t.Fatal(err)
	}
	j.short, j.noCut = true, true
	if _, err := a.Raise(Enrolment, ""); err == nil {
		t.Fatal("a torn record was reported saved")
	}
	j.short = false
	torn := len(j.b)
	if _, err := a.Raise(RoutineLock, "front-door"); err == nil || len(j.b) != torn {
		t.Fatalf("a record was appended after a fragment not cut back: %v", err)
	}
	j.noCut = false
	saved, err := a.Raise(RoutineLock, "back-door")
	if err != nil {
		t.Fatal(err)
	}
	j.short = true
	if _, err := a.Raise(RoutineLock, "side-door"); err == nil {
		t.Fatal("a torn record was reported saved")
	}
	b, err := New(Config{Send: (&core{}).Send, Light: &bulb{}, Journal: &journal{b: slices.Clone(j.b)}})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !slices.ContainsFunc(b.Log(), func(r Record) bool { return r.ID == saved.ID && r.Device == "back-door" }) {
		t.Fatalf("a saved record was lost to a later cut-back: %+v", b.Log())
	}
}

// TestOneOfferPerTelling (NET-2 Texts and calls; #4903): two callers
// that find the same alert unsent, two Core(true) calls or a Raise and a
// Core, offer it once between them. The kernel's first Send blocks until
// the second caller has had time to reach Send too; it still takes one
// copy, and an alert resolved before the kernel took it is not offered,
// even when it is resolved after Core collected it. A Core that offers a
// Raise's new telling before the Raise reaches the offer lock leaves the
// Raise nothing to send; a telling raised again while Core offers the
// older one is still offered; a core going down offers nothing.
// Catches collecting an unsent alert outside the offer lock.
func TestOneOfferPerTelling(t *testing.T) {
	type gate struct {
		mu      sync.Mutex
		refuse  bool
		block   bool
		got     int
		entered chan struct{}
		release chan struct{}
		light   Light            // nil is a plain bulb
		now     func() time.Time // nil is time.Now
	}
	newAlerts := func(g *gate) *Alerts {
		g.entered, g.release = make(chan struct{}), make(chan struct{})
		send := func(wire.Alert) error {
			g.mu.Lock()
			if g.refuse {
				g.mu.Unlock()
				return channel.ErrNoSession
			}
			g.got++
			first := g.block
			g.block = false
			g.mu.Unlock()
			if first {
				close(g.entered)
				<-g.release
			}
			return nil
		}
		light := g.light
		if light == nil {
			light = &bulb{}
		}
		a, err := New(Config{Send: send, Light: light, Journal: &journal{}, Now: g.now})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	race := func(g *gate, first, second func()) {
		t.Helper()
		var wg sync.WaitGroup
		wg.Go(first)
		select {
		case <-g.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the first offer never reached Send")
		}
		wg.Go(second)
		time.Sleep(100 * time.Millisecond) // the second caller reaches Send or the offer lock
		close(g.release)
		wg.Wait()
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.got != 1 {
			t.Fatalf("the kernel took %d copies of one alert, want 1", g.got)
		}
	}

	// Two Core(true) calls, as a hello and a tick, for an alert the
	// kernel refused while the core was gone.
	g := &gate{refuse: true}
	a := newAlerts(g)
	if r, _ := a.Raise(HeadFork, ""); r.Sent {
		t.Fatal("a refused text counts as sent")
	}
	g.mu.Lock()
	g.refuse, g.block = false, true
	g.mu.Unlock()
	race(g, func() { a.Core(true) }, func() { a.Core(true) })

	// A Raise offering a new alert and a Core coming up.
	g = &gate{block: true}
	a = newAlerts(g)
	race(g, func() { _, _ = a.Raise(DoorForced, "front-door") }, func() { a.Core(true) })
	if r := a.Status().Open; len(r) != 1 || !r[0].Sent {
		t.Fatalf("the offered alert: %+v", r)
	}

	// An alert the owner resolved before the kernel took it is not
	// offered when the core comes back: there is nothing left to act on.
	g = &gate{refuse: true}
	a = newAlerts(g)
	r, _ := a.Raise(HeadFork, "")
	if err := a.Resolve(r.ID); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.refuse = false
	g.mu.Unlock()
	a.Core(true)
	if g.got != 0 {
		t.Fatalf("a resolved alert was offered %d times", g.got)
	}

	// Resolved while Core offers the alert before it: Core collected both,
	// and offers only the one still open.
	g = &gate{refuse: true}
	a = newAlerts(g)
	_, _ = a.Raise(HeadFork, "")
	r, _ = a.Raise(UnusualUnlock, "front-door")
	g.mu.Lock()
	g.refuse, g.block = false, true
	g.mu.Unlock()
	done := make(chan struct{})
	go func() { a.Core(true); close(done) }()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first offer never reached Send")
	}
	if err := a.Resolve(r.ID); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	<-done
	g.mu.Lock()
	if g.got != 1 {
		t.Fatalf("the kernel took %d texts, want only the open alert's", g.got)
	}
	g.mu.Unlock()

	wait := func(ch <-chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("waiting for " + what)
		}
	}
	until := func(a *Alerts, ok func(Record) bool, what string) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); !slices.ContainsFunc(a.Log(), ok); {
			if time.Now().After(end) {
				t.Fatal("waiting for " + what)
			}
			time.Sleep(time.Millisecond)
		}
	}

	// Core sends a Raise's new telling first: Core's light is held until
	// the Raise has put its record, and the Raise's light until Core has
	// returned, so Core collects and offers the record before the Raise
	// takes the offer lock. The Raise then finds it taken.
	b := &bulb{}
	g = &gate{light: b}
	a = newAlerts(g)
	coreShown, releaseCore, coreDone, raised := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.mu.Lock()
	base := len(b.shown)
	b.hook = func(n int) {
		switch n - base {
		case 1: // Core's
			close(coreShown)
			<-releaseCore
		case 2: // the Raise's
			<-coreDone
		}
	}
	b.mu.Unlock()
	go func() { a.Core(true); close(coreDone) }()
	wait(coreShown, "Core's light")
	go func() { _, _ = a.Raise(DoorForced, "front-door"); close(raised) }()
	until(a, func(r Record) bool { return r.Kind == DoorForced }, "the Raise's record")
	close(releaseCore)
	wait(raised, "the Raise")
	g.mu.Lock()
	if g.got != 1 {
		t.Fatalf("Core offered a Raise's telling first, and the kernel took %d copies, want 1", g.got)
	}
	g.mu.Unlock()

	// A newer telling lands while Core offers the older one: the older
	// offer does not mark it sent, so the Raise offers it too.
	var clockMu sync.Mutex
	clock := time.Date(2026, 10, 29, 3, 0, 0, 0, time.UTC)
	g = &gate{refuse: true, now: func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }}
	a = newAlerts(g)
	_, _ = a.Raise(DoorForced, "front-door")
	g.mu.Lock()
	g.refuse, g.block = false, true
	g.mu.Unlock()
	coreDone, raised = make(chan struct{}), make(chan struct{})
	go func() { a.Core(true); close(coreDone) }()
	wait(g.entered, "Core's offer")
	clockMu.Lock()
	clock = clock.Add(FoldCall)
	clockMu.Unlock()
	go func() { _, _ = a.Raise(DoorForced, "front-door"); close(raised) }()
	until(a, func(r Record) bool { return r.Kind == DoorForced && r.Count == 2 }, "the newer telling")
	close(g.release)
	wait(coreDone, "Core")
	wait(raised, "the Raise")
	g.mu.Lock()
	if g.got != 2 {
		t.Fatalf("the kernel took %d calls for two tellings, want 2", g.got)
	}
	g.mu.Unlock()
	if r := a.Status().Open; len(r) != 1 || !r[0].Sent || r[0].Count != 2 {
		t.Fatalf("the re-told alert: %+v", r)
	}

	// A core going down offers nothing; coming up offers the unsent alert.
	g = &gate{refuse: true}
	a = newAlerts(g)
	_, _ = a.Raise(HeadFork, "")
	g.mu.Lock()
	g.refuse = false
	g.mu.Unlock()
	a.Core(false)
	if g.got != 0 {
		t.Fatalf("a core going down was offered %d texts", g.got)
	}
	a.Core(true)
	if g.got != 1 {
		t.Fatalf("a core coming up was offered %d texts, want 1", g.got)
	}
}
