package alert

// REQ: NET-2

import (
	"errors"
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
}

func (b *bulb) Show(c Colour) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.shown = append(b.shown, c)
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

// TestDroppedTextStillOnLight (NET-2 Texts and calls): a text the core
// refuses, and one it takes and drops, still show red on the light, stay
// open on the page and stay in the log, across a restart; only the
// enforcer's page resolves them, and the light goes off only then.
// Catches reliance on the core.
func TestDroppedTextStillOnLight(t *testing.T) {
	j := &journal{}
	r := newRig(t, j)
	if c := r.bulb.now(); c != Off {
		t.Fatalf("light %v before any alert", c)
	}
	r.core.refuse = true
	refused, err := r.a.Raise(UnusualUnlock, "front-door")
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
			t.Fatalf("light %v with two unresolved alerts", c)
		}
		st := r.a.Status()
		if len(st.Open) != 2 || st.Open[0].Device != "front-door" || st.Open[1].Device != "back-door" {
			t.Fatalf("open on the page: %v", st.Open)
		}
		if len(r.a.Log()) != 2 {
			t.Fatalf("log %v", r.a.Log())
		}
	}

	// The core coming back is offered the refused text again; taking it
	// resolves nothing.
	r2 := newRig(t, j)
	if len(r2.core.got) != 1 || !strings.Contains(r2.core.got[0].Text, "front-door") {
		t.Fatalf("resent on the core's return: %v", r2.core.got)
	}
	if c := r2.bulb.now(); c != Red {
		t.Fatalf("light %v after the core took the text", c)
	}
	if err := r2.a.Resolve(refused.ID); err != nil {
		t.Fatal(err)
	}
	if c := r2.bulb.now(); c != Red {
		t.Fatalf("light %v with one alert still open", c)
	}
	if err := r2.a.Resolve(dropped.ID); err != nil {
		t.Fatal(err)
	}
	if c := r2.bulb.now(); c != Off {
		t.Fatalf("light %v once the owner resolved both", c)
	}
	if err := r2.a.Resolve(dropped.ID); !errors.Is(err, ErrUnknown) {
		t.Fatalf("resolving twice: %v", err)
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
		// says so, with no condition on it (UX fix-lists on #3909).
		if s.delivery == Text && !strings.HasSuffix(w, "its light stays red until you do.") {
			t.Fatalf("kind %d's text does not say the light stays red until cleared: %q", k, w)
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

// The light: recovery pending is red with nothing open; the core down is
// amber; a paused channel is red and resolves only by resuming.
func TestLightStates(t *testing.T) {
	r := newRig(t, &journal{})
	r.a.Recovery(true)
	if r.bulb.now() != Red {
		t.Fatal("recovery pending is not red")
	}
	r.a.Recovery(false)
	r.a.Core(false)
	if r.bulb.now() != Amber {
		t.Fatal("core down is not amber")
	}
	r.a.Core(true)
	r.a.Paused()
	st := r.a.Status()
	if r.bulb.now() != Red || len(st.Open) != 1 || st.Open[0].Kind != ChannelPaused {
		t.Fatalf("paused: %+v", st)
	}
	if err := r.a.Resolve(st.Open[0].ID); !errors.Is(err, ErrResolved) {
		t.Fatalf("resolving a pause without resuming: %v", err)
	}
	if err := r.a.Resumed(); err != nil || r.bulb.now() != Off {
		t.Fatalf("resumed: %v %v", err, r.bulb.now())
	}
	r.a.SafetyOff("boiler", wire.VerbOff)
	if len(r.core.got) != 2 || !strings.Contains(r.core.got[1].Text, "boiler") {
		t.Fatalf("safety off: %v", r.core.got)
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
