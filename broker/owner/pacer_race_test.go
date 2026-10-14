package owner

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// gatedModem holds the first Send inside the modem until open is closed,
// so a test can run a second send while the first is still in flight.
// fail, when set, fails every Send without sending.
type gatedModem struct {
	modem.Modem
	once    sync.Once
	entered chan struct{}
	open    chan struct{}
	fail    error
}

func (g *gatedModem) Send(to, text string) error {
	if g.fail != nil {
		return g.fail
	}
	first := false
	g.once.Do(func() { first = true })
	if first && g.open != nil {
		close(g.entered)
		<-g.open
	}
	return g.Modem.Send(to, text)
}

// raceRig opens a channel allowed perHour texts an hour whose modem holds
// the first send until the returned func is called.
func raceRig(t *testing.T, perHour int) (*rig, *gatedModem, func()) {
	t.Helper()
	st := &MemStore{}
	if err := st.Save(State{Pacing: Pacing{PerHour: perHour}}); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, st)
	g := &gatedModem{entered: make(chan struct{}), open: make(chan struct{})}
	r.edit = func(c *Config) { g.Modem = c.Modem; c.Modem = g }
	r.ch = r.open()
	var once sync.Once
	return r, g, func() { once.Do(func() { close(g.open) }) }
}

// inFlight runs send in the background and returns once it is inside the
// modem; wait returns its error after the modem is opened.
func inFlight(t *testing.T, g *gatedModem, send func() error) (wait func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- send() }()
	select {
	case <-g.entered:
	case err := <-done:
		t.Fatalf("first send returned %v before reaching the modem", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first send never reached the modem")
	}
	return func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("first send never returned")
			return nil
		}
	}
}

// REQ: CH-15 (#1638)
// With an allowance of 1 and an approval request still inside the modem,
// a concurrent NotifyNow is refused: the request's text is counted before
// it is sent, so exactly one text goes (Security S1 on #1574).
func TestInFlightRequestSpendsTheAllowance(t *testing.T) {
	r, g, open := raceRig(t, 1)
	defer open()
	wait := inFlight(t, g, func() error {
		_, err := r.ch.Request([]Item{lowItem("m0")}, 0)
		return err
	})
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d with a request in the modem, want 0", a)
	}
	if err := r.ch.NotifyNow("Q1 asks: which time?"); !errors.Is(err, ErrPaced) {
		t.Fatalf("NotifyNow beside an in-flight request: %v, want ErrPaced", err)
	}
	open()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || strings.Contains(got[0], "Q1 asks") {
		t.Fatalf("sent %q, want only the request", got)
	}
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d after one send of 1, want 0", a)
	}
}

// REQ: CH-15 (#1638)
// An urgent text and an auto-reply notice are counted before they are
// sent too: a non-urgent Post while one is inside the modem is held.
func TestInFlightUnpacedSendSpendsTheAllowance(t *testing.T) {
	for name, send := range map[string]func(*rig) error{
		"urgent": func(r *rig) error { return r.ch.Post(ClassSecurity, "Security alert.") },
		"auto-reply": func(r *rig) error {
			_, err := r.ch.QueueAutoReply(AutoReply{Ref: "t1", Recipients: []string{"bob@example.test"}, Body: "Thanks, got it."})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, g, open := raceRig(t, 1)
			defer open()
			wait := inFlight(t, g, func() error { return send(r) })
			if err := r.ch.Post(ClassUpdate, "An update."); err != nil {
				t.Fatal(err)
			}
			open()
			if err := wait(); err != nil {
				t.Fatal(err)
			}
			if got := r.sentTexts(); len(got) != 1 || got[0] == "An update." {
				t.Fatalf("sent %q, want only the first text", got)
			}
			if h := r.held(); len(h) != 1 || h[0].Text != "An update." {
				t.Fatalf("held %+v, want the update", h)
			}
		})
	}
}

// REQ: CH-15 (#1638)
// A release checks and counts each text in one step: when another send
// spends the last text between the release's first check and its send
// (here from the Current hook, which runs in that gap), the held text
// stays held.
func TestReleaseRechecksBeforeItSends(t *testing.T) {
	r, _, open := raceRig(t, 1)
	open()
	r.ch.mu.Lock()
	r.ch.codes.st.Held = []HeldText{{Text: "Cleared.", Class: ClassUpdate, At: r.clock(), Subjects: []string{"k"}}}
	r.ch.mu.Unlock()
	spent := false
	r.ch.SetCurrent(func([]string) bool {
		if !spent {
			spent = true
			if err := r.ch.Post(ClassSecurity, "Security alert."); err != nil {
				t.Error(err)
			}
		}
		return true
	})
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Security alert." {
		t.Fatalf("sent %q, want only the alert", got)
	}
	if h := r.held(); len(h) != 1 {
		t.Fatalf("held %d, want the cleared text kept", len(h))
	}
}

// REQ: CH-15 (#1638)
// A text counted before its send is uncounted when the send fails or the
// text is dropped as no longer true, so neither spends the allowance.
func TestFailedOrDroppedSendIsUncounted(t *testing.T) {
	r, g, open := raceRig(t, 2)
	open()
	g.fail = modem.ErrDown
	for name, send := range map[string]func() error{
		"urgent":     func() error { return r.ch.Post(ClassSecurity, "Security alert.") },
		"post":       func() error { return r.ch.Post(ClassUpdate, "An update.") },
		"notify-now": func() error { return r.ch.NotifyNow("Q1 asks: which time?") },
		"request": func() error {
			_, err := r.ch.Request([]Item{lowItem("m0")}, 0)
			return err
		},
	} {
		if err := send(); err == nil {
			t.Fatalf("%s: nil error from a down modem", name)
		}
		if a := r.ch.Allowance(r.clock()); a != 2 {
			t.Fatalf("%s: allowance %d after a failed send, want 2", name, a)
		}
	}
	g.fail = nil
	r.ch.SetCurrent(func([]string) bool { return false })
	if err := r.ch.PostAbout(ClassUpdate, "Cleared.", []string{"k"}); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("stale text sent: %q", got)
	}
	if a := r.ch.Allowance(r.clock()); a != 2 {
		t.Fatalf("allowance %d after a dropped text, want 2", a)
	}
}
