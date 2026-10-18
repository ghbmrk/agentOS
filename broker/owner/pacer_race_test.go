package owner

import (
	"errors"
	"fmt"
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
	// failAfter, when set, runs inside a failing Send, before it returns.
	failAfter func()
}

func (g *gatedModem) Send(to, text string) error {
	if g.fail != nil {
		if g.failAfter != nil {
			g.failAfter()
		}
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
	if err := st.Save(State{Pacing: Pacing{PerHour: perHour, ApprovalHeld: true}}); err != nil {
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
// A text counted before its send is uncounted when the modem proves it
// was not sent (modem.ErrNotSent) or it is dropped as no longer true, so
// neither spends the allowance. A failure that may hide a text that went
// (modem.ErrDown alone: no receipt) keeps the count (security R2 on #1686).
func TestOnlyUnsentTextIsUncounted(t *testing.T) {
	sends := map[string]func(r *rig) error{
		"urgent":     func(r *rig) error { return r.ch.Post(ClassSecurity, "Security alert.") },
		"post":       func(r *rig) error { return r.ch.Post(ClassUpdate, "An update.") },
		"notify-now": func(r *rig) error { return r.ch.NotifyNow("Q1 asks: which time?") },
		"request": func(r *rig) error {
			_, err := r.ch.Request([]Item{lowItem("m0")}, 0)
			return err
		},
		"auto-reply": func(r *rig) error {
			_, err := r.ch.QueueAutoReply(AutoReply{Ref: "t1", Recipients: []string{"bob@example.test"}, Body: "Thanks, got it."})
			return err
		},
	}
	for _, c := range []struct {
		name  string
		fail  error
		spent int
	}{{"not-sent", modem.ErrNotSent, 0}, {"maybe-sent", modem.ErrDown, 1}} {
		fail, spent := c.fail, c.spent
		for name, send := range sends {
			t.Run(name+"/"+c.name, func(t *testing.T) {
				r, g, open := raceRig(t, 2)
				open()
				g.fail = fail
				err := send(r)
				if name != "auto-reply" && err == nil {
					t.Fatal("nil error from a failed send")
				}
				if a := r.ch.Allowance(r.clock()); a != 2-spent {
					t.Fatalf("allowance %d after a failed send, want %d", a, 2-spent)
				}
			})
		}
	}
	r, _, open := raceRig(t, 2)
	open()
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

// REQ: CH-15 (#1638)
// Each paced send checks the allowance and counts its text in one hold
// of the lock, so no send beside it can spend the last text in between
// (P/UX/L3 on #1686: an unlock between the two survived the other tests).
func TestPacedCheckAndCountShareOneHold(t *testing.T) {
	for name, send := range map[string]func(r *rig) error{
		"post":       func(r *rig) error { return r.ch.Post(ClassUpdate, "An update.") },
		"notify-now": func(r *rig) error { return r.ch.NotifyNow("Q1 asks: which time?") },
		"release": func(r *rig) error {
			r.ch.mu.Lock()
			r.ch.codes.st.Held = []HeldText{{Text: "Held.", Class: ClassUpdate, At: r.clock()}}
			r.ch.mu.Unlock()
			return r.ch.Release()
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, _, open := raceRig(t, 2)
			open()
			if err := send(r); err != nil {
				t.Fatal(err)
			}
			if got := r.sentTexts(); len(got) != 1 {
				t.Fatalf("sent %q, want one text", got)
			}
			r.ch.mu.Lock()
			checked, counted := r.ch.checkedIn, r.ch.countedIn
			r.ch.mu.Unlock()
			if counted == 0 || checked != counted {
				t.Fatalf("checked in hold %d, counted in hold %d: want one hold", checked, counted)
			}
		})
	}
}

// REQ: CH-15 (#1638)
// Two sends that count at once both stay counted. A send that read the
// clock before the lock could count an earlier time than a send that
// counted while it waited; the later stamp then read as a clock step back
// and was dropped, so two texts went with one counted (security B1 on
// #1686). Here a concurrent urgent send runs inside each clock read of
// the send under test, at a later time.
func TestConcurrentCountsAreAllKept(t *testing.T) {
	sends := map[string]func(r *rig) error{
		"urgent":     func(r *rig) error { return r.ch.Post(ClassSecurity, "First alert.") },
		"post":       func(r *rig) error { return r.ch.Post(ClassUpdate, "An update.") },
		"notify-now": func(r *rig) error { return r.ch.NotifyNow("Q1 asks: which time?") },
		"release": func(r *rig) error {
			r.ch.mu.Lock()
			r.ch.codes.st.Held = []HeldText{{Text: "Held.", Class: ClassUpdate, At: r.clock()}}
			r.ch.mu.Unlock()
			return r.ch.Release()
		},
	}
	for name, send := range sends {
		reads := skewRun(t, send, 0)
		for k := 1; k <= reads; k++ {
			t.Run(fmt.Sprintf("%s/read%d", name, k), func(t *testing.T) { skewRun(t, send, k) })
		}
	}
}

// skewRun runs send on a fresh channel allowed 5 texts an hour. At the
// k-th clock read, it moves the clock a second on and runs an urgent
// send beside it, letting it finish first unless send holds the lock,
// and returns the time read before the move. It then checks both texts
// went and both are counted. It returns how many clock reads send made.
func skewRun(t *testing.T, send func(*rig) error, k int) int {
	t.Helper()
	st := &MemStore{}
	if err := st.Save(State{Pacing: Pacing{PerHour: 5}}); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, st)
	var (
		mu    sync.Mutex
		armed bool
		reads int
		other chan error
	)
	r.edit = func(c *Config) {
		c.Now = func() time.Time {
			mu.Lock()
			if !armed {
				mu.Unlock()
				return r.clock()
			}
			reads++
			fire := reads == k
			if fire {
				armed = false
			}
			mu.Unlock()
			now := r.clock()
			if fire {
				r.advance(time.Second)
				other = make(chan error, 1)
				go func() { other <- r.ch.Post(ClassSecurity, "Second alert.") }()
				select {
				case err := <-other:
					other <- err
				case <-time.After(100 * time.Millisecond):
				}
			}
			return now
		}
	}
	r.ch = r.open()
	mu.Lock()
	armed = true
	mu.Unlock()
	if err := send(r); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	armed = false
	n := reads
	mu.Unlock()
	if k == 0 {
		return n
	}
	if other == nil {
		t.Fatalf("send made %d clock reads, fewer than %d", n, k)
	}
	if err := <-other; err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 2 {
		t.Fatalf("sent %q, want two texts", got)
	}
	if a := r.ch.Allowance(r.clock()); a != 3 {
		t.Fatalf("allowance %d after two texts of 5, want 3", a)
	}
	return n
}

// REQ: CH-15 (#1638)
// A text counts toward the hour from when its send returned, not from
// when it was counted before the send: one that waited two minutes in the
// modem still spends the allowance 59 minutes after it went (security R3
// on #1686).
func TestCountRunsFromTheSend(t *testing.T) {
	for _, c := range []struct {
		name string
		fail error
	}{{"sent", nil}, {"maybe-sent", modem.ErrDown}} {
		t.Run(c.name, func(t *testing.T) {
			r, g, open := raceRig(t, 1)
			g.fail = c.fail
			if c.fail != nil {
				g.failAfter = func() { r.advance(2 * time.Minute) }
			}
			wait := func() error { return nil }
			if c.fail == nil {
				wait = inFlight(t, g, func() error { return r.ch.Post(ClassSecurity, "Security alert.") })
				r.advance(2 * time.Minute)
				open()
			} else {
				open()
				_ = r.ch.Post(ClassSecurity, "Security alert.")
			}
			if err := wait(); err != nil {
				t.Fatal(err)
			}
			r.advance(59 * time.Minute)
			if a := r.ch.Allowance(r.clock()); a != 0 {
				t.Fatalf("allowance %d 59 minutes after the send, want 0", a)
			}
			r.advance(2 * time.Minute)
			if a := r.ch.Allowance(r.clock()); a != 1 {
				t.Fatalf("allowance %d an hour after the send, want 1", a)
			}
		})
	}
}

// asyncRaceRig is raceRig with textAfterReply sending on its own goroutine,
// as agentosd runs it (#1746).
func asyncRaceRig(t *testing.T, perHour int) (*rig, *gatedModem, func()) {
	t.Helper()
	st := &MemStore{}
	if err := st.Save(State{Pacing: Pacing{PerHour: perHour, ApprovalHeld: true}}); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, st)
	r.async = true
	g := &gatedModem{entered: make(chan struct{}), open: make(chan struct{})}
	r.edit = func(c *Config) { g.Modem = c.Modem; c.Modem = g }
	r.ch = r.open()
	var once sync.Once
	return r, g, func() { once.Do(func() { close(g.open) }) }
}

// REQ: CH-15 (#1638, #1746)
// The texts a local page call sends after its reply (textAfterReply: the
// sign-in text and the wrong-code alert) are counted before they reach
// the modem too: the page call has returned, the text is still inside the
// modem, and the hour is already spent, so a concurrent NotifyNow is
// refused and a Post is held. A text the modem proves unsent is uncounted.
func TestInFlightTextAfterReplySpendsTheAllowance(t *testing.T) {
	calls := map[string]func(r *rig){
		"sign-in": func(r *rig) {
			if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
				r.t.Fatal(err)
			}
		},
		"wrong-code": func(r *rig) {
			if _, _, err := r.ch.LocalSignIn("000000"); err == nil {
				r.t.Fatal("wrong code accepted")
			}
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			r, g, open := asyncRaceRig(t, 1)
			defer func() { open(); r.ch.WaitSends() }()
			// The reply comes first (#1746): the call returns while its
			// text waits in the modem.
			call(r)
			select {
			case <-g.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("no text after the reply reached the modem")
			}
			if a := r.ch.Allowance(r.clock()); a != 0 {
				t.Fatalf("allowance %d with a text after the reply in the modem, want 0", a)
			}
			if err := r.ch.NotifyNow("Q1 asks: which time?"); !errors.Is(err, ErrPaced) {
				t.Fatalf("NotifyNow beside an in-flight text after the reply: %v, want ErrPaced", err)
			}
			if err := r.ch.Post(ClassUpdate, "An update."); err != nil {
				t.Fatal(err)
			}
			open()
			r.ch.WaitSends()
			got := r.sentTexts()
			if len(got) != 1 || got[0] == "An update." || strings.Contains(got[0], "Q1 asks") {
				t.Fatalf("sent %q, want only the text after the reply", got)
			}
			if h := r.held(); len(h) != 1 || h[0].Text != "An update." {
				t.Fatalf("held %+v, want the update", h)
			}
		})
		t.Run(name+"/not-sent", func(t *testing.T) {
			r, g, open := asyncRaceRig(t, 1)
			open()
			g.fail = modem.ErrNotSent
			call(r)
			r.ch.WaitSends()
			if a := r.ch.Allowance(r.clock()); a != 1 {
				t.Fatalf("allowance %d after an unsent text after the reply, want 1", a)
			}
		})
	}
}
