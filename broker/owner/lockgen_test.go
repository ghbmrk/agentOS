package owner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-7, CH-11, CH-18, ARC-2
// Also serves the UX-2wb-1 finding (no SPEC ID).

// heldModem holds every text until let is closed, telling entered of the
// first one: a notification still in delivery.
type heldModem struct {
	modem.Modem
	once    sync.Once
	entered chan struct{}
	let     chan struct{}
}

func (m *heldModem) Send(to, text string) error {
	m.once.Do(func() { close(m.entered) })
	<-m.let
	return m.Modem.Send(to, text)
}

// SR3-1: a local sign-in reports the lock generation it authenticated
// under, read in the critical section that checked the code, so a lock
// during its sign-in text is never credited to it; RESUME bound to that
// generation is refused at its commit point.
func TestLocalSignInReportsItsOwnLockGeneration(t *testing.T) {
	r := newRig(t, nil)
	r.async = true
	held := &heldModem{entered: make(chan struct{}), let: make(chan struct{})}
	r.edit = func(c *Config) { held.Modem = c.Modem; c.Modem = held }
	r.ch = r.open()
	r.eng.Stop(context.Background())
	before := r.ch.LocalStatus().Locks
	code := r.totp()
	type res struct {
		locks uint64
		err   error
	}
	done := make(chan res, 1)
	go func() {
		_, locks, err := r.ch.LocalSignIn(code)
		done <- res{locks, err}
	}()
	<-held.entered // the sign-in text is out; the code was accepted
	if err := r.ch.RequireUnlock(); err != nil {
		t.Fatal(err)
	}
	close(held.let)
	got := <-done
	if got.err != nil || got.locks != before {
		t.Fatalf("sign-in: locks %d (before %d), %v", got.locks, before, got.err)
	}
	st := r.ch.LocalStatus()
	if st.Unlocked || st.Locks != before+1 {
		t.Fatalf("after lock: %+v", st)
	}
	if _, err := r.ch.LocalResume(got.locks, r.ch.StopGen()); !errors.Is(err, ErrLocked) {
		t.Fatalf("RESUME under the old generation: %v", err)
	}
	if !r.eng.Stopped() {
		t.Fatal("resumed after the lock")
	}
	// A new sign-in binds the new generation, and RESUME runs under it.
	_, locks, err := r.ch.LocalSignIn(r.totp())
	if err != nil || locks != st.Locks {
		t.Fatalf("new sign-in: locks %d, %v", locks, err)
	}
	if msg, err := r.ch.LocalResume(locks, r.ch.StopGen()); err != nil || r.eng.Stopped() {
		t.Fatalf("RESUME after a new sign-in: %q %v", msg, err)
	}
}

// UX-2wb-1: LocalSignIn returns while its sign-in text is still in the modem,
// so the page's 10 s call limit is not spent on a 220 s send; the text goes
// once the modem lets it.
func TestLocalSignInRepliesBeforeItsTextIsSent(t *testing.T) {
	r := newRig(t, nil)
	r.async = true
	held := &heldModem{entered: make(chan struct{}), let: make(chan struct{})}
	r.edit = func(c *Config) { held.Modem = c.Modem; c.Modem = held }
	r.ch = r.open()
	done := make(chan error, 1)
	go func() {
		_, _, err := r.ch.LocalSignIn(r.totp())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sign-in waited for the modem")
	}
	<-held.entered
	close(held.let)
	r.ch.WaitSends()
	if m := <-r.phone.Inbox(); !strings.Contains(m.Text, "Wi-Fi") {
		t.Fatalf("sign-in text %q", m.Text)
	}
}

// UX-2wb-1: a page answer is replied to before its alert text leaves the
// modem; the decision is already taken, and the text goes once the modem
// lets it.
func TestLocalAnswerRepliesBeforeItsTextIsSent(t *testing.T) {
	r := newRig(t, nil)
	r.async = true
	held := &heldModem{entered: make(chan struct{}), let: make(chan struct{})}
	r.edit = func(c *Config) { held.Modem = c.Modem; c.Modem = held }
	r.ch = r.open()
	// Let the request's own text through; the answer's texts are the ones held.
	close(held.let)
	id, _ := r.ch.RequestLocal(localItem("i1"), 0)
	r.inbox()
	held.let = make(chan struct{})
	held.once = sync.Once{}
	held.entered = make(chan struct{})
	type res struct {
		msg string
		err error
	}
	done := make(chan res, 1)
	go func() {
		msg, err := r.ch.LocalAnswer(id, r.sum(id), true, r.totp())
		done <- res{msg, err}
	}()
	var got res
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("answer waited for the modem")
	}
	if got.err != nil || !strings.HasPrefix(got.msg, "Approved "+id) {
		t.Fatalf("answer: %q %v", got.msg, got.err)
	}
	if d := r.decisions(); len(d) != 1 || !d[0].Approved {
		t.Fatalf("decisions %+v", d)
	}
	<-held.entered
	close(held.let)
	r.ch.WaitSends()
}

// The shutdown drain (DrainSends) waits for texts in flight, up to its bound.
func TestShutdownDrainWaitsForTextsInFlightUpToItsBound(t *testing.T) {
	r := newRig(t, nil)
	r.async = true
	held := &heldModem{entered: make(chan struct{}), let: make(chan struct{})}
	r.edit = func(c *Config) { held.Modem = c.Modem; c.Modem = held }
	r.ch = r.open()
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	<-held.entered
	start := time.Now()
	r.ch.DrainSends(50*time.Millisecond, nil)
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("drain returned with a text in the modem")
	}
	released := make(chan struct{})
	go func() { time.Sleep(20 * time.Millisecond); close(held.let); close(released) }()
	start = time.Now()
	r.ch.DrainSends(5*time.Second, nil)
	if time.Since(start) > 2*time.Second {
		t.Fatal("drain waited past the send")
	}
	<-released
}

// A drain whose live hook says nothing is left to send the texts (no modem
// bridge on owner.sock) ends at once, not at its bound (Security S5,
// Potency P6 on #1746).
func TestShutdownDrainEndsWhenNothingIsLeftToSend(t *testing.T) {
	r := newRig(t, nil)
	r.async = true
	held := &heldModem{entered: make(chan struct{}), let: make(chan struct{})}
	r.edit = func(c *Config) { held.Modem = c.Modem; c.Modem = held }
	r.ch = r.open()
	defer func() { close(held.let); r.ch.WaitSends() }()
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	<-held.entered
	for name, live := range map[string]func() bool{
		"gone at the start": func() bool { return false },
		"gone during it":    goneAfter(3),
	} {
		start := time.Now()
		r.ch.DrainSends(5*time.Second, live)
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("%s: drain waited %v for a bridge that had gone", name, took)
		}
	}
}

// goneAfter says live n times, then gone.
func goneAfter(n int) func() bool {
	var calls atomic.Int32
	return func() bool { return calls.Add(1) <= int32(n) }
}
