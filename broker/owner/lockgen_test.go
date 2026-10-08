package owner

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-7, CH-11, CH-18, ARC-2

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
	if _, err := r.ch.LocalResume(got.locks); !errors.Is(err, ErrLocked) {
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
	if msg, err := r.ch.LocalResume(locks); err != nil || r.eng.Stopped() {
		t.Fatalf("RESUME after a new sign-in: %q %v", msg, err)
	}
}
