package owner

import (
	"testing"
	"time"
)

// REQ: CH-15

// A clock correction that leaves LocalAlertAt in the future must not
// suppress sign-in alerts until real time catches up (#1442): a future
// value counts as expired, as the pacer treats a future window. One
// nanosecond ahead is enough, so a guard with slack still fails.
func TestFutureLocalAlertAtDoesNotSuppressSignInAlerts(t *testing.T) {
	r := newRig(t, nil)
	code := r.totp()
	r.ch.mu.Lock()
	r.ch.codes.st.LocalAlertAt = r.clock().Add(time.Nanosecond)
	r.ch.mu.Unlock()
	if _, _, err := r.ch.LocalSignIn(code); err != nil {
		t.Fatal(err)
	}
	want := "A phone signed in on my Wi-Fi at " + r.clock().Format("15:04") + ". Not you? Text STOP."
	if got := r.inbox(); got != want {
		t.Fatalf("sign-in alert after the clock moved back: %q", got)
	}
}

// An alert stamped exactly now is still inside the hour and is held.
func TestEqualLocalAlertAtIsHeld(t *testing.T) {
	r := newRig(t, nil)
	code := r.totp()
	r.ch.mu.Lock()
	r.ch.codes.st.LocalAlertAt = r.clock()
	r.ch.mu.Unlock()
	if _, _, err := r.ch.LocalSignIn(code); err != nil {
		t.Fatal(err)
	}
	r.ch.WaitSends()
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("sign-in texted inside the hour: %q", m.Text)
	default:
	}
}
