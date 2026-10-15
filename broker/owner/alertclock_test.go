package owner

import (
	"testing"
	"time"
)

// REQ: CH-15

// A clock correction that leaves LocalAlertAt in the future must not
// suppress sign-in alerts until real time catches up (#1442): a future
// value counts as expired, as the pacer treats a future window.
func TestFutureLocalAlertAtDoesNotSuppressSignInAlerts(t *testing.T) {
	r := newRig(t, nil)
	// A clock correction left the last alert a day ahead of now.
	r.ch.mu.Lock()
	r.ch.codes.st.LocalAlertAt = r.clock().Add(24 * time.Hour)
	r.ch.mu.Unlock()
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	want := "A phone signed in on my Wi-Fi at " + r.clock().Format("15:04") + ". Not you? Text STOP."
	if got := r.inbox(); got != want {
		t.Fatalf("sign-in alert after the clock moved back: %q", got)
	}
}
