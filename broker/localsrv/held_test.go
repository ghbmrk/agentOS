package localsrv

// REQ: CH-19, CH-21, CH-8

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// TestHeldOpNeedsSession (HELD-4): the held-text op refuses a missing,
// made-up or ended token and reaches nothing; a live session reads the
// list, as often as it likes. Without Config.Held it is not served.
func TestHeldOpNeedsSession(t *testing.T) {
	r := newRig(t)
	if r.srv.Ops()[localapi.OpHeld] != nil {
		t.Fatal("served with nothing kept")
	}
	reads := 0
	want := localapi.HeldList{Items: []localapi.HeldItem{{ID: "1", Kind: localapi.HeldCode, At: time.Unix(0, 0), Text: "I fixed the code."}}}
	r.srv.cfg.Held = func() localapi.HeldList { reads++; return want }
	r.ops = r.srv.Ops()
	for _, tok := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), "made-up"} {
		if _, err := r.call(localapi.OpHeld, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
			t.Errorf("token %q: %v", tok, err)
		}
	}
	if _, err := r.raw(localapi.OpHeld, `{}`); code(err) != localapi.ErrUnauthorized {
		t.Errorf("no args: %v", err)
	}
	if reads != 0 {
		t.Fatalf("read %d times without a session", reads)
	}
	tok := r.signIn()
	for range 2 {
		got, err := r.call(localapi.OpHeld, localapi.Auth{Token: tok})
		if l, ok := got.(localapi.HeldList); err != nil || !ok || len(l.Items) != 1 || l.Items[0].Text != "I fixed the code." {
			t.Fatalf("read %v %v", got, err)
		}
	}
	if _, err := r.call(localapi.OpSignOut, localapi.Auth{Token: tok}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.call(localapi.OpHeld, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("after sign-out: %v", err)
	}
	if reads != 2 {
		t.Fatalf("read %d times", reads)
	}
}
