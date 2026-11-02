package plan_test

// REQ: CLK-7, PLN-5

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
)

// A sign-in's code exchange still in flight when its guest is forgotten
// (the owner's wall passed, or the sign-in was removed) is dropped: nothing
// is stored and the guest does not come back as a sign-in guest. Forget
// reports a commit that landed before it, so its caller's account of the
// sign-in is final (#3149 item 1).
func TestPlanForgetEndsALateCodeExchange(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	f.gate = make(chan struct{})
	if err := p.BeginSignIn("g"); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, "g")
	type done struct {
		resp *http.Response
		d    string
	}
	out := make(chan done, 1)
	go func() {
		resp, d := p.Do(context.Background(), "g", req("POST", "/oauth/token", form, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), nil)
		out <- done{resp, d}
	}()
	for f.exchanges.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if p.Forget("g") {
		t.Fatal("Forget reported a commit that has not happened")
	}
	close(f.gate)
	got := <-out
	if got.resp != nil || got.d != plan.DEnded {
		t.Fatalf("the late exchange: %v %q", got.resp, got.d)
	}
	if p.Signing("g") || p.SignedIn("g") || p.Signed() {
		t.Fatalf("after the late exchange: signing=%v signedIn=%v stored=%v", p.Signing("g"), p.SignedIn("g"), p.Signed())
	}

	signIn(t, p, "h") // the gate stays open
	if !p.Forget("h") {
		t.Fatal("Forget did not report the committed sign-in")
	}
	if p.SignedIn("h") || !p.Signed() {
		t.Fatal("Forget dropped the login or kept the mark")
	}
}

// The user code shown to the owner is the one the clerk forwarded on the
// declared device step to that sign-in guest, recorded per guest and
// dropped with it; only a device step declares where it is (#3149 item 3).
func TestPlanRecordsTheForwardedUserCode(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	usercode := func(guest string) (*http.Response, string) {
		return p.Do(context.Background(), guest, req("POST", "/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`,
			map[string]string{"Content-Type": "application/json"}), nil)
	}
	if resp, _ := usercode("run"); resp != nil || p.UserCode("run") != "" {
		t.Fatal("a run guest reached the device step")
	}
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	resp, d := usercode("s")
	if d != "" {
		t.Fatalf("device step: %s", d)
	}
	if out := read(t, resp); !strings.Contains(out, `"user_code":"ABCD-1234"`) || resp.StatusCode != 200 {
		t.Fatalf("the device answer the guest got: %d %q", resp.StatusCode, out)
	}
	if c := p.UserCode("s"); c != "ABCD-1234" {
		t.Fatalf("recorded code %q", c)
	}
	if p.UserCode("other") != "" {
		t.Fatal("another guest has the code")
	}
	p.Forget("s")
	if p.UserCode("s") != "" {
		t.Fatal("the code outlived its guest")
	}

	d2 := f.decl(t)
	for i := range d2.Endpoints {
		if d2.Endpoints[i].Kind == plan.Code {
			d2.Endpoints[i].UserCode = "user_code"
		}
	}
	if _, err := plan.New(d2, f.sec, f.roots); err == nil {
		t.Fatal("a code exchange declared a user code")
	}
}
