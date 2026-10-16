package localsrv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: ONB-3, ONB-9, CRED-5

// fakePlanSignIn is agentosd's post-setup plan sign-in: ready says whether
// it would start, link is what it returns, waiting whether a sign-in still
// waits for the owner (a start that returns a code sets it).
type fakePlanSignIn struct {
	ready, waiting bool
	link           string
	err            error
	started        int
}

func (f *fakePlanSignIn) Ready() bool   { return f.ready }
func (f *fakePlanSignIn) Waiting() bool { return f.waiting }
func (f *fakePlanSignIn) Start(context.Context) (string, string, string, error) {
	f.started++
	if f.err != nil {
		return "", "", "", f.err
	}
	f.waiting = true
	return f.link, "ABCD-EF23", "OpenAI", nil
}

func (r *rig) planSignIn(tok, c string) (localapi.PlanSignInStarted, error) {
	r.t.Helper()
	out, err := r.call(localapi.OpPlanSignIn, localapi.PlanSignInStart{Token: tok, Code: c})
	if err != nil {
		return localapi.PlanSignInStarted{}, err
	}
	return out.(localapi.PlanSignInStarted), nil
}

// #1264 item 1: after setup, a signed-in page asks whether the plan's
// sign-in is offered and starts it; neither works without a live session,
// and a closed gate offers and starts nothing.
func TestThePlanSignInNeedsASessionAndAnOpenGate(t *testing.T) {
	r := newRig(t)
	f := &fakePlanSignIn{link: "https://auth.openai.com/codex/device"}
	r.srv.cfg.PlanSignIn = f
	if _, err := r.call(localapi.OpPlanSignInReady, localapi.Auth{}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("ready without a token: %v", err)
	}
	if _, err := r.planSignIn("", good); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("start without a token: %v", err)
	}
	tok := r.signIn()
	out, err := r.call(localapi.OpPlanSignInReady, localapi.Auth{Token: tok})
	if err != nil || out.(localapi.PlanSignIn).Ready {
		t.Fatalf("closed gate: %v %v", out, err)
	}
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrBadArgs || f.started != 0 {
		t.Fatalf("closed gate start: %v %d", err, f.started)
	}
	f.ready = true
	out, err = r.call(localapi.OpPlanSignInReady, localapi.Auth{Token: tok})
	if err != nil || !out.(localapi.PlanSignIn).Ready {
		t.Fatalf("open gate: %v %v", out, err)
	}
	a, err := r.planSignIn(tok, good)
	if err != nil || a.Refusal != "" || a.DeviceCode != (localapi.DeviceCode{Link: f.link, Code: "ABCD-EF23", From: "OpenAI"}) {
		t.Fatalf("start: %+v %v", a, err)
	}
	r.srv.cfg.PlanSignIn = nil
	out, err = r.call(localapi.OpPlanSignInReady, localapi.Auth{Token: tok})
	if err != nil || out.(localapi.PlanSignIn).Ready {
		t.Fatalf("no sign-in: %v %v", out, err)
	}
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrBadArgs {
		t.Fatalf("no sign-in start: %v", err)
	}
}

// CRED-5: whoever approves the code becomes the plan's login, so a stolen
// session alone cannot start it: as for a SIM, it always takes a code from
// the owner's code generator, and wrong codes count toward the socket's
// limit. The unlock proof is not such a code.
func TestThePlanSignInAlwaysTakesACode(t *testing.T) {
	r := newRig(t)
	f := &fakePlanSignIn{ready: true, link: "https://auth.openai.com/codex/device"}
	r.srv.cfg.PlanSignIn = f
	tok := r.signIn()
	signIns := r.own.signIns
	if a, err := r.planSignIn(tok, ""); err != nil || a.Refusal != localapi.RefusedCodeNeeded || f.started != 0 || r.own.signIns != signIns {
		t.Fatalf("no code: %+v %v", a, err)
	}
	if _, err := r.planSignIn(tok, owner.UnlockProofPrefix+"ticket"); code(err) != localapi.ErrBadArgs || f.started != 0 {
		t.Fatalf("unlock proof: %v", err)
	}
	for i := 0; i < WrongPerMinute; i++ {
		if a, err := r.planSignIn(tok, "000000"); err != nil || a.Refusal != localapi.RefusedWrongCode || f.started != 0 {
			t.Fatalf("wrong code %d: %+v %v", i, a, err)
		}
	}
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrLimited || f.started != 0 {
		t.Fatalf("past the limit: %v", err)
	}
}

// The page shows only what the provider issued: a link that is not an
// https page fails, busy is the page's busy, any other error a fixed
// failure, and starts are bounded per minute.
func TestThePlanSignInRelaysOnlyAProvidersCode(t *testing.T) {
	r := newRig(t)
	f := &fakePlanSignIn{ready: true, link: "http://auth.openai.com/codex/device"}
	r.srv.cfg.PlanSignIn = f
	tok := r.signIn()
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrFailed {
		t.Fatalf("http link: %v", err)
	}
	// The refused link's worker has stopped waiting: the provider's own
	// busy is what the page relays.
	f.waiting = false
	f.link, f.err = "https://auth.openai.com/codex/device", SignInBusy
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrSignInBusy {
		t.Fatalf("busy: %v", err)
	}
	f.err = errors.New("provagent: /var/lib/x")
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrFailed {
		t.Fatalf("other error: %v", err)
	}
	// The http link and the other error each started a worker; the busy
	// start did not, so it does not count toward the bound.
	f.err = nil
	for i := 2; i < localapi.DeviceCodesPerMinute; i++ {
		f.waiting = false
		if _, err := r.planSignIn(tok, good); err != nil {
			t.Fatal(err)
		}
	}
	f.waiting = false
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrLimited || f.started != localapi.DeviceCodesPerMinute+1 {
		t.Fatalf("past the bound: %v %d", err, f.started)
	}
}

func (r *rig) planReady(tok string) localapi.PlanSignIn {
	r.t.Helper()
	out, err := r.call(localapi.OpPlanSignInReady, localapi.Auth{Token: tok})
	if err != nil {
		r.t.Fatal(err)
	}
	return out.(localapi.PlanSignIn)
}

// REQ: G1-1264-busy-1
// #1945: the owner leaves the page, or taps "I signed in", before approving
// the provider's code. While that sign-in waits, the session that started
// it gets its link and code back, on the home page's ask and on a second
// start, without a code and without a new start. Another session gets them
// only after a good code, which moves them to that session; the code alone
// starts nothing. Once the sign-in stops waiting, nothing is kept.
func TestAStartedPlanSignInComesBackToItsSession(t *testing.T) {
	r := newRig(t)
	f := &fakePlanSignIn{ready: true, link: "https://auth.openai.com/codex/device"}
	r.srv.cfg.PlanSignIn = f
	tok := r.signIn()
	want := localapi.DeviceCode{Link: f.link, Code: "ABCD-EF23", From: "OpenAI"}
	if a, err := r.planSignIn(tok, good); err != nil || a.DeviceCode != want {
		t.Fatalf("start: %+v %v", a, err)
	}
	if ps := r.planReady(tok); !ps.Ready || ps.DeviceCode != want {
		t.Fatalf("ready after the start: %+v", ps)
	}
	signIns := r.own.signIns
	if a, err := r.planSignIn(tok, ""); err != nil || a.Refusal != "" || a.DeviceCode != want || f.started != 1 || r.own.signIns != signIns {
		t.Fatalf("again from the same session: %+v %v %d", a, err, f.started)
	}

	other := r.signIn()
	signIns = r.own.signIns
	if ps := r.planReady(other); ps.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("another session read the code: %+v", ps)
	}
	if a, err := r.planSignIn(other, ""); err != nil || a.Refusal != localapi.RefusedCodeNeeded || a.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("another session without a code: %+v %v", a, err)
	}
	if a, err := r.planSignIn(other, "000000"); err != nil || a.Refusal != localapi.RefusedWrongCode || a.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("another session with a wrong code: %+v %v", a, err)
	}
	if a, err := r.planSignIn(other, good); err != nil || a.DeviceCode != want || f.started != 1 || r.own.signIns != signIns+2 {
		t.Fatalf("another session with a code: %+v %v %d", a, err, f.started)
	}
	if ps := r.planReady(other); ps.DeviceCode != want {
		t.Fatalf("not kept for the session that proved the owner: %+v", ps)
	}
	if ps := r.planReady(tok); ps.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("still kept for the first session: %+v", ps)
	}

	f.waiting = false
	if ps := r.planReady(other); !ps.Ready || ps.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("kept after the sign-in stopped waiting: %+v", ps)
	}
	if a, err := r.planSignIn(other, ""); err != nil || a.Refusal != localapi.RefusedCodeNeeded {
		t.Fatalf("no code after the wait: %+v %v", a, err)
	}
	if a, err := r.planSignIn(other, good); err != nil || a.DeviceCode != want || f.started != 2 {
		t.Fatalf("a new start: %+v %v %d", a, err, f.started)
	}
	f.ready = false
	if ps := r.planReady(other); ps.Ready || ps.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("shown once the sign-in closed: %+v", ps)
	}
}

// REQ: G1-1264-busy-2
// #1945, #1941 Security 1: a start that would be refused as busy or past
// the per-minute bound is refused before the code is checked, so the
// owner's code is not spent on it. A start that never reached the
// provider (a wrong code, a busy provider) does not count toward the bound.
func TestARefusedPlanSignInSpendsNoCode(t *testing.T) {
	r := newRig(t)
	f := &fakePlanSignIn{ready: true, waiting: true, link: "https://auth.openai.com/codex/device"}
	r.srv.cfg.PlanSignIn = f
	tok := r.signIn()
	signIns := r.own.signIns
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrSignInBusy || f.started != 0 || r.own.signIns != signIns {
		t.Fatalf("busy: %v %d %d", err, f.started, r.own.signIns-signIns)
	}
	if ps := r.planReady(tok); ps.DeviceCode != (localapi.DeviceCode{}) {
		t.Fatalf("a code nobody here started: %+v", ps)
	}

	f.waiting = false
	for i := 0; i < 3; i++ {
		if a, err := r.planSignIn(tok, "000000"); err != nil || a.Refusal != localapi.RefusedWrongCode {
			t.Fatalf("wrong code: %+v %v", a, err)
		}
	}
	f.err = SignInBusy
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrSignInBusy {
		t.Fatalf("busy at the provider: %v", err)
	}
	f.err = errors.New("provagent: failed")
	for i := 0; i < localapi.DeviceCodesPerMinute; i++ {
		if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrFailed {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	f.err = nil
	signIns = r.own.signIns
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrLimited || r.own.signIns != signIns || f.started != localapi.DeviceCodesPerMinute+1 {
		t.Fatalf("past the bound: %v %d %d", err, r.own.signIns-signIns, f.started)
	}
	r.now = r.now.Add(time.Minute)
	if a, err := r.planSignIn(tok, good); err != nil || a.Link != f.link {
		t.Fatalf("a minute later: %+v %v", a, err)
	}
}
