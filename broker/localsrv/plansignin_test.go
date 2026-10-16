package localsrv

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: ONB-3, ONB-9, CRED-5

// fakePlanSignIn is agentosd's post-setup plan sign-in: ready says whether
// it would start, link is what it returns.
type fakePlanSignIn struct {
	ready   bool
	link    string
	err     error
	started int
}

func (f *fakePlanSignIn) Ready() bool { return f.ready }
func (f *fakePlanSignIn) Start(context.Context) (string, string, string, error) {
	f.started++
	if f.err != nil {
		return "", "", "", f.err
	}
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
	f.link, f.err = "https://auth.openai.com/codex/device", SignInBusy
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrSignInBusy {
		t.Fatalf("busy: %v", err)
	}
	f.err = errors.New("provagent: /var/lib/x")
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrFailed {
		t.Fatalf("other error: %v", err)
	}
	f.err = nil
	for i := 3; i < localapi.DeviceCodesPerMinute; i++ {
		if _, err := r.planSignIn(tok, good); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.planSignIn(tok, good); code(err) != localapi.ErrLimited || f.started != localapi.DeviceCodesPerMinute {
		t.Fatalf("past the bound: %v %d", err, f.started)
	}
}
