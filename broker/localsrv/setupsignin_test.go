package localsrv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: ONB-3, CRED-5, CRED-1

// fakeSignIn stands in for agentosd's setup-mode provider worker.
type fakeSignIn struct {
	ready            map[string]bool
	link, code, from string
	err              error
	starts           []string
}

func (f *fakeSignIn) Ready(p string) bool { return f.ready[p] }

func (f *fakeSignIn) Start(_ context.Context, p string) (string, string, string, error) {
	f.starts = append(f.starts, p)
	return f.link, f.code, f.from, f.err
}

func signInRig(t *testing.T) (*setupRig, *fakeProviders, *fakeSignIn) {
	r, f := providersRig(t)
	f.plan = true
	si := &fakeSignIn{ready: map[string]bool{"codex": true}, link: "https://auth.openai.com/codex/device", code: "ABCD-1234", from: "OpenAI"}
	r.s.cfg.SignIn = si
	return r, f, si
}

// c4e2: setup lists the plan as signed in by device code only while the
// box can start its sign-in, and the op relays the provider's page, code
// and issuer and nothing else.
func TestSetupStartsThePlanSignIn(t *testing.T) {
	r, _, si := signInRig(t)
	var l localapi.SetupProviders
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil || len(l.Providers) != 3 || !l.Providers[2].DeviceCode || l.Providers[2].APIKey {
		t.Fatalf("list %v %+v", err, l)
	}
	if l.Providers[0].DeviceCode {
		t.Fatal("a key provider listed with device code")
	}
	var d localapi.DeviceCode
	if err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, &d); err != nil {
		t.Fatal(err)
	}
	if d != (localapi.DeviceCode{Link: "https://auth.openai.com/codex/device", Code: "ABCD-1234", From: "OpenAI"}) {
		t.Fatalf("answer %+v", d)
	}
	if strings.Contains(d.String(), "ABCD") || strings.Contains(fmt.Sprintf("%#v", d), "ABCD") {
		t.Fatal("DeviceCode prints its code")
	}
	if len(si.starts) != 1 || si.starts[0] != "codex" {
		t.Fatalf("starts %v", si.starts)
	}

	si.ready["codex"] = false
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil || l.Providers[2].DeviceCode {
		t.Fatalf("not ready but listed with device code: %v %+v", err, l)
	}
	if err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, nil); code(err) != localapi.ErrBadArgs {
		t.Fatalf("not ready: %v", err)
	}
	r.s.cfg.SignIn = nil
	if err := r.call(localapi.OpSetupProviders, nil, &l); err != nil || l.Providers[2].DeviceCode {
		t.Fatalf("no sign-in but listed with device code: %+v", l)
	}
	if len(si.starts) != 1 {
		t.Fatalf("starts %v", si.starts)
	}
}

// Only a provider the vault lists with device code, and of the vault's id
// shape, is started; a busy sign-in and any other failure are fixed codes
// that carry nothing the worker said; what the page would show is checked
// before it is relayed.
func TestSetupSignInRefusals(t *testing.T) {
	r, _, si := signInRig(t)
	for _, p := range []string{"openai", "nope", "", "Codex", strings.Repeat("a", 65)} {
		r.now = r.now.Add(time.Minute)
		if err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: p}, nil); code(err) != localapi.ErrBadArgs {
			t.Errorf("%q: %v", p, err)
		}
	}
	if len(si.starts) != 0 {
		t.Fatalf("started %v", si.starts)
	}
	for _, c := range []struct {
		name             string
		link, code, from string
		err              error
		want             string
	}{
		{"busy", "", "", "", fmt.Errorf("x: %w", SignInBusy), localapi.ErrSignInBusy},
		{"failed", "", "", "", errors.New("CANARY worker said"), localapi.ErrFailed},
		{"http link", "http://auth.openai.com/codex/device", "ABCD-1234", "OpenAI", nil, localapi.ErrFailed},
		{"link with user", "https://u@auth.openai.com/codex/device", "ABCD-1234", "OpenAI", nil, localapi.ErrFailed},
		{"script link", "javascript:alert(1)", "ABCD-1234", "OpenAI", nil, localapi.ErrFailed},
		{"bad code", "https://auth.openai.com/codex/device", "<b>x</b>", "OpenAI", nil, localapi.ErrFailed},
		{"no issuer", "https://auth.openai.com/codex/device", "ABCD-1234", "", nil, localapi.ErrFailed},
		{"markup issuer", "https://auth.openai.com/codex/device", "ABCD-1234", "<i>OpenAI</i>", nil, localapi.ErrFailed},
	} {
		r.now = r.now.Add(time.Minute)
		si.link, si.code, si.from, si.err = c.link, c.code, c.from, c.err
		err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, nil)
		if code(err) != c.want || strings.Contains(fmt.Sprint(err), "CANARY") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// Each start may make a worker, so starts are bounded per minute, and a
// finished setup starts none.
func TestSetupSignInsAreBoundedAndCloseAtFinish(t *testing.T) {
	r, _, si := signInRig(t)
	for i := 0; i < localapi.DeviceCodesPerMinute; i++ {
		if err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, nil); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, nil); code(err) != localapi.ErrLimited {
		t.Fatalf("past the limit: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	r.enrollAndConfirm()
	if err := r.call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err != nil {
		t.Fatal(err)
	}
	n := len(si.starts)
	if err := r.call(localapi.OpSetupDeviceCode, localapi.DeviceCodeStart{Provider: "codex"}, nil); code(err) != localapi.ErrSetupClosed {
		t.Fatalf("after finish: %v", err)
	}
	if len(si.starts) != n {
		t.Fatal("a closed setup started a sign-in")
	}
}
