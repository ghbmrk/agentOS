package localsrv

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CLK-9, CLK-1, CH-7

type fakeAccount struct {
	begun    []string
	reg      *localapi.AccountRegistration
	finished []string
	err      error
}

func (f *fakeAccount) Begin(_ context.Context, use string, reg *localapi.AccountRegistration) (string, string, error) {
	f.begun, f.reg = append(f.begun, use), reg
	return "https://accounts.google.com/o/oauth2/v2/auth?state=s", "", f.err
}

func (f *fakeAccount) Finish(_ context.Context, use, pasted string) (string, error) {
	f.finished = append(f.finished, use+" "+pasted)
	return "signedin " + use, f.err
}

// #3006: the Connect page's two frames reach the account's clerk only with
// a live session, and only for an account agentosd serves.
func TestConnectingAnAccountNeedsASession(t *testing.T) {
	r := newRig(t)
	f := &fakeAccount{}
	r.srv.cfg.Accounts = map[string]AccountSignIn{"gmail": f}
	reg := &localapi.AccountRegistration{ID: "id.apps.googleusercontent.com", Secret: "synthetic-secret"}
	if _, err := r.call(localapi.OpAccountBegin, localapi.AccountBegin{Account: "gmail", Use: "watch", Registration: reg}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("no token: %v", err)
	}
	if _, err := r.call(localapi.OpAccountFinish, localapi.AccountFinish{Token: strings.Repeat("ab", localapi.TokenBytes), Account: "gmail", Use: "watch", Pasted: "http://127.0.0.1/?code=c"}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("unminted token: %v", err)
	}
	if len(f.begun)+len(f.finished) != 0 {
		t.Fatalf("clerk reached without a session: %v %v", f.begun, f.finished)
	}
	tok := r.signIn()
	out, err := r.call(localapi.OpAccountBegin, localapi.AccountBegin{Token: tok, Account: "gmail", Use: "watch", Registration: reg})
	if err != nil || out.(localapi.AccountBegun).Consent == "" || *f.reg != *reg {
		t.Fatalf("begin: %v %v %v", out, err, f.reg)
	}
	out, err = r.call(localapi.OpAccountFinish, localapi.AccountFinish{Token: tok, Account: "gmail", Use: "sort", Pasted: "http://127.0.0.1/?code=c"})
	if err != nil || out.(localapi.AccountFinished).Detail != "signedin sort" || f.finished[0] != "sort http://127.0.0.1/?code=c" {
		t.Fatalf("finish: %v %v %v", out, err, f.finished)
	}
	// A sign-in again carries no registration.
	if _, err := r.call(localapi.OpAccountBegin, localapi.AccountBegin{Token: tok, Account: "gmail", Use: "sort"}); err != nil || f.reg != nil {
		t.Fatalf("again: %v %v", err, f.reg)
	}
}

// The page is treated as compromised: every field is bounded again here,
// an account agentosd does not serve is refused, and unknown fields are
// refused, all before the clerk is reached.
func TestConnectingAnAccountRefusesWhatThePageCannotSend(t *testing.T) {
	r := newRig(t)
	f := &fakeAccount{}
	r.srv.cfg.Accounts = map[string]AccountSignIn{"gmail": f}
	tok := r.signIn()
	long := strings.Repeat("x", localapi.MaxClientField+1)
	for name, a := range map[string]localapi.AccountBegin{
		"account not served": {Token: tok, Account: "outlook", Use: "watch"},
		"no use":             {Token: tok, Account: "gmail"},
		"use not an ID":      {Token: tok, Account: "gmail", Use: "Watch me"},
		"use too long":       {Token: tok, Account: "gmail", Use: strings.Repeat("w", localapi.MaxID+1)},
		"empty client":       {Token: tok, Account: "gmail", Use: "watch", Registration: &localapi.AccountRegistration{Secret: "s"}},
		"long client":        {Token: tok, Account: "gmail", Use: "watch", Registration: &localapi.AccountRegistration{ID: long, Secret: "s"}},
		"long secret":        {Token: tok, Account: "gmail", Use: "watch", Registration: &localapi.AccountRegistration{ID: "i", Secret: long}},
	} {
		if _, err := r.call(localapi.OpAccountBegin, a); code(err) != localapi.ErrBadArgs {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, a := range map[string]localapi.AccountFinish{
		"account not served": {Token: tok, Account: "outlook", Use: "watch", Pasted: "p"},
		"no paste":           {Token: tok, Account: "gmail", Use: "watch"},
		"long paste":         {Token: tok, Account: "gmail", Use: "watch", Pasted: strings.Repeat("p", localapi.MaxPasted+1)},
		"no use":             {Token: tok, Account: "gmail", Pasted: "p"},
	} {
		if _, err := r.call(localapi.OpAccountFinish, a); code(err) != localapi.ErrBadArgs {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.raw(localapi.OpAccountBegin, `{"token":"`+tok+`","account":"gmail","use":"watch","verifier":"v"}`); code(err) != localapi.ErrBadArgs {
		t.Errorf("unknown field: %v", err)
	}
	if len(f.begun)+len(f.finished) != 0 {
		t.Fatalf("clerk reached on a refusal: %v %v", f.begun, f.finished)
	}
	// No accounts at all: both ops refuse.
	r.srv.cfg.Accounts = nil
	if _, err := r.call(localapi.OpAccountBegin, localapi.AccountBegin{Token: tok, Account: "gmail", Use: "watch"}); code(err) != localapi.ErrBadArgs {
		t.Fatalf("none served: %v", err)
	}
}

// A clerk that does not answer is a fixed failure, never its own text.
func TestAnAccountClerkThatFailsIsAFixedFailure(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Accounts = map[string]AccountSignIn{"gmail": &fakeAccount{err: errors.New("run: dial /run/agentos-mail/owner.sock: refused")}}
	tok := r.signIn()
	if _, err := r.call(localapi.OpAccountBegin, localapi.AccountBegin{Token: tok, Account: "gmail", Use: "watch"}); code(err) != localapi.ErrFailed {
		t.Fatalf("begin: %v", err)
	}
	if _, err := r.call(localapi.OpAccountFinish, localapi.AccountFinish{Token: tok, Account: "gmail", Use: "watch", Pasted: "p"}); code(err) != localapi.ErrFailed {
		t.Fatalf("finish: %v", err)
	}
}
