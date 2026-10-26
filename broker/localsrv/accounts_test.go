package localsrv

import (
	"context"
	"errors"
	"reflect"
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

// REQ: TN-account-plan-6

// fakePlanner is the mail clerk's sign-in that also prepares the plan.
type fakePlanner struct {
	fakeAccount
	plan  localapi.AccountPlanned
	err   error
	calls int
}

func (f *fakePlanner) Plan(context.Context) (localapi.AccountPlanned, error) {
	f.calls++
	return f.plan, f.err
}

// planFixed is the plan with no mailbox read: the card, the wallet and the
// mailbox, as clerk/run answers it.
func planFixed() []localapi.AccountPlanItem {
	return []localapi.AccountPlanItem{
		{ID: "payment-card", Name: "Payment card", Kind: "money", Group: "payment", Source: "always", Preselected: true, Label: "Full power, same as yours"},
		{ID: "payment-wallet", Name: "Payment wallet", Kind: "money", Group: "payment", Source: "always", Label: "Full power, same as yours"},
		{ID: "mailbox", Name: "Give me an email address? About 1 minute.", Kind: "mail", Group: "mailbox", Source: "always", Label: "Full power, same as yours"},
	}
}

// TN-account-plan-6 on agentosd's side, one case per lifecycle row: agentosd
// relays the one planner's answer as it is, after a session, and refuses
// an answer past the plan's bounds rather than pass it to the page.
func TestAccountPlanLifecycle(t *testing.T) {
	r := newRig(t)
	gmail := append(planFixed(), localapi.AccountPlanItem{ID: "gmail", Name: "Gmail", Kind: "mail", Group: "account", Source: "mail",
		Preselected: true, Label: "Narrower than you, watched", Advice: "narrower", Connected: true})
	f := &fakePlanner{plan: localapi.AccountPlanned{Items: gmail}}
	r.srv.cfg.Accounts = map[string]AccountSignIn{"gmail": f, "other": &fakeAccount{}}
	if _, err := r.call(localapi.OpAccountPlan, localapi.Auth{}); code(err) != localapi.ErrUnauthorized || f.calls != 0 {
		t.Fatalf("no session: %v, %d calls", err, f.calls)
	}
	tok := r.signIn()
	for _, row := range []struct {
		name string
		plan localapi.AccountPlanned
	}{
		{"first setup, Gmail signed in under watch", localapi.AccountPlanned{Items: gmail}},
		{"page reopened", localapi.AccountPlanned{Items: gmail}},
		{"mail clerk restarted", localapi.AccountPlanned{Items: gmail}},
		{"grant refused at refresh", localapi.AccountPlanned{Reason: "reconnect"}},
		{"mailbox over IMAP", localapi.AccountPlanned{Items: planFixed()}},
		{"no mailbox signed in", localapi.AccountPlanned{Items: planFixed()}},
	} {
		f.plan = row.plan
		out, err := r.call(localapi.OpAccountPlan, localapi.Auth{Token: tok})
		if err != nil || !reflect.DeepEqual(out, row.plan) {
			t.Fatalf("%s: %+v %v, want %+v", row.name, out, err, row.plan)
		}
	}
	for name, bad := range map[string]localapi.AccountPlanned{
		"a reason with items":    {Items: planFixed(), Reason: "reconnect"},
		"a reason not an ID":     {Reason: "Gmail said: no"},
		"an ID not plain":        {Items: []localapi.AccountPlanItem{{ID: "Gmail", Name: "Gmail", Kind: "mail", Group: "account", Source: "mail"}}},
		"a name on two lines":    {Items: []localapi.AccountPlanItem{{ID: "gmail", Name: "Gmail\nFrom: x", Kind: "mail", Group: "account", Source: "mail"}}},
		"a label past its bound": {Items: []localapi.AccountPlanItem{{ID: "gmail", Name: "Gmail", Kind: "mail", Group: "account", Source: "mail", Label: strings.Repeat("a", localapi.MaxPlanText+1)}}},
		"no name":                {Items: []localapi.AccountPlanItem{{ID: "gmail", Kind: "mail", Group: "account", Source: "mail"}}},
		"too many items":         {Items: make([]localapi.AccountPlanItem, localapi.MaxPlanItems+1)},
	} {
		f.plan = bad
		if _, err := r.call(localapi.OpAccountPlan, localapi.Auth{Token: tok}); code(err) != localapi.ErrFailed {
			t.Fatalf("%s: %v, want failed", name, err)
		}
	}
	f.plan, f.err = localapi.AccountPlanned{Items: gmail}, errors.New("no answer")
	if _, err := r.call(localapi.OpAccountPlan, localapi.Auth{Token: tok}); code(err) != localapi.ErrFailed {
		t.Fatalf("the clerk failed: %v", err)
	}
	// No clerk prepares a plan, or two would: nothing to choose by.
	f.err = nil
	r.srv.cfg.Accounts = map[string]AccountSignIn{"gmail": &fakeAccount{}}
	if _, err := r.call(localapi.OpAccountPlan, localapi.Auth{Token: tok}); code(err) != localapi.ErrFailed {
		t.Fatalf("no planner: %v", err)
	}
	r.srv.cfg.Accounts = map[string]AccountSignIn{"gmail": f, "mail2": &fakePlanner{}}
	if _, err := r.call(localapi.OpAccountPlan, localapi.Auth{Token: tok}); code(err) != localapi.ErrFailed {
		t.Fatalf("two planners: %v", err)
	}
}
