package localsrv

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CAP-3, CH-7, CH-8

// W3-forget-b3r: a signed-in page lists the owner's recent tasks and asks
// to forget one by its goal ID alone, with whether the owner's session is
// unlocked (the signal FORGET by text gets); a bad ID never reaches the
// forget.
func TestARecentTaskIsAskedToBeForgottenFromASession(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	out, err := r.call(localapi.OpForgetTasks, localapi.Auth{Token: tok})
	if err != nil || !out.(localapi.ForgetTasks).Locked {
		t.Fatalf("locked list %+v %v", out, err)
	}
	r.own.unlocked = true
	out, err = r.call(localapi.OpForgetTasks, localapi.Auth{Token: tok})
	if l := out.(localapi.ForgetTasks); err != nil || l.Locked || len(l.Tasks) != 1 || l.Tasks[0].ID != "owner:a" {
		t.Fatalf("list %+v %v", out, err)
	}
	out, err = r.call(localapi.OpForget, localapi.Forget{Token: tok, ID: "owner:a"})
	if err != nil || out.(localapi.Text).Text != "Asked." {
		t.Fatalf("ask %v %v", out, err)
	}
	r.own.unlocked = false
	if _, err := r.call(localapi.OpForget, localapi.Forget{Token: tok, ID: "owner:a"}); err != nil {
		t.Fatal(err)
	}
	for _, in := range []localapi.Forget{{Token: tok}, {Token: tok, ID: strings.Repeat("a", localapi.MaxGoal+1)}} {
		if _, err := r.call(localapi.OpForget, in); code(err) != localapi.ErrBadArgs {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if strings.Join(r.forgets, ",") != "owner:a@unlocked,owner:a" {
		t.Fatalf("forgets %v", r.forgets)
	}
	r.srv.cfg.ForgetTasks, r.srv.cfg.Forget = nil, nil
	for op, args := range map[string]any{
		localapi.OpForgetTasks: localapi.Auth{Token: tok},
		localapi.OpForget:      localapi.Forget{Token: tok, ID: "owner:a"},
	} {
		if _, err := r.call(op, args); code(err) != localapi.ErrFailed {
			t.Errorf("%s with no hook: %v", op, err)
		}
	}
}
