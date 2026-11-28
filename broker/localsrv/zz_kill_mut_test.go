package localsrv

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-14, SR3-1
// MUT-kill-5974-owner part 2 (#6670): the localsrv.go statements and
// comparisons that mutgate left alive on #5974, each pinned by a test
// that fails without it.

func TestKillNewDefaultsTheClock(t *testing.T) {
	s := New(Config{})
	if s.cfg.Now == nil {
		t.Fatal("New left Config.Now nil")
	}
	if d := time.Since(s.cfg.Now()); d < -time.Minute || d > time.Minute {
		t.Errorf("the default clock reads %v from time.Now", d)
	}
}

func TestKillDecodeReadsNoArgsAsEmpty(t *testing.T) {
	var in localapi.SignIn
	if err := decode(nil, &in); err != nil || in != (localapi.SignIn{}) {
		t.Errorf("decode(nil) = %v, %+v; want nil and a zero value", err, in)
	}
}

func TestKillSignInTakesACodeOfTheMaximumLength(t *testing.T) {
	r := newRig(t)
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: strings.Repeat("7", localapi.MaxCode)}); code(err) == localapi.ErrBadArgs {
		t.Errorf("a %d-character code was refused as bad args", localapi.MaxCode)
	}
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: strings.Repeat("7", localapi.MaxCode+1)}); code(err) != localapi.ErrBadArgs {
		t.Errorf("a %d-character code: %v, want bad args", localapi.MaxCode+1, err)
	}
}

func TestKillRunInboxWithNothingRunSaysDiscarded(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	out, err := r.call(localapi.OpRunInbox, localapi.RunInbox{Token: tok, Shown: []string{"1"}})
	if err != nil || out != (localapi.Answered{Text: "Discarded."}) {
		t.Errorf("run none of one shown = %+v, %v; want Discarded.", out, err)
	}
}

// killStatusCount counts the owner status reads.
type killStatusCount struct {
	*fakeOwner
	n int
}

func (k *killStatusCount) LocalStatus() owner.LocalStatus {
	k.n++
	return k.fakeOwner.LocalStatus()
}

func TestKillAMalformedTokenNeverReadsTheOwner(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	k := &killStatusCount{fakeOwner: &fakeOwner{now: &now, left: 24}}
	s := New(Config{Owner: k, Now: func() time.Time { return now }})
	for _, tok := range []string{"", "abc", strings.Repeat("a", 2*localapi.TokenBytes+1)} {
		if _, ok := s.live(tok); ok {
			t.Errorf("token %q is live", tok)
		}
	}
	if k.n != 0 {
		t.Errorf("malformed tokens read the owner status %d times, want 0", k.n)
	}
}
