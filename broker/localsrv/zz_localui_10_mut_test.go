package localsrv

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-19, SR3-1
// MUT-kill-localui-10 (#6774): the adoptSIM statements and comparison that
// mutgate left alive on #6597, each pinned by a test that fails without it.

// mut10SignInOwner is the rig's owner with LocalSignIn's answer replaced.
type mut10SignInOwner struct {
	*fakeOwner
	err      error
	addLocks uint64
}

func (m *mut10SignInOwner) LocalSignIn(code string) (time.Time, uint64, error) {
	until, locks, err := m.fakeOwner.LocalSignIn(code)
	if m.err != nil {
		return until, locks, m.err
	}
	return until, locks + m.addLocks, err
}

// A code of exactly MaxCode characters is a code to check, not bad args.
func TestMut10AdoptSIMTakesACodeOfTheMaximumLength(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	a, err := r.adopt(tok, simTag, strings.Repeat("7", localapi.MaxCode))
	if err != nil || a.Refusal != localapi.RefusedWrongCode {
		t.Errorf("a %d-character code: %+v, %v; want a wrong-code refusal", localapi.MaxCode, a, err)
	}
}

// A sign-in that fails for another reason than a wrong code adopts nothing.
func TestMut10AdoptSIMFailsWhenTheCodeCannotBeChecked(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.srv.cfg.Owner = &mut10SignInOwner{fakeOwner: r.own, err: errors.New("owner: vault unreachable")}
	if _, err := r.adopt(tok, simTag, good); code(err) != localapi.ErrFailed || len(r.adopted) != 0 {
		t.Errorf("unchecked code: %v, adopted %v; want failed and nothing adopted", err, r.adopted)
	}
}

// SR3-1: a lock between the token check and the code ends the session, even
// where the owner's status read after it still shows the old generation.
func TestMut10AdoptSIMAfterALockEndsTheSession(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.srv.cfg.Owner = &mut10SignInOwner{fakeOwner: r.own, addLocks: 1}
	if _, err := r.adopt(tok, simTag, good); code(err) != localapi.ErrUnauthorized || len(r.adopted) != 0 {
		t.Fatalf("locked meanwhile: %v, adopted %v; want unauthorized", err, r.adopted)
	}
	if _, ok := r.srv.live(tok); ok {
		t.Error("the session outlived a lock seen by its code")
	}
}

// A good code refreshes the session: a RESUME just after takes no code.
func TestMut10AdoptSIMRefreshesTheSession(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.now = r.now.Add(localapi.FreshFor + time.Minute)
	if a, err := r.adopt(tok, simTag, good); err != nil || a.Text != SIMAdopted {
		t.Fatalf("adopt: %+v, %v", a, err)
	}
	out, err := r.call(localapi.OpResume, localapi.Resume{Token: tok})
	if a, _ := out.(localapi.Answered); err != nil || a.Refusal == localapi.RefusedCodeNeeded {
		t.Errorf("resume after adopting: %+v, %v; want no code asked", out, err)
	}
}

// An adoption the bridge fails is reported failed, not done.
func TestMut10AdoptSIMReportsTheBridgesFailure(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.srv.cfg.AdoptSIM = func(string) error { return errors.New("modem: bridge gone") }
	if out, err := r.call(localapi.OpSIM, localapi.AdoptSIM{Token: tok, SIM: simTag, Code: good}); code(err) != localapi.ErrFailed {
		t.Errorf("bridge failure: %+v, %v; want failed", out, err)
	}
}

// NewSetup with no clock reads time.Now.
func TestMut10NewSetupDefaultsTheClock(t *testing.T) {
	s := NewSetup(SetupConfig{Record: FileRecord{Path: filepath.Join(t.TempDir(), "setup.json")}})
	if s.cfg.Now == nil {
		t.Fatal("NewSetup left SetupConfig.Now nil")
	}
	if d := time.Since(s.cfg.Now()); d < -time.Minute || d > time.Minute {
		t.Errorf("the default clock reads %v from time.Now", d)
	}
}

// A RESUME code of exactly MaxCode characters is a code to check, not bad
// args.
func TestMut10ResumeTakesACodeOfTheMaximumLength(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.now = r.now.Add(localapi.FreshFor + time.Minute)
	out, err := r.call(localapi.OpResume, localapi.Resume{Token: tok, Code: strings.Repeat("7", localapi.MaxCode)})
	if a, _ := out.(localapi.Answered); err != nil || a.Refusal != localapi.RefusedWrongCode {
		t.Errorf("a %d-character code: %+v, %v; want a wrong-code refusal", localapi.MaxCode, out, err)
	}
}
