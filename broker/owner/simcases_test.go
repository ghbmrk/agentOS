package owner

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// SIM-cases: owner-visible cases taken from the W5-D drafts (briefs/SIM-cases.md),
// written against main's channel rather than the drafts' types.

// REQ: OP-4, CH-15 (SIM-cases: #335, #336, #337 allowance survives restart)
func TestSpentAllowanceSurvivesARestart(t *testing.T) {
	r := pacedRig(t, Pacing{}, 12, 0)
	for i := 1; i <= 3; i++ {
		if err := r.ch.Inform(fmt.Sprintf("Update %d.", i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.sentTexts(); len(got) != 3 {
		t.Fatalf("sent before restart: %q", got)
	}
	r.ch = r.open() // restart from saved state
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d after restart, want 0", a)
	}
	if err := r.ch.Inform("Update 4."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("restart refilled the allowance: %q", got)
	}
	if h := r.held(); len(h) != 1 || h[0].Text != "Update 4." {
		t.Fatalf("held: %+v", h)
	}
	r.advance(61 * time.Minute)
	r.ch = r.open()
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Update 4." {
		t.Fatalf("after the hour: %q", got)
	}
}

// signInFailStore fails any save that records a local sign-in.
type signInFailStore struct{ MemStore }

func (s *signInFailStore) Save(st State) error {
	if len(st.LocalSignIns) > 0 {
		return errors.New("disk full")
	}
	return s.MemStore.Save(st)
}

// On main a local sign-in whose record cannot be saved still stands, and
// the owner is texted about it at once rather than in the hourly coalesced
// text; the draft's "no authority without the record" is not carried.
// REQ: CH-15, OP-4 (SIM-cases: #307 sign-in record save fails)
func TestSignInWhoseRecordSaveFailsIsTextedAtOnce(t *testing.T) {
	r := newRig(t, &signInFailStore{})
	// A second sign-in within the hour would be held for the coalesced
	// text if recorded; unrecorded, each is texted when it happens.
	for i := 0; i < 2; i++ {
		code := r.totp()
		at := r.clock().Format("15:04")
		if _, _, err := r.ch.LocalSignIn(code); err != nil {
			t.Fatalf("sign-in %d: %v", i+1, err)
		}
		if got := r.inbox(); got != "A phone signed in on my Wi-Fi at "+at+". Not you? Text STOP." {
			t.Fatalf("sign-in %d alert: %q", i+1, got)
		}
		r.advance(10 * time.Minute)
	}
	// Told once each: neither a restart nor the hourly text repeats them.
	r.ch = r.open()
	r.advance(SignInAlertEvery)
	r.ch.Tick()
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("sign-in texted twice: %q", m.Text)
	default:
	}
}

// loadFailStore cannot read owner state and counts save attempts.
type loadFailStore struct{ saves int }

func (s *loadFailStore) Load() (State, error) { return State{}, errors.New("state unreadable") }
func (s *loadFailStore) Save(State) error     { s.saves++; return nil }

// Unreadable owner state stops the channel from starting: no channel runs
// on empty state and nothing overwrites the unreadable file. STOP while the
// state is unreadable is SIM-owner-hold's.
// REQ: OP-4, CH-15 (SIM-cases: #306 startup on load failure)
func TestUnreadableStateRefusesToStartAndWritesNothing(t *testing.T) {
	s := &loadFailStore{}
	ch, err := New(Config{Owner: ownerNum, Engine: &fakeEngine{}, Store: s, Secrets: testSecrets})
	if err == nil || ch != nil {
		t.Fatalf("New on unreadable state: %v, %v", ch, err)
	}
	if s.saves != 0 {
		t.Fatalf("%d saves over unreadable state", s.saves)
	}
}
