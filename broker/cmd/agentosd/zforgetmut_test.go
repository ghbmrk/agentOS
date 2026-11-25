package main

// REQ: LOG-4, OWN-6

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// These checks run inside existing tests in forgetpage_test.go, not as
// tests of their own: a new top-level test changes this package's run
// list, which mutgate reads as widening every test's reach (#6385).

// steppedClock answers at for its first n calls and at+forgetFor after,
// so a find expires between two named steps of one page op.
func steppedClock(at time.Time, n int) func() time.Time {
	calls := 0
	return func() time.Time {
		calls++
		if calls > n {
			return at.Add(forgetFor)
		}
		return at
	}
}

// A find that expires before the page reads its subjects back offers no
// tap: the page gets ErrEraseUnavailable, not a challenge over no subjects.
func aFindExpiredBeforeItsChallengeOffersNoTap(t *testing.T) {
	r := newForgetPageRig(t)
	r.b.f.now = steppedClock(time.Now(), 1) // find's clock read only
	f, err := r.p.Find(context.Background(), "sess-a", "Bob")
	if code(err) != localapi.ErrEraseUnavailable || f.Handle != "" || f.Challenge != nil {
		t.Fatalf("expired between find and shown: %+v %v", f, err)
	}
}

// A find that expires after the tap verified but before the confirm takes
// it is stale, so the page looks the name up again, and nothing is erased.
func aFindExpiredAfterTheTapIsStale(t *testing.T) {
	r := newForgetPageRig(t)
	// find, Find's shown and Confirm's shown read the clock live; take
	// reads it expired.
	r.b.f.now = steppedClock(time.Now(), 3)
	f := r.find("sess-a", "Bob")
	if _, err := r.tap("sess-a", f, f.Challenge, r.pk.anchors[0]); code(err) != localapi.ErrEraseStale {
		t.Fatalf("expired at take: %v", err)
	}
	if len(r.k.erases) != 0 || len(r.told) != 0 {
		t.Fatalf("erased %v, told %v", r.k.erases, r.told)
	}
}

// keysFail is a key reader whose anchors or enrollments cannot be read.
type keysFail struct{ anchors, enrollments error }

func (k keysFail) Anchors(context.Context) ([]key.PublicKey, error) { return nil, k.anchors }
func (k keysFail) Enrollments(context.Context) ([]key.Enrollment, []key.PublicKey, error) {
	return nil, nil, k.enrollments
}

// Unreadable anchors or enrollments are an error, not an owner with no
// keys: a tap is never checked against a partial key set.
func ownerKeysFailOnUnreadableKeys(t *testing.T) {
	want := errors.New("kernel: keys unreadable")
	for _, k := range []keysFail{{anchors: want}, {enrollments: want}} {
		if _, _, _, err := ownerKeys(context.Background(), k); !errors.Is(err, want) {
			t.Fatalf("ownerKeys(%+v): %v", k, err)
		}
	}
}
