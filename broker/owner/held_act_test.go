package owner

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// REQ: REV-3, CH-4, CH-10

// heldActItem is a high-risk item with an act and an undo window.
func heldActItem(ref, act string) Item {
	it := actItem(ref, act)
	it.UndoWindow = 10 * time.Minute
	return it
}

// holdFailStore fails every save that records a held effect, so the
// channel cannot hold one.
type holdFailStore struct{ MemStore }

func (s *holdFailStore) Save(st State) error {
	for _, q := range st.Queued {
		if q.Held {
			return errors.New("disk full")
		}
	}
	return s.MemStore.Save(st)
}

func verifierRigWith(t *testing.T, store Store) (*rig, *fakeVerifier) {
	t.Helper()
	r := newRig(t, store)
	f := &fakeVerifier{seed: testSecrets.TOTPSeed, now: r.clock}
	r.verifier = f
	r.ch = r.open()
	return r, f
}

// A held act goes to the checker held, an unheld one not; UNDO withdraws
// a held act, so an effect the owner cancelled cannot run later. A
// withdrawal that fails is said, not hidden (REV-3, CH-4).
func TestUndoWithdrawsAHeldActsApproval(t *testing.T) {
	r, f := newVerifierRig(t)
	id, _ := r.ch.Request([]Item{heldActItem("a", "act-a"), actItem("b", "act-b")}, 0)
	r.inbox()
	u := holdRe.FindStringSubmatch(r.say("YES " + id + " " + r.totp()))
	if u == nil {
		t.Fatal("no hold")
	}
	if got := f.held[len(f.held)-1]; !reflect.DeepEqual(got, []bool{true, false}) {
		t.Fatalf("held flags sent with the code: %v", got)
	}
	r.decisions()
	if got := r.say("UNDO " + u[1]); got != "Cancelled "+u[1]+". It did not run." {
		t.Fatalf("undo: %q", got)
	}
	if !reflect.DeepEqual(f.revoked, []string{"act-a"}) {
		t.Fatalf("revoked %q", f.revoked)
	}

	f.revokeErr = errors.New("checker down")
	id, _ = r.ch.Request([]Item{heldActItem("c", "act-c")}, 0)
	r.inbox()
	u = holdRe.FindStringSubmatch(r.say("YES " + id + " " + r.totp()))
	if got := r.say("UNDO " + u[1]); got != "Cancelled "+u[1]+", but the box could not withdraw its approval, so it may still run." {
		t.Fatalf("undo with a failed withdrawal: %q", got)
	}

	// A verifier that cannot revoke cannot withdraw either.
	r = newRig(t, &MemStore{})
	f = &fakeVerifier{seed: testSecrets.TOTPSeed, now: r.clock}
	r.verifier = plainVerifier{f}
	r.ch = r.open()
	id, _ = r.ch.Request([]Item{heldActItem("d", "act-d")}, 0)
	r.inbox()
	u = holdRe.FindStringSubmatch(r.say("YES " + id + " " + r.totp()))
	if got := r.say("UNDO " + u[1]); got != "Cancelled "+u[1]+", but the box could not withdraw its approval, so it may still run." {
		t.Fatalf("undo with a verifier that cannot revoke: %q", got)
	}
}

// plainVerifier checks codes but cannot revoke or release.
type plainVerifier struct{ f *fakeVerifier }

func (p plainVerifier) VerifyTOTP(code string, after int64, counted bool, cas ...CheckerAct) (int64, bool, error) {
	return p.f.VerifyTOTP(code, after, counted, cas...)
}

// toggleStore fails every save while fail is set.
type toggleStore struct {
	MemStore
	fail bool
}

func (s *toggleStore) Save(st State) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.MemStore.Save(st)
}

// A held act is released at the checker only once its item has left the
// queue UNDO reads, never while UNDO can still cancel it (security S1 on
// #2501): an UNDO in the window's last second finds the act still shut and
// it never opens; a release names only the items due, and only once their
// retirement is saved (REV-3, CH-10).
func TestAHeldActIsReleasedOnlyAfterUndoCloses(t *testing.T) {
	store := &toggleStore{}
	r, f := verifierRigWith(t, store)
	yes := func(ref, act string) string {
		id, _ := r.ch.Request([]Item{heldActItem(ref, act)}, 0)
		r.inbox()
		u := holdRe.FindStringSubmatch(r.say("YES " + id + " " + r.totp()))
		if u == nil {
			t.Fatal("no hold")
		}
		return u[1]
	}
	a := yes("a", "act-a")
	r.advance(10*time.Minute - time.Second)
	if due := r.ch.DueAutoReplies(); len(due) != 0 || len(f.released) != 0 {
		t.Fatalf("released inside the window: %v %q", due, f.released)
	}
	if got := r.say("UNDO " + a); got != "Cancelled "+a+". It did not run." {
		t.Fatalf("undo: %q", got)
	}
	r.advance(time.Hour)
	if due := r.ch.DueAutoReplies(); len(due) != 0 || len(f.released) != 0 {
		t.Fatalf("an undone act was released: %v %q", due, f.released)
	}

	b := yes("b", "act-b")
	yes("c", "act-c")
	r.advance(10 * time.Minute)
	if due := r.ch.DueAutoReplies(); len(due) != 2 || !reflect.DeepEqual(sorted(f.released), []string{"act-b", "act-c"}) {
		t.Fatalf("due %v, released %q", due, f.released)
	}
	if got := r.say("UNDO " + b); !strings.Contains(got, "past its undo window") {
		t.Fatalf("undo after release: %q", got)
	}

	f.released = nil
	yes("d", "act-d")
	r.advance(10 * time.Minute)
	store.fail = true
	if due := r.ch.DueAutoReplies(); len(due) != 1 || len(f.released) != 0 {
		t.Fatalf("released with its retirement unsaved: %v %q", due, f.released)
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

// A restart cancels every held effect, and withdraws its act (REV-3).
func TestRestartWithdrawsHeldActs(t *testing.T) {
	r, f := verifierRigWith(t, &MemStore{})
	id, _ := r.ch.Request([]Item{heldActItem("a", "act-a")}, 0)
	r.inbox()
	if holdRe.FindStringSubmatch(r.say("YES "+id+" "+r.totp())) == nil {
		t.Fatal("no hold")
	}
	r.decisions()
	r.ch = r.open()
	r.ch.Boot()
	if got := r.inbox(); strings.Contains(got, "withdraw") {
		t.Fatalf("restart text: %q", got)
	}
	if !reflect.DeepEqual(f.revoked, []string{"act-a"}) {
		t.Fatalf("revoked %q", f.revoked)
	}

	id, _ = r.ch.Request([]Item{heldActItem("b", "act-b")}, 0)
	r.inbox()
	r.say("YES " + id + " " + r.totp())
	f.revokeErr = errors.New("checker down")
	r.ch = r.open()
	r.ch.Boot()
	if got := r.inbox(); !strings.Contains(got, "could not withdraw their approvals, so they may still run") {
		t.Fatalf("restart text with a failed withdrawal: %q", got)
	}
}

// An item that cannot be held is denied, and its act withdrawn, so it is
// not left approved at the checker while the owner is told it did not run
// (REV-3).
func TestAnUnheldActIsWithdrawn(t *testing.T) {
	r, f := verifierRigWith(t, &holdFailStore{})
	id, _ := r.ch.Request([]Item{heldActItem("a", "act-a")}, 0)
	r.inbox()
	if got := r.say("YES " + id + " " + r.totp()); !strings.Contains(got, "Could not hold 1 for undo, so it did not run.") {
		t.Fatalf("confirmation: %q", got)
	}
	if !reflect.DeepEqual(f.revoked, []string{"act-a"}) {
		t.Fatalf("revoked %q", f.revoked)
	}
	if ds := r.decisions(); len(ds) != 1 || ds[0].Approved || ds[0].Why != "not held" {
		t.Fatalf("decisions %+v", ds)
	}

	f.revokeErr = errors.New("checker down")
	id, _ = r.ch.Request([]Item{heldActItem("b", "act-b")}, 0)
	r.inbox()
	if got := r.say("YES " + id + " " + r.totp()); !strings.Contains(got, "the box could not withdraw its approval, so it may still run.") {
		t.Fatalf("confirmation with a failed withdrawal: %q", got)
	}
}

// An item already decided carries no act: after NO for item 1, the YES
// that approves the rest sends only item 2's (CH-4, CH-10).
func TestADecidedItemsActIsNotSent(t *testing.T) {
	r, f := newVerifierRig(t)
	id, _ := r.ch.Request([]Item{actItem("a", "act-a"), actItem("b", "act-b")}, 0)
	r.inbox()
	r.say("NO " + id + " 1")
	if got := r.say("YES " + id + " " + r.totp()); !strings.HasPrefix(got, "Approved "+id) {
		t.Fatalf("YES: %q", got)
	}
	if got := f.acts[len(f.acts)-1]; !reflect.DeepEqual(got, []string{"act-b"}) {
		t.Fatalf("acts sent with the code: %q", got)
	}
}

// With a checker, a correct grid cell still approves no act: only the
// checker records the approvals holders spend (CH-4, CH-10).
func TestAGridCellApprovesNoActEvenWithAChecker(t *testing.T) {
	r, f := newVerifierRig(t)
	id, _ := r.ch.Request([]Item{actItem("a", "act-a")}, 0)
	r.inbox()
	r.ch.mu.Lock()
	cell := r.ch.codes.gridChallenge()
	r.ch.mu.Unlock()
	if cell == "" {
		t.Fatal("no grid")
	}
	if got := r.say("YES " + id + " " + GridCell(testSecrets.GridSeed, cell)); strings.HasPrefix(got, "Approved") {
		t.Fatalf("grid cell approved an act: %q", got)
	}
	for _, d := range r.decisions() {
		if d.Approved {
			t.Fatalf("decided %+v", d)
		}
	}
	if len(f.approved) != 0 {
		t.Fatalf("approved %q", f.approved)
	}
}
