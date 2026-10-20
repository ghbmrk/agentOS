package owner

import (
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// REQ: REV-3, CH-4, CH-10, ADP-9

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

// With a checker, a correct grid cell allows its items' acts: the
// checker records allowed approvals, which serve irreversible acts but
// no secret one (CH-4, CH-10, ADP-9). If the checker records nothing,
// nothing is approved and the item stays open.
func TestAGridCellAllowsItsActs(t *testing.T) {
	r, f := newVerifierRig(t)
	id, _ := r.ch.Request([]Item{actItem("a", "act-a")}, 0)
	cell := toldCell(t, r.inbox())

	// A failed allow spends nothing: the owner resends the cell they were
	// told, and it approves (#2514 L3 blocker 1).
	f.allowErr = errors.New("checker down")
	if got := r.say("YES " + id + " " + cell); got != allowErr {
		t.Fatalf("grid cell with a failed allow: %q", got)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}
	if !reflect.DeepEqual(f.revoked, []string{"act-a"}) {
		t.Fatalf("a failed allow was not withdrawn: %q", f.revoked)
	}

	f.allowErr = nil
	if got := r.say("YES " + id + " " + cell); !strings.HasPrefix(got, "Approved "+id) {
		t.Fatalf("the same grid cell again: %q", got)
	}
	if !reflect.DeepEqual(f.allowed, []CheckerAct{{Act: "act-a"}}) {
		t.Fatalf("allowed %+v", f.allowed)
	}
	if len(f.approved) != 0 || len(f.acts) != 0 {
		t.Fatalf("the Verifier saw a grid cell: approved %q, calls %q", f.approved, f.acts)
	}
	r.ch.mu.Lock()
	wrong := len(r.ch.codes.st.Wrong)
	r.ch.mu.Unlock()
	if wrong != 0 {
		t.Fatalf("%d wrong codes counted", wrong)
	}
	ds := r.decisions()
	if len(ds) != 1 || !ds[0].Approved || !ds[0].Allowed {
		t.Fatalf("decided %+v", ds)
	}
}

// Every step after a grid cell's allow that fails withdraws the allow
// before the owner is told it did not count; the only fallible one is the
// spend's save, since closing the request cannot fail and a failed hold
// withdraws its own act (holdLocked). A withdrawal that fails too says the
// act may still run (#2514 L3 Security delta blocker 1).
func TestAGridCellWhoseSpendFailsWithdrawsItsAllow(t *testing.T) {
	store := &toggleStore{}
	r, f := verifierRigWith(t, store)
	id, _ := r.ch.Request([]Item{actItem("a", "act-a")}, 0)
	cell := toldCell(t, r.inbox())

	store.fail = true
	if got := r.say("YES " + id + " " + cell); got != stateErr {
		t.Fatalf("grid cell with a failed spend: %q", got)
	}
	if !reflect.DeepEqual(f.allowed, []CheckerAct{{Act: "act-a"}}) || !reflect.DeepEqual(f.revoked, []string{"act-a"}) {
		t.Fatalf("allowed %+v, withdrew %q", f.allowed, f.revoked)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}

	f.revokeErr = errors.New("checker timed out")
	if got := r.say("YES " + id + " " + cell); got != allowUnknownErr+" Reply NO "+id+" to withdraw it." {
		t.Fatalf("grid cell whose withdrawal failed: %q", got)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}

	// Once saves work, the same cell approves and nothing is withdrawn.
	store.fail, f.revokeErr, f.revoked = false, nil, nil
	if got := r.say("YES " + id + " " + cell); !strings.HasPrefix(got, "Approved "+id) {
		t.Fatalf("the same cell once saves work: %q", got)
	}
	if len(f.revoked) != 0 {
		t.Fatalf("withdrew %q", f.revoked)
	}
	if ds := r.decisions(); len(ds) != 1 || !ds[0].Allowed {
		t.Fatalf("decided %+v", ds)
	}
}

// toldCell returns the answer to the grid cell named in text, the one the
// owner was told to send.
func toldCell(t *testing.T, text string) string {
	t.Helper()
	m := regexp.MustCompile(`grid cell ([A-Z][0-9]+)`).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no grid cell offered in %q", text)
	}
	return GridCell(testSecrets.GridSeed, m[1])
}

// An allowed approval never serves an act that releases a secret, so a
// grid cell for one is refused before any allow, says why, and counts
// nothing; a code-generator code still approves it (CH-4, CH-10).
func TestAGridCellCannotApproveASecretAct(t *testing.T) {
	r, f := newVerifierRig(t)
	it := actItem("a", "act-a")
	it.Facts.Kind = SecretReveal
	id, _ := r.ch.Request([]Item{it}, 0)
	cell := toldCell(t, r.inbox())

	if got := r.say("YES " + id + " " + cell); got != secretActErr {
		t.Fatalf("grid cell for a secret act: %q", got)
	}
	if len(f.allowed) != 0 || len(f.acts) != 0 {
		t.Fatalf("allowed %+v, Verifier calls %q", f.allowed, f.acts)
	}
	r.ch.mu.Lock()
	wrong, used := len(r.ch.codes.st.Wrong), len(r.ch.codes.st.GridUsed)
	r.ch.mu.Unlock()
	if wrong != 0 || used != 0 {
		t.Fatalf("wrong %d, grid cells used %d", wrong, used)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("decided %+v", ds)
	}

	if got := r.say("YES " + id + " " + r.totp()); !strings.HasPrefix(got, "Approved "+id) {
		t.Fatalf("code-generator code: %q", got)
	}
	if ds := r.decisions(); len(ds) != 1 || !ds[0].Approved || ds[0].Allowed {
		t.Fatalf("decided %+v", ds)
	}
}

// A texted code never allows a secret act either. No request texts a code
// for one, since revealing a secret is never low tier, so the guard is
// checked where the texted code is compared (#2514 combined delta).
func TestATextedCodeCannotAllowASecretAct(t *testing.T) {
	r, f := newVerifierRig(t)
	r.ch.mu.Lock()
	ok, allowed, _, msg := r.ch.checkLocked("123456", "123456", r.ch.cfg.Now(), []CheckerAct{{Act: "act-a", Secret: true}})
	r.ch.mu.Unlock()
	if ok || allowed || msg != secretActErr {
		t.Fatalf("texted code for a secret act: ok %v allowed %v %q", ok, allowed, msg)
	}
	if len(f.allowed) != 0 {
		t.Fatalf("allowed %+v", f.allowed)
	}
}
