package change

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-1, OP-4, OP-5
//
// SR3-4: the update code settles a staged image adoption by its exact ID.
// Confirming or failing it again after it was settled is a success that
// changes nothing, so the applier can retry after a crash or an error; a
// save that fails leaves the adoption staged, in memory and on disk, so
// the obligation to settle it survives.

func stagedEnv(t *testing.T) (*env, Report) {
	t.Helper()
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hi")
	e.owner.approve = true
	r := e.release(release(t, 40, false, map[string][]byte{"host-image/release": []byte("a")}))
	if r.State != StateAdopted || r.ID == r.Short {
		t.Fatal(r)
	}
	e.p.Digest()
	return e, r
}

func (e *env) adoption(id string) Adoption {
	e.t.Helper()
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	for _, a := range e.p.st.Adoptions {
		if a.ID == id {
			return *a
		}
	}
	e.t.Fatalf("no adoption %s", id)
	return Adoption{}
}

// reopen starts a pipeline over the saved state, as after a restart.
func (e *env) reopen() {
	e.t.Helper()
	p, err := New(e.p.cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.open(p)
}

func (e *env) reverts() int {
	n := 0
	for _, st := range e.eng.List() {
		if strings.Contains(st.Intent.ID, ":revert:") {
			n++
		}
	}
	return n
}

func TestConfirmStagedIsIdempotentByExactID(t *testing.T) {
	e, r := stagedEnv(t)
	if err := e.p.ConfirmStaged(r.Short); err == nil {
		t.Fatal("confirmed by the owner-facing ID, which can be reused")
	}
	if err := e.p.ConfirmStaged(r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Staged || !a.Confirmed || a.Reverted != "" {
		t.Fatalf("adoption %+v", a)
	}
	if d := e.p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "Installed update 40.") {
		t.Fatalf("digest: %q", d)
	}
	e.reopen()
	if err := e.p.ConfirmStaged(r.ID); err != nil {
		t.Fatal("replay after a restart:", err)
	}
	if d := e.p.Digest(); len(d) != 0 {
		t.Fatalf("replay said it again: %q", d)
	}
	if err := e.p.StageFailed(bg, r.ID); err == nil {
		t.Fatal("a confirmed image fell back")
	}
	if a := e.adoption(r.ID); a.Reverted != "" || e.reverts() != 0 {
		t.Fatalf("confirmed adoption reverted: %+v", a)
	}
}

func TestConfirmStagedRefusesOtherAdoptions(t *testing.T) {
	e, _ := stagedEnv(t)
	s := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hi"), "skills/x": []byte("1")}})
	if s.State != StateAdopted {
		t.Fatal(s)
	}
	for _, ref := range []string{s.ID, "nope"} {
		if err := e.p.ConfirmStaged(ref); err == nil {
			t.Fatalf("confirmed %s", ref)
		}
		if err := e.p.StageFailed(bg, ref); err == nil {
			t.Fatalf("failed %s", ref)
		}
	}
	if a := e.adoption(s.ID); a.Confirmed || a.Reverted != "" {
		t.Fatalf("skill adoption %+v", a)
	}
}

func TestConfirmStagedSaveFailureKeepsItStaged(t *testing.T) {
	e, r := stagedEnv(t)
	e.store.Fail = errors.New("disk full")
	if err := e.p.ConfirmStaged(r.ID); err == nil {
		t.Fatal("confirmed without saving")
	}
	if a := e.adoption(r.ID); !a.Staged || a.Confirmed {
		t.Fatalf("in memory after a failed save: %+v", a)
	}
	e.store.Fail = nil
	e.reopen()
	if a := e.adoption(r.ID); !a.Staged || a.Confirmed {
		t.Fatalf("on disk after a failed save: %+v", a)
	}
	if err := e.p.ConfirmStaged(r.ID); err != nil {
		t.Fatal("retry:", err)
	}
	e.reopen()
	if a := e.adoption(r.ID); a.Staged || !a.Confirmed {
		t.Fatalf("after the retry: %+v", a)
	}
}

func TestStageFailedIsIdempotentByExactID(t *testing.T) {
	e, r1 := stagedEnv(t)
	if err := e.p.ConfirmStaged(r1.ID); err != nil {
		t.Fatal(err)
	}
	r := e.release(release(t, 41, false, map[string][]byte{"host-image/release": []byte("b")}))
	e.p.Digest()
	if r.State != StateAdopted {
		t.Fatal(r)
	}
	if err := e.p.StageFailed(bg, r.Short); err == nil {
		t.Fatal("fell back by the owner-facing ID")
	}
	e.store.Fail = errors.New("disk full")
	if err := e.p.StageFailed(bg, r.ID); err == nil {
		t.Fatal("reverted without saving")
	}
	e.store.Fail = nil
	if a := e.adoption(r.ID); a.Reverted != "" || !a.Staged {
		t.Fatalf("after a failed save: %+v", a)
	}
	if err := e.p.StageFailed(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if e.reverts() == 0 {
		t.Fatal("no revert intent")
	}
	if got := string(e.p.Files("host-image")["host-image/release"]); got != update.Digest([]byte("a")) {
		t.Fatal("fallback did not restore the previous image")
	}
	e.reopen()
	if err := e.p.StageFailed(bg, r.ID); err != nil {
		t.Fatal("replay after a restart:", err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyFallback || e.reverts() != 0 {
		t.Fatalf("replay: adoption %+v, new reverts %d", a, e.reverts())
	}
	if err := e.p.ConfirmStaged(r.ID); err == nil {
		t.Fatal("a fallen-back image confirmed")
	}
}

// Until the update code settles a staged image, only it can: an owner's
// UNDO, or the pipeline's own revert, would leave the image installed
// with its adoption undone, and the applier could never confirm it.
func TestStagedImageIsNotUndoneBeforeItSettles(t *testing.T) {
	e, r1 := stagedEnv(t)
	if err := e.p.ConfirmStaged(r1.ID); err != nil {
		t.Fatal(err)
	}
	r := e.release(release(t, 41, false, map[string][]byte{"host-image/release": []byte("b")}))
	if d := e.p.Digest(); len(d) == 0 || !strings.HasSuffix(d[len(d)-1], " MORE "+r.Short) || strings.Contains(d[len(d)-1], "UNDO") {
		t.Fatalf("offered an undo of a staged image: %q", d)
	}
	err := e.p.Revert(bg, r.Short, OriginOwner)
	if err == nil || err.Error() != "Update 41 starts at the next restart; undo it after." {
		t.Fatalf("owner undo of a staged image: %v", err)
	}
	if err := e.p.revert(bg, r.ID, OriginPipeline, WhyRegression); err == nil {
		t.Fatal("the pipeline undid a staged image")
	}
	if a := e.adoption(r.ID); a.Reverted != "" || !a.Staged || e.reverts() != 0 {
		t.Fatalf("adoption %+v, reverts %d", a, e.reverts())
	}
	if err := e.p.ConfirmStaged(r.ID); err != nil {
		t.Fatal(err)
	}
	if d := e.p.Digest(); len(d) != 1 || !strings.Contains(d[0], "UNDO "+r.Short) {
		t.Fatalf("no undo offered once it started: %q", d)
	}
	if err := e.p.Revert(bg, r.Short, OriginOwner); err != nil {
		t.Fatal("undo after the image started:", err)
	}
}

// REQ: UPD-1, UPD-8, OP-4, OP-5, CH-12
//
// SR3-4f-2: a staged image may be undone until the applier starts to
// install it. The pipeline asks the applier (Withdrawer) first, outside
// its lock; the applier settles an image it dropped with WhyDropped.

// withdrawer stands in for the update applier. Withdraw takes held, as
// the applier takes its lock.
type withdrawer struct {
	held  sync.Mutex
	mu    sync.Mutex
	calls []string
	err   error
}

func (w *withdrawer) Withdraw(id string) error {
	w.held.Lock()
	defer w.held.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, id)
	return w.err
}

func (w *withdrawer) called() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.calls)
}

// installing is the applier's answer in its handover window.
type installing struct{}

func (installing) Error() string  { return "apply: a release is being applied" }
func (installing) Handover() bool { return true }

// pendingStaged is a confirmed release 40 (image "a") and a staged
// release 41 (image "b") the applier has not installed yet.
func pendingStaged(t *testing.T) (*env, Report, *withdrawer) {
	t.Helper()
	e, r1 := stagedEnv(t)
	if err := e.p.ConfirmStaged(r1.ID); err != nil {
		t.Fatal(err)
	}
	r := e.release(release(t, 41, false, map[string][]byte{"host-image/release": []byte("b")}))
	if r.State != StateAdopted || !e.adoption(r.ID).Staged {
		t.Fatal(r)
	}
	w := &withdrawer{}
	e.p.SetWithdrawer(w)
	return e, r, w
}

func (e *env) image() string {
	return string(e.p.Files("host-image")["host-image/release"])
}

func TestOwnerUndoesAPendingStagedRelease(t *testing.T) {
	e, r, w := pendingStaged(t)
	if err := e.p.Revert(bg, r.Short, OriginOwner); err != nil {
		t.Fatal("owner undo of a pending staged release:", err)
	}
	if got := w.called(); len(got) != 1 || got[0] != r.ID {
		t.Fatalf("withdraw calls %q", got)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyOwner || e.reverts() != 1 {
		t.Fatalf("adoption %+v, reverts %d", a, e.reverts())
	}
	if e.image() != update.Digest([]byte("a")) {
		t.Fatal("previous image not restored")
	}
}

func TestRecheckRevertsAPendingStagedRelease(t *testing.T) {
	e, r, w := pendingStaged(t)
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if string(tr["host-image/release"]) == update.Digest([]byte("b")) && string(pr.Input) == exfilProbe {
			return []byte("leaked"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	// Unprotected, as no image adoption is today (owner-approved and
	// attested ones only raise a Concern).
	e.p.mu.Lock()
	e.p.adoptionByIDLocked(r.ID).Basis = BasisStanding
	e.p.mu.Unlock()
	ids, err := e.p.Recheck(bg)
	if err != nil || !slices.Contains(ids, r.ID) {
		t.Fatalf("recheck: %v %v", ids, err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhySecurity || len(w.called()) != 1 {
		t.Fatalf("adoption %+v, withdraw calls %q", a, w.called())
	}
}

func TestUndoRefusedInTheHandoverWindow(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.err = installing{}
	err := e.p.Revert(bg, r.Short, OriginOwner)
	if err == nil || err.Error() != "Update 41 is being installed; undo it after it starts." {
		t.Fatalf("undo while installing: %v", err)
	}
	w.err = errors.New("disk full")
	if err := e.p.revert(bg, r.ID, OriginPipeline, WhySecurity); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("withdraw error: %v", err)
	}
	e.p.SetWithdrawer(nil)
	if err := e.p.Revert(bg, r.Short, OriginOwner); err == nil || err.Error() != "Update 41 starts at the next restart; undo it after." {
		t.Fatalf("no applier: %v", err)
	}
	if a := e.adoption(r.ID); a.Reverted != "" || !a.Staged || e.reverts() != 0 || e.image() != update.Digest([]byte("b")) {
		t.Fatalf("adoption %+v, reverts %d", a, e.reverts())
	}
}

// The applier holds its lock while it settles (Resume calls StageFailed);
// an owner UNDO at the same moment asks it to withdraw. Withdraw must run
// outside the pipeline's lock, or the two wait on each other.
func TestUndoAndSettleDoNotDeadlock(t *testing.T) {
	e, r, w := pendingStaged(t)
	held := make(chan struct{})
	done := make(chan error, 2)
	go func() {
		w.held.Lock() // Resume holds the applier's lock
		close(held)
		time.Sleep(50 * time.Millisecond) // the owner's UNDO asks meanwhile
		done <- e.p.StageFailed(bg, r.ID)
		w.held.Unlock()
	}()
	go func() {
		<-held
		done <- e.p.Revert(bg, r.Short, OriginOwner) // may lose to the fallback
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("deadlock: Withdraw called under the pipeline lock")
		}
	}
	if a := e.adoption(r.ID); a.Reverted == "" {
		t.Fatalf("adoption %+v", a)
	}
}

func TestStageDroppedIsIdempotentByExactID(t *testing.T) {
	e, r, w := pendingStaged(t)
	if d := e.p.Digest(); len(d) == 0 || !strings.HasPrefix(d[len(d)-1], "Staged update 41; I will install it when I am free.") {
		t.Fatalf("digest: %q", d)
	}
	if err := e.p.StageDropped(bg, r.Short); err == nil {
		t.Fatal("dropped by the owner-facing ID")
	}
	e.store.Fail = errors.New("disk full")
	if err := e.p.StageDropped(bg, r.ID); err == nil {
		t.Fatal("reverted without saving")
	}
	e.store.Fail = nil
	if a := e.adoption(r.ID); a.Reverted != "" || !a.Staged {
		t.Fatalf("after a failed save: %+v", a)
	}
	if err := e.p.StageDropped(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyDropped || e.reverts() != 1 || e.image() != update.Digest([]byte("a")) {
		t.Fatalf("adoption %+v, reverts %d", a, e.reverts())
	}
	if len(w.called()) != 0 {
		t.Fatal("the applier's own drop asked it to withdraw")
	}
	if d := e.p.Digest(); len(d) != 0 {
		t.Fatalf("a dropped release was reported: %q", d)
	}
	e.reopen()
	if err := e.p.StageDropped(bg, r.ID); err != nil || e.reverts() != 0 {
		t.Fatalf("replay after a restart: %v, new reverts %d", err, e.reverts())
	}
	if err := e.p.ConfirmStaged(r.ID); err == nil {
		t.Fatal("a dropped image confirmed")
	}
	r2 := e.release(release(t, 42, false, map[string][]byte{"host-image/release": []byte("c")}))
	if err := e.p.ConfirmStaged(r2.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.p.StageDropped(bg, r2.ID); err == nil {
		t.Fatal("a confirmed image dropped")
	}
}
