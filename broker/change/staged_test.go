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
	whys  []string
	err   error
	// then runs after a withdrawal, under held, as the applier's next
	// Tick settles the drop.
	then func(id string)
	// refused runs when Withdraw returns err, under held.
	refused func(id string)
}

func (w *withdrawer) Withdraw(id, why string) error {
	w.held.Lock()
	defer w.held.Unlock()
	w.mu.Lock()
	w.calls = append(w.calls, id)
	w.whys = append(w.whys, why)
	err, then, refused := w.err, w.then, w.refused
	w.mu.Unlock()
	if err == nil && then != nil {
		then(id)
	}
	if err != nil && refused != nil {
		refused(id)
	}
	return err
}

func (w *withdrawer) called() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.calls)
}

// installing is the applier's answer in its handover window.
// starts: the image may start before it is undone.
type installing struct{ starts bool }

func (installing) Error() string  { return "apply: a release is being applied" }
func (installing) Handover() bool { return true }
func (i installing) Starts() bool { return i.starts }

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

// L3-1: a withdrawal is also a drop. When the revert that follows it
// fails (STOP holds the pipeline's own), the applier's StageDropped still
// reverts the adoption, so the digest stops promising to install it. It
// is recorded as the Recheck revert it was, never as a drop Loop 3 offers
// again (SR3-4f-2-r1b).
func TestWithdrawnThenRevertFailsIsSettledByTheDrop(t *testing.T) {
	e, r, w := pendingStaged(t)
	if _, err := e.eng.Stop(bg); err != nil {
		t.Fatal(err)
	}
	if err := e.p.revert(bg, r.ID, OriginPipeline, WhySecurity); err == nil {
		t.Fatal("auto revert ran during STOP")
	}
	if a := e.adoption(r.ID); len(w.called()) != 1 || a.Reverted != "" || !a.Staged {
		t.Fatalf("adoption %+v, withdraw calls %q", a, w.called())
	}
	if err := e.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := e.p.StageDropped(bg, r.ID); err != nil { // the applier's next Tick
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhySecurity || e.image() != update.Digest([]byte("a")) {
		t.Fatalf("adoption %+v", a)
	}
	if d := e.p.Digest(); slices.ContainsFunc(d, func(l string) bool { return strings.Contains(l, "I will install it") }) ||
		!slices.Contains(d, "Undid "+r.Short+": it failed a security check.") {
		t.Fatalf("digest still promises the withdrawn release: %q", d)
	}
}

// L3-1: the applier settles the drop before the owner's own revert runs;
// that revert then finds no active adoption, and the undo still succeeds.
// The drop is recorded as the owner's undo (SR3-4f-2-r1b).
func TestOwnerUndoLosesToTheDrop(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.then = func(id string) {
		if err := e.p.StageDropped(bg, id); err != nil {
			t.Error("drop:", err)
		}
	}
	if err := e.p.Revert(bg, r.Short, OriginOwner); err != nil {
		t.Fatal("owner undo that lost to the drop:", err)
	}
	// Both reverts are journaled; the owner's found nothing to undo.
	if a := e.adoption(r.ID); a.Reverted != WhyOwner || e.image() != update.Digest([]byte("a")) {
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

// REQ: UPD-1, UPD-8, CH-12, OP-5
//
// SR3-4f-3b: a security recheck whose revert of an unprotected staged
// adoption the applier refuses (its release is being installed) sets a
// Concern, so the digest says so, and the next pass reverts it.

// failsSecurity makes image "b" fail the security suite and the staged
// adoption unprotected, as TestRecheckRevertsAPendingStagedRelease does.
func (e *env) failsSecurity(id string) {
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if string(tr["host-image/release"]) == update.Digest([]byte("b")) && string(pr.Input) == exfilProbe {
			return []byte("leaked"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	e.p.mu.Lock()
	e.p.adoptionByIDLocked(id).Basis = BasisStanding
	e.p.mu.Unlock()
}

// The refused-revert digest lines: the applier will not start the image,
// or it may start before it is undone (SR3-4f-3 B5).
const (
	wontStartLine = "Update 41 failed a security check while it was being installed; I will not start it. Nothing is needed from you."
	mayStartLine  = "Update 41 failed a security check while it was being installed; it may start before I can undo it. Nothing is needed from you."
)

// handoverOnly is a handover refusal that does not say whether the image
// starts first: the digest must not promise that it does not.
type handoverOnly struct{}

func (handoverOnly) Error() string  { return "apply: a release is being applied" }
func (handoverOnly) Handover() bool { return true }

// Mutants: drop ConcernStarts from the digest, or read a refusal with no
// Starts as will not start, and the line promises what may not hold.
func TestRefusedSecurityRevertSetsConcern(t *testing.T) {
	for name, c := range map[string]struct {
		err    error
		starts bool
	}{
		"will not start": {installing{}, false},
		"may start":      {installing{starts: true}, true},
		"not said":       {handoverOnly{}, true},
	} {
		t.Run(name, func(t *testing.T) {
			starts := c.starts
			line, other := wontStartLine, mayStartLine
			if starts {
				line, other = other, line
			}
			e, r, w := pendingStaged(t)
			e.failsSecurity(r.ID)
			w.err = c.err
			ids, err := e.p.Recheck(bg)
			if err != nil || slices.Contains(ids, r.ID) {
				t.Fatalf("recheck: %v %v", ids, err)
			}
			if got := w.whys; len(got) != 1 || got[0] != WhySecurity {
				t.Fatalf("withdraw reasons %q", got)
			}
			e.reopen()
			if a := e.adoption(r.ID); a.Concern != WhySecurity || a.ConcernStarts != starts || a.Reverted != "" || !a.Staged {
				t.Fatalf("adoption %+v", a)
			}
			d := e.p.Digest()
			if !slices.Contains(d, line) || slices.Contains(d, other) {
				t.Fatalf("digest: %q", d)
			}
			for _, l := range d {
				if strings.Contains(l, "pdate 41") && (strings.Contains(l, "UNDO") || strings.Contains(l, "only version")) {
					t.Fatalf("digest offers what the owner cannot do: %q", l)
				}
				if strings.Contains(l, "as soon as it starts") || !starts && strings.Contains(l, "start before") {
					t.Fatalf("digest promises a start: %q", l)
				}
			}
			w = &withdrawer{}
			e.p.SetWithdrawer(w)
			e.failsSecurity(r.ID)
			if ids, err := e.p.Recheck(bg); err != nil || !slices.Contains(ids, r.ID) {
				t.Fatalf("recheck once it can withdraw: %v %v", ids, err)
			}
			if a := e.adoption(r.ID); a.Reverted != WhySecurity {
				t.Fatalf("adoption %+v", a)
			}
			if d := e.p.Digest(); slices.Contains(d, line) {
				t.Fatalf("digest after the revert: %q", d)
			}
		})
	}
}

// B4: only a security revert sets the Concern. A refused regression
// revert keeps its error and sets none; and a regression Concern on an
// unprotected adoption is never told as a refused security revert.
// Mutants: drop why == WhySecurity from Recheck, or a.Concern ==
// WhySecurity from the digest.
func TestRefusedRegressionRevertSetsNoConcern(t *testing.T) {
	e, r, w := pendingStaged(t)
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if string(tr["host-image/release"]) == update.Digest([]byte("b")) && string(pr.Input) == "skills/greet" {
			return []byte("bye"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	e.p.mu.Lock()
	e.p.adoptionByIDLocked(r.ID).Basis = BasisStanding
	e.p.mu.Unlock()
	w.err = installing{}
	ids, err := e.p.Recheck(bg)
	if !handover(err) || slices.Contains(ids, r.ID) {
		t.Fatalf("recheck: %v %v", ids, err)
	}
	if got := w.whys; len(got) != 1 || got[0] != WhyRegression {
		t.Fatalf("withdraw reasons %q", got)
	}
	if a := e.adoption(r.ID); a.Concern != "" {
		t.Fatalf("adoption %+v", a)
	}
	e.p.mu.Lock()
	e.p.adoptionByIDLocked(r.ID).Concern = WhyRegression
	e.p.mu.Unlock()
	for _, l := range e.p.Digest() {
		if strings.Contains(l, "failed a security check") {
			t.Fatalf("digest: %q", l)
		}
	}
}

// An owner's refused UNDO is answered to the owner; it sets no Concern.
func TestRefusedOwnerUndoSetsNoConcern(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.err = installing{}
	if err := e.p.Revert(bg, r.Short, OriginOwner); err == nil {
		t.Fatal("undo while installing")
	}
	if got := w.whys; len(got) != 1 || got[0] != WhyOwner {
		t.Fatalf("withdraw reasons %q", got)
	}
	if a := e.adoption(r.ID); a.Concern != "" {
		t.Fatalf("adoption %+v", a)
	}
}

// REQ: UPD-1, OP-5
//
// SR3-4f-3c: Withdraw races ConfirmStaged (the applier settles the boot
// while the pipeline asks it to withdraw). StageDropped of the confirmed
// adoption is refused with the permanent ErrNotStaged, so the applier
// clears its obligation instead of retrying it on every Tick.
func TestDropOfAConfirmedAdoptionIsPermanentlyRefused(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.then = func(id string) {
		if err := e.p.ConfirmStaged(id); err != nil {
			t.Error("confirm:", err)
		}
	}
	_ = e.p.Revert(bg, r.Short, OriginOwner) // either outcome; the drop is what matters
	for i := 0; i < 2; i++ {
		err := e.p.StageDropped(bg, r.ID)
		var perm interface{ Permanent() bool }
		if !errors.Is(err, ErrNotStaged) || !errors.As(err, &perm) || !perm.Permanent() {
			t.Fatalf("drop %d of a confirmed adoption: %v", i, err)
		}
	}
	if err := e.p.StageDropped(bg, "no-such-id"); !errors.Is(err, ErrNotStaged) {
		t.Fatalf("drop of an unknown adoption: %v", err)
	}
}

// REQ: UPD-8, OP-5
//
// A security withdrawal the applier refused in its handover window is
// kept by the applier, which withdraws the image itself once it can
// (SR3-4f-3 B2): the drop that settles it is the security revert, never
// a drop Loop 3 offers again. A first revert's why still stays.
func TestRefusedSecurityWithdrawalIsNotADrop(t *testing.T) {
	for _, c := range []struct {
		name  string
		first string // a revert cut short after its withdrawal, or none
		want  string
	}{
		{"security", "", WhySecurity},
		{"owner, then security", WhyOwner, WhyOwner},
	} {
		e, r, w := pendingStaged(t)
		if c.first != "" {
			w.then = func(string) { e.store.Fail = errors.New("disk full") }
			if e.p.revert(bg, r.ID, origin(c.first), c.first) == nil {
				t.Fatalf("%s: first revert ran without saving", c.name)
			}
			e.store.Fail = nil
			e.reopen()
			w = &withdrawer{}
			e.p.SetWithdrawer(w)
		}
		w.err = installing{}
		if err := e.p.revert(bg, r.ID, OriginPipeline, WhySecurity); !handover(err) {
			t.Fatalf("%s: security revert: %v", c.name, err)
		}
		e.reopen()
		if err := e.p.StageDropped(bg, r.ID); err != nil {
			t.Fatal(c.name, err)
		}
		if a := e.adoption(r.ID); a.Reverted != c.want {
			t.Fatalf("%s: reverted %q, want %q", c.name, a.Reverted, c.want)
		}
	}
}
