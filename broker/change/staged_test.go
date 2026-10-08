package change

import (
	"errors"
	"strings"
	"testing"

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
