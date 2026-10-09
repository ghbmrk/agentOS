package apply

import (
	"context"
	"testing"
	"time"
)

// REQ: UPD-8, UPD-5
//
// SR3-6: a security fix queued on its attestation authority is not
// activated once the box's attestor policy narrowed; the pending
// automatic authorization is dropped, and Loop 3's next check schedules
// the release again under the current policy (the owner's path).

func TestSR36NarrowedPolicyDropsPendingSecurityFix(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.must(r.store.NoteAttestors(nil, nil)) // the owner removed the attestor
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(r.act.installed) != 0 || r.act.restarts != 0 {
		t.Fatalf("activated under a retired authority: %+v", r.act)
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("staged under a retired authority")
	}
	if r.a.st.Pending != nil || r.a.rel != nil {
		t.Fatal("the pending automatic authorization was kept")
	}
}

// The narrowing lands between the dispatch checks and the stage: Stage,
// the commit point, refuses it and the pending release is dropped.
func TestSR36NarrowingAtDispatchIsRefusedAtStage(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.pol.atDispatch = func() { r.must(r.store.NoteAttestors(nil, nil)) }
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(r.act.installed) != 0 {
		t.Fatal("installed under a retired authority")
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("staged under a retired authority")
	}
	if r.a.st.Pending != nil || r.a.rel != nil {
		t.Fatal("the pending automatic authorization was kept")
	}
}

// An ordinary release the owner adopted does not rest on attestation, so
// a policy change does not hold it.
func TestSR36OwnerPathUnaffectedByPolicyChange(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, false), "owner1"))
	r.must(r.store.NoteAttestors(nil, nil))
	r.clk.add(7 * time.Hour)
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(r.act.installed) != 1 {
		t.Fatal("the owner's release was not activated")
	}
}
