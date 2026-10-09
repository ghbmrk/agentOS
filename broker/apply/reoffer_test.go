package apply

import (
	"context"
	"errors"
	"testing"
)

// REQ: UPD-1, UPD-5, SR3-4f-2-r1e
//
// SR3-4f-2-r1e (LATER SR3-4f-2 l4): an adoption that arrives while
// another release is being applied is refused with ErrApplying and
// dropped, so the change pipeline records it WhyDropped and Loop 3 offers
// the release again at its next check (SR3-4f-2-r1a).
func TestIncomingAdoptionRefusedWhileApplyingIsDropped(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	var during error
	r.act.onInstall = func() { during = r.a.Schedule(r.release(2, true), "a2") }
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if !errors.Is(during, ErrApplying) {
		t.Fatalf("schedule during the install: %v", during)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	r.settledInstalledAs("a1")
	r.dropsAre("a2")
	if err := r.a.Schedule(r.release(2, true), "a2"); !errors.Is(err, ErrRetired) {
		t.Fatalf("dropped adoption scheduled again: %v", err)
	}
}
