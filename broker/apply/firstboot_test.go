package apply

import (
	"context"
	"errors"
	"testing"
)

// REQ: UPD-3
// First boot hands the newest stable release to the activator at once:
// no jitter, and no change-pipeline adoption to confirm or revert, since
// the box has no owner, tasks or held-out cases yet.
func TestFirstBootReleaseIsDueAtOnceAndNeedsNoAdoption(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.ScheduleFirstBoot(r.release(1, false)))
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("a first-boot release waited: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 1 {
		t.Fatalf("installed %+v", in)
	}
	if len(r.pipe.confirmed)+len(r.pipe.failed) != 0 {
		t.Fatalf("pipeline touched: %+v", r.pipe)
	}
	if r.a.FellBack(1) {
		t.Fatal("an installed release reads as fallen back")
	}
}

// REQ: UPD-3
// A first-boot release that falls back is remembered across restarts and
// never handed over again, so the box does not boot-loop into it.
func TestFirstBootFallbackIsRememberedAndNotRetried(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, false)
	r.must(r.a.ScheduleFirstBoot(rel))
	r.act.failBoot = true
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if len(r.pipe.confirmed)+len(r.pipe.failed) != 0 {
		t.Fatalf("pipeline touched: %+v", r.pipe)
	}
	r.restart()
	if !r.a.FellBack(1) || r.a.FellBack(2) {
		t.Fatal("fallback not remembered for exactly that release")
	}
	if err := r.a.ScheduleFirstBoot(rel); !errors.Is(err, ErrFellBack) {
		t.Fatalf("the fallen-back release was taken again: %v", err)
	}
	if ok, _ := r.a.Tick(ctx); ok || len(r.act.installed) != 1 {
		t.Fatalf("handed over again: %v", r.act.installed)
	}
}

// Ordinary scheduling still needs an adoption: only ScheduleFirstBoot
// skips the pipeline.
func TestScheduleStillNeedsAnAdoption(t *testing.T) {
	r := newRig(t)
	if err := r.a.Schedule(r.release(1, false), ""); err == nil {
		t.Fatal("scheduled without an adoption")
	}
}
