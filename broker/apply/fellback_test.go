package apply

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// fellBackOnce is a rig whose release 1, adopted as a1, fell back by boot
// counting and was settled (returned with the rig); the applier has restarted since. Its store
// checks every release the rig makes, so a later release stages too.
func fellBackOnce(t *testing.T) (*rig, *update.Verified) {
	t.Helper()
	r := newRig(t)
	r.mirror = updatetest.NewMirror(t)
	r.store = r.mirror.Box(0)
	r.restart()
	rel := r.release(1, false)
	r.must(r.a.Schedule(rel, "a1"))
	r.clk.add(7 * time.Hour)
	r.act.failBoot = true
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(context.Background()))
	if !r.a.FellBack(1) {
		t.Fatal("fallback not recorded")
	}
	r.act.failBoot = false
	r.restart()
	return r, rel
}

// REQ: UPD-1
// A release that fell back is never handed over again through Schedule,
// whatever adoption asks for it, so the box does not boot into the same
// bad release again. The refused adoption is settled, not left staged.
func TestScheduleRefusesAFallenBackRelease(t *testing.T) {
	r, rel := fellBackOnce(t)
	ctx := context.Background()
	if err := r.a.Schedule(rel, "a2"); !errors.Is(err, ErrFellBack) {
		t.Fatalf("the fallen-back release was taken again: %v", err)
	}
	r.clk.add(7 * time.Hour)
	if ok, _ := r.a.Tick(ctx); ok || len(r.act.installed) != 1 {
		t.Fatalf("handed over again: %v", r.act.installed)
	}
	if !slices.Contains(r.pipe.dropped, "a2") {
		t.Fatalf("refused adoption not settled: %+v", r.pipe)
	}
}

// REQ: UPD-1
// The refusal is by version: a later release still replaces the
// fallen-back one.
func TestScheduleAdmitsANewerReleaseAfterAFallback(t *testing.T) {
	r, _ := fellBackOnce(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(2, false), "a2"))
	r.clk.add(7 * time.Hour)
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 2 {
		t.Fatalf("installed %+v", in)
	}
}
