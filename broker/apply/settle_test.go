package apply

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-1, UPD-1a, OP-4, OP-5
//
// SR3-4: settling an apply after the restart spans three stores: the
// update store (installed.json, staged.json), the change pipeline's
// adoption and the applier's own state. Each step is idempotent for the
// exact release and adoption, and the applier clears its in-flight record
// last, in memory only once it is saved, so a cut before or after any step
// converges on a later Resume without installing again.

var errIO = errors.New("input/output error")

// handedOver schedules release 1 for adoption a1 and restarts into it;
// the boot falls back when fail is set.
func handedOver(t *testing.T, fail bool) (*rig, *update.Verified) {
	t.Helper()
	r := newRig(t)
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.act.failBoot = fail
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	return r, rel
}

// settledInstalled checks the converged state after a good boot.
func (r *rig) settledInstalled() {
	r.t.Helper()
	if in, _ := r.store.Installed(); in.Version != 1 || in.UsrRootHash != strings.Repeat("0f", 32) {
		r.t.Fatalf("installed %+v", in)
	}
	if _, ok, _ := r.store.Staged(); ok {
		r.t.Fatal("still staged")
	}
	if len(r.pipe.confirmed) != 1 || r.pipe.confirmed[0] != "a1" || len(r.pipe.failed) != 0 {
		r.t.Fatalf("pipeline: %+v", r.pipe)
	}
	if len(r.act.installed) != 1 || r.act.restarts != 1 {
		r.t.Fatalf("installed again: %+v", r.act)
	}
	if got := r.a.Status(); got != "" {
		r.t.Fatalf("status: %q", got)
	}
	if r.saved().Applying != nil {
		r.t.Fatal("apply still in flight on disk")
	}
	r.restart()
	if got := r.a.Status(); got != "" {
		r.t.Fatalf("status after a restart: %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != "Update 1 is installed." {
		r.t.Fatalf("digest: %q", d)
	}
}

// settledFellBack checks the converged state after a fallback, and that
// a later update is taken.
func (r *rig) settledFellBack(rel *update.Verified) {
	r.t.Helper()
	if in, _ := r.store.Installed(); in.Version != 0 {
		r.t.Fatalf("installed %+v", in)
	}
	if _, ok, _ := r.store.Staged(); ok {
		r.t.Fatal("still staged")
	}
	if len(r.pipe.failed) != 1 || r.pipe.failed[0] != "a1" || len(r.pipe.confirmed) != 0 {
		r.t.Fatalf("pipeline: %+v", r.pipe)
	}
	if !strings.HasPrefix(r.a.Status(), "Update 1 did not start cleanly") || !r.a.FellBack(1) {
		r.t.Fatalf("status: %q", r.a.Status())
	}
	if r.saved().Applying != nil {
		r.t.Fatal("apply still in flight on disk")
	}
	r.admitsNext(rel)
}

// admitsNext: Tick takes the next update (a new adoption; the same
// release stands in for a later one, which the rig's store cannot check).
func (r *rig) admitsNext(rel *update.Verified) {
	r.t.Helper()
	r.act.failBoot = false
	r.restart()
	r.must(r.a.Schedule(rel, "a2"))
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		r.t.Fatalf("next update: %v %v", ok, err)
	}
}

func (r *rig) saved() state {
	r.t.Helper()
	b, err := r.state.Load()
	r.must(err)
	var st state
	r.must(json.Unmarshal(b, &st))
	return st
}

// Acceptance 1: the confirmation fails after the update store committed
// the release and consumed staged.json.
func TestConfirmationErrorAfterCommitConverges(t *testing.T) {
	r, _ := handedOver(t, false)
	ctx := context.Background()
	r.restart()
	r.pipe.confirmErr = errIO
	if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
		t.Fatalf("resume: %v", err)
	}
	if in, _ := r.store.Installed(); in.Version != 1 {
		t.Fatalf("not committed: %+v", in)
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("staged.json not consumed")
	}
	if r.saved().Applying == nil || r.a.Status() == "" {
		t.Fatal("settled before the adoption was confirmed")
	}
	for i := 0; i < 3; i++ { // reopen and retry, more than once
		r.restart()
		r.must(r.a.Resume(ctx))
	}
	r.settledInstalled()
}

// Acceptance 2: installed.json was written, staged.json not yet removed.
func TestCommitCutBeforeStagedCleanupConverges(t *testing.T) {
	r, _ := handedOver(t, false)
	ctx := context.Background()
	staged, err := os.ReadFile(filepath.Join(r.store.Dir, "staged.json"))
	r.must(err)
	r.restart()
	r.pipe.confirmErr = errIO
	_ = r.a.Resume(ctx)
	r.must(os.WriteFile(filepath.Join(r.store.Dir, "staged.json"), staged, 0o600))
	r.restart()
	r.must(r.a.Resume(ctx))
	r.settledInstalled()
}

// Acceptance 2 and 3: the pipeline confirmed, the applier's own state
// was not saved. The obligation stays, in memory and on disk.
func TestStateSaveFailureAfterConfirmKeepsTheObligation(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		r, _ := handedOver(t, false)
		ctx := context.Background()
		r.restart()
		r.state.Fail = errIO
		if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
			t.Fatalf("resume: %v", err)
		}
		if len(r.pipe.confirmed) != 1 {
			t.Fatalf("pipeline: %+v", r.pipe)
		}
		if !strings.Contains(r.a.Status(), "Update 1") {
			t.Fatalf("status claims settled: %q", r.a.Status())
		}
		if r.a.st.Applying == nil {
			t.Fatal("in-flight record dropped from memory")
		}
		r.state.Fail = nil
		if reopen {
			r.restart()
		}
		r.must(r.a.Resume(ctx))
		r.must(r.a.Resume(ctx))
		r.settledInstalled()
	}
}

// Acceptance 3: a different release with the same version is never
// taken for the one handed over.
func TestDifferentReleaseWithTheSameVersionIsNotSettled(t *testing.T) {
	r, _ := handedOver(t, false)
	ctx := context.Background()
	r.must(os.Remove(filepath.Join(r.store.Dir, "staged.json")))
	r.must(os.WriteFile(filepath.Join(r.store.Dir, "installed.json"),
		[]byte(`{"version":1,"manifest_sha256":"`+strings.Repeat("ee", 32)+`","usr_root_hash":"`+strings.Repeat("0f", 32)+`"}`), 0o600))
	r.restart()
	if err := r.a.Resume(ctx); err == nil {
		t.Fatal("settled against another release")
	}
	if len(r.pipe.confirmed) != 0 || r.saved().Applying == nil {
		t.Fatalf("confirmed or cleared: %+v", r.pipe)
	}
}

// Acceptance 4: the pipeline's revert fails after the stage was dropped.
func TestFallbackRevertErrorConverges(t *testing.T) {
	r, rel := handedOver(t, true)
	ctx := context.Background()
	r.restart()
	r.pipe.failErr = errIO
	if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
		t.Fatalf("resume: %v", err)
	}
	if r.a.FellBack(1) {
		t.Fatal("fallback recorded before the adoption was reverted")
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	r.must(r.a.Resume(ctx))
	r.settledFellBack(rel)
}

// Acceptance 4: the pipeline reverted, the applier's state was not saved.
func TestFallbackStateSaveFailureKeepsTheObligation(t *testing.T) {
	for _, reopen := range []bool{false, true} {
		r, rel := handedOver(t, true)
		ctx := context.Background()
		r.restart()
		r.state.Fail = errIO
		if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
			t.Fatalf("resume: %v", err)
		}
		if r.a.FellBack(1) {
			t.Fatal("fallback recorded in memory without being saved")
		}
		if r.a.st.Applying == nil {
			t.Fatal("in-flight record dropped from memory")
		}
		r.state.Fail = nil
		if reopen {
			r.restart()
		}
		r.must(r.a.Resume(ctx))
		r.settledFellBack(rel)
	}
}

// Review blocker 2a: the activator took the release but the save that
// records it failed. The apply is not reported as succeeded: the slot is
// abandoned and the release stays pending, so a restart in the same boot
// cannot undo an activation the journal calls done.
func TestHandoverSaveFailureIsNotSuccess(t *testing.T) {
	r := newRig(t)
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.act.onInstall = func() { r.state.Fail = errIO }
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if in := r.intents(); len(in) != 1 || in[0].State == journal.Succeeded {
		t.Fatalf("journal: %+v", in)
	}
	if r.act.abandoned != 1 || r.act.restarts != 0 {
		t.Fatalf("activator: %+v", r.act)
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("still staged")
	}
	if r.a.st.Applying != nil || r.a.st.Pending == nil {
		t.Fatalf("state: %+v", r.a.st)
	}
	r.state.Fail, r.act.onInstall = nil, nil
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("retry: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(context.Background()))
	if in, _ := r.store.Installed(); in.Version != 1 || len(r.pipe.confirmed) != 1 || len(r.pipe.failed) != 0 {
		t.Fatalf("installed %+v, pipeline %+v", in, r.pipe)
	}
}

// If the activator cannot abandon the unrecorded handover either, the
// rollback point stays, and the next Tick in the same boot abandons it
// before it applies the release again.
func TestUnabandonedHandoverIsAbandonedByTheNextTick(t *testing.T) {
	r := newRig(t)
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.act.onInstall = func() { r.state.Fail, r.act.abandonErr = errIO, errIO }
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if r.a.st.Applying == nil || r.a.st.Applying.Installed {
		t.Fatalf("in memory: %+v", r.a.st.Applying)
	}
	r.state.Fail, r.act.abandonErr, r.act.onInstall = nil, nil, nil
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("retry: %v %v", ok, err)
	}
	if r.act.abandoned != 1 || len(r.act.installed) != 2 {
		t.Fatalf("activator: %+v", r.act)
	}
	r.restart()
	r.must(r.a.Resume(context.Background()))
	if in, _ := r.store.Installed(); in.Version != 1 || len(r.pipe.confirmed) != 1 || len(r.pipe.failed) != 0 {
		t.Fatalf("installed %+v, pipeline %+v", in, r.pipe)
	}
}

// Review blocker 2b: a rollback point that never durably recorded the
// handover, then a new boot on the old root (a power cut mid-handover),
// is not a fallback. The stage is dropped, the adoption is left alone and
// nothing is marked as fallen back, so the release is tried again.
func TestUnrecordedHandoverThenPowerCutIsNotAFallback(t *testing.T) {
	r := newRig(t)
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.act.onInstall = func() { r.state.Fail, r.act.abandonErr = errIO, errIO }
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if pt := r.saved().Applying; pt == nil || pt.Installed {
		t.Fatalf("saved point %+v", pt)
	}
	// Power cut: counted tries on the new slot run out and the old root
	// boots.
	r.state.Fail, r.act.abandonErr, r.act.onInstall = nil, nil, nil
	r.act.failBoot = true
	r.must(r.act.Restart(context.Background()))
	r.restart()
	r.must(r.a.Resume(context.Background()))
	r.must(r.a.Resume(context.Background()))
	if len(r.pipe.failed) != 0 || len(r.pipe.confirmed) != 0 || r.a.FellBack(1) {
		t.Fatalf("judged a fallback: pipeline %+v", r.pipe)
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("still staged")
	}
	if r.saved().Applying != nil || strings.Contains(r.a.Status(), "did not start") {
		t.Fatalf("status %q", r.a.Status())
	}
	r.admitsNext(rel)
}
