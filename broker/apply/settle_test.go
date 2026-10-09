package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
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
	r.dropsAre("a1") // SR3-4f-2b: nothing holds it after the restart
	r.admitsNext(rel)
}

// SR3-4f-1a (SR3-4-f2): the update store already holds the handed-over
// release as installed (CommitRelease ran after a blessed boot of its
// root), but the box booted the old root before the applier recorded the
// outcome. The apply is installed, not fallen back: the adoption is
// confirmed, never reverted, and the next update is taken.

const otherRootLine = "Update 1 is installed, but I started the previous version this time. " +
	"I will start update 1 at my next restart. Nothing is needed from you."

// bootOldRoot reboots the box into the old root (its health check
// passes) and restarts the applier.
func (r *rig) bootOldRoot() {
	r.t.Helper()
	r.act.next = strings.Repeat(oldHash, 32)
	r.must(r.act.Restart(context.Background()))
	r.restart()
}

// settledOnOldRoot checks the converged state after bootOldRoot, over
// three Resumes, and that the next update is admitted.
func (r *rig) settledOnOldRoot(rel *update.Verified) {
	r.t.Helper()
	for i := 0; i < 3; i++ {
		r.must(r.a.Resume(context.Background()))
	}
	st := r.saved()
	if st.Applying != nil || r.a.FellBack(1) || st.Last == nil || st.Last.Kind != "installed_other_root" {
		r.t.Fatalf("settled as %+v, fell back %v", st.Last, r.a.FellBack(1))
	}
	if in, _ := r.store.Installed(); in.Version != 1 || in.UsrRootHash != strings.Repeat("0f", 32) {
		r.t.Fatalf("installed %+v", in)
	}
	if _, ok, _ := r.store.Staged(); ok {
		r.t.Fatal("still staged")
	}
	if len(r.pipe.confirmed) != 1 || r.pipe.confirmed[0] != "a1" || len(r.pipe.failed) != 0 {
		r.t.Fatalf("pipeline: %+v", r.pipe)
	}
	for _, c := range r.pipe.calls {
		if strings.HasPrefix(c, "fail ") {
			r.t.Fatalf("StageFailed called: %q", r.pipe.calls)
		}
	}
	if len(r.act.installed) != 1 {
		r.t.Fatalf("installed again: %+v", r.act)
	}
	r.restart()
	if got := r.a.Status(); got != otherRootLine {
		r.t.Fatalf("status: %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != otherRootLine {
		r.t.Fatalf("digest: %q", d)
	}
	// The next update: the same release stands in for a later one, so the
	// store is set back to the image's own release.
	r.must(os.WriteFile(filepath.Join(r.store.Dir, "installed.json"), []byte(`{"version":0}`), 0o600))
	r.admitsNext(rel)
}

// The cut is after ConfirmStaged: only the applier's save failed.
func TestConfirmedThenOldRootConverges(t *testing.T) {
	r, rel := handedOver(t, false)
	ctx := context.Background()
	r.restart()
	r.pipe.onConfirm = func() { r.state.Fail = errIO }
	if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
		t.Fatalf("resume: %v", err)
	}
	r.state.Fail, r.pipe.onConfirm = nil, nil
	r.bootOldRoot()
	r.settledOnOldRoot(rel)
}

// The cut is after CommitRelease and before ConfirmStaged: the adoption
// is still staged, and is confirmed on the old root.
func TestCommittedBeforeConfirmThenOldRootConverges(t *testing.T) {
	r, rel := handedOver(t, false)
	ctx := context.Background()
	r.restart()
	r.pipe.confirmErr = errIO
	if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
		t.Fatalf("resume: %v", err)
	}
	if in, _ := r.store.Installed(); in.Version != 1 || len(r.pipe.confirmed) != 0 {
		t.Fatalf("installed %+v, pipeline %+v", in, r.pipe)
	}
	r.bootOldRoot()
	r.settledOnOldRoot(rel)
}

// SR3-4f-1b (SR3-4-f5): Install runs at most twice for one release with
// no recorded outcome; then the release is refused until the owner
// retries it. A boot on the old root after an unrecorded Install proves
// nothing about the release, so no fallback is recorded.

const unrecordedLine = "I could not record update 1 as installed, twice, so I will not try it again on my own. " +
	"You can retry it on my Wi-Fi page."

// unrecordedAttempt ticks once with the save that records the handover
// failing and Abandon failing, so the slot stays installed.
func (r *rig) unrecordedAttempt() {
	r.t.Helper()
	r.act.onInstall = func() { r.state.Fail, r.act.abandonErr = errIO, errIO }
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		r.t.Fatalf("tick: %v %v", ok, err)
	}
	r.state.Fail, r.act.abandonErr, r.act.onInstall = nil, nil, nil
}

// twiceUnrecorded runs three Tick/restart cycles on the old root, each
// scheduling release 1 again under a new adoption (a1 to a3), since a
// dropped adoption is retired; the third finds the bound.
func twiceUnrecorded(t *testing.T) (*rig, *update.Verified) {
	t.Helper()
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.act.failBoot = true // every reboot keeps the old root
	for i := 0; i < 3; i++ {
		if ok, err := r.a.Tick(ctx); ok || err != nil { // settles the last attempt
			t.Fatalf("cycle %d: %v %v", i, ok, err)
		}
		if err := r.a.Schedule(rel, fmt.Sprintf("a%d", i+1)); err != nil && i < 2 {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if i < 2 {
			r.unrecordedAttempt()
		} else if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("cycle %d: tick %v %v, Install called %d times", i, ok, err, len(r.act.installed))
		}
		r.must(r.act.Restart(ctx))
		r.restart()
	}
	r.must(r.a.Resume(ctx))
	return r, rel
}

func TestInstalledSaveFailingIsBoundedPerRelease(t *testing.T) {
	r, rel := twiceUnrecorded(t)
	ctx := context.Background()
	if len(r.act.installed) != 2 {
		t.Fatalf("installed %d times", len(r.act.installed))
	}
	st := r.saved()
	if r.a.FellBack(1) || st.Applying != nil || st.Last == nil || st.Last.Kind != "unrecorded" {
		t.Fatalf("settled as %+v, fell back %v, pipeline %q", st.Last, r.a.FellBack(1), r.pipe.calls)
	}
	if len(r.pipe.confirmed) != 0 || len(r.pipe.failed) != 0 {
		t.Fatalf("pipeline: %q", r.pipe.calls)
	}
	r.dropsAre("a1", "a2", "a3") // a3 was refused at the bound
	if got := r.a.Status(); got != unrecordedLine {
		t.Fatalf("status: %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != unrecordedLine {
		t.Fatalf("digest: %q", d)
	}
	if err := r.a.Schedule(rel, "a4"); !errors.Is(err, ErrRefused) {
		t.Fatalf("refused release scheduled again: %v", err)
	}
	if ok, err := r.a.Tick(ctx); ok || err != nil || len(r.act.installed) != 2 {
		t.Fatalf("fourth tick: %v %v, installed %d", ok, err, len(r.act.installed))
	}
}

// The refusal names the release, and only Retry lifts it, durably.
func TestRefusedReleaseIsRetriedOnlyByTheOwner(t *testing.T) {
	r, rel := twiceUnrecorded(t)
	ctx := context.Background()
	if err := r.a.Schedule(rel, "b1"); !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), rel.Ref().ManifestSHA256) {
		t.Fatalf("schedule: %v", err)
	}
	r.state.Fail = errIO
	if err := r.a.Retry(rel.Ref()); !errors.Is(err, errIO) {
		t.Fatalf("retry: %v", err)
	}
	if err := r.a.Schedule(rel, "b2"); !errors.Is(err, ErrRefused) {
		t.Fatalf("refusal lifted without being saved: %v", err)
	}
	r.state.Fail = nil
	r.must(r.a.Retry(rel.Ref()))
	r.restart()
	if got := r.a.Status(); got != "" {
		t.Fatalf("status after retry: %q", got)
	}
	r.must(r.a.Schedule(rel, "b3"))
	if ok, err := r.a.Tick(ctx); !ok || err != nil || len(r.act.installed) != 3 {
		t.Fatalf("tick after retry: %v %v, installed %d", ok, err, len(r.act.installed))
	}
}

// A recorded handover resets the count: one unrecorded attempt before
// it and one after are not two.
func TestRecordedHandoverResetsTheUnrecordedCount(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.unrecordedAttempt()
	r.act.failBoot = true
	if ok, err := r.a.Tick(ctx); !ok || err != nil { // recorded, then falls back
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if !r.a.FellBack(1) {
		t.Fatal("recorded handover not judged")
	}
	r.must(r.a.Schedule(rel, "a2"))
	r.unrecordedAttempt()
	r.restart()
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.must(r.a.Schedule(rel, "a3")) // a2 was dropped across the restart
	if ok, err := r.a.Tick(ctx); !ok || err != nil || len(r.act.installed) != 4 {
		t.Fatalf("tick: %v %v, installed %d", ok, err, len(r.act.installed))
	}
}

// A failed slot write is not an unrecorded install: it never counts.
func TestFailedInstallsDoNotCount(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.installErr = errInstall
	for i := 0; i < 3; i++ {
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
	}
	r.act.installErr = nil
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
}

// SR3-4f-1c: New drops a pending release even when the saved state still
// holds it, here after a narrowed policy whose abandon failed; a
// *update.Verified is never persisted, so Tick has nothing to install.
func TestRestartDropsPendingEvenAfterAFailedAbandon(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.pol.atDispatch = func() { r.must(r.store.NoteAttestors(nil, nil)) }
	r.act.abandonErr = errIO
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	// SR3-4f-2b: the Tick's settle saved the drop, and settled it once.
	if st := r.saved(); st.Pending != nil || st.Applying == nil {
		t.Fatalf("saved pending %+v, applying %+v", st.Pending, st.Applying)
	}
	r.act.abandonErr = nil
	r.restart()
	if r.a.st.Pending != nil {
		t.Fatalf("pending after New: %+v", r.a.st.Pending)
	}
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if r.saved().Pending != nil || len(r.act.installed) != 0 {
		t.Fatalf("pending %+v, installed %v", r.saved().Pending, r.act.installed)
	}
	r.dropsAre("a1")
}

// SR3-4f-1a: an update store that cannot be read on the old root is not
// a fallback. Resume returns the error with the apply still in flight,
// and settles once the read recovers (Security 4a 1, L3 1 on #597).
func oldRootReadFails(t *testing.T, breakStore func(path string)) {
	t.Helper()
	r, rel := handedOver(t, false)
	ctx := context.Background()
	r.restart()
	r.pipe.confirmErr = errIO // the cut is between CommitRelease and ConfirmStaged
	if err := r.a.Resume(ctx); !errors.Is(err, errIO) {
		t.Fatalf("resume: %v", err)
	}
	path := filepath.Join(r.store.Dir, "installed.json")
	good, err := os.ReadFile(path)
	r.must(err)
	breakStore(path)
	r.bootOldRoot()
	for i := 0; i < 2; i++ {
		if err := r.a.Resume(ctx); err == nil {
			t.Fatal("settled without reading the update store")
		}
	}
	if r.a.FellBack(1) || len(r.pipe.failed) != 0 || r.saved().Applying == nil {
		t.Fatalf("judged a fallback: %q, applying %v", r.pipe.calls, r.saved().Applying)
	}
	r.must(os.RemoveAll(path))
	r.must(os.WriteFile(path, good, 0o600))
	r.settledOnOldRoot(rel)
}

func TestUnreadableInstalledOnOldRootIsRetried(t *testing.T) {
	oldRootReadFails(t, func(path string) {
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInstalledAsDirectoryOnOldRootIsRetried(t *testing.T) {
	oldRootReadFails(t, func(path string) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	})
}

// SR3-4f-1a: on the old root, the update store naming another build of
// the same version is not the handed-over release: the apply fell back,
// and nothing is confirmed (Security 4a 2, L3 2 on #597).
func TestAnotherBuildInstalledOnOldRootFellBack(t *testing.T) {
	for name, other := range map[string]struct{ root, manifest bool }{
		"another root":     {root: true},
		"another manifest": {manifest: true},
		"version only":     {root: true, manifest: true},
	} {
		t.Run(name, func(t *testing.T) {
			r, rel := handedOver(t, false)
			root, manifest := strings.Repeat("0f", 32), rel.Ref().ManifestSHA256
			if other.root {
				root = strings.Repeat("1e", 32)
			}
			if other.manifest {
				manifest = strings.Repeat("ee", 32)
			}
			r.must(os.WriteFile(filepath.Join(r.store.Dir, "installed.json"),
				[]byte(`{"version":1,"manifest_sha256":"`+manifest+`","usr_root_hash":"`+root+`"}`), 0o600))
			r.bootOldRoot()
			r.must(r.a.Resume(context.Background()))
			st := r.saved()
			if st.Applying != nil || st.Last == nil || st.Last.Kind != "fell_back" || !r.a.FellBack(1) {
				t.Fatalf("settled as %+v", st.Last)
			}
			for _, c := range r.pipe.calls {
				if strings.HasPrefix(c, "confirm ") {
					t.Fatalf("confirmed: %q", r.pipe.calls)
				}
			}
		})
	}
}

// SR3-4f-1b: within one boot, with Abandon working, a release whose
// handover cannot be recorded is installed twice, then refused with its
// line; Retry is refused while an install is in flight (Security 4a 3
// and 5, L3 3 on #597).
func TestUnrecordedBoundHoldsWithinOneBoot(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	var retryErr error
	r.act.onInstall = func() {
		r.state.Fail = errIO
		if len(r.act.installed) == 1 {
			retryErr = r.a.Retry(r.release(1, true).Ref())
		}
	}
	for i := 0; i < 5; i++ {
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("tick %d: %v %v", i, ok, err)
		}
		r.state.Fail = nil
	}
	if !errors.Is(retryErr, ErrApplying) {
		t.Fatalf("retry while installing: %v", retryErr)
	}
	if len(r.act.installed) != 2 || r.act.restarts != 0 {
		t.Fatalf("installs %d, restarts %d", len(r.act.installed), r.act.restarts)
	}
	if st := r.saved(); st.Last == nil || st.Last.Kind != "unrecorded" || st.Applying != nil {
		t.Fatalf("settled as %+v", st.Last)
	}
	if got := r.a.Status(); got != unrecordedLine {
		t.Fatalf("status: %q", got)
	}
}

// REQ: UPD-1, UPD-8, OP-4, OP-5
//
// SR3-4f-2: an adoption whose release leaves the applier before it is
// installed is settled with StageDropped, after the applier's own save;
// a failed call stays an obligation the next Tick retries. Withdraw gives
// a pending release up for the pipeline's revert, and refuses from the
// save before the install until the boot after it settles.

// drops lists the adoptions StageDropped was called for, in order.
func (r *rig) drops() []string {
	r.t.Helper()
	r.pipe.mu.Lock()
	defer r.pipe.mu.Unlock()
	var out []string
	for _, c := range r.pipe.calls {
		if id, ok := strings.CutPrefix(c, "drop "); ok {
			out = append(out, id)
		}
	}
	return out
}

func (r *rig) dropsAre(want ...string) {
	r.t.Helper()
	if got := r.drops(); strings.Join(got, ",") != strings.Join(want, ",") {
		r.t.Fatalf("StageDropped calls %q, want %q", got, want)
	}
	if d := r.saved().Dropped; len(d) != 0 {
		r.t.Fatalf("obligations left: %q", d)
	}
}

func TestWithdrawDropsPending(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.state.Fail = errIO
	if err := r.a.Withdraw("a1", "owner"); !errors.Is(err, errIO) || r.a.st.Pending == nil {
		t.Fatalf("withdraw without saving: %v", err)
	}
	r.state.Fail = nil
	r.must(r.a.Withdraw("a1", "owner"))
	if ok, err := r.a.Tick(ctx); ok || err != nil || len(r.act.installed) != 0 {
		t.Fatalf("tick: %v %v, installed %d", ok, err, len(r.act.installed))
	}
	if r.saved().Pending != nil || r.a.rel != nil {
		t.Fatal("a withdrawn release is still pending")
	}
	if err := r.a.Schedule(rel, "a1"); !errors.Is(err, ErrRetired) {
		t.Fatalf("withdrawn adoption scheduled again: %v", err)
	}
	// The withdrawal is also a drop: if the caller's own revert failed or
	// was cut short (STOP, a cut before its journal), this settles it; the
	// pipeline makes it a no-op when the revert ran (L3-1).
	r.dropsAre("a1")
	r.must(r.a.Withdraw("other", "owner")) // not held: nothing to give up, still dropped
	if _, err := r.a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	r.dropsAre("a1", "other")

	r.must(r.a.Schedule(rel, "a2"))
	var during error
	r.act.onInstall = func() { during = r.a.Withdraw("a2", "owner") }
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if !errors.Is(during, ErrApplying) {
		t.Fatalf("withdraw during the install: %v", during)
	}
	if err := r.a.Withdraw("a2", "owner"); !errors.Is(err, ErrApplying) {
		t.Fatalf("withdraw before the restart settled: %v", err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	r.settledInstalledAs("a2")
}

// A withdrawal cut short before any Tick, its revert lost with the
// process, is still settled by the next Tick (L3-1).
func TestWithdrawDropSurvivesARestart(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.must(r.a.Withdraw("a1", "owner"))
	r.restart()
	r.must(r.a.Resume(ctx))
	if _, err := r.a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	r.dropsAre("a1")
}

// settledInstalledAs: the release was installed and adoption confirmed.
func (r *rig) settledInstalledAs(adoption string) {
	r.t.Helper()
	if in, _ := r.store.Installed(); in.Version != 1 || len(r.pipe.confirmed) != 1 || r.pipe.confirmed[0] != adoption {
		r.t.Fatalf("installed %+v, pipeline %+v", in, r.pipe)
	}
}

func TestPolicyDropSettlesTheAdoption(t *testing.T) {
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.must(r.store.NoteAttestors(nil, nil))
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.dropsAre("a1")
}

func TestPolicyMovedAtStageSettlesTheAdoption(t *testing.T) {
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.pol.atDispatch = func() { r.must(r.store.NoteAttestors(nil, nil)) }
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(r.act.installed) != 0 {
		t.Fatal("installed")
	}
	r.dropsAre("a1")
}

// The pipeline is told only after a drop is saved: told first, a restart
// could forget the drop and take the reverted adoption again
// (SR3-4f-2b). Here Tick's narrowing drop meets a failing state store.
func TestDropIsSavedBeforeThePipelineIsTold(t *testing.T) {
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.must(r.store.NoteAttestors(nil, nil))
	r.state.Fail = errIO
	if ok, _ := r.a.Tick(context.Background()); ok {
		t.Fatal("applied")
	}
	if d := r.drops(); len(d) != 0 {
		t.Fatalf("pipeline told before the save: %q", d)
	}
	r.state.Fail = nil
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.dropsAre("a1")
}

func TestSupersedeSettlesTheOldAdoption(t *testing.T) {
	r := newRig(t)
	rel1 := r.release(1, true)
	r.must(r.a.Schedule(rel1, "a1"))
	r.must(r.a.Schedule(rel1, "a1")) // the same release again: kept
	r.dropsAre()
	r.must(r.a.Schedule(rel1, "a2")) // a new adoption of it
	if d := r.saved().Dropped; len(d) != 1 || d[0] != "a1" {
		t.Fatalf("obligation not saved: %q", d)
	}
	if err := r.a.Schedule(rel1, "a1"); !errors.Is(err, ErrRetired) {
		t.Fatalf("dropped adoption scheduled again: %v", err)
	}
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil || r.saved().Applying.Adoption != "a2" {
		t.Fatalf("tick: %v %v, installed %v", ok, err, r.act.installed)
	}
	r.dropsAre("a1")
}

// A pending release saved before a process restart is not kept: New
// retires its adoption and the next Tick settles it; the release is
// scheduled again only under a new ID.
func TestNewDropsASavedPendingRelease(t *testing.T) {
	r := newRig(t)
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	r.restart()
	if ok, err := r.a.Tick(context.Background()); ok || err != nil || len(r.act.installed) != 0 {
		t.Fatalf("tick: %v %v, installed %d", ok, err, len(r.act.installed))
	}
	r.dropsAre("a1")
	if err := r.a.Schedule(rel, "a1"); !errors.Is(err, ErrRetired) {
		t.Fatalf("schedule: %v", err)
	}
	r.must(r.a.Schedule(rel, "a2"))
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.dropsAre("a1")
}

func TestNotHandedAbandonAcrossRestartSettles(t *testing.T) {
	ctx := context.Background()
	// In the same boot the release is still pending: no settle, and the
	// next Tick installs it (A5).
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.unrecordedAttempt()
	if ok, err := r.a.Tick(ctx); !ok || err != nil || len(r.act.installed) != 2 {
		t.Fatalf("same boot: %v %v, installed %d", ok, err, len(r.act.installed))
	}
	r.dropsAre()

	// After a process restart nothing holds it: settled at once.
	r = newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.unrecordedAttempt()
	r.restart()
	r.must(r.a.Resume(ctx))
	r.must(r.a.Resume(ctx))
	r.dropsAre("a1")
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded {
		t.Fatalf("settled as %+v", st.Last)
	}
}

func TestUnrecordedBoundSettlesTheAdoption(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.onInstall = func() { r.state.Fail = errIO }
	for i := 0; i < 5; i++ {
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("tick %d: %v %v", i, ok, err)
		}
		r.state.Fail = nil
	}
	if len(r.act.installed) != 2 {
		t.Fatalf("installs %d", len(r.act.installed))
	}
	r.dropsAre("a1")
}

func TestRefusedRefSettlesTheIncomingAdoption(t *testing.T) {
	r, rel := twiceUnrecorded(t)
	before := r.drops()
	if err := r.a.Schedule(rel, "b1"); !errors.Is(err, ErrRefused) {
		t.Fatalf("schedule: %v", err)
	}
	if d := r.saved().Dropped; len(d) != 1 || d[0] != "b1" {
		t.Fatalf("obligation not saved: %q", d)
	}
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.dropsAre(append(before, "b1")...)
	r.must(r.a.Retry(rel.Ref()))
	r.must(r.a.Schedule(rel, "b2"))
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("tick after retry: %v %v", ok, err)
	}
	r.dropsAre(append(before, "b1")...)
}

func TestDropSettleFailureConverges(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.must(r.store.NoteAttestors(nil, nil))
	r.pipe.dropErr = errIO
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if d := r.saved().Dropped; len(d) != 1 || d[0] != "a1" {
		t.Fatalf("obligation: %q", d)
	}
	r.restart() // the obligation is durable
	for i := 0; i < 2; i++ {
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
	}
	r.dropsAre("a1", "a1")
}

// SR3-4f-2c: a security release whose attestor policy narrowed after the
// install is not restarted into (SR3-6, UPD-8).
func TestNarrowingAfterInstallIsNotRestarted(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.onInstall = func() { r.working = true } // holds the restart
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if pt := r.saved().Applying; pt == nil || !pt.Installed || !pt.Security {
		t.Fatalf("not handed over: %+v", pt)
	}
	r.must(r.store.NoteAttestors(nil, nil))
	r.working = false
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if r.act.restarts != 0 || r.act.abandoned != 1 || r.a.FellBack(1) {
		t.Fatalf("activator %+v", r.act)
	}
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded {
		t.Fatalf("settled as %+v", st.Last)
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("still staged")
	}
	r.dropsAre("a1")
}

// A process restart loses the held release, so a security fix handed over
// before it cannot be judged again: it fails closed (SR3-4f-2c).
func TestSecurityHandoverAfterAProcessRestartFailsClosed(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.onInstall = func() { r.working = true } // holds the restart
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart() // the broker restarts in the same boot
	r.must(r.a.Resume(ctx))
	r.working = false
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if r.act.restarts != 0 || r.act.abandoned != 1 || r.a.FellBack(1) {
		t.Fatalf("activator %+v", r.act)
	}
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded {
		t.Fatalf("settled as %+v", st.Last)
	}
	r.dropsAre("a1")
}

// An ordinary release is restarted into after a narrowing: its restart
// never rested on the attestors.
func TestNarrowingAfterInstallKeepsAnOrdinaryRelease(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, false), "a1"))
	r.clk.add(7 * time.Hour)
	r.act.onInstall = func() { r.working = true }
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.must(r.store.NoteAttestors(nil, nil))
	r.working = false
	if ok, err := r.a.Tick(ctx); !ok || err != nil || r.act.abandoned != 0 {
		t.Fatalf("tick: %v %v, activator %+v", ok, err, r.act)
	}
	r.dropsAre()
}

// REQ: UPD-1, UPD-8, OP-4, OP-5
//
// SR3-4f-3a: a security recheck that fails an adoption whose release the
// activator already took withdraws it in the boot it was handed over in:
// Abandon, DropStaged, then Applying cleared. Only a security failure
// withdraws; an owner UNDO or a regression revert keeps the refusal, and
// so does an install in flight or a new boot.

// installedHeld schedules release 1 (security when security is set) for
// adoption a1 and installs it, holding the restart.
func installedHeld(t *testing.T, security bool) *rig {
	t.Helper()
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, security), "a1"))
	if !security {
		r.clk.add(7 * time.Hour) // past the jitter
	}
	r.act.onInstall = func() { r.working = true } // holds the restart
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if pt := r.saved().Applying; pt == nil || !pt.Installed {
		t.Fatalf("not handed over: %+v", pt)
	}
	r.act.onInstall = nil
	return r
}

// withdrawn: the handover was undone and the adoption dropped, with no
// fallback recorded and nothing restarted into.
func (r *rig) withdrawn() {
	r.t.Helper()
	if r.act.restarts != 0 || r.act.abandoned != 1 || r.a.FellBack(1) {
		r.t.Fatalf("activator %+v, fell back %v", r.act, r.a.FellBack(1))
	}
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded {
		r.t.Fatalf("settled as %+v, applying %+v", st.Last, st.Applying)
	}
	if _, ok, _ := r.store.Staged(); ok {
		r.t.Fatal("still staged")
	}
	if in, _ := r.store.Installed(); in.Version == 1 {
		r.t.Fatal("committed")
	}
	r.working = false
	if ok, err := r.a.Tick(context.Background()); ok || err != nil || r.act.restarts != 0 {
		r.t.Fatalf("tick: %v %v, restarts %d", ok, err, r.act.restarts)
	}
	r.dropsAre("a1")
	if err := r.a.Schedule(r.release(1, true), "a1"); !errors.Is(err, ErrRetired) {
		r.t.Fatalf("withdrawn adoption scheduled again: %v", err)
	}
}

func TestSecurityRecheckWithdrawsAnInstalledImage(t *testing.T) {
	for name, security := range map[string]bool{"security fix": true, "ordinary": false} {
		t.Run(name, func(t *testing.T) {
			r := installedHeld(t, security)
			r.must(r.recheck("a1"))
			r.withdrawn()
		})
	}
}

// From the save before the install until Installed is saved, the
// applier is executing: the withdraw is refused as a handover, nothing
// is abandoned, and the pipeline's next Recheck gets it.
func TestSecurityWithdrawWhileExecutingIsRetried(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	var during error
	r.act.onInstall = func() {
		r.working = true
		during = r.a.Withdraw("a1", WhySecurity)
	}
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	var h interface{ Handover() bool }
	if !errors.Is(during, ErrApplying) || !errors.As(during, &h) || !h.Handover() {
		t.Fatalf("withdraw during the install: %v", during)
	}
	if r.act.abandoned != 0 {
		t.Fatalf("abandoned while executing: %+v", r.act)
	}
	r.act.onInstall = nil
	r.must(r.recheck("a1"))
	r.withdrawn()
}

// A failed Abandon clears nothing and is reported; the durable flag keeps
// the restart from booting the image, across a process restart, until a
// later Tick completes the withdraw. An ordinary release past its jitter
// shows it is the flag, not the policy check, that holds the restart.
func TestWithdrawAbandonFailureKeepsTheImageFromBooting(t *testing.T) {
	r := installedHeld(t, false)
	ctx := context.Background()
	r.act.abandonErr = errIO
	err := r.a.Withdraw("a1", WhySecurity)
	if !errors.Is(err, ErrApplying) || !errors.Is(err, errIO) {
		t.Fatalf("withdraw with Abandon failing: %v", err)
	}
	if pt := r.saved().Applying; pt == nil || !pt.Installed || !pt.Withdrawing {
		t.Fatalf("applying %+v", pt)
	}
	r.working = false
	if ok, err := r.a.Tick(ctx); ok || !errors.Is(err, errIO) || r.act.restarts != 0 {
		t.Fatalf("tick: %v %v, restarts %d", ok, err, r.act.restarts)
	}
	r.restart() // the broker restarts in the same boot
	r.must(r.a.Resume(ctx))
	if ok, err := r.a.Tick(ctx); ok || !errors.Is(err, errIO) || r.act.restarts != 0 {
		t.Fatalf("tick after a process restart: %v %v, restarts %d", ok, err, r.act.restarts)
	}
	if got := r.a.Status(); got != "Update 1 failed a security check; I will not start it. Nothing is needed from you." {
		t.Fatalf("status: %q", got)
	}
	r.act.abandonErr = nil
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.withdrawn()
}

// Abandon took, the save after it failed, and the box rebooted into the
// old root: that is the withdraw finishing, not a fallback.
func TestHalfWithdrawnThenOldRootIsNotAFallback(t *testing.T) {
	r := installedHeld(t, true)
	ctx := context.Background()
	r.act.onAbandon = func() { r.state.Fail = errIO }
	err := r.a.Withdraw("a1", WhySecurity)
	r.state.Fail = nil
	if !errors.Is(err, ErrApplying) || !errors.Is(err, errIO) || r.act.abandoned != 1 {
		t.Fatalf("withdraw with the save failing: %v, activator %+v", err, r.act)
	}
	if pt := r.saved().Applying; pt == nil || !pt.Withdrawing {
		t.Fatalf("applying %+v", pt)
	}
	r.bootOldRoot()
	r.must(r.a.Resume(ctx))
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded || r.a.FellBack(1) {
		t.Fatalf("settled as %+v, fell back %v", st.Last, r.a.FellBack(1))
	}
	for _, c := range r.pipe.calls {
		if strings.HasPrefix(c, "fail ") || strings.HasPrefix(c, "confirm ") {
			t.Fatalf("pipeline: %q", r.pipe.calls)
		}
	}
	r.dropsAre("a1")
}

// Only a security failure withdraws an installed image: an owner UNDO and
// a regression revert are still refused, as is any reason in a new boot.
// Mutant: drop the why check, and the owner's UNDO abandons the image.
func TestOwnerUndoStillRefusedAfterInstall(t *testing.T) {
	r := installedHeld(t, true)
	ctx := context.Background()
	for _, why := range []string{"owner", "regression", ""} {
		var h interface{ Handover() bool }
		if err := r.a.Withdraw("a1", why); !errors.Is(err, ErrApplying) || !errors.As(err, &h) {
			t.Fatalf("withdraw for %q: %v", why, err)
		}
	}
	if pt := r.saved().Applying; r.act.abandoned != 0 || pt == nil || pt.Withdrawing {
		t.Fatalf("activator %+v, applying %+v", r.act, pt)
	}
	r.working = false
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if err := r.a.Withdraw("a1", WhySecurity); !errors.Is(err, ErrApplying) || r.act.abandoned != 0 {
		t.Fatalf("withdraw in the new boot: %v, activator %+v", err, r.act)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	r.settledInstalledAs("a1")
}

// REQ: UPD-1, OP-5
//
// SR3-4f-3c: a withdraw that races the confirm (the adoption confirmed
// after the applier dropped it) gets a permanent refusal from
// StageDropped, and the obligation is cleared rather than retried on
// every Tick.
func TestPermanentDropRefusalIsCleared(t *testing.T) {
	r, _ := handedOver(t, false)
	ctx := context.Background()
	r.must(r.a.Resume(ctx))
	r.settledInstalledAs("a1")
	r.must(r.a.Withdraw("a1", "owner")) // the race: dropped after the confirm
	for i := 0; i < 3; i++ {
		if _, err := r.a.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	r.dropsAre("a1")
}

// A transient refusal still stays for the next settle.
func TestTransientDropRefusalStays(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.must(r.a.Withdraw("a1", "owner"))
	r.pipe.dropErr = errIO
	if _, err := r.a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if d := r.saved().Dropped; len(d) != 1 {
		t.Fatalf("obligations: %q", d)
	}
	if _, err := r.a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	r.dropsAre("a1", "a1")
}

// apply's WhySecurity is the pipeline's.
func TestWhySecurityMatchesThePipeline(t *testing.T) {
	if WhySecurity != change.WhySecurity {
		t.Fatalf("%q != %q", WhySecurity, change.WhySecurity)
	}
}
