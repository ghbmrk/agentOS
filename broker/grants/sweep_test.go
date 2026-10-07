package grants

import (
	"context"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/reversible"
)

// REQ: REV-3, CH-16

// crash restarts the rig on a copy of its journal as it is now, as if the
// broker had stopped at this instant: anything still running in the old
// gate keeps writing to the old store only.
func (r *rig) crash() {
	r.t.Helper()
	snap, err := r.store.ReadAll()
	if err != nil {
		r.t.Fatal(err)
	}
	r.store = &journal.MemStore{}
	if err := r.store.Rewrite(snap); err != nil {
		r.t.Fatal(err)
	}
	r.openWith(func() Owner { return r.own })
}

func stagedRig(t *testing.T) *rig {
	t.Helper()
	form := reversible.Form{Stage: "draft.save", Inverse: "draft.discard"}
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": form}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	return r
}

// TestBootSweepUnstagesAStageReconciledAfterItsCancel (RV11, L3 F2 on
// #76): a stage in flight at a crash is unknown at the next start, so the
// restart's cancel of its hold finds nothing to unstage; when the journal
// later learns the stage succeeded, the boot sweep removes the staged copy
// (the effect never ran), without texting the owner.
func TestBootSweepUnstagesAStageReconciledAfterItsCancel(t *testing.T) {
	r := stagedRig(t)
	sid := reversible.StageID("agent/s1", 1)
	block := make(chan struct{})
	defer close(block)
	r.exec.mu.Lock()
	r.exec.block = map[string]chan struct{}{sid: block}
	r.exec.mu.Unlock()
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	req, items := r.own.last(t)
	d := r.own.hold(req, 1, items[0])
	r.g.Decide(d)
	for st, err := r.g.Get(sid); err != nil || st.State != journal.InFlight; st, err = r.g.Get(sid) {
		time.Sleep(time.Millisecond) // journaled before its executor runs
	}

	r.crash()
	r.g.Sweep()
	r.g.Decide(owner.Decision{Request: d.Hold, Item: 1, Ref: "agent/s1", Why: "restart", Hold: d.Hold})
	r.g.Wait()
	r.g.Reissue(nil)
	r.g.Wait()
	if st := r.state(sid); st.State != journal.OutcomeUnknown {
		t.Fatalf("stage after the crash: %s", st.State)
	}
	if _, err := r.g.Get(reversible.InverseID("agent/s1", 1)); err == nil {
		t.Fatal("unstaged a stage whose outcome is unknown")
	}
	// Reconciliation finds the draft was made.
	if _, err := r.eng.Resolve(sid, 1, journal.Outcome{Result: journal.ResultSucceeded, Evidence: "done:" + sid}, "reconcile"); err != nil {
		t.Fatal(err)
	}

	notes := len(r.own.notes)
	r.crash()
	r.g.Sweep()
	r.g.Wait()
	inv := reversible.InverseID("agent/s1", 1)
	if st := r.state(inv); st.State != journal.Succeeded || st.Intent.Action != "draft.discard" {
		t.Fatalf("boot sweep left the staged copy: %s", st.State)
	}
	if got := r.exec.params[inv][reversible.ParamStaged]; got != "done:"+sid {
		t.Fatalf("inverse removed %v, not the stage's copy", got)
	}
	if r.exec.runs("agent/s1") != 0 || len(r.own.notes) != notes {
		t.Fatalf("ran %d, notes %q", r.exec.runs("agent/s1"), r.own.notes[notes:])
	}
	// A second sweep does nothing more.
	r.g.Sweep()
	r.g.Wait()
	if r.exec.runs(inv) != 1 {
		t.Fatalf("inverse ran %d times", r.exec.runs(inv))
	}
}

// TestBootSweepSettlesAStopHeldReleaseCarriedOverARestart (RV11, L3 F2 on
// #76): a released effect that STOP held over a restart has no endHeld
// record in the new gate, so when it then ends without sending, its
// staged copy stayed. The boot sweep leaves the copy while the release may
// still send it, and hands it to endHeld, so it is removed once the
// effect ends: here the recheck after RESUME refuses it, since the
// owner's approval did not survive the restart (GR8), whether the guest's
// dispatch goes through the gate or the engine (found by Tick).
func TestBootSweepSettlesAStopHeldReleaseCarriedOverARestart(t *testing.T) {
	r := stagedRig(t)
	for _, id := range []string{"agent/s1", "agent/s2"} {
		r.effect(id, "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
		r.g.Flush()
		r.approveHeld()
	}
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	for _, id := range []string{"agent/s1", "agent/s2"} {
		if st := r.state(id); st.State != journal.Authorized {
			t.Fatalf("%s during STOP: %s", id, st.State)
		}
	}

	r.crash()
	notes := len(r.own.notes)
	r.g.Sweep()
	r.g.Wait()
	for _, id := range []string{"agent/s1", "agent/s2"} {
		if _, err := r.g.Get(reversible.InverseID(id, 1)); err == nil {
			t.Fatalf("unstaged %s while its release may still send it", id)
		}
	}
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	r.g.Dispatch(context.Background(), "agent/s1")
	r.eng.Dispatch(context.Background(), "agent/s2")
	r.g.Tick()
	r.g.Wait()
	for _, id := range []string{"agent/s1", "agent/s2"} {
		if st := r.state(id); st.State != journal.Denied || r.exec.runs(id) != 0 {
			t.Fatalf("%s after RESUME: %s, ran %d", id, st.State, r.exec.runs(id))
		}
		if st := r.state(reversible.InverseID(id, 1)); st.State != journal.Succeeded {
			t.Fatalf("%s: a STOP-held release that ended after a restart kept its staged copy: %s", id, st.State)
		}
	}
	if n := r.own.notes[notes:]; len(n) != 0 {
		t.Fatalf("a clean unstage texted the owner: %q", n)
	}
}

// TestBootSweepLeavesWhatAReleaseOrALiveHoldStillUses: the sweep never
// removes the copy a sent effect completed, a live hold's stage, a copy
// the adapter reported gone or edited, or anything when no form stages;
// and an inverse that fails leaves the copy and tells the owner in the
// fixed RV7 line.
func TestBootSweepLeavesWhatAReleaseOrALiveHoldStillUses(t *testing.T) {
	r := stagedRig(t)
	send := func(id string) {
		t.Helper()
		r.effect(id, "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
		r.g.Flush()
		r.approveHeld()
	}
	send("agent/sent")
	send("agent/gone")
	send("agent/edited")
	r.exec.mu.Lock()
	r.exec.fail = map[string]bool{"agent/gone": true, "agent/edited": true}
	r.exec.evidence = map[string]string{"agent/gone": reversible.EvidenceGone, "agent/edited": reversible.EvidenceEdited}
	r.exec.mu.Unlock()
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	send("agent/live")

	r.g.Sweep()
	r.g.Wait()
	for _, id := range []string{"agent/sent", "agent/gone", "agent/edited", "agent/live"} {
		if _, err := r.g.Get(reversible.InverseID(id, 1)); err == nil {
			t.Fatalf("sweep unstaged %s", id)
		}
	}
	if st := r.state("agent/live"); st.State != journal.Pending {
		t.Fatalf("live hold: %s", st.State)
	}

	// A restart ends the live hold without the owner (RV6): its copy is
	// swept, and when the adapter does not apply the inverse the copy is
	// left and the owner told once.
	r.crash()
	r.exec.mu.Lock()
	r.exec.fail[reversible.InverseID("agent/live", 1)] = true
	r.exec.mu.Unlock()
	notes := len(r.own.notes)
	r.g.Sweep()
	r.g.Wait()
	if st := r.state(reversible.InverseID("agent/live", 1)); st.State != journal.NotApplied {
		t.Fatalf("inverse: %s", st.State)
	}
	if n := r.own.notes[notes:]; len(n) != 1 || n[0] != sweptHold+" did not run, but its draft or staged copy could not be removed, so it was left as is." {
		t.Fatalf("notes %q", n)
	}

	// No forms: nothing to sweep.
	plain := newRig(t, nil)
	plain.g.Sweep()
	plain.g.Wait()
	if len(plain.eng.List()) != 0 {
		t.Fatalf("sweep with no forms journaled %d intents", len(plain.eng.List()))
	}
}
