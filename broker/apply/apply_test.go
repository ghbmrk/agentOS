package apply

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-1, UPD-1a, UPD-5, UPD-6
//
// Update apply, broker side (UPD-a): a verified release the change
// pipeline staged is handed to the A/B activator by a journaled intent
// with a rollback point, only outside a call, accepted work and the
// owner's excluded hours; after the restart it is committed once the
// health check passed, or dropped when boot counting fell back.

func TestSecurityFixAppliesAtTheNextQuietMomentAndCommitsAfterHealthCheck(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.must(r.a.Schedule(rel, "a1"))
	ok, err := r.a.Tick(ctx)
	if err != nil || !ok {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if len(r.act.installed) != 1 || r.act.installed[0] != 1 || r.act.restarts != 1 {
		t.Fatalf("activator: %+v", r.act)
	}
	its := r.intents()
	if len(its) != 1 || its[0].State != journal.Succeeded || its[0].Intent.Action != journal.ActionReleaseActivate ||
		its[0].Intent.Origin != Origin || its[0].Intent.Account != journal.BrokerAccount {
		t.Fatalf("intents: %+v", its)
	}
	// The rollback point is in the intent: the release it replaces and
	// the one it activates, each with its /usr root hash (UPD-1a).
	p := its[0].Intent.Params
	if fmt.Sprint(p["from"]) != "0" || fmt.Sprint(p["to"]) != "1" ||
		p["to_usr"] != strings.Repeat("0f", 32) || p["from_usr"] != strings.Repeat(oldHash, 32) || p["adoption"] != "a1" {
		t.Fatalf("params: %+v", p)
	}
	if st, ok, _ := r.store.Staged(); !ok || st.Version != 1 {
		t.Fatal("not staged before the restart")
	}
	if !strings.Contains(r.a.Status(), "restart") {
		t.Fatalf("status: %q", r.a.Status())
	}

	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 1 {
		t.Fatalf("installed %+v", in)
	}
	if len(r.pipe.confirmed) != 1 || r.pipe.confirmed[0] != "a1" || len(r.pipe.failed) != 0 {
		t.Fatalf("pipeline: %+v", r.pipe)
	}
	if got := r.a.Status(); got != "Update 1 is installed." {
		t.Fatalf("status: %q", got)
	}
	// Done: nothing more happens.
	if ok, _ := r.a.Tick(ctx); ok || r.act.restarts != 1 {
		t.Fatal("applied again")
	}
}

// UPD-6: never during a call, accepted work, or the owner's excluded
// hours, at the start and again just before dispatch.
func TestNeverAppliesDuringACallWorkOrExcludedHours(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	for name, set := range map[string]func(bool){
		"call":     func(b bool) { r.inCall = b },
		"work":     func(b bool) { r.working = b },
		"excluded": func(b bool) { r.excluded = func(time.Time) bool { return b } },
	} {
		set(true)
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("%s: applied (%v)", name, err)
		}
		if !strings.Contains(r.a.Status(), "when the box is free") {
			t.Fatalf("%s: status %q", name, r.a.Status())
		}
		set(false)
	}
	if len(r.act.installed) != 0 || len(r.intents()) != 0 {
		t.Fatal("handed over while busy")
	}
	// A call that starts between the check and dispatch stops it.
	id := r.a.nextID(1)
	in := r.a.intent(id)
	if _, err := r.eng.Submit(in); err != nil {
		t.Fatal(err)
	}
	if _, err := r.eng.Authorize(ctx, id); err != nil {
		t.Fatal(err)
	}
	r.inCall = true
	if st, _ := r.eng.Dispatch(ctx, id); st.State == journal.Succeeded || len(r.act.installed) != 0 {
		t.Fatalf("dispatched during a call: %s", st.State)
	}
	r.inCall = false
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("free again: %v %v", ok, err)
	}
}

// UPD-5: an ordinary release waits a random jitter before its quiet
// moment; a security fix does not.
func TestStableReleaseWaitsForItsJitter(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, false), "a1"))
	if ok, _ := r.a.Tick(ctx); ok {
		t.Fatal("applied before its jitter")
	}
	r.clk.add(3*time.Hour - time.Minute)
	if ok, _ := r.a.Tick(ctx); ok {
		t.Fatal("applied before its jitter")
	}
	r.clk.add(time.Minute)
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("after its jitter: %v %v", ok, err)
	}
}

// UPD-1: a release that fails its health check falls back by boot
// counting with no owner action; the box drops the staged release and
// reverts the adoption, and rewinds nothing that lives outside the image:
// the journal, root metadata (key revocations), the installed record.
func TestFallbackRevertsTheAdoptionAndRewindsNothing(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	root, err := os.ReadFile(filepath.Join(r.store.Dir, "root.json"))
	r.must(err)
	r.act.failBoot = true
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	before := len(r.eng.List())
	r.restart()
	r.must(r.a.Resume(ctx))
	if len(r.pipe.failed) != 1 || r.pipe.failed[0] != "a1" || len(r.pipe.confirmed) != 0 {
		t.Fatalf("pipeline: %+v", r.pipe)
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("still staged after the fallback")
	}
	if in, _ := r.store.Installed(); in.Version != 0 {
		t.Fatalf("installed %+v", in)
	}
	if b, _ := os.ReadFile(filepath.Join(r.store.Dir, "root.json")); !bytes.Equal(b, root) {
		t.Fatal("root metadata rewound")
	}
	if its := r.intents(); len(its) != 1 || its[0].State != journal.Succeeded || len(r.eng.List()) != before {
		t.Fatalf("journal changed: %+v", its)
	}
	if got := r.a.Status(); got != "Update 1 did not start cleanly, so the box went back to the version it had." {
		t.Fatalf("status: %q", got)
	}
}

// The new slot booted but its health check has not run yet: wait, then
// commit once the boot is blessed.
func TestHealthCheckPendingWaits(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.pending = true
	if ok, _ := r.a.Tick(ctx); !ok {
		t.Fatal("not applied")
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 0 || len(r.pipe.confirmed)+len(r.pipe.failed) != 0 {
		t.Fatal("judged before the health check")
	}
	r.act.boot.Blessed = true
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 1 || len(r.pipe.confirmed) != 1 {
		t.Fatal("not committed after the health check")
	}
}

// Before the restart, the running boot is the old one: that is not a
// fallback.
func TestResumeBeforeTheRestartJudgesNothing(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.installErr = nil
	id := r.a.nextID(1)
	in := r.a.intent(id)
	if _, err := r.eng.Submit(in); err != nil {
		t.Fatal(err)
	}
	if _, err := r.eng.Authorize(ctx, id); err != nil {
		t.Fatal(err)
	}
	if st, err := r.eng.Dispatch(ctx, id); err != nil || st.State != journal.Succeeded {
		t.Fatalf("%s %v", st.State, err)
	}
	r.restart() // the broker restarted, the box did not
	r.must(r.a.Resume(ctx))
	if len(r.pipe.failed)+len(r.pipe.confirmed) != 0 {
		t.Fatalf("judged without a reboot: %+v", r.pipe)
	}
	if _, ok, _ := r.store.Staged(); !ok {
		t.Fatal("staged release dropped")
	}
}

func TestInstallFailureStagesNothingAndRetries(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.installErr = errInstall
	if ok, _ := r.a.Tick(ctx); ok || r.act.restarts != 0 || r.act.abandoned != 1 {
		t.Fatal("restarted, or not abandoned, after a failed install")
	}
	if _, ok, _ := r.store.Staged(); ok {
		t.Fatal("staged after a failed install")
	}
	r.act.installErr = nil
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("retry: %v %v", ok, err)
	}
}

// Only the applier's own intent, for the release it holds, passes.
func TestCheckAllowsOnlyTheScheduledRelease(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	good := r.a.intent(r.a.nextID(1))
	if err := r.a.Check(ctx, journal.PhaseAuthorize, good); err != nil {
		t.Fatal(err)
	}
	bad := []journal.Intent{good, good, good, good, good}
	bad[0].Origin = "owner"
	bad[1].Origin = "guest:m1"
	bad[2].Action = "meta.loops.on"
	bad[3].ID = "upd:apply:2:n1"
	bad[4].Account = "mail"
	for _, in := range bad {
		if err := r.a.Check(ctx, journal.PhaseAuthorize, in); err == nil {
			t.Fatalf("allowed %+v", in)
		}
	}
	if err := r.a.Schedule(nil, "a0"); err == nil {
		t.Fatal("scheduled an unverified release")
	}
}

// The broker stopped mid-handover: in the same boot the apply is
// abandoned; after a reboot it is judged by the boot, as any apply is.
func TestStoppedMidHandover(t *testing.T) {
	for name, rebooted := range map[string]bool{"same boot": false, "rebooted into it": true} {
		r := newRig(t)
		ctx := context.Background()
		rel := r.release(1, true)
		r.must(r.store.Stage(rel))
		r.must(r.state.Save([]byte(`{"seq":1,"applying":{"id":"upd:apply:1:n1","from":0,"to":1,"to_usr":"` +
			strings.Repeat("0f", 32) + `","adoption":"a1","boot_id":"boot0","installed":false},"applied":{}}`)))
		if rebooted {
			r.act.boot = Boot{ID: "boot1", UsrRootHash: strings.Repeat("0f", 32), Blessed: true}
		}
		r.restart()
		r.must(r.a.Resume(ctx))
		in, _ := r.store.Installed()
		switch {
		case rebooted && (in.Version != 1 || len(r.pipe.confirmed) != 1):
			t.Fatalf("%s: not committed: %+v", name, in)
		case !rebooted && (in.Version != 0 || r.act.abandoned != 1 || len(r.pipe.failed)+len(r.pipe.confirmed) != 0):
			t.Fatalf("%s: %+v abandoned %d", name, in, r.act.abandoned)
		}
		if _, ok, _ := r.store.Staged(); ok {
			t.Fatalf("%s: still staged", name)
		}
		r.must(r.a.Schedule(r.release(2, true), "a2"))
	}
}

// Security F1 on #133: a call that starts during the slot write delays
// the restart until it ends, and a broker that stopped before the restart
// restarts on its next free tick.
type slowActivator struct {
	*activator
	during func()
}

func (s slowActivator) Install(ctx context.Context, v *update.Verified) error {
	err := s.activator.Install(ctx, v)
	s.during()
	return err
}

func TestRestartWaitsForTheBoxToBeFreeAfterTheSlotWrite(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.act0 = slowActivator{r.act, func() { r.inCall = true }}
	r.restart()
	r.must(r.a.Schedule(rel, "a1"))
	if ok, err := r.a.Tick(ctx); ok || err != nil || len(r.act.installed) != 1 || r.act.restarts != 0 {
		t.Fatalf("restarted during a call: %v %v", ok, err)
	}
	if !strings.Contains(r.a.Status(), "installing") {
		t.Fatalf("status: %q", r.a.Status())
	}
	r.inCall = false
	if ok, err := r.a.Tick(ctx); !ok || err != nil || r.act.restarts != 1 {
		t.Fatalf("not restarted once free: %v %v", ok, err)
	}
}

func TestBrokerStoppedBeforeTheRestartRestartsLater(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	id := r.a.nextID(1)
	in := r.a.intent(id)
	if _, err := r.eng.Submit(in); err != nil {
		t.Fatal(err)
	}
	if _, err := r.eng.Authorize(ctx, id); err != nil {
		t.Fatal(err)
	}
	if st, err := r.eng.Dispatch(ctx, id); err != nil || st.State != journal.Succeeded {
		t.Fatalf("%s %v", st.State, err)
	}
	r.restart() // the broker stopped before restarting the box
	r.must(r.a.Resume(ctx))
	r.working = true
	if ok, _ := r.a.Tick(ctx); ok {
		t.Fatal("restarted during accepted work")
	}
	r.working = false
	if ok, err := r.a.Tick(ctx); !ok || err != nil || r.act.restarts != 1 {
		t.Fatalf("not restarted: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 1 {
		t.Fatalf("installed %+v", in)
	}
}
