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
	// UX-133-1: an install is said once, in the digest, not in STATUS.
	if got := r.a.Status(); got != "" {
		t.Fatalf("status: %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != "Update 1 is installed." {
		t.Fatalf("digest: %q", d)
	}
	if d := r.a.Digest(); len(d) != 0 {
		t.Fatalf("digest again: %q", d)
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
	// UX-133-3: STATUS says why it waits.
	for _, c := range []struct {
		set  func(bool)
		line string
	}{
		{func(b bool) { r.inCall = b }, "Update 1 will install after the current call."},
		{func(b bool) { r.working = b }, "Update 1 will install once the agent's current task is done."},
		{func(b bool) { r.excluded = func(time.Time) bool { return b } }, "Update 1 will install after your update-free hours."},
		{func(b bool) {
			if b {
				r.talk = r.clk.now().Add(-5 * time.Minute)
			} else {
				r.talk = time.Time{}
			}
		}, "Update 1 will install once your conversation pauses."},
	} {
		c.set(true)
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("%s: applied (%v)", c.line, err)
		}
		if got := r.a.Status(); got != c.line {
			t.Fatalf("status %q, want %q", got, c.line)
		}
		c.set(false)
	}
	if len(r.act.installed) != 0 || len(r.intents()) != 0 {
		t.Fatal("handed over while busy")
	}
	// A call that starts between the check and dispatch stops it.
	id := r.a.nextID(1)
	in, err := r.a.intent(ctx, id)
	r.must(err)
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

// UX-133-4: a conversation in the last 10 minutes holds the apply, also
// for a security fix; one 11 minutes ago does not.
func TestRecentConversationHoldsTheApply(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.talk = r.clk.now().Add(-5 * time.Minute)
	if ok, _ := r.a.Tick(ctx); ok {
		t.Fatal("applied 5 minutes after a message")
	}
	r.talk = r.clk.now().Add(-11 * time.Minute)
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("held 11 minutes after a message: %v", err)
	}
}

// UX-133-3: before its moment, an update says it will install soon.
func TestWaitingForItsMomentSaysSoon(t *testing.T) {
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, false), "a1"))
	r.inCall = true // not yet its moment: the call is not the reason
	if got := r.a.Status(); got != "Update 1 will install soon. Nothing is needed from you." {
		t.Fatalf("status: %q", got)
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
	// UX-133-2: in STATUS until the next update installs, and once in
	// the digest.
	want := "Update 1 did not start cleanly, so the box went back to the version it had. Nothing is needed from you. It won't be tried again; a later update will replace it."
	if got := r.a.Status(); got != want {
		t.Fatalf("status: %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != want {
		t.Fatalf("digest: %q", d)
	}
	if got := r.a.Status(); got != want {
		t.Fatalf("status after the digest: %q", got)
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
	in, err := r.a.intent(ctx, id)
	r.must(err)
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
	good, err := r.a.intent(ctx, r.a.nextID(1))
	r.must(err)
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
	in, err := r.a.intent(ctx, id)
	r.must(err)
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

// Security ruling on UX-133-4: talk holds a security fix for at most 2
// hours from when it became due, so an agent replying every 5 minutes
// cannot hold it for ever. An ordinary release has no such bound.
func TestTalkHoldsASecurityFixForAtMostTwoHours(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	for i := 0; i < 23; i++ { // 23 x 5 minutes: under 2 hours
		r.talk = r.clk.now()
		r.clk.add(5 * time.Minute)
		if ok, _ := r.a.Tick(ctx); ok {
			t.Fatalf("applied at %d minutes during talk", (i+1)*5)
		}
	}
	r.talk = r.clk.now()
	r.clk.add(5 * time.Minute) // 2 hours since it became due
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("held past 2 hours by talk: %v", err)
	}
	// A call still holds it.
	r2 := newRig(t)
	r2.must(r2.a.Schedule(r2.release(1, true), "a1"))
	r2.clk.add(3 * time.Hour)
	r2.inCall = true
	if ok, _ := r2.a.Tick(ctx); ok {
		t.Fatal("applied during a call after the talk bound")
	}
}

// L3 MUST 1 on #133: STOP holds the handover and the restart. STOP during
// the slot write keeps the release installed and the box running; a later
// tick after RESUME restarts.
func TestStopHoldsTheRestart(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rel := r.release(1, true)
	r.act0 = slowActivator{r.act, func() { r.stopped = true }}
	r.restart()
	r.must(r.a.Schedule(rel, "a1"))
	if ok, _ := r.a.Tick(ctx); ok || r.act.restarts != 0 || len(r.act.installed) != 1 {
		t.Fatal("restarted after STOP during the slot write")
	}
	r.restart() // and the broker restarts while STOP holds
	r.must(r.a.Resume(ctx))
	if ok, _ := r.a.Tick(ctx); ok || r.act.restarts != 0 {
		t.Fatal("restarted while STOP holds")
	}
	r.stopped = false
	if ok, err := r.a.Tick(ctx); !ok || err != nil || r.act.restarts != 1 {
		t.Fatalf("not restarted after RESUME: %v", err)
	}
}

func TestStopHoldsTheHandover(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.stopped = true
	if ok, _ := r.a.Tick(ctx); ok || len(r.act.installed) != 0 {
		t.Fatal("handed over during STOP")
	}
	if got := r.a.Status(); got != "Update 1 is on hold while actions are stopped; it installs after RESUME." {
		t.Fatalf("status: %q", got)
	}
}

// Reconcile answers a replayed activation from saved state.
func TestReconcileAfterReplay(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	if ok, _ := r.a.Tick(ctx); !ok {
		t.Fatal("not applied")
	}
	id := r.intents()[0].Intent.ID
	r.restart()
	if o := r.a.Reconcile(ctx, journal.Intent{ID: id}, 1); o.Result != journal.ResultSucceeded {
		t.Fatalf("%s: %+v", id, o)
	}
	if o := r.a.Reconcile(ctx, journal.Intent{ID: "upd:apply:1:n99"}, 1); o.Result != journal.ResultNotApplied {
		t.Fatalf("unknown attempt: %+v", o)
	}
	if !strings.Contains(r.a.Status(), "installing") {
		t.Fatalf("same boot after a broker restart: %q", r.a.Status())
	}
}

func TestCryptoRandStaysInRange(t *testing.T) {
	for _, n := range []int64{-1, 0, 1, 7, int64(6 * time.Hour)} {
		for i := 0; i < 50; i++ {
			v := cryptoRand(n)
			if n <= 0 && v != 0 || n > 0 && (v < 0 || v >= n) {
				t.Fatalf("cryptoRand(%d) = %d", n, v)
			}
		}
	}
}
