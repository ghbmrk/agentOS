package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-1, UPD-1a, UPD-5, UPD-6
//
// Update apply, broker side (UPD-a): a verified release the change
// pipeline staged is handed to the A/B activator by a kernel plan step
// whose logged result is the rollback point, only outside a call, accepted work and the
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
	ps := r.plans()
	if len(ps) != 1 || ps[0].Status != kernel.SDone || ps[0].Plan.Steps[0].Verb != "change-account" ||
		ps[0].Plan.Steps[0].Args[ArgRoot] != strings.Repeat("0f", 32) {
		t.Fatalf("plans: %+v", ps)
	}
	// The rollback point is the step's logged result: the release it
	// replaces and the one it activates, each with its /usr root hash
	// (UPD-1a, UPD-6).
	want := fmt.Sprintf("rollback point: release 0 on root %s; activating release 1 on root %s",
		strings.Repeat(oldHash, 32), strings.Repeat("0f", 32))
	if d := ps[0].Steps[0].Detail; d != want {
		t.Fatalf("logged result %q, want %q", d, want)
	}
	if st, ok, _ := r.store.Staged(); !ok || st.Version != 1 {
		t.Fatal("not staged before the restart")
	}
	// Restarted, before Resume settles it: no restart is promised (#3829).
	if got := r.a.Status(); got != "Update 1 may have started already. Nothing is needed from you." {
		t.Fatalf("status: %q", got)
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
		{func(b bool) { r.working = b }, "Update 1 will install once my current task is done."},
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
	if len(r.act.installed) != 0 || len(r.plans()) != 0 {
		t.Fatal("handed over while busy")
	}
	// A call that starts between the submission and the dispatch stops
	// it: the clerk re-checks the box before it acts (CLK-2).
	r.hold = true
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("held tick: %v %v", ok, err)
	}
	r.hold, r.inCall = false, true
	r.tick()
	if ps := r.plans(); len(ps) != 1 || ps[0].Status != kernel.SFailed || len(r.act.installed) != 0 {
		t.Fatalf("dispatched during a call: %+v", ps)
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
// the kernel log, root metadata (key revocations), the installed record.
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
	before := len(r.k.Log().Entries())
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
	if ps := r.plans(); len(ps) != 1 || ps[0].Status != kernel.SDone || len(r.k.Log().Entries()) != before {
		t.Fatalf("kernel log changed: %+v", ps)
	}
	// UX-133-2: in STATUS until the next update installs, and once in
	// the digest.
	want := "Update 1 did not start cleanly, so I went back to the version I had. Nothing is needed from you. It won't be tried again; a later update will replace it."
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
	r.act.restartErr = errors.New("no restart yet")
	if ok, err := r.a.Tick(ctx); !ok || err == nil || len(r.act.installed) != 1 {
		t.Fatalf("not handed over: %v %v", ok, err)
	}
	r.act.restartErr = nil
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

// A failed install's error can name a host path. The logged result must not.
func TestAFailedInstallRecordsNoHostPath(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	canary := "/var/lib/agentos/slots/b"
	r.act.installErr = errors.New("write " + canary + ": permission denied")
	if ok, _ := r.a.Tick(ctx); ok {
		t.Fatal("installed")
	}
	ps := r.plans()
	if len(ps) != 1 || ps[0].Status != kernel.SFailed {
		t.Fatalf("plans %+v", ps)
	}
	ev := ps[0].Steps[0].Detail
	if strings.Contains(ev, canary) || strings.Contains(ev, "/var/") {
		t.Fatalf("evidence %q", ev)
	}
}

func TestScheduleRefusesAnUnverifiedRelease(t *testing.T) {
	r := newRig(t)
	r.release(1, true)
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

// An ordinary release: a security fix fails closed after a process
// restart instead (SR3-4f-2c).
func TestBrokerStoppedBeforeTheRestartRestartsLater(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, false), "a1"))
	r.clk.add(6 * time.Hour) // past its jitter
	r.act.restartErr = errors.New("stopped")
	if ok, err := r.a.Tick(ctx); !ok || err == nil || len(r.act.installed) != 1 {
		t.Fatalf("not handed over: %v %v", ok, err)
	}
	r.act.restartErr = nil
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
	rel := r.release(1, false) // a security fix fails closed after a process restart (SR3-4f-2c)
	r.act0 = slowActivator{r.act, func() { r.stopped = true }}
	r.restart()
	r.must(r.a.Schedule(rel, "a1"))
	r.clk.add(7 * time.Hour) // past the jitter
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

// Probe answers a lost activation from saved state after a process
// restart: done once the activator took it, notdone for a plan never
// handed over (KRN-8).
func TestProbeAfterProcessRestart(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.restartErr = errors.New("stopped")
	if ok, _ := r.a.Tick(ctx); !ok {
		t.Fatal("not applied")
	}
	req := kernel.Request{Plan: r.plans()[0].Plan}
	r.restart()
	if o := r.a.Probe(req, r.k.State()); o.Outcome != "done" || o.Detail != "handed over; restart pending" {
		t.Fatalf("%+v", o)
	}
	req.Plan.ID = "upd:apply:1:n99"
	if o := r.a.Probe(req, r.k.State()); o.Outcome != "notdone" {
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
