package locks_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/locks"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: NET-6

// config is r's gate config over driver d and alerts a.
func config(r *rig, d locks.Driver, a locks.Alerts) locks.Config {
	return locks.Config{
		Owner: r.phone.public(), Driver: d, Alerts: a, Zone: zone, Now: r.clock.Now,
		Codes: func(string, string) ([]byte, error) { return []byte(plumberPIN), nil },
		Log:   func(s string) { r.mu.Lock(); r.log = append(r.log, s); r.mu.Unlock() },
	}
}

// logCount is how many of r's log lines hold sub.
func logCount(r *rig, sub string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, l := range r.log {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// ctxDriver is the fake radio, keeping the context of every Lock and
// SetCodes call.
type ctxDriver struct {
	*radio
	mu   sync.Mutex
	ctxs []context.Context
}

func (d *ctxDriver) keep(ctx context.Context) {
	d.mu.Lock()
	d.ctxs = append(d.ctxs, ctx)
	d.mu.Unlock()
}

func (d *ctxDriver) Lock(ctx context.Context, device string) error {
	d.keep(ctx)
	return d.radio.Lock(ctx, device)
}

func (d *ctxDriver) SetCodes(ctx context.Context, device string, codes []locks.Code) error {
	d.keep(ctx)
	return d.radio.SetCodes(ctx, device, codes)
}

// A gate refuses a config missing any part, and reads the wall clock when
// none is given.
func TestNewRefusesIncompleteConfig(t *testing.T) {
	r := newRig(t, at(10, 0))
	for name, cut := range map[string]func(*locks.Config){
		"owner":  func(c *locks.Config) { c.Owner = key.PublicKey{} },
		"driver": func(c *locks.Config) { c.Driver = nil },
		"alerts": func(c *locks.Config) { c.Alerts = nil },
		"codes":  func(c *locks.Config) { c.Codes = nil },
		"zone":   func(c *locks.Config) { c.Zone = nil },
		"log":    func(c *locks.Config) { c.Log = nil },
	} {
		c := config(r, r.radio, &alerts{})
		cut(&c)
		if g, err := locks.New(c); err == nil {
			g.Close()
			t.Errorf("a config without its %s was taken", name)
		}
	}
	c := config(r, r.radio, &alerts{})
	c.Now = nil
	g, err := locks.New(c)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	h := policy.Hours{From: 7, To: 22}
	before := locks.Unusual(time.Now(), zone, h)
	got := g.Unusual(policy.Device{ID: "front", Class: policy.ClassLock, UsualHours: &h})
	after := locks.Unusual(time.Now(), zone, h)
	if got != before && got != after {
		t.Errorf("a gate with no clock read unusual=%v, the wall clock %v", got, before)
	}
}

// Close stops the teller: an alert told after it is never raised.
func TestCloseStopsTeller(t *testing.T) {
	r := newRig(t, at(10, 0))
	a := &alerts{}
	g, err := locks.New(config(r, r.radio, a))
	if err != nil {
		t.Fatal(err)
	}
	g.Tick(r.doc)
	g.WaitWork()
	if err := g.Act(context.Background(), "back", action.Unlock, ""); err != nil {
		t.Fatal(err)
	}
	g.WaitTold()
	a.mu.Lock()
	a.kinds = nil
	a.mu.Unlock()
	g.Close()
	if err := g.Act(context.Background(), "front", action.Unlock, ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.kinds) != 0 {
		t.Errorf("a closed gate raised %v", a.kinds)
	}
}

// The relock is due before the unlock is sent, so an unlock whose answer
// never comes is still relocked on time.
func TestUnlockWithNoAnswerStillRelocks(t *testing.T) {
	r := newRig(t, at(10, 0))
	entered, release := make(chan struct{}), make(chan struct{})
	r.radio.holdAct = func() { close(entered); <-release }
	done := make(chan struct{})
	go func() { r.tap("front", action.Unlock); close(done) }()
	<-entered
	r.clock.add(locks.RelockAfter)
	r.gate.Tick(r.doc)
	r.gate.WaitWork()
	got := count(r.radio.did(), "lock front")
	r.radio.holdAct = nil
	close(release)
	<-done
	if got != 1 {
		t.Errorf("an unlock still on its way was not relocked at its interval: %v", r.radio.did())
	}
}

// After a failed unlock the lock's own report of it is told again, not
// taken as the enforcer's act.
func TestFailedActReportToldOnce(t *testing.T) {
	r := newRig(t, at(10, 0))
	r.radio.actFails = errors.New("link dropped after the write")
	if err := r.tap("front", action.Unlock); err == nil {
		t.Fatal("a failed act reported success")
	}
	if n := countKind(r.alerts.kinds, alert.RoutineUnlock); n != 1 {
		t.Fatalf("the failed unlock was told %d times", n)
	}
	r.gate.Seen(locks.Event{Device: "front", Report: locks.Unlocked})
	r.tick()
	if n := countKind(r.alerts.kinds, alert.RoutineUnlock); n != 2 {
		t.Errorf("the lock's report after a failed unlock was taken as ours: %v", r.alerts.kinds)
	}
}

// A routine disarm is logged only: no alert, and no alert of no kind.
func TestRoutineDisarmLoggedOnly(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("alarm", action.Disarm); err != nil {
		t.Fatal(err)
	}
	r.tick()
	if !r.logged("alarm disarmed.") || len(r.alerts.kinds) != 0 || r.logged("not raised") {
		t.Errorf("a routine disarm: alerts %v, log %v", r.alerts.kinds, r.log)
	}
}

// A second challenge is drawn only for an unlock or a disarm.
func TestSecondOnlyForGatedActs(t *testing.T) {
	r := newRig(t, at(3, 0))
	if _, err := r.gate.Second(r.doc, "alarm", action.Arm); !errors.Is(err, locks.ErrMalformed) {
		t.Errorf("a second challenge for arming: %v", err)
	}
}

// A report from a lock the last Tick's policy did not hold is dropped,
// even when the next Tick's policy holds it.
func TestReportBeforeTickHeldLockDropped(t *testing.T) {
	r := newRig(t, at(10, 0))
	r.doc.Devices = append(r.doc.Devices, policy.Device{ID: "side", Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"})
	r.gate.Seen(locks.Event{Device: "side", Report: locks.Unlocked})
	r.tick()
	if len(r.alerts.kinds) != 0 || !r.logged("1 reports for devices that cannot make them, dropped") {
		t.Errorf("a report before the lock was held: alerts %v, log %v", r.alerts.kinds, r.log)
	}
}

// without is doc with device id removed.
func without(doc policy.Document, id string) policy.Document {
	doc.Devices = slices.DeleteFunc(slices.Clone(doc.Devices), func(d policy.Device) bool { return d.ID == id })
	doc.Standing = slices.DeleteFunc(slices.Clone(doc.Standing), func(s policy.StandingRule) bool { return s.Device == id })
	return doc
}

// A lock the policy drops forgets its relock, and a report from it that
// the policy no longer holds is ignored.
func TestDroppedLockForgotten(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.gate.Seen(locks.Event{Device: "front", Report: locks.Unlocked})
	r.gate.Tick(without(r.doc, "front"))
	r.gate.WaitWork()
	r.clock.add(2 * locks.RelockAfter)
	r.tick()
	if n := count(r.radio.did(), "lock front"); n != 0 {
		t.Errorf("a lock dropped from the policy and back kept its old relock: %v", r.radio.did())
	}
}

// Reports are acted on in device order, so the log reads the same each run.
func TestReportsActedInOrder(t *testing.T) {
	ids := []string{"l1", "l2", "l3", "l4", "l5", "l6", "l7"}
	for range 5 {
		r := newRig(t, at(10, 0))
		for _, id := range ids {
			r.doc.Devices = append(r.doc.Devices, policy.Device{ID: id, Network: policy.NetDevices, Class: policy.ClassLock, Secure: "lock"})
		}
		r.tick()
		for _, id := range slices.Backward(ids) {
			r.gate.Seen(locks.Event{Device: id, Report: locks.Unlocked, Rule: "nobody"})
		}
		r.tick()
		var got []string
		r.mu.Lock()
		for _, l := range r.log {
			if d, ok := strings.CutPrefix(l, "locks: "); ok && strings.Contains(d, "outside its signed window") {
				got = append(got, strings.Fields(d)[0])
			}
		}
		r.mu.Unlock()
		if !slices.Equal(got, ids) {
			t.Fatalf("reports acted on in order %v, want %v", got, ids)
		}
	}
}

// Only a lock gets a keypad-code push.
func TestOnlyLocksGetCodes(t *testing.T) {
	r := newRig(t, at(10, 0))
	r.doc.Devices = append(r.doc.Devices,
		policy.Device{ID: "plug2", Network: policy.NetDevices, Class: policy.ClassPlug, Secure: "off"},
		policy.Device{ID: "alarm2", Network: policy.NetDevices, Class: policy.ClassAlarm})
	r.tick()
	for _, c := range r.radio.did() {
		if strings.HasPrefix(c, "codes plug2") || strings.HasPrefix(c, "codes alarm2") {
			t.Errorf("a device that is not a lock got codes: %v", r.radio.did())
		}
	}
}

// The relock's and the code push's contexts end when their calls return.
func TestDriverContextsEnd(t *testing.T) {
	r := newRig(t, at(10, 0))
	d := &ctxDriver{radio: r.radio}
	g, err := locks.New(config(r, d, &alerts{}))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	g.Tick(r.doc)
	g.WaitWork()
	if err := g.Act(context.Background(), "front", action.Unlock, ""); err != nil {
		t.Fatal(err)
	}
	r.clock.add(locks.RelockAfter)
	g.Tick(r.doc)
	g.WaitWork()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.ctxs) < 3 {
		t.Fatalf("%d driver calls, want code pushes and a relock", len(d.ctxs))
	}
	for i, c := range d.ctxs {
		if c.Err() == nil {
			t.Errorf("driver call %d's context still live after it returned", i)
		}
	}
}

// A failed code push is retried after the wait, logged as the push's own
// failure, and retried even when the codes return to what was last set.
func TestFailedCodePushRetried(t *testing.T) {
	r := newRig(t, at(8, 0))
	r.clock.set(at(9, 0))
	r.radio.fail = errors.New("radio down")
	r.tick()
	r.radio.fail = nil
	if !r.logged("keypad codes on front not set") {
		t.Errorf("a failed push was not logged: %v", r.log)
	}
	r.clock.add(6 * time.Second)
	r.tick()
	if c := r.radio.codesOn("front"); len(c) != 1 || c[0].Rule != "plumber" {
		t.Errorf("after the retry wait the lock holds %+v, want the plumber's code", c)
	}

	r = newRig(t, at(8, 0))
	r.clock.set(at(11, 59))
	r.radio.fail = errors.New("radio down")
	r.tick()
	r.radio.fail = nil
	r.clock.set(at(12, 1))
	n := count(r.radio.did(), "codes front 0")
	r.tick()
	if count(r.radio.did(), "codes front 0") != n+1 {
		t.Errorf("a failed push was not retried when the codes went back: %v", r.radio.did())
	}
}

// A clock that steps back after a good push does not hold up the next.
func TestCodePushAfterClockStepsBack(t *testing.T) {
	r := newRig(t, at(8, 0))
	r.clock.set(at(9, 0))
	r.radio.fail = errors.New("radio down")
	r.tick()
	r.radio.fail = nil
	r.clock.add(6 * time.Second)
	r.tick()
	r.clock.set(at(9, 0))
	r.doc.Standing = append(r.doc.Standing, policy.StandingRule{ID: "cleaner", Device: "front", Action: locks.ActionCode, FromMS: at(8, 30).UnixMilli(), ToMS: at(10, 0).UnixMilli()})
	n := count(r.radio.did(), "codes front 1")
	r.tick()
	if count(r.radio.did(), "codes front 1") != n+1 {
		t.Errorf("the new codes were not pushed after the clock stepped back: %v", r.radio.did())
	}
}

// A relock is told once: the lock's own report of it is the relock.
func TestRelockToldOnce(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.clock.add(locks.RelockAfter)
	r.tick()
	if n := countKind(r.alerts.kinds, alert.RoutineLock); n != 1 {
		t.Fatalf("a relock told %d times", n)
	}
	r.gate.Seen(locks.Event{Device: "front", Report: locks.Locked})
	r.tick()
	if n := countKind(r.alerts.kinds, alert.RoutineLock); n != 1 {
		t.Errorf("the relock's own report was told again: %v", r.alerts.kinds)
	}
}

// A failed relock waits retryAfter, is logged once until one succeeds, and
// logged again on the next failure after that.
func TestFailedRelockWaitsAndLogsOnce(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.clock.add(locks.RelockAfter)
	r.radio.fail = errors.New("no answer")
	r.tick()
	r.clock.add(time.Second)
	r.tick()
	if n := count(r.radio.did(), "lock front"); n != 1 {
		t.Errorf("a failed relock was tried again before the wait: %v", r.radio.did())
	}
	r.clock.add(5 * time.Second)
	r.tick()
	if n := count(r.radio.did(), "lock front"); n != 2 {
		t.Errorf("a failed relock was not tried again after the wait: %v", r.radio.did())
	}
	if n := logCount(r, "relocking front failed"); n != 1 {
		t.Errorf("two failures logged %d times, want once", n)
	}
	r.radio.fail = nil
	r.clock.add(5 * time.Second)
	r.tick()
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.clock.add(locks.RelockAfter)
	r.radio.fail = errors.New("no answer")
	r.tick()
	if n := logCount(r, "relocking front failed"); n != 2 {
		t.Errorf("a failure after a good relock logged %d in all, want 2", n)
	}
}

// An unlock while a relock runs moves the relock to its own interval, not
// to the next tick.
func TestUnlockDuringRelockWaitsItsInterval(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.clock.add(locks.RelockAfter)
	entered, release := make(chan struct{}), make(chan struct{})
	r.radio.afterLock = func() { close(entered); <-release }
	done := make(chan struct{})
	go func() { r.tick(); close(done) }()
	<-entered
	r.radio.afterLock = nil
	r.clock.add(500 * time.Millisecond)
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	r.clock.add(time.Second)
	r.tick()
	if n := count(r.radio.did(), "lock front"); n != 1 {
		t.Errorf("relocked before the second unlock's interval: %v", r.radio.did())
	}
	r.clock.add(locks.RelockAfter)
	r.tick()
	if n := count(r.radio.did(), "lock front"); n != 2 {
		t.Errorf("not relocked at the second unlock's interval: %v", r.radio.did())
	}
}
