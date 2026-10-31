package locks_test

// REQ: NET-6, NET-4, NET-7

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/locks"
	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// A18 Locks: a visitor's keypad code works only inside its signed window.
// The enforcer sets the code on the lock only while the window is open,
// with the window as the lock's own schedule, and removes it when the
// window ends. Catches a code left on the lock, or set early.
func TestVisitorCodeOnlyInsideWindow(t *testing.T) {
	r := newRig(t, at(8, 59))
	try := func(when time.Time, want bool) {
		t.Helper()
		r.clock.set(when)
		r.tick()
		if _, ok := r.radio.keypad("front", plumberPIN); ok != want {
			t.Errorf("at %s the plumber's code works: %v, want %v", when.Format("15:04"), ok, want)
		}
		r.radio.Lock(context.Background(), "front")
	}
	try(at(8, 59), false)
	if c := r.radio.codesOn("front"); len(c) != 0 {
		t.Errorf("a code on the lock before its window: %+v", c)
	}
	try(at(9, 0), true)
	c := r.radio.codesOn("front")
	if len(c) != 1 || c[0].Rule != "plumber" || c[0].FromMS != at(9, 0).UnixMilli() || c[0].ToMS != at(12, 0).UnixMilli() {
		t.Errorf("the lock's schedule is not the signed window: %+v", c)
	}
	try(at(11, 59), true)
	try(at(12, 0), false)
	if c := r.radio.codesOn("front"); len(c) != 0 {
		t.Errorf("the code is still on the lock after its window: %+v", c)
	}
	// The back door's code is never on the front door.
	r.clock.set(at(13, 30))
	r.tick()
	if _, ok := r.radio.keypad("front", walkerPIN); ok {
		t.Error("the back door's code opens the front door")
	}
	if _, ok := r.radio.keypad("back", walkerPIN); !ok {
		t.Error("the walker's code does not open the back door inside its window")
	}
	// A code is pushed once per change, not every tick, and a lock whose
	// push failed is tried again.
	n := len(r.radio.did())
	r.tick()
	if len(r.radio.did()) != n {
		t.Errorf("codes pushed again with nothing changed: %v", r.radio.did()[n:])
	}
	// A revoked rule leaves the lock at the next tick.
	r.doc.Standing = r.doc.Standing[:1]
	r.tick()
	if c := r.radio.codesOn("back"); len(c) != 0 {
		t.Errorf("a revoked code is still on the lock: %+v", c)
	}
}

// After a restart the first tick clears any code the enforcer set before,
// so a code revoked while it was down does not stay on the lock.
func TestRestartClearsStaleCodes(t *testing.T) {
	r := newRig(t, at(10, 0))
	r.radio.locks["front"].codes = []locks.Code{{Rule: "old", PIN: []byte("1111"), FromMS: 0, ToMS: at(23, 0).UnixMilli()}}
	r.doc.Standing = nil
	r.tick()
	if c := r.radio.codesOn("front"); len(c) != 0 {
		t.Errorf("a stale code survived the first tick: %+v", c)
	}
}

// A keypad code the store cannot give, or that is not digits, is never
// pushed, and a push that fails is retried.
func TestBadCodeNotPushedAndPushRetried(t *testing.T) {
	r := newRig(t, at(9, 30))
	r.doc.Standing = append(r.doc.Standing, policy.StandingRule{ID: "nobody", Device: "front", Action: locks.ActionCode, FromMS: at(9, 0).UnixMilli(), ToMS: at(10, 0).UnixMilli()})
	r.radio.fail = errors.New("radio down")
	r.tick()
	if !r.logged("not set") {
		t.Error("a failed push was not logged")
	}
	r.radio.fail = nil
	r.clock.add(2 * time.Second)
	r.tick()
	if c := r.radio.codesOn("front"); len(c) != 0 {
		t.Errorf("pushed before the retry wait: %+v", c)
	}
	r.clock.add(5 * time.Second)
	r.tick()
	c := r.radio.codesOn("front")
	if len(c) != 1 || c[0].Rule != "plumber" {
		t.Errorf("after the retry the lock holds %+v, want the plumber's code only", c)
	}
	if !r.logged("no usable keypad code held for rule nobody") {
		t.Error("a rule with no code held was not logged")
	}
}

// A18 Locks: an unlock or disarm at an unusual time is refused without a
// second passkey assertion. Catches one owner tap unlocking a door at
// 3 a.m. (the ENF-s Security finding on #3670).
func TestUnusualTimeNeedsSecondAssertion(t *testing.T) {
	for _, c := range []struct {
		device string
		act    action.Act
		text   alert.Kind
	}{{"front", action.Unlock, alert.UnusualUnlock}, {"alarm", action.Disarm, alert.UnusualDisarm}} {
		t.Run(string(c.act), func(t *testing.T) {
			r := newRig(t, at(3, 0))
			err := r.tap(c.device, c.act)
			if !errors.Is(err, locks.ErrSecond) {
				t.Fatalf("one tap at 03:00: %v, want ErrSecond", err)
			}
			if len(r.radio.did()) != 0 {
				t.Fatalf("one tap reached the radio: %v", r.radio.did())
			}
			if err := r.second(c.device, c.act); err != nil {
				t.Fatal(err)
			}
			if err := r.tap(c.device, c.act); err != nil {
				t.Fatalf("two taps at 03:00: %v", err)
			}
			if !r.alerts.has(c.text) {
				t.Errorf("an unusual-time %s was not texted", c.act)
			}
			// The second assertion works once.
			if err := r.tap(c.device, c.act); !errors.Is(err, locks.ErrSecond) {
				t.Errorf("a second assertion used twice: %v", err)
			}
			// It is for that device and act only.
			if c.act == action.Unlock {
				if err := r.second("front", action.Unlock); err != nil {
					t.Fatal(err)
				}
				if err := r.tap("back", action.Unlock); !errors.Is(err, locks.ErrSecond) {
					t.Errorf("a second assertion for the front door unlocked the back door: %v", err)
				}
			}
			// It expires with its window.
			if err := r.second(c.device, c.act); err != nil {
				t.Fatal(err)
			}
			r.clock.add(action.Window)
			if err := r.tap(c.device, c.act); !errors.Is(err, locks.ErrSecond) {
				t.Errorf("an expired second assertion: %v", err)
			}
		})
	}
	// The hours: 06:59 and 22:00 are unusual, 07:00 and 21:59 are not.
	for _, c := range []struct {
		t    time.Time
		want bool
	}{{at(6, 59), true}, {at(7, 0), false}, {at(21, 59), false}, {at(22, 0), true}, {at(0, 0), true}} {
		if got := locks.Unusual(c.t, zone); got != c.want {
			t.Errorf("Unusual(%s) = %v, want %v", c.t.Format("15:04"), got, c.want)
		}
	}
	// At a usual time one tap is enough.
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Errorf("one tap at 10:00: %v", err)
	}
}

// A18 Locks: a text reply does not stand in for the second assertion.
// Only the owner's passkey over the second challenge counts: a reply's
// words, the first tap's assertion again, a tap over another second
// challenge, or nothing are each refused, and each spends the challenge.
// Catches a SIM swap or a forged reply approving a 3 a.m. unlock.
func TestTextReplyIsNotSecondAssertion(t *testing.T) {
	r := newRig(t, at(2, 30))
	first, err := r.book.Issue(r.doc, "front", action.Unlock, "", r.now())
	if err != nil {
		t.Fatal(err)
	}
	firstSig := r.phone.sign(first.Msg)
	other, err := r.gate.Second(r.doc, "back", action.Unlock)
	if err != nil {
		t.Fatal(err)
	}
	for name, sig := range map[string][]byte{
		"a text reply":      []byte("YES"),
		"the first tap":     firstSig,
		"another challenge": r.phone.sign(other.Msg),
		"nothing":           nil,
	} {
		s, err := r.gate.Second(r.doc, "front", action.Unlock)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.gate.Confirm(s.ID, sig); !errors.Is(err, locks.ErrNotOwner) {
			t.Errorf("%s as the second assertion: %v", name, err)
		}
		if err := r.gate.Confirm(s.ID, r.phone.sign(s.Msg)); !errors.Is(err, locks.ErrGone) {
			t.Errorf("after %s the challenge still works: %v", name, err)
		}
	}
	if _, err := r.book.Redeem(r.doc, first.ID, firstSig, r.now()); !errors.Is(err, locks.ErrSecond) {
		t.Errorf("unlocked at 02:30 with no second assertion: %v", err)
	}
	if r.radio.unlocked("front") || len(r.radio.did()) != 0 {
		t.Errorf("the radio was asked: %v", r.radio.did())
	}
	// A second challenge is only for an unlock or a disarm the device takes.
	for _, c := range []struct {
		device string
		act    action.Act
	}{{"plug", action.Unlock}, {"front", action.Disarm}, {"tv", action.Unlock}, {"front", action.On}, {"gone", action.Unlock}} {
		if _, err := r.gate.Second(r.doc, c.device, c.act); err == nil {
			t.Errorf("a second challenge for %s on %s", c.act, c.device)
		}
	}
}

// A18 Locks: an unlock inside a signed standing rule needs no ask: the
// visitor's code opens the lock inside its window with no tap and no
// text, the enforcer logs it, and the lock still relocks after the
// interval. Catches a standing rule that texts or asks per use.
func TestStandingRuleUnlockNoAsk(t *testing.T) {
	r := newRig(t, at(10, 0))
	r.tick()
	e, ok := r.radio.keypad("front", plumberPIN)
	if !ok {
		t.Fatal("the plumber's code does not open the door inside its window")
	}
	r.gate.Seen(e)
	r.tick()
	if !r.alerts.has(alert.RoutineUnlock) || r.alerts.texts() != 0 {
		t.Errorf("a standing-rule unlock: raised %v, want one log line and no text", r.alerts.kinds)
	}
	r.clock.add(locks.RelockAfter - time.Second)
	r.tick()
	if !r.radio.unlocked("front") {
		t.Error("relocked before the interval")
	}
	r.clock.add(time.Second)
	r.tick()
	if r.radio.unlocked("front") {
		t.Error("not relocked after the interval")
	}
}

// A18 Locks: an unlock outside a signed standing rule is refused. A lock
// that reports a keypad unlock with a rule's code outside its window, or a
// rule for another lock, a rule that is not a code, or one that does not
// exist, is relocked at the next tick, not after the interval. Catches a
// lock or radio that kept a code past its window.
func TestUnlockOutsideRuleRefused(t *testing.T) {
	for name, c := range map[string]struct {
		when time.Time
		rule string
	}{
		"before the window": {at(8, 0), "plumber"},
		"after the window":  {at(12, 0), "plumber"},
		"another lock's":    {at(13, 30), "walker"},
		"no such rule":      {at(10, 0), "ghost"},
		"not a code rule":   {at(10, 0), "hold-open"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, c.when)
			r.doc.Standing = append(r.doc.Standing, policy.StandingRule{ID: "hold-open", Device: "front", Action: "unlock", FromMS: at(9, 0).UnixMilli(), ToMS: at(12, 0).UnixMilli()})
			r.radio.locks["front"].unlocked = true
			r.gate.Seen(locks.Event{Device: "front", Report: locks.Unlocked, Rule: c.rule})
			r.tick()
			if r.radio.unlocked("front") {
				t.Error("an unlock outside its rule was not relocked at once")
			}
			if !r.logged("outside its signed window") {
				t.Error("the refusal was not logged")
			}
		})
	}
	// A page unlock needs a challenge: the gate does nothing for any other
	// act or a route.
	r := newRig(t, at(10, 0))
	for _, a := range []action.Act{action.On, action.Open, action.Arm, action.Fly} {
		if err := r.gate.Act(context.Background(), "front", a, ""); !errors.Is(err, locks.ErrNotLock) {
			t.Errorf("the gate did %s: %v", a, err)
		}
	}
	if err := r.gate.Act(context.Background(), "front", action.Unlock, "route"); !errors.Is(err, locks.ErrNotLock) {
		t.Errorf("the gate took a route: %v", err)
	}
	if len(r.radio.did()) != 0 {
		t.Errorf("the radio was asked: %v", r.radio.did())
	}
}

// A18 Locks: agentOS cannot widen the rule. A widened window, a new code
// rule or a code rule moved to another lock is a loosening (it waits for
// the owner's passkey and 10 minutes), and the gate sets on the lock only
// the window of the policy in force, never one it was handed: Tick takes
// the document in force and nothing else. Catches a core that stretches
// the plumber's window.
func TestCoreCannotWidenRule(t *testing.T) {
	base := fixture()
	widen := map[string]func(d *policy.Document){
		"earlier start": func(d *policy.Document) { d.Standing[0].FromMS = at(8, 0).UnixMilli() },
		"later end":     func(d *policy.Document) { d.Standing[0].ToMS = at(13, 0).UnixMilli() },
		"a new code": func(d *policy.Document) {
			d.Standing = append(d.Standing, policy.StandingRule{ID: "courier", Device: "front", Action: locks.ActionCode, FromMS: at(9, 0).UnixMilli(), ToMS: at(10, 0).UnixMilli()})
		},
		"another lock": func(d *policy.Document) { d.Standing[0].Device = "back" },
	}
	for name, f := range widen {
		next := fixture()
		next.Version++
		f(&next)
		if c := policy.Classify(base, next); c.Tightening {
			t.Errorf("%s classified as a tightening: %+v", name, c)
		}
	}
	// Narrowing stays an asserted tightening (the owner's tap, ENF-a-3).
	narrow := fixture()
	narrow.Version++
	narrow.Standing[0].ToMS = at(11, 0).UnixMilli()
	if c := policy.Classify(base, narrow); !c.Tightening || !c.Owner {
		t.Errorf("narrowing the plumber's code: %+v, want an asserted tightening", c)
	}
	// The lock holds the window in force.
	r := newRig(t, at(9, 30))
	r.tick()
	c := r.radio.codesOn("front")
	if len(c) != 1 || c[0].FromMS != at(9, 0).UnixMilli() || c[0].ToMS != at(12, 0).UnixMilli() {
		t.Errorf("the lock's schedule is not the signed window: %+v", c)
	}
	r.clock.set(at(12, 30))
	r.tick()
	if _, ok := r.radio.keypad("front", plumberPIN); ok {
		t.Error("the plumber's code works past the signed window")
	}
}

// A18 Locks: an unlock assertion replayed, or made for another lock or
// action, is refused, and the lock relocks after an unlock. Catches a tap
// that opens the door twice, or the back door.
func TestReplayedAssertionRefused(t *testing.T) {
	r := newRig(t, at(10, 0))
	c, err := r.book.Issue(r.doc, "front", action.Unlock, "", r.now())
	if err != nil {
		t.Fatal(err)
	}
	sig := r.phone.sign(c.Msg)
	if _, err := r.book.Redeem(r.doc, c.ID, sig, r.now()); err != nil {
		t.Fatal(err)
	}
	r.radio.Lock(context.Background(), "front")
	if _, err := r.book.Redeem(r.doc, c.ID, sig, r.now()); !errors.Is(err, action.ErrGone) {
		t.Errorf("a replayed unlock: %v", err)
	}
	if r.radio.unlocked("front") {
		t.Error("the replay unlocked the door")
	}
	if n := count(r.radio.did(), "unlock front"); n != 1 {
		t.Errorf("the door was unlocked %d times by one tap", n)
	}
}

func TestAssertionForOtherLockOrActionRefused(t *testing.T) {
	r := newRig(t, at(10, 0))
	front, _ := r.book.Issue(r.doc, "front", action.Unlock, "", r.now())
	back, _ := r.book.Issue(r.doc, "back", action.Unlock, "", r.now())
	alarm, _ := r.book.Issue(r.doc, "alarm", action.Disarm, "", r.now())
	arm, _ := r.book.Issue(r.doc, "alarm", action.Arm, "", r.now())
	// The front door's tap on the back door's challenge, and on the alarm's.
	frontSig := r.phone.sign(front.Msg)
	if _, err := r.book.Redeem(r.doc, back.ID, frontSig, r.now()); !errors.Is(err, action.ErrNotOwner) {
		t.Errorf("the front door's tap unlocked the back door: %v", err)
	}
	if _, err := r.book.Redeem(r.doc, alarm.ID, frontSig, r.now()); !errors.Is(err, action.ErrNotOwner) {
		t.Errorf("an unlock tap disarmed the alarm: %v", err)
	}
	if _, err := r.book.Redeem(r.doc, arm.ID, r.phone.sign(alarm.Msg), r.now()); !errors.Is(err, action.ErrNotOwner) {
		t.Errorf("a disarm tap armed the alarm: %v", err)
	}
	// A second assertion is not an action tap either.
	s, _ := r.gate.Second(r.doc, "front", action.Unlock)
	if _, err := r.book.Redeem(r.doc, front.ID, r.phone.sign(s.Msg), r.now()); !errors.Is(err, action.ErrNotOwner) {
		t.Errorf("a second assertion stood in for the first: %v", err)
	}
	if len(r.radio.did()) != 0 {
		t.Errorf("the radio was asked: %v", r.radio.did())
	}
	// A lock takes no other act; a plug takes no unlock.
	for _, c := range []struct {
		device string
		act    action.Act
	}{{"front", action.On}, {"front", action.Open}, {"front", action.Disarm}, {"plug", action.Unlock}} {
		if _, err := r.book.Issue(r.doc, c.device, c.act, "", r.now()); !errors.Is(err, action.ErrRefused) {
			t.Errorf("a challenge for %s on %s: %v", c.act, c.device, err)
		}
	}
}

// A18 Locks: the lock relocks after the interval, whoever unlocked it: the
// owner's tap, its own key or keypad, or a report from nowhere (the vendor
// app, or a radio process misusing its keys). A relock that fails is
// tried again. A report of "locked" never cancels a relock, since the
// radio is untrusted. Catches a door left open by a compromised stack.
func TestRelocksAfterInterval(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.gate.Seen(locks.Event{Device: "front", Report: locks.Locked}) // a lie
	r.clock.add(locks.RelockAfter - time.Millisecond)
	r.tick()
	if !r.radio.unlocked("front") {
		t.Fatal("relocked early")
	}
	r.clock.add(time.Millisecond)
	r.radio.fail = errors.New("radio down")
	r.tick()
	r.radio.fail = nil
	if !r.radio.unlocked("front") || !r.logged("relocking front failed") {
		t.Fatal("a failed relock was not logged")
	}
	r.clock.add(5 * time.Second)
	r.tick()
	if r.radio.unlocked("front") {
		t.Error("a failed relock was not tried again")
	}
	// An unlock the enforcer only sees.
	r.radio.locks["back"].unlocked = true
	r.gate.Seen(locks.Event{Device: "back", Report: locks.Unlocked})
	r.tick()
	r.clock.add(locks.RelockAfter)
	r.tick()
	if r.radio.unlocked("back") {
		t.Error("an unlock by the vendor app or a key was not relocked")
	}
	// A flood of reports is dropped and every lock relocks at once.
	r.radio.locks["front"].unlocked, r.radio.locks["back"].unlocked = true, true
	for i := 0; i < locks.MaxEvents+1; i++ {
		r.gate.Seen(locks.Event{Device: "tv", Report: locks.Unlocked})
	}
	r.tick()
	if r.radio.unlocked("front") || r.radio.unlocked("back") || !r.logged("too many reports") {
		t.Error("a flood of reports did not relock every lock")
	}
	// The relock is due before the unlock is sent, so an unlock whose
	// answer never came is still relocked.
	r2 := newRig(t, at(10, 0))
	r2.radio.fail = errors.New("no answer")
	if err := r2.tap("front", action.Unlock); !errors.Is(err, action.ErrUnsure) {
		t.Fatalf("an unanswered unlock: %v", err)
	}
	r2.radio.fail = nil
	r2.clock.add(locks.RelockAfter)
	r2.tick()
	if got := r2.radio.did(); count(got, "lock front") != 1 {
		t.Errorf("an unanswered unlock was not relocked: %v", got)
	}
}

// A18 Locks: a routine unlock is logged, not texted; an unusual-time
// unlock the enforcer only sees (a key at 3 a.m.) is texted. The enforcer's
// own unlock is told once, not again when the lock reports it.
func TestRoutineUnlockLoggedNotTexted(t *testing.T) {
	r := newRig(t, at(10, 0))
	if err := r.tap("front", action.Unlock); err != nil {
		t.Fatal(err)
	}
	r.gate.Seen(locks.Event{Device: "front", Report: locks.Unlocked})
	r.tick()
	r.gate.Seen(locks.Event{Device: "back", Report: locks.Unlocked})
	r.tick()
	if r.alerts.texts() != 0 {
		t.Errorf("a routine unlock was texted: %v", r.alerts.kinds)
	}
	if n := countKind(r.alerts.kinds, alert.RoutineUnlock); n != 2 {
		t.Errorf("logged %d routine unlocks, want 2 (the tap once, the key once): %v", n, r.alerts.kinds)
	}
	if err := r.tap("alarm", action.Disarm); err != nil || !r.logged("alarm disarmed.") || r.alerts.texts() != 0 {
		t.Errorf("a routine disarm: %v, texts %d", err, r.alerts.texts())
	}
	r.clock.set(at(3, 0).Add(24 * time.Hour)) // the next night
	r.gate.Seen(locks.Event{Device: "back", Report: locks.Unlocked})
	r.gate.Seen(locks.Event{Device: "alarm", Report: locks.Disarmed})
	r.tick()
	if !r.alerts.has(alert.UnusualUnlock) || !r.alerts.has(alert.UnusualDisarm) {
		t.Errorf("an unusual-time unlock or disarm seen was not texted: %v", r.alerts.kinds)
	}
	// A report for a device that cannot make it is dropped.
	before := len(r.alerts.kinds)
	for _, e := range []locks.Event{{Device: "plug", Report: locks.Unlocked}, {Device: "front", Report: locks.Disarmed}, {Device: "alarm", Report: locks.Unlocked}, {Device: "tv", Report: locks.Unlocked}, {Device: "front", Report: 9}, {Device: "no such", Report: locks.Unlocked}} {
		r.gate.Seen(e)
	}
	r.tick()
	if len(r.alerts.kinds) != before {
		t.Errorf("a report from the wrong device was told: %v", r.alerts.kinds[before:])
	}
}

// A18 Locks: a frozen device is isolated with outbound access cut to its
// list. A Wi-Fi lock whose firmware the owner froze keeps no pair path
// and reaches only its allow list, while the enforcer still relocks it.
// Catches a frozen lock left open to the house.
func TestFrozenDeviceIsolated(t *testing.T) {
	doc := fixture()
	doc.Devices = append(doc.Devices,
		policy.Device{ID: "gate", Network: policy.NetDevices, WiFi: "vlan120", Class: policy.ClassLock, Secure: "lock", Allow: []string{"gate.example"}, VendorCloud: true},
		policy.Device{ID: "phone", Network: policy.NetOwner},
	)
	doc.Pairs = []policy.Pair{{A: "gate", B: "phone"}}
	layout := nft.Layout{
		WAN: "wan0", Owner: "own0", Household: "hh0", Guests: "gst0", Admin: "adm0",
		Core: "core0", Edge: "edge0", Trunk: "ap0", APMgmt: "apm0",
		APAdmin:     []netip.Addr{netip.MustParseAddr("10.70.0.2")},
		ISP:         []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		EdgeGateway: netip.MustParseAddr("10.60.0.1"),
		PagePort:    8443, ChannelPort: 7443, CorePagePort: 443,
	}
	open, err := nft.Paths(doc, layout)
	if err != nil {
		t.Fatal(err)
	}
	if len(open) == 0 {
		t.Fatal("the fixture's pair has no path before the freeze")
	}
	frozen := doc
	frozen.Holds = []policy.Hold{{Device: "gate", Kind: policy.HoldFirmware}}
	if !frozen.Unpatched("gate") || frozen.Linked("gate") {
		t.Error("a frozen lock still counts as patched or linked")
	}
	paths, err := nft.Paths(frozen, layout)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if p.From == "ap0.120" || p.To == "ap0.120" {
			t.Errorf("a path with the frozen lock: %+v", p)
		}
	}
	sets, err := nft.AllowSets(frozen, layout)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range sets {
		if s.Set4 == nft.DeviceSet(120, false) {
			found = true
			if len(s.Names) != 1 || s.Names[0] != "gate.example" {
				t.Errorf("the frozen lock reaches %v, want its list", s.Names)
			}
		}
	}
	if !found {
		t.Error("the frozen lock has no allow set")
	}
	// The enforcer still relocks a frozen lock.
	r := newRig(t, at(10, 0))
	r.doc = frozen
	r.radio.locks["gate"] = &fakeLock{unlocked: true}
	r.gate.Seen(locks.Event{Device: "gate", Report: locks.Unlocked})
	r.tick()
	r.clock.add(locks.RelockAfter)
	r.tick()
	if r.radio.unlocked("gate") {
		t.Error("a frozen lock was not relocked")
	}
}

func count(calls []string, want string) int {
	n := 0
	for _, c := range calls {
		if c == want {
			n++
		}
	}
	return n
}

func countKind(ks []alert.Kind, want alert.Kind) int {
	n := 0
	for _, k := range ks {
		if k == want {
			n++
		}
	}
	return n
}
