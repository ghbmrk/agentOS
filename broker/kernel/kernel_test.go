package kernel_test

// REQ: KRN-1, KRN-4, KRN-5, KRN-6, KRN-7, KRN-8, LOG-2, LOG-5, CLK-2, KEY-8

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const hour = int64(3_600_000)

type pair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func gen(seed byte) pair {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	p := ed25519.NewKeyFromSeed(s)
	return pair{p.Public().(ed25519.PublicKey), p}
}

type rig struct {
	t      *testing.T
	owner  pair
	holder pair
	head   pair
	store  *kernel.MemStore
	anchor *kernel.MemAnchor
	mail   *clerk.Mail
	k      *kernel.Kernel
	root   key.Key
}

func cfg(r *rig) kernel.Config {
	return kernel.Config{Store: r.store, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv,
		Rand: rand.NewChaCha8([32]byte{1})}
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, owner: gen(1), holder: gen(2), head: gen(3), store: &kernel.MemStore{}, anchor: &kernel.MemAnchor{}}
	r.mail = clerk.NewMail("mail", r.owner.pub)
	r.boot(0)
	r.root = key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "mail",
		Verbs: []key.Verb{key.Organize, key.Trash, key.Unsubscribe}, Serial: "r1"})
	must(t, r.k.Issue(0, r.root))
	must(t, r.k.Log().Anchor())
	return r
}

func (r *rig) boot(now int64) {
	l, err := kernel.Open(cfg(r))
	must(r.t, err)
	r.k, err = kernel.Boot(l, r.owner.pub, map[string]kernel.Clerk{"mail": r.mail}, now)
	must(r.t, err)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (r *rig) derive(c ...key.Caveat) key.Key {
	k, err := key.Derive(r.root, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return k
}

func st(v key.Verb, to string) key.Step {
	s := key.Step{Verb: v, Clerk: "mail", Args: map[string]key.Arg{}}
	for _, n := range key.ArgNames(v) {
		s.Args[n] = key.Arg{Value: to}
	}
	return s
}

func (r *rig) plan(id string, k key.Key, steps ...key.Step) {
	r.t.Helper()
	must(r.t, r.k.Submit(0, kernel.Plan{ID: id, Key: k, Steps: steps}))
}

func (r *rig) status(id string) string { return r.k.State().Plans[id].Status }

func TestReversibleStepRunsOnceAndReplayMatches(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Trash, "m1"), st(key.Organize, "m2"))
	must(t, r.k.Tick(10))
	must(t, r.k.Tick(20))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 2 {
		t.Fatalf("status %s effects %d", r.status("p1"), len(r.mail.Effects()))
	}
	re, err := kernel.Replay(r.owner.pub, r.k.Log().Entries())
	must(t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		t.Fatal("replay differs from the live state (KRN-1)")
	}
}

func TestPlannerArgIsRefusedWholePlanRejected(t *testing.T) {
	r := newRig(t)
	one := int64(1)
	k := r.derive(key.LimitArg(key.ArgBound{Name: "msg", Min: &one}))
	bad := st(key.Draft, "5")
	bad.Args["msg"] = key.Arg{Value: "5", Source: key.SrcPlanner}
	r.plan("p1", k, st(key.Organize, "9"), bad)
	if r.status("p1") != kernel.SRejected || len(r.mail.Effects()) != 0 {
		t.Fatal("a refused step must reject the whole plan before any step runs (KRN-5)")
	}
}

func TestUnknownRootRejected(t *testing.T) {
	r := newRig(t)
	other := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "never-logged"})
	r.plan("p1", other, st(key.Trash, "m1"))
	if r.status("p1") != kernel.SRejected {
		t.Fatal("a root not in the log must not authorize (KEY-1)")
	}
}

func TestHoldWindowThenNoveltyWindow(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, 4*hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Tick(0))
	must(t, r.k.Tick(4*hour-1))
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a novel irreversible step ran inside its window (KEY-8)")
	}
	must(t, r.k.Tick(4*hour))
	if len(r.mail.Effects()) != 1 {
		t.Fatal("step did not run after its window")
	}
	// the same shape to the same recipient, a day on, is known: the base window applies
	must(t, r.k.Submit(30*hour, kernel.Plan{ID: "p2", Key: k, Steps: []key.Step{st(key.Unsubscribe, "list-a")}}))
	must(t, r.k.Tick(30*hour))
	must(t, r.k.Tick(31*hour))
	if len(r.mail.Effects()) != 2 {
		t.Fatalf("known shape should wait only the base window, effects %d", len(r.mail.Effects()))
	}
	// a new recipient is a new shape: the novelty window applies (KEY-8)
	must(t, r.k.Submit(32*hour, kernel.Plan{ID: "p3", Key: k, Steps: []key.Step{st(key.Unsubscribe, "list-b")}}))
	must(t, r.k.Tick(32*hour))
	must(t, r.k.Tick(35*hour))
	if len(r.mail.Effects()) != 2 {
		t.Fatal("a new recipient ran inside the novelty window")
	}
	must(t, r.k.Tick(36*hour))
	if len(r.mail.Effects()) != 3 {
		t.Fatal("a new recipient did not run after the novelty window")
	}
}

func TestRevokeDuringHoldCancelsWithNoEffect(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Tick(0))
	v, err := key.Verify(k, r.owner.pub)
	must(t, err)
	must(t, r.k.Revoke(10, v.IDs[len(v.IDs)-1]))
	must(t, r.k.Tick(2*hour))
	if r.status("p1") != kernel.SCancelled || len(r.mail.Effects()) != 0 {
		t.Fatalf("status %s effects %d", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestPauseWaitsStopCancels(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	v, _ := key.Verify(k, r.owner.pub)
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Tick(0))
	must(t, r.k.Pause(1, v.ID()))
	must(t, r.k.Tick(2*hour))
	if r.status("p1") != kernel.SActive || len(r.mail.Effects()) != 0 {
		t.Fatal("a paused key must wait")
	}
	must(t, r.k.Unpause(2*hour+1, v.ID()))
	must(t, r.k.Stop(2*hour+2))
	must(t, r.k.Tick(3*hour))
	if r.status("p1") != kernel.SCancelled || len(r.mail.Effects()) != 0 {
		t.Fatal("stop must cancel the plan with no effect (KRN-6)")
	}
}

func TestLostAckIsProbedAndDoneOnce(t *testing.T) {
	r := newRig(t)
	r.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" {
			return clerk.FaultLostAck
		}
		return ""
	}
	r.plan("p1", r.root, st(key.Trash, "m1"))
	must(t, r.k.Tick(0))
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("a lost answer must leave the step unknown")
	}
	must(t, r.k.Tick(kernel.ProbeEvery-1))
	must(t, r.k.Tick(kernel.ProbeEvery))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("status %s effects %d (KRN-8)", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestDroppedStepIsRedoneWithoutSecondCharge(t *testing.T) {
	r := newRig(t)
	drops := 1
	r.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" && drops > 0 {
			drops--
			return clerk.FaultDrop
		}
		return ""
	}
	k := r.derive(key.LimitUses(1))
	r.plan("p1", k, st(key.Trash, "m1"))
	must(t, r.k.Tick(0))
	must(t, r.k.Tick(kernel.ProbeEvery))
	must(t, r.k.Tick(kernel.ProbeEvery+1))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("status %s effects %d: a redo must not be refused by its own charge", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestParkedAfterTenUnknownChecks(t *testing.T) {
	r := newRig(t)
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultDrop }
	r.plan("p1", r.root, st(key.Trash, "m1"))
	for i := int64(0); i <= kernel.MaxChecks+1; i++ {
		must(t, r.k.Tick(i*kernel.ProbeEvery))
	}
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PParked || len(r.mail.Effects()) != 0 {
		t.Fatal("ten unknown checks must park the step (KRN-8)")
	}
}

func TestSameEffectWithinADayNeedsFreshKey(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Tick(0))
	r.plan("p2", r.root, st(key.Unsubscribe, "list-a"))
	if r.status("p2") != kernel.SRejected {
		t.Fatal("the same irreversible effect within 24h must be refused (KRN-8)")
	}
}

func TestRestartAfterDispatchBeforeResultProbes(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Trash, "m1"))
	must(t, r.k.Tick(0))
	cutLast(t, r.store, 1) // the result never reached disk; the effect did
	r.boot(1)
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("an in-flight step must come back unknown")
	}
	must(t, r.k.Tick(1+kernel.ProbeEvery))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("status %s effects %d", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestPendingPlanIsDecidedAtBoot(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Trash, "m1"))
	cutLast(t, r.store, 1) // decision lost
	r.boot(1)
	if r.status("p1") != kernel.SActive {
		t.Fatalf("status %s", r.status("p1"))
	}
}

func TestOwnerCancelAndUndo(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Cancel(1, "p1"))
	if r.status("p1") != kernel.SCancelled {
		t.Fatal("cancel")
	}
	r.plan("p2", r.root, st(key.Trash, "m1"))
	must(t, r.k.Tick(2))
	must(t, r.k.Undo(3, "p2", 0))
	if !r.k.State().Plans["p2"].Steps[0].Undone {
		t.Fatal("undo")
	}
}

func TestDuplicatePlanIDRefused(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Trash, "m1"))
	if err := r.k.Submit(0, kernel.Plan{ID: "p1", Key: r.root, Steps: []key.Step{st(key.Trash, "m2")}}); !errors.Is(err, kernel.ErrDuplicatePlan) {
		t.Fatal(err)
	}
}

// cutLast removes the last n sealed frames from a store, as a crash would.
func cutLast(t *testing.T, s *kernel.MemStore, n int) {
	t.Helper()
	var ends []int
	for off := 0; off < len(s.B); {
		off += 4 + int(binary.BigEndian.Uint32(s.B[off:]))
		ends = append(ends, off)
	}
	must(t, s.Truncate(ends[len(ends)-1-n]))
}

// Log.

func TestLogReopensIdentical(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Trash, "m1"))
	must(t, r.k.Tick(1))
	before := r.k.Log().Entries()
	r.boot(2)
	if !kernel.Same(before, r.k.Log().Entries()[:len(before)]) {
		t.Fatal("reopen changed history")
	}
}

func TestLogTamperTruncationForkTorn(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.root, st(key.Trash, "m1"))
	must(t, r.k.Tick(1))
	must(t, r.k.Log().Anchor())
	good := append([]byte(nil), r.store.B...)

	flip := append([]byte(nil), good...)
	flip[len(flip)/2] ^= 1
	if _, err := kernel.Open(withStore(r, &kernel.MemStore{B: flip})); !errors.Is(err, kernel.ErrCorrupt) {
		t.Fatalf("tamper: %v", err)
	}

	short := &kernel.MemStore{B: good[:len(good)/2]}
	if _, err := kernel.Open(withStore(r, short)); !errors.Is(err, kernel.ErrTruncated) {
		t.Fatalf("truncated below the anchor: %v", err)
	}

	// a different history of the same length
	f := newRig(t)
	f.plan("other", f.root, st(key.Organize, "zzz"))
	must(t, f.k.Tick(1))
	c := cfg(r)
	c.Store = f.store
	if l, err := kernel.Open(c); err == nil && l.Len() >= int(r.anchor.H.Seq) {
		t.Fatal("a forked history must not open against the anchor (LOG-2)")
	}

	torn := &kernel.MemStore{B: append(append([]byte(nil), good...), 0, 0, 1, 0, 9, 9)}
	l, err := kernel.Open(withStore(r, torn))
	must(t, err)
	if len(torn.B) != len(good) || l.Len() != len(r.k.Log().Entries()) {
		t.Fatal("a torn final frame must be trimmed")
	}
}

func withStore(r *rig, s kernel.Store) kernel.Config {
	c := cfg(r)
	c.Store = s
	return c
}

func TestUnanchoredWideningIsDroppedButDispatchIsKept(t *testing.T) {
	r := newRig(t) // root issue is anchored
	r.plan("p1", r.root, st(key.Trash, "m1"))
	must(t, r.k.Tick(1))
	must(t, r.k.Stop(2))
	n := r.k.Log().Len()
	must(t, r.k.Resume(3)) // widening, no anchor after it
	r.boot(4)
	if !r.k.State().Stopped || r.k.Log().Len() != n {
		t.Fatal("an unconfirmed resume must not count after restart (KRN-7)")
	}
	must(t, r.k.Resume(5))
	must(t, r.k.Log().Anchor())
	r.boot(6)
	if r.k.State().Stopped {
		t.Fatal("an anchored resume must stand")
	}
	if r.status("p1") != kernel.SDone {
		t.Fatal("dispatch and result entries must never be dropped (KRN-8)")
	}
}

func TestEntryTypesAreClosed(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.Log().Append(0, "mystery", 1, struct{}{}); !errors.Is(err, kernel.ErrUnknown) {
		t.Fatal("unknown type must be refused (LOG-5)")
	}
	if _, err := r.k.Log().Append(0, kernel.TStop, 2, struct{}{}); !errors.Is(err, kernel.ErrUnknown) {
		t.Fatal("unknown version must be refused (LOG-5)")
	}
}

// REQ: KRN-8
func TestCancelledPlanStillReconcilesAndBlocksDuplicate(t *testing.T) {
	r := newRig(t)
	probeDown := true
	r.mail.Fault = func(op string, _ kernel.Request) string {
		switch {
		case op == "do":
			return clerk.FaultLostAck
		case op == "probe" && probeDown:
			return clerk.FaultFail
		}
		return ""
	}
	r.plan("p1", r.root, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Tick(0))
	must(t, r.k.Cancel(1, "p1"))
	must(t, r.k.Tick(kernel.ProbeEvery))
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("the unknown step must stay unknown while the probe is unanswered")
	}
	r.plan("p2", r.root, st(key.Unsubscribe, "list-a"))
	must(t, r.k.Tick(kernel.ProbeEvery+1))
	if r.status("p2") == kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("a cancelled plan's unreconciled effect must block the same effect (KRN-8): p2 %s effects %d", r.status("p2"), len(r.mail.Effects()))
	}
	probeDown = false
	must(t, r.k.Tick(2*kernel.ProbeEvery+2))
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PDone {
		t.Fatal("a cancelled plan must still settle its unknown step by probing")
	}
}

// REQ: KEY-2, KRN-3
func TestPlannerCannotAttestArgSourceTaskRecipientOrAmount(t *testing.T) {
	r := newRig(t)
	one := int64(1)
	k := r.derive(key.LimitArg(key.ArgBound{Name: "msg", Min: &one}))
	s := st(key.Draft, "5")
	s.Args["msg"] = key.Arg{Value: "5", Source: key.SrcClerk}
	r.plan("p1", k, s)
	if r.status("p1") != kernel.SRejected || len(r.mail.Effects()) != 0 {
		t.Fatal("a planner-written source must not satisfy an argument bound (KEY-2)")
	}
	spend := r.derive(key.LimitSpendTask(100))
	big := st(key.Buy, "7")
	big.Args["amount"] = key.Arg{Value: "500"}
	big.Amount, big.Task, big.Recipient = 0, "other", "elsewhere"
	r.plan("p2", spend, big)
	if r.status("p2") != kernel.SRejected {
		t.Fatal("a planner-set amount field must not hide the amount argument (KRN-3)")
	}
	odd := st(key.Buy, "8")
	odd.Args["amount"] = key.Arg{Value: "lots"}
	r.plan("p3", spend, odd)
	if r.status("p3") != kernel.SRejected {
		t.Fatal("an unreadable amount must be refused")
	}
	r.plan("p4", spend, func() key.Step { x := st(key.Trash, "9"); x.Task = "forged"; return x }())
	got := r.k.State().Plans["p4"].Plan.Steps[0]
	if got.Task != "p4" || got.Recipient != "9" {
		t.Fatalf("task and recipient are derived, got %q %q", got.Task, got.Recipient)
	}
}

// The guards read only a verb's declared arguments, so none of them moves by
// adding, renaming or dropping one (KRN-8, KEY-8, KEY-2).
func TestUndeclaredOrMissingArgumentsRejectThePlan(t *testing.T) {
	r := newRig(t)
	spend := r.derive(key.LimitSpendTask(10))
	extra := st(key.Unsubscribe, "list-a")
	extra.Args["note"] = key.Arg{Value: "again"}
	renamed := key.Step{Verb: key.Send, Clerk: "mail", Args: map[string]key.Arg{"list": {Value: "x"}, "msg": {Value: "x"}}}
	price := st(key.Buy, "shop")
	delete(price.Args, "amount")
	price.Args["price"] = key.Arg{Value: "100000"}
	missing := st(key.Send, "x")
	delete(missing.Args, "to")
	for name, s := range map[string]key.Step{"extra": extra, "renamed": renamed, "price": price, "missing": missing} {
		k := r.root
		if name == "price" {
			k = spend
		}
		r.plan("p-"+name, k, s)
		if r.status("p-"+name) != kernel.SRejected {
			t.Fatalf("%s: a step off its verb's argument list must reject the plan", name)
		}
	}
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a rejected plan must have no effect")
	}
}

// REQ: KRN-8
func TestAmountHasOneSpellingSoDuplicateGuardHolds(t *testing.T) {
	r := newRig(t)
	buy := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "r2"})
	must(t, r.k.Issue(0, buy))
	step := func(amount string) key.Step {
		s := st(key.Buy, "shop")
		s.Args["amount"] = key.Arg{Value: amount}
		return s
	}
	r.plan("p1", buy, step("10"))
	must(t, r.k.Tick(0))
	for i, a := range []string{"10", "010", "+10", "-0"} {
		id := "q" + string(rune('a'+i))
		r.plan(id, buy, step(a))
		if r.status(id) != kernel.SRejected {
			t.Fatalf("amount %q repeated within 24h must be refused", a)
		}
	}
	if len(r.mail.Effects()) != 1 {
		t.Fatalf("effects = %d, want 1", len(r.mail.Effects()))
	}
}

// probeClerk records, inside Do, what State.Dispatched says of the request it
// was given and of three copies a caller could forge.
type probeClerk struct {
	st                                      func() *kernel.State
	real, otherStep, otherKey, otherAttempt bool
	req                                     kernel.Request
}

func (c *probeClerk) Do(r kernel.Request, _ kernel.View) kernel.Result {
	s := c.st()
	c.req, c.real = r, s.Dispatched(r)
	f := r
	f.Step.Verb = key.Trash
	c.otherStep = s.Dispatched(f)
	f = r
	f.Key = key.Key{}
	c.otherKey = s.Dispatched(f)
	f = r
	f.Attempt++
	c.otherAttempt = s.Dispatched(f)
	return kernel.Result{Outcome: "ok"}
}
func (c *probeClerk) Probe(kernel.Request, kernel.View) string { return "done" }

// REQ: CLK-2
func TestDispatchedHoldsOnlyForTheRequestTheKernelMade(t *testing.T) {
	r := newRig(t)
	c := &probeClerk{}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: r.head.pub,
		Sign: r.head.priv, Rand: rand.NewChaCha8([32]byte{1})})
	must(t, err)
	r.k, err = kernel.Boot(l, r.owner.pub, map[string]kernel.Clerk{"mail": c}, 0)
	must(t, err)
	c.st = r.k.State
	must(t, r.k.Issue(0, r.root))
	must(t, l.Anchor())
	r.plan("p1", r.root, st(key.Organize, "m1"))
	must(t, r.k.Tick(10))
	if !c.real || c.otherStep || c.otherKey || c.otherAttempt {
		t.Fatalf("real %v, forged step %v key %v attempt %v", c.real, c.otherStep, c.otherKey, c.otherAttempt)
	}
	if r.k.State().Dispatched(c.req) {
		t.Fatal("a settled step still counts as dispatched")
	}
}
