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
	return key.Step{Verb: v, Clerk: "mail", Recipient: to, Task: "t",
		Args: map[string]key.Arg{"msg": {Value: to, Source: key.SrcClerk}}}
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
	bad := st(key.Trash, "5")
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
	// the same shape is no longer novel: the base window applies
	r.plan("p2", k, st(key.Unsubscribe, "list-b"))
	must(t, r.k.Tick(5*hour))
	must(t, r.k.Tick(6*hour))
	if len(r.mail.Effects()) != 2 {
		t.Fatalf("known shape should wait only the base window, effects %d", len(r.mail.Effects()))
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
