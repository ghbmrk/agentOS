package kernel_test

// REQ: KRN-1, KRN-4, KRN-5, KRN-6, KRN-7, KRN-8, LOG-2, LOG-5, CLK-2, KEY-1, KEY-3, KEY-8

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
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

// flakyAnchor is an anchor that can be taken away: nothing new is confirmed while down.
type flakyAnchor struct {
	*kernel.MemAnchor
	down bool
}

func (a *flakyAnchor) Put(h kernel.Head) error {
	if a.down {
		return errors.New("anchor down")
	}
	return a.MemAnchor.Put(h)
}

type rig struct {
	t      *testing.T
	owner  pair
	holder pair
	head   pair
	store  *kernel.MemStore
	anchor *flakyAnchor
	mail   *clerk.Mail
	k      *kernel.Kernel
	ck     key.Key // the home clerk's key: the passkey's grant to the holder
	now    int64   // the mail clerk's own clock
}

// tick runs the kernel at now, with the clerk's own clock at now too.
func (r *rig) tick(now int64) error {
	r.now = now
	return r.k.Tick(now)
}

func cfg(r *rig) kernel.Config {
	return kernel.Config{Store: r.store, Anchor: r.anchor, Pub: r.head.pub, Sign: r.head.priv,
		Rand: rand.NewChaCha8([32]byte{1})}
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, owner: gen(1), holder: gen(2), head: gen(3), store: &kernel.MemStore{}, anchor: &flakyAnchor{MemAnchor: &kernel.MemAnchor{}}}
	r.mail = clerk.NewMail("mail", r.anchors())
	r.mail.Clock = func() int64 { return r.now }
	r.boot(0)
	// The grant anchors itself: the rig adds no anchor of its own.
	r.ck = r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "mail",
		Verbs: []key.Verb{key.Organize, key.Trash, key.Unsubscribe}, Serial: "r1"}), 1<<40)
	return r
}

// anchors is the rig's passkey set: the owner's one passkey as its anchor.
func (r *rig) anchors() []ed25519.PublicKey { return []ed25519.PublicKey{r.owner.pub} }

// grant has the passkey grant root and the home clerk's key to it, a hold
// before the test, so both are live (D-146). It returns the clerk key.
func (r *rig) grant(root key.Key, spendDay int64, c ...key.Caveat) key.Key {
	r.t.Helper()
	ck, err := key.ClerkKey(root, r.owner.priv, r.holder.pub, 0, spendDay, c...)
	must(r.t, err)
	must(r.t, r.k.Issue(-kernel.GrantHold, root, ck))
	return ck
}

func (r *rig) boot(now int64) {
	l, err := kernel.Open(cfg(r))
	must(r.t, err)
	r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{"mail": r.mail}, now)
	must(r.t, err)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (r *rig) derive(c ...key.Caveat) key.Key {
	k, err := key.Derive(r.ck, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return k
}

func st(v key.Verb, to string) kernel.PlanStep {
	s := kernel.PlanStep{Verb: v, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(v) {
		s.Args[n] = to
	}
	return s
}

// sign signs p as the rig's holder, who holds the clerk key and every key the rig derives.
func (r *rig) sign(p kernel.Plan) kernel.Plan { return kernel.SignPlan(p, r.holder.priv) }

func (r *rig) plan(id string, k key.Key, steps ...kernel.PlanStep) {
	r.t.Helper()
	must(r.t, r.k.Submit(0, r.sign(kernel.Plan{ID: id, Key: k, Steps: steps})))
}

func (r *rig) status(id string) string { return r.k.State().Plans[id].Status }

func TestReversibleStepRunsOnceAndReplayMatches(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"), st(key.Organize, "m2"))
	must(t, r.tick(10))
	must(t, r.tick(20))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 2 {
		t.Fatalf("status %s effects %d", r.status("p1"), len(r.mail.Effects()))
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
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
	r.plan("p1", k, st(key.Organize, "9"), bad)
	if r.status("p1") != kernel.SRejected || len(r.mail.Effects()) != 0 {
		t.Fatal("a refused step must reject the whole plan before any step runs (KRN-5)")
	}
}

func TestUnknownRootRejected(t *testing.T) {
	r := newRig(t)
	other, err := key.ClerkKey(key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "never-logged"}),
		r.owner.priv, r.holder.pub, 0, 1)
	must(t, err)
	p := r.sign(kernel.Plan{ID: "p1", Key: other, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})
	if _, _, rf := kernel.Admit(r.k.State(), p, 0); rf == nil || rf.Code != kernel.CUngranted {
		t.Fatalf("a root not in the log must not authorize (KEY-1): %v", rf)
	}
	must(t, r.k.Submit(0, p))
	if r.status("p1") != kernel.SRejected {
		t.Fatal("rejected")
	}
}

func TestHoldWindowThenNoveltyWindow(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, 4*hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.tick(4*hour-1))
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a novel irreversible step ran inside its window (KEY-8)")
	}
	must(t, r.tick(4*hour))
	if len(r.mail.Effects()) != 1 {
		t.Fatal("step did not run after its window")
	}
	// the same shape to the same recipient, a day on, is known: the base window applies
	must(t, r.k.Submit(30*hour, r.sign(kernel.Plan{ID: "p2", Key: k, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
	must(t, r.tick(30*hour))
	must(t, r.tick(31*hour))
	if len(r.mail.Effects()) != 2 {
		t.Fatalf("known shape should wait only the base window, effects %d", len(r.mail.Effects()))
	}
	// a new recipient is a new shape: the novelty window applies (KEY-8)
	must(t, r.k.Submit(32*hour, r.sign(kernel.Plan{ID: "p3", Key: k, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-b")}})))
	must(t, r.tick(32*hour))
	must(t, r.tick(35*hour))
	if len(r.mail.Effects()) != 2 {
		t.Fatal("a new recipient ran inside the novelty window")
	}
	must(t, r.tick(36*hour))
	if len(r.mail.Effects()) != 3 {
		t.Fatal("a new recipient did not run after the novelty window")
	}
}

func TestRevokeDuringHoldCancelsWithNoEffect(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.k.Revoke(10, k.Tip()))
	must(t, r.tick(2*hour))
	if r.status("p1") != kernel.SCancelled || len(r.mail.Effects()) != 0 {
		t.Fatalf("status %s effects %d", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestPauseWaitsStopCancels(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.k.Pause(1, k.Tip()))
	must(t, r.tick(2*hour))
	if r.status("p1") != kernel.SActive || len(r.mail.Effects()) != 0 {
		t.Fatal("a paused key must wait")
	}
	must(t, r.k.Unpause(2*hour+1, k.Tip()))
	must(t, r.k.Stop(2*hour+2))
	must(t, r.tick(3*hour))
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
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(0))
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("a lost answer must leave the step unknown")
	}
	must(t, r.tick(kernel.ProbeEvery-1))
	must(t, r.tick(kernel.ProbeEvery))
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
	must(t, r.tick(0))
	must(t, r.tick(kernel.ProbeEvery))
	must(t, r.tick(kernel.ProbeEvery+1))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("status %s effects %d: a redo must not be refused by its own charge", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestParkedAfterTenUnknownChecks(t *testing.T) {
	r := newRig(t)
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultDrop }
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	for i := int64(0); i <= kernel.MaxChecks+1; i++ {
		must(t, r.tick(i*kernel.ProbeEvery))
	}
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PParked || len(r.mail.Effects()) != 0 {
		t.Fatal("ten unknown checks must park the step (KRN-8)")
	}
}

func TestSameEffectWithinADayNeedsFreshKey(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	r.plan("p2", r.ck, st(key.Unsubscribe, "list-a"))
	if r.status("p2") != kernel.SRejected {
		t.Fatal("the same irreversible effect within 24h must be refused (KRN-8)")
	}
}

func TestRestartAfterDispatchBeforeResultProbes(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(0))
	cutLast(t, r.store, 1) // the result never reached disk; the effect did
	r.boot(1)
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("an in-flight step must come back unknown")
	}
	must(t, r.tick(1+kernel.ProbeEvery))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("status %s effects %d", r.status("p1"), len(r.mail.Effects()))
	}
}

func TestPendingPlanIsDecidedAtBoot(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
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
	r.plan("p2", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(2))
	must(t, r.k.Undo(3, "p2", 0))
	if !r.k.State().Plans["p2"].Steps[0].Undone {
		t.Fatal("undo")
	}
}

// Undoing an irreversible step does not unsend it: the duplicate guard stays (KRN-8).
func TestUndoKeepsTheDuplicateGuardOfAnIrreversibleStep(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.k.Undo(1, "p1", 0))
	r.plan("p2", r.ck, st(key.Unsubscribe, "list-a"))
	if r.status("p2") != kernel.SRejected {
		t.Fatal("undo must not reopen an irreversible effect")
	}
}

// Argument boundaries are part of the fingerprint. These two sends collide
// when fields are joined with separators ("to=bob,to=x,msg=m" against
// "to=x,msg=m,to=bob" once sorted) and must not (KRN-8).
func TestFingerprintDoesNotCollideAcrossArgumentBoundaries(t *testing.T) {
	send := func(to, msg string) key.Step {
		return kernel.Normalize("p", kernel.PlanStep{Verb: key.Send, Clerk: "mail", Args: map[string]string{"to": to, "msg": msg}})
	}
	a, b := send("bob,to=x", "m"), send("x", "m,to=bob")
	if kernel.Fingerprint(a) == kernel.Fingerprint(b) {
		t.Fatal("different arguments must fingerprint differently")
	}
	if kernel.Fingerprint(a) != kernel.Fingerprint(send("bob,to=x", "m")) {
		t.Fatal("the same effect must fingerprint the same")
	}
}

// A declared argument with no value names nothing to act on (KEY-2).
func TestEmptyDeclaredArgumentRejectsThePlan(t *testing.T) {
	r := newRig(t)
	err := r.k.Submit(0, r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{st(key.Trash, "")}}))
	must(t, err)
	if r.status("p1") != kernel.SRejected {
		t.Fatal("an empty argument must reject the plan")
	}
}

func TestDuplicatePlanIDRefused(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	if err := r.k.Submit(0, r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{st(key.Trash, "m2")}})); !errors.Is(err, kernel.ErrDuplicatePlan) {
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
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(1))
	before := r.k.Log().Entries()
	r.boot(2)
	if !kernel.Same(before, r.k.Log().Entries()[:len(before)]) {
		t.Fatal("reopen changed history")
	}
}

func TestLogTamperTruncationForkTorn(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(1))
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
	f.plan("other", f.ck, st(key.Organize, "zzz"))
	must(t, f.k.Tick(1))
	c := cfg(r)
	c.Store = f.store
	if _, err := kernel.Open(c); !errors.Is(err, kernel.ErrFork) {
		t.Fatalf("a forked history must not open against the anchor (LOG-2): %v", err)
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
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(1))
	must(t, r.k.Stop(2))
	n := r.k.Log().Len()
	r.anchor.down = true
	if err := r.k.Resume(3); err == nil { // widening the anchor cannot confirm
		t.Fatal("a resume the anchor cannot confirm must report it")
	}
	r.boot(4)
	if !r.k.State().Stopped || r.k.Log().Len() != n {
		t.Fatal("an unconfirmed resume must not count after restart (KRN-7)")
	}
	r.anchor.down = false
	must(t, r.k.Resume(5))
	r.boot(6)
	if r.k.State().Stopped {
		t.Fatal("an anchored resume must stand")
	}
	if r.status("p1") != kernel.SDone {
		t.Fatal("dispatch and result entries must never be dropped (KRN-8)")
	}
}

// A widening whose anchor failed is already in live state; the log must refuse
// to build on it, so no later entry can make a restart keep it (KRN-7).
func TestFailedResumeHasNoEffectAndDoesNotSurviveReboot(t *testing.T) {
	r := newRig(t)
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.k.Stop(1))
	r.anchor.down = true
	if err := r.k.Resume(2); err == nil {
		t.Fatal("an unconfirmed resume must report it")
	}
	if err := r.tick(3); err == nil { // the broken log refuses the dispatch entry, so the clerk is never called
		t.Fatal("nothing may be appended after an unconfirmed widening")
	}
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a failed resume must not let a step run")
	}
	r.anchor.down = false
	if err := r.k.Stop(4); !errors.Is(err, kernel.ErrBroken) {
		t.Fatalf("the log must stay broken until reopened: %v", err)
	}
	r.boot(5)
	if !r.k.State().Stopped {
		t.Fatal("a resume the anchor never confirmed must not survive a reboot")
	}
	must(t, r.tick(6))
	if len(r.mail.Effects()) != 0 {
		t.Fatal("the plan must stay stopped")
	}
}

// A failed Unpause is the same: the key stays paused after a reboot.
func TestFailedUnpauseAndIssueDoNotSurviveReboot(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Pause(1, r.ck.Tip()))
	r.anchor.down = true
	if err := r.k.Unpause(2, r.ck.Tip()); err == nil {
		t.Fatal("an unconfirmed unpause must report it")
	}
	other := key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "r2"})
	if err := r.k.Issue(3, other); !errors.Is(err, kernel.ErrBroken) {
		t.Fatalf("nothing may build on an unconfirmed widening: %v", err)
	}
	r.anchor.down = false
	r.boot(4)
	if !r.k.State().Changes.Paused[r.ck.Tip()] {
		t.Fatal("an unpause the anchor never confirmed must not survive a reboot")
	}
	r.plan("p1", other, st(key.Trash, "m1"))
	if r.status("p1") != kernel.SRejected {
		t.Fatal("a root whose anchor failed must be unknown after a reboot (KEY-1)")
	}
}

// A failed Issue itself: no plan runs under it, and a reboot forgets it.
func TestFailedIssueHasNoEffectAndDoesNotSurviveReboot(t *testing.T) {
	r := newRig(t)
	other := key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "r2"})
	r.anchor.down = true
	if err := r.k.Issue(1, other); err == nil {
		t.Fatal("an unconfirmed issue must report it")
	}
	if err := r.k.Submit(2, r.sign(kernel.Plan{ID: "p1", Key: other, Steps: []kernel.PlanStep{st(key.Trash, "m1")}})); err == nil {
		t.Fatal("nothing may build on an unconfirmed issue")
	}
	r.anchor.down = false
	r.boot(3)
	r.plan("p2", other, st(key.Trash, "m1"))
	must(t, r.tick(4))
	if r.status("p2") != kernel.SRejected || len(r.mail.Effects()) != 0 {
		t.Fatal("an issue the anchor never confirmed must not survive a reboot (KEY-1)")
	}
}

// A narrowing stays in force when its anchor fails, and the log stays usable:
// Open keeps it either way, so refusing the owner's next stop would help nobody.
func TestFailedAnchorAfterNarrowingKeepsItAndTheLog(t *testing.T) {
	r := newRig(t)
	r.anchor.down = true
	if err := r.k.Stop(1); err == nil {
		t.Fatal("an unconfirmed stop must report it")
	}
	if !r.k.State().Stopped {
		t.Fatal("a stop stays in force")
	}
	if err := r.k.Pause(2, r.ck.Tip()); err == nil || errors.Is(err, kernel.ErrBroken) {
		t.Fatalf("the log stays usable: the pause is recorded and only its anchor fails: %v", err)
	}
	if !r.k.State().Changes.Paused[r.ck.Tip()] {
		t.Fatal("a pause stays in force")
	}
	r.anchor.down = false
	r.boot(3)
	if !r.k.State().Stopped {
		t.Fatal("a stop is kept after restart whether or not it was anchored (KRN-7)")
	}
}

// Every owner action anchors itself: a widening that returned nil survives a reboot,
// and Issue does too, with no anchor from the caller.
func TestOwnerActionsAnchorThemselves(t *testing.T) {
	r := newRig(t)
	r.boot(1) // the rig's own Issue is the only thing anchoring the root
	r.plan("p0", r.ck, st(key.Trash, "m0"))
	if r.status("p0") != kernel.SActive {
		t.Fatal("an issued root must survive restart with no explicit anchor (KEY-1)")
	}
	must(t, r.k.Stop(2))
	must(t, r.k.Resume(3))
	r.boot(4)
	if r.k.State().Stopped {
		t.Fatal("a resume that returned nil must survive restart (KRN-7)")
	}
	must(t, r.k.Pause(5, r.ck.Tip()))
	must(t, r.k.Unpause(6, r.ck.Tip()))
	r.boot(7)
	if r.k.State().Changes.Paused[r.ck.Tip()] {
		t.Fatal("an unpause that returned nil must survive restart (KRN-7)")
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
	r.plan("p1", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0))
	must(t, r.k.Cancel(1, "p1"))
	must(t, r.tick(kernel.ProbeEvery))
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PUnknown {
		t.Fatal("the unknown step must stay unknown while the probe is unanswered")
	}
	r.plan("p2", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(kernel.ProbeEvery+1))
	if r.status("p2") == kernel.SDone || len(r.mail.Effects()) != 1 {
		t.Fatalf("a cancelled plan's unreconciled effect must block the same effect (KRN-8): p2 %s effects %d", r.status("p2"), len(r.mail.Effects()))
	}
	probeDown = false
	must(t, r.tick(2*kernel.ProbeEvery+2))
	if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PDone {
		t.Fatal("a cancelled plan must still settle its unknown step by probing")
	}
}

// The plan format has no source, task, recipient or amount for a planner to
// write: the kernel derives all four, and a planner's argument never counts as
// owner or clerk sourced.
// REQ: KEY-2, KRN-3
func TestKernelDerivesSourceTaskRecipientAndAmount(t *testing.T) {
	r := newRig(t)
	one := int64(1)
	k := r.derive(key.LimitArg(key.ArgBound{Name: "msg", Min: &one}))
	r.plan("p1", k, st(key.Draft, "5"))
	if r.status("p1") != kernel.SRejected || len(r.mail.Effects()) != 0 {
		t.Fatal("a planner argument must not satisfy an argument bound (KEY-2)")
	}
	spend := r.derive(key.LimitSpendTask(100))
	big := st(key.Buy, "7")
	big.Args["amount"] = "500"
	r.plan("p2", spend, big)
	if r.status("p2") != kernel.SRejected {
		t.Fatal("the amount argument alone must set the amount (KRN-3)")
	}
	odd := st(key.Buy, "8")
	odd.Args["amount"] = "lots"
	r.plan("p3", spend, odd)
	if r.status("p3") != kernel.SRejected {
		t.Fatal("an unreadable amount must be refused")
	}
	r.plan("p4", spend, st(key.Trash, "9"))
	got := r.k.State().Plans["p4"].Plan.Step(0)
	if got.Task != "p4" || got.Recipient != "9" || got.Amount != 0 || got.Args["target"].Source != key.SrcPlanner {
		t.Fatalf("source, task, recipient and amount are derived, got %+v", got)
	}
}

// The guards read only a verb's declared arguments, so none of them moves by
// adding, renaming or dropping one (KRN-8, KEY-8, KEY-2).
func TestUndeclaredOrMissingArgumentsRejectThePlan(t *testing.T) {
	r := newRig(t)
	spend := r.derive(key.LimitSpendTask(10))
	extra := st(key.Unsubscribe, "list-a")
	extra.Args["note"] = "again"
	renamed := kernel.PlanStep{Verb: key.Send, Clerk: "mail", Args: map[string]string{"list": "x", "msg": "x"}}
	price := st(key.Buy, "shop")
	delete(price.Args, "amount")
	price.Args["price"] = "100000"
	missing := st(key.Send, "x")
	delete(missing.Args, "to")
	for name, s := range map[string]kernel.PlanStep{"extra": extra, "renamed": renamed, "price": price, "missing": missing} {
		k := r.ck
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
	buy := r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Buy}, Serial: "r2"}), 1<<40)
	step := func(amount string) kernel.PlanStep {
		s := st(key.Buy, "shop")
		s.Args["amount"] = amount
		return s
	}
	r.plan("p1", buy, step("10"))
	must(t, r.tick(0))
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

// The strip probe from #2566's Security review: a planner holding a narrowed
// key drops its links and submits the bare root. Holding a narrowed key must
// never confer more than it allows (KEY-3).
func TestStrippedKeyIsRefused(t *testing.T) {
	r := newRig(t)
	planner := gen(4)
	k, err := key.Derive(r.ck, r.holder.priv, planner.pub, key.LimitRate(2))
	must(t, err)
	organize := func(n int) []kernel.PlanStep {
		var s []kernel.PlanStep
		for i := 0; i < n; i++ {
			s = append(s, st(key.Organize, fmt.Sprintf("m%d", i)))
		}
		return s
	}
	// The planner's own use of its key runs, within the key.
	must(t, r.k.Submit(0, kernel.SignPlan(kernel.Plan{ID: "p0", Key: k, Steps: organize(2)}, planner.priv)))
	must(t, r.tick(10))
	if r.status("p0") != kernel.SDone || len(r.mail.Effects()) != 2 {
		t.Fatalf("holder's own plan: status %s, %d effects", r.status("p0"), len(r.mail.Effects()))
	}
	// Stripped to the root, re-derived off it, or signed by no holder: refused.
	stripped := key.Key{Root: k.Root}
	for id, p := range map[string]kernel.Plan{
		"p1": kernel.SignPlan(kernel.Plan{ID: "p1", Key: stripped, Steps: organize(3)}, planner.priv),
		"p2": kernel.SignPlan(kernel.Plan{ID: "p2", Key: key.Extend(r.ck, planner.priv,
			key.Link{Caveats: []key.Caveat{key.LimitRate(1000)}, Holder: planner.pub}), Steps: organize(3)}, planner.priv),
		"p3": {ID: "p3", Key: k, Steps: organize(1)},
	} {
		must(t, r.k.Submit(20, p))
		must(t, r.tick(30))
		if r.status(id) != kernel.SRejected || len(r.mail.Effects()) != 2 {
			t.Fatalf("%s: status %s, %d effects past LimitRate(2)", id, r.status(id), len(r.mail.Effects()))
		}
		// The clerk refuses it on its own check, whatever the kernel decided (CLK-2).
		if rf := clerk.Check(r.anchors(), "mail", r.mail.Facts, 30, kernel.Request{Plan: p}, r.k.State()); rf == nil || rf.Code != kernel.CKey {
			t.Fatalf("%s: clerk check %v", id, rf)
		}
	}
}

// JSON encodes invalid UTF-8 as U+FFFD, so a signature over one such plan
// would also cover another: a plan whose text is not UTF-8 is refused.
func TestPlanTextMustBeUTF8(t *testing.T) {
	r := newRig(t)
	a := r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{st(key.Organize, "m\xff")}})
	b := a
	b.Steps = []kernel.PlanStep{st(key.Organize, "m\xfe")}
	for _, p := range []kernel.Plan{a, b} {
		if _, err := kernel.VerifyPlan(p, []ed25519.PublicKey{r.owner.pub}); !errors.Is(err, kernel.ErrNotText) {
			t.Fatalf("verify %q: %v, want ErrNotText", p.Steps[0].Args, err)
		}
	}
	must(t, r.k.Submit(0, b))
	must(t, r.tick(10))
	if r.status("p1") != kernel.SRejected || len(r.mail.Effects()) != 0 {
		t.Fatalf("non-UTF-8 plan: status %s, %d effects", r.status("p1"), len(r.mail.Effects()))
	}
}

// park runs plan p1 (one trash step) with every answer lost until the step
// parks after MaxChecks, and returns the time of the last check.
func (r *rig) park(k key.Key) int64 {
	r.t.Helper()
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultDrop }
	r.plan("p1", k, st(key.Trash, "m1"))
	at := int64(0)
	for i := int64(0); i <= kernel.MaxChecks+1; i++ {
		at = i * kernel.ProbeEvery
		must(r.t, r.tick(at))
	}
	if ph := r.k.State().Plans["p1"].Steps[0].Phase; ph != kernel.PParked {
		r.t.Fatalf("phase %s, want parked", ph)
	}
	r.mail.Fault = nil
	return at
}

// A parked step is not a dead end: STATUS lists it with the clerk's last
// answer and whether it may be retried (KRN-8, CH-11, OWN-16).
func TestStatusListsUnsettledSteps(t *testing.T) {
	r := newRig(t)
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultDrop }
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(0))
	want := kernel.Unsettled{Plan: "p1", Verb: key.Trash, Clerk: "mail", Phase: kernel.PUnknown, Detail: "no answer"}
	if got := r.k.State().Status(); len(got) != 1 || got[0] != want {
		t.Fatalf("status %+v, want %+v", got, want)
	}
	for i := int64(1); i <= kernel.MaxChecks+1; i++ {
		must(t, r.tick(i*kernel.ProbeEvery))
	}
	want.Phase, want.Checks, want.Retry = kernel.PParked, kernel.MaxChecks, true
	if got := r.k.State().Status(); len(got) != 1 || got[0] != want {
		t.Fatalf("status %+v, want %+v", got, want)
	}
	must(t, r.k.Cancel(kernel.MaxChecks*kernel.ProbeEvery*2, "p1"))
	if got := r.k.State().Status(); len(got) != 1 || got[0].Retry {
		t.Fatalf("a cancelled plan's parked step is still listed, and is not retried: %+v", got)
	}
}

// RETRY sends a parked step again under its own idempotency key, once, and the
// log replays to the same state (KRN-8, KRN-1).
func TestRetryRedispatchesAParkedStep(t *testing.T) {
	r := newRig(t)
	at := r.park(r.ck)
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultDrop }
	must(t, r.k.Retry(at+1, "p1", 0))
	must(t, r.tick(at+2))
	must(t, r.tick(at+2+kernel.ProbeEvery)) // one check: the retry starts the count again
	if ph := r.k.State().Plans["p1"].Steps[0].Phase; ph != kernel.PUnknown {
		t.Fatalf("phase %s after a retry and one check, want unknown", ph)
	}
	r.mail.Fault = nil
	must(t, r.tick(at+2+2*kernel.ProbeEvery))
	must(t, r.tick(at+3+2*kernel.ProbeEvery))
	if r.status("p1") != kernel.SDone || len(r.mail.Effects()) != 1 || r.mail.Effects()[0].Idem != kernel.Idem("p1", 0) {
		t.Fatalf("status %s, effects %+v", r.status("p1"), r.mail.Effects())
	}
	if got := r.k.State().Status(); len(got) != 0 {
		t.Fatalf("a settled step is still listed: %+v", got)
	}
	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		t.Fatal("replay differs after a retry")
	}
}

// RETRY widens nothing else: the redo meets the same checks as any dispatch,
// so a key revoked, or a STOP, while the step was parked still refuses it.
func TestRetryRunsTheKeyChecksAgain(t *testing.T) {
	for name, narrow := range map[string]func(*rig, int64) error{
		"revoked": func(r *rig, at int64) error { return r.k.Revoke(at, r.ck.Tip()) },
		"stopped": func(r *rig, at int64) error { return r.k.Stop(at) },
	} {
		r := newRig(t)
		at := r.park(r.ck)
		must(t, narrow(r, at+1))
		must(t, r.k.Retry(at+2, "p1", 0))
		must(t, r.tick(at+3))
		if r.status("p1") != kernel.SCancelled || len(r.mail.Effects()) != 0 {
			t.Fatalf("%s: status %s, %d effects", name, r.status("p1"), len(r.mail.Effects()))
		}
	}
}

// Only a parked step of a live plan can be retried; anything else is refused
// and leaves no entry.
func TestRetryRefusesAStepThatIsNotParked(t *testing.T) {
	r := newRig(t)
	r.mail.Fault = func(string, kernel.Request) string { return clerk.FaultDrop }
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(0)) // unknown, still being reconciled
	r.mail.Fault = nil
	r.plan("p2", r.ck, st(key.Organize, "m2"))
	must(t, r.tick(1)) // done
	c := newRig(t)
	at := c.park(c.ck)
	must(t, c.k.Cancel(at+1, "p1")) // parked, but the owner cancelled the plan
	for _, x := range []struct {
		r     *rig
		plan  string
		index int
	}{{r, "p1", 0}, {r, "p2", 0}, {r, "p2", 1}, {r, "nope", 0}, {c, "p1", 0}} {
		n := x.r.k.Log().Len()
		if err := x.r.k.Retry(at+2, x.plan, x.index); !errors.Is(err, kernel.ErrNotParked) || x.r.k.Log().Len() != n {
			t.Fatalf("retry %s/%d: %v, log %d -> %d", x.plan, x.index, err, n, x.r.k.Log().Len())
		}
	}
}

// RETRY is a widening: one whose anchor failed does not survive a restart,
// and the step stays parked with no effect (KRN-7).
func TestUnanchoredRetryDoesNotSurviveReboot(t *testing.T) {
	r := newRig(t)
	at := r.park(r.ck)
	r.anchor.down = true
	if err := r.k.Retry(at+1, "p1", 0); err == nil {
		t.Fatal("an unconfirmed retry must report it")
	}
	if err := r.tick(at + 2); err == nil {
		t.Fatal("nothing may be appended after an unconfirmed retry")
	}
	r.anchor.down = false
	r.boot(at + 3)
	must(t, r.tick(at+4))
	if ph := r.k.State().Plans["p1"].Steps[0].Phase; ph != kernel.PParked || len(r.mail.Effects()) != 0 {
		t.Fatalf("phase %s, %d effects after an unconfirmed retry", ph, len(r.mail.Effects()))
	}
}

// The clerk judges the hold on its own clock: a kernel whose clock runs ahead
// releases a held step, and the clerk still refuses it inside the window
// (CLK-2, KEY-8).
func TestClerkKeepsTheHoldWhenTheKernelClockRunsAhead(t *testing.T) {
	r := newRig(t)
	k := r.derive(key.LimitHold(hour, hour))
	r.plan("p1", k, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(0)) // held at 0
	r.now = hour / 2   // the clerk's clock: half the window
	must(t, r.k.Tick(2*hour))
	if len(r.mail.Effects()) != 0 || r.status("p1") != kernel.SFailed {
		t.Fatalf("status %s, %d effects: the clerk released a hold on the kernel's clock", r.status("p1"), len(r.mail.Effects()))
	}
	if d := r.k.State().Plans["p1"].Steps[0].Detail; d != clerk.RHold {
		t.Fatalf("detail %q, want %q", d, clerk.RHold)
	}
}

// Dispatched answers only for the exact plan the log admitted, with its step
// in flight: not before the dispatch, not after the result, not for another
// step, and not for a plan under the same id with other steps or another key,
// which the holder could sign as validly (CLK-2, KRN-8).
func TestDispatchedAnswersOnlyForTheLoggedPlanInFlight(t *testing.T) {
	r := newRig(t)
	p := r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{st(key.Organize, "m1")}})
	twin := r.sign(kernel.Plan{ID: "p1", Key: r.ck, Steps: []kernel.PlanStep{st(key.Organize, "m2")}})
	rekeyed := r.sign(kernel.Plan{ID: "p1", Key: r.derive(key.LimitUses(5)), Steps: p.Steps})
	answers := func() map[string]bool {
		got := map[string]bool{}
		for name, q := range map[string]kernel.Request{"admitted": {Plan: p}, "twin": {Plan: twin},
			"rekeyed": {Plan: rekeyed}, "other step": {Plan: p, Index: 1}} {
			_, got[name] = r.k.State().Dispatched(q)
		}
		return got
	}
	var during map[string]bool
	r.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" {
			during = answers()
		}
		return ""
	}
	must(t, r.k.Submit(0, p))
	none := map[string]bool{"admitted": false, "twin": false, "rekeyed": false, "other step": false}
	if got := answers(); !reflect.DeepEqual(got, none) {
		t.Fatalf("before the dispatch: %v", got)
	}
	must(t, r.tick(1))
	if want := map[string]bool{"admitted": true, "twin": false, "rekeyed": false, "other step": false}; !reflect.DeepEqual(during, want) {
		t.Fatalf("in flight: %v, want %v", during, want)
	}
	if got := answers(); !reflect.DeepEqual(got, none) {
		t.Fatalf("after the result: %v", got)
	}
}
