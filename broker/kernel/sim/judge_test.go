package sim

// REQ: KEY-8, KEY-9

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// heldView is a log that granted every key long ago and has the one step in
// flight with the hold d: the least a view says, so only the hold oracle
// can judge the effect.
type heldView struct{ d kernel.Dispatch }

func (heldView) Granted(key.ID) (int64, bool)                     { return -kernel.GrantHold, true }
func (heldView) Enrollments() ([]key.Enrollment, []key.PublicKey) { return nil, nil }
func (heldView) ChangesView() *key.Changes                        { return &key.Changes{} }
func (heldView) LedgerBefore(uint64) key.Ledger                   { return nil }
func (v heldView) Dispatched(kernel.Request) (kernel.Dispatch, bool) {
	return v.d, true
}
func (heldView) OneOffLine(key.ID, int64) int64         { return 0 }
func (heldView) Task(string, int64) (kernel.Task, bool) { return kernel.Task{}, false }

// The sweep's own oracle judges an irreversible effect by the hold the key
// and the step's worth set (KEY-8, KEY-9) on the true clock: one a
// millisecond before the step is due is inside its window, one at its due
// time, an approved one, and one with no window are not; one never held
// is, when the key holds.
func TestTheOracleJudgesTheHoldOnTheTrueClock(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	owner, holder := gen(rng), gen(rng)
	root := key.Issue(owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Post}, Serial: "j1"})
	ck, err := key.ClerkKey(root, owner.pass, holder.pub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := key.Derive(ck, holder.priv, holder.pub, key.LimitHold(hour/6, hour/2))
	if err != nil {
		t.Fatal(err)
	}
	const heldAt = 10 * hour
	due := heldAt + hour/6 // a post reaches data at rank 1: no worth term
	for _, c := range []struct {
		name   string
		k      key.Key
		now    int64
		d      kernel.Dispatch
		inside bool
	}{
		{"a millisecond early", hk, due - 1, kernel.Dispatch{Held: true, HeldAt: heldAt}, true},
		{"at its due time", hk, due, kernel.Dispatch{Held: true, HeldAt: heldAt}, false},
		{"approved early", hk, due - 1, kernel.Dispatch{Held: true, HeldAt: heldAt, Approved: true}, false},
		{"never held", hk, due, kernel.Dispatch{}, true},
		{"novel, past the base window only", hk, due, kernel.Dispatch{Held: true, HeldAt: heldAt, Novel: true}, true},
		{"no window", ck, heldAt, kernel.Dispatch{}, false},
	} {
		now := c.now
		w := &world{anchors: []key.PublicKey{owner.pk}, now: &now, done: map[string]bool{}, dead: map[key.ID]bool{}}
		p := kernel.SignPlan(kernel.Plan{ID: "j", Key: c.k, Steps: []kernel.PlanStep{{Verb: key.Post, Clerk: "mail", Args: map[string]string{"to": "alice", "msg": "hi"}}}}, holder.priv)
		w.judge(kernel.Request{Plan: p}, heldView{c.d})
		if got := slices.Contains(w.bad, "irreversible effect inside its hold window"); got != c.inside || len(w.bad) > 1 {
			t.Errorf("%s: judged %q", c.name, w.bad)
		}
	}
}

// The hostile clock jumps just past every held step's window, worth term
// included, and a step never due sets no jump: a held send whose hold is
// longer than the few hours a quiet jump takes runs at the jumped clock,
// and one held near the end of int64 leaves the jump at a few hours.
func TestTheHostileClockJumpsPastEveryHold(t *testing.T) {
	for _, c := range []struct {
		name    string
		hold    int64
		pastDue bool
	}{
		{"a ten-hour hold", 10 * hour, true},
		{"a hold never due", math.MaxInt64 - hour, false},
	} {
		rng := rand.New(rand.NewPCG(3, 4))
		var nseed [32]byte
		s := &sim{rng: rng, anchor: &anchor{}, nonce: rand.NewChaCha8(nseed), now: key.DayMS}
		s.disk = &Disk{rng: rng}
		s.owner, s.holder, s.head, s.spare = gen(rng), gen(rng), gen(rng), gen(rng)
		s.w = &world{anchors: []key.PublicKey{s.owner.pk, s.spare.pk}, rng: rng, now: &s.now, reads: &[2]int64{math.MinInt64, math.MinInt64}, done: map[string]bool{}, dead: map[key.ID]bool{}}
		s.w.mail = s.w.newMail()
		if err := s.boot(); err != nil {
			t.Fatal(err)
		}
		root := key.Issue(s.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Send}, Serial: "h1"})
		ck := s.clerkKey(s.owner.pass, root)
		if err := s.k.Issue(s.now-kernel.GrantHold, approve([]key.Key{root, ck}, s.owner, s.spare), root, ck); err != nil {
			t.Fatal(err)
		}
		hk, err := key.Derive(ck, s.holder.priv, s.holder.pub, key.LimitHold(c.hold, c.hold))
		if err != nil {
			t.Fatal(err)
		}
		p := kernel.SignPlan(kernel.Plan{ID: "h", Key: hk, Steps: []kernel.PlanStep{{Verb: key.Send, Clerk: "mail", Args: map[string]string{"to": "a", "msg": "hi"}}}}, s.holder.priv)
		if err := s.k.Submit(s.now, p); err != nil {
			t.Fatal(err)
		}
		if err := s.k.Tick(s.now); err != nil || s.k.State().Plans["h"].Steps[0].Phase != kernel.PHeld {
			t.Fatalf("%s: not held: %v", c.name, err)
		}
		ahead := s.pastHolds()
		quiet := ahead > 0 && ahead <= 6*hour // pastHolds' jump with nothing due
		if c.pastDue && (ahead <= c.hold || ahead > c.hold+hour) || !c.pastDue && !quiet {
			t.Fatalf("%s: jump %d", c.name, ahead)
		}
		if a := kernel.Next(s.k.State(), "h", s.now+ahead); c.pastDue != (a.Kind == kernel.ActDispatch) {
			t.Errorf("%s: at the jumped clock, act %+v", c.name, a)
		}
	}
}
