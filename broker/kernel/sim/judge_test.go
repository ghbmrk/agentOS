package sim

// REQ: KEY-7, KEY-8, KEY-9, TIM-1

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
		w := &world{anchors: []key.PublicKey{owner.pk}, now: &now, reads: &[2]int64{math.MaxInt64, math.MinInt64}, done: map[string]bool{}, dead: map[key.ID]bool{}}
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
		if err := s.k.Issue(s.now, approve([]key.Key{root, ck}, s.owner, s.spare), root, ck); err != nil {
			t.Fatal(err)
		}
		s.now += kernel.GrantHold // the kernel reads its clock, so the grant waits its hold
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

// A kernel that decides on its clock alone, not the guard's interval, ends a
// hold the earliest reading has not reached and acts under a key the latest
// reading has passed: the sweep's two clock invariants catch both, and the
// kernel that reads the interval waits the hold and rejects the plan (TIM-1,
// KEY-7, KEY-8).
func TestNoReadingKernelFailsBothClockInvariants(t *testing.T) {
	for _, c := range []struct {
		bad        string
		hold, life int64
	}{
		{"a hold ended before its due by the earliest reading", hour, 0},
		{"effect under a key once a reading passed its expiry", 0, hour},
	} {
		for _, m := range []Mutant{"", MutantNoClock} {
			rng := rand.New(rand.NewPCG(5, 6))
			var nseed [32]byte
			s := &sim{cfg: Config{Mutant: m}, rng: rng, anchor: &anchor{}, nonce: rand.NewChaCha8(nseed), now: key.DayMS}
			s.disk = &Disk{rng: rng}
			s.owner, s.holder, s.head, s.spare = gen(rng), gen(rng), gen(rng), gen(rng)
			s.w = &world{anchors: []key.PublicKey{s.owner.pk, s.spare.pk}, rng: rng, now: &s.now, reads: &s.reads, done: map[string]bool{}, dead: map[key.ID]bool{}}
			s.w.mail = s.w.newMail()
			if err := s.boot(); err != nil {
				t.Fatal(err)
			}
			root := key.Issue(s.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Send}, Serial: "n1"})
			ck := s.clerkKey(s.owner.pass, root)
			if err := s.k.Issue(s.now, approve([]key.Key{root, ck}, s.owner, s.spare), root, ck); err != nil {
				t.Fatal(err)
			}
			s.now += kernel.GrantHold
			cv := key.LimitExpires(s.now + c.life)
			if c.hold > 0 {
				cv = key.LimitHold(c.hold, c.hold)
			}
			hk, err := key.Derive(ck, s.holder.priv, s.holder.pub, cv)
			if err != nil {
				t.Fatal(err)
			}
			s.late = 2 * hour // the guard's sources disagree: one runs two hours ahead
			p := kernel.SignPlan(kernel.Plan{ID: "n", Key: hk, Steps: []kernel.PlanStep{{Verb: key.Send, Clerk: "mail", Args: map[string]string{"to": "a", "msg": "hi"}}}}, s.holder.priv)
			if err := s.k.Submit(s.kt(), p); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := s.k.Tick(s.kt()); err != nil {
					t.Fatal(err)
				}
				s.now, s.early = s.now+c.hold, 2*hour // to the hold's due on the true clock; one source runs two hours behind
			}
			caught, st := slices.Contains(s.w.bad, c.bad), s.k.State().Plans["n"]
			if m == MutantNoClock && !caught || m == "" && (len(s.w.bad) > 0 || c.hold > 0 && (len(st.Steps) == 0 || st.Steps[0].Phase != kernel.PHeld) || c.life > 0 && st.Status != kernel.SRejected) {
				t.Errorf("%q, mutant %q: judged %q, plan %s %+v", c.bad, m, s.w.bad, st.Status, st.Steps)
			}
		}
	}
}

// The cut-off judges the phone's grants on its entry's time: a grant live
// by then stays, at that time exactly too; one still in its hold then, or
// one the log never took, never goes live, though the kernel's time has
// since passed its hold. Only the held one counts as cancelled (D-146, TIM-1).
func TestTheCutOffJudgesGrantsOnItsEntrysTime(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	var nseed [32]byte
	t0 := key.DayMS
	s := &sim{rng: rng, anchor: &anchor{}, nonce: rand.NewChaCha8(nseed), now: t0}
	s.disk = &Disk{rng: rng}
	s.owner, s.holder, s.head, s.spare = gen(rng), gen(rng), gen(rng), gen(rng)
	s.w = &world{anchors: []key.PublicKey{s.owner.pk, s.spare.pk}, rng: rng, now: &s.now, reads: &s.reads, done: map[string]bool{}, dead: map[key.ID]bool{}}
	s.w.mail = s.w.newMail()
	if err := s.boot(); err != nil {
		t.Fatal(err)
	}
	grant := func(at int64, serial string) key.ID {
		t.Helper()
		s.now = at
		root := key.Issue(s.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Send}, Serial: serial})
		ck := s.clerkKey(s.owner.pass, root)
		if err := s.k.Issue(s.kt(), approve([]key.Key{root, ck}, s.owner, s.spare), root, ck); err != nil {
			t.Fatal(err)
		}
		return ck.Tip()
	}
	live, edge, held := grant(t0, "c1"), grant(t0+hour/2, "c2"), grant(t0+hour, "c3")
	cutAt := t0 + hour/2 + kernel.GrantHold // edge goes live at the cut-off exactly
	s.phone = gen(rng)
	if err := s.k.Enroll(s.kt(), key.Enroll(s.spare.pass, s.phone.pk)); err != nil {
		t.Fatal(err)
	}
	s.now = cutAt
	if err := s.k.Unenroll(s.kt(), key.Unenroll(s.owner.pass, s.phone.pk)); err != nil {
		t.Fatal(err)
	}
	s.now = cutAt + 2*hour // a later entry, past the held grant's hold
	if err := s.k.Stop(s.kt()); err != nil {
		t.Fatal(err)
	}
	s.now += hour
	var never key.ID
	never[0] = 1
	s.byPhone = []key.ID{live, edge, held, never}
	s.cut()
	for id, dead := range map[key.ID]bool{live: false, edge: false, held: true, never: true} {
		if s.w.dead[id] != dead {
			t.Errorf("grant %x: dead %v, want %v", id[:4], s.w.dead[id], dead)
		}
	}
	if s.cutCancelled != 1 {
		t.Errorf("%d grants counted cancelled, want the held one", s.cutCancelled)
	}
}

// A big batch refused for its second passkey is counted; a clerk key past
// ClerkLife is excused only while the kernel's earliest reading is behind
// the true time, by its step back or its sources' spread (D-146, TIM-1).
func TestRefusedBigExcusesOnlyAClockBehind(t *testing.T) {
	for _, c := range []struct {
		name         string
		ahead, early int64
		excused      bool
	}{
		{"stepped back", -2 * hour, 0, true},
		{"a source behind", 0, hour, true},
		{"on the true time", 0, 0, false},
		{"ahead", hour, 0, false},
		{"ahead past its source's spread", 2 * hour, hour, false},
	} {
		s := &sim{now: key.DayMS, ahead: c.ahead, early: c.early}
		if err := s.refusedBig(kernel.ErrLife); (err == nil) != c.excused {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	s := &sim{}
	if err := s.refusedBig(kernel.ErrNeedsCosign); err != nil || s.bigRefused != 1 {
		t.Errorf("a refusal for its second passkey: %v, counted %d", err, s.bigRefused)
	}
}

// The two clock invariants judge at their edges: a hold whose earliest
// reading is a millisecond short of its due ended early, one at its due did
// not; an effect whose latest reading reached the key's expiry exactly is
// under an expired key, one a millisecond short is not (TIM-1, KEY-7, KEY-8).
func TestTheClockInvariantsJudgeAtTheirEdges(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	owner, holder := gen(rng), gen(rng)
	root := key.Issue(owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Post}, Serial: "e1"})
	ck, err := key.ClerkKey(root, owner.pass, holder.pub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := key.Derive(ck, holder.priv, holder.pub, key.LimitHold(hour/6, hour/2))
	if err != nil {
		t.Fatal(err)
	}
	const heldAt, na = 10 * hour, 20 * hour
	ek, err := key.Derive(ck, holder.priv, holder.pub, key.LimitExpires(na))
	if err != nil {
		t.Fatal(err)
	}
	due := heldAt + hour/6
	held := kernel.Dispatch{Held: true, HeldAt: heldAt}
	for _, c := range []struct {
		name  string
		k     key.Key
		now   int64
		reads [2]int64
		bad   string
	}{
		{"earliest a millisecond short of the due", hk, due, [2]int64{due - 1, due}, "a hold ended before its due by the earliest reading"},
		{"earliest at the due", hk, due, [2]int64{due, due}, ""},
		{"latest at the expiry", ek, na - 1, [2]int64{na - 1, na}, "effect under a key once a reading passed its expiry"},
		{"latest a millisecond short of the expiry", ek, na - 1, [2]int64{na - 1, na - 1}, ""},
	} {
		now, reads := c.now, c.reads
		w := &world{anchors: []key.PublicKey{owner.pk}, now: &now, reads: &reads, done: map[string]bool{}, dead: map[key.ID]bool{}}
		p := kernel.SignPlan(kernel.Plan{ID: "e", Key: c.k, Steps: []kernel.PlanStep{{Verb: key.Post, Clerk: "mail", Args: map[string]string{"to": "alice", "msg": "hi"}}}}, holder.priv)
		w.judge(kernel.Request{Plan: p}, heldView{held})
		if want := c.bad != ""; want != (len(w.bad) == 1) || want && w.bad[0] != c.bad || !want && len(w.bad) > 0 {
			t.Errorf("%s: judged %q", c.name, w.bad)
		}
	}
}
