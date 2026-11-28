package sim

// REQ: EVL-1, KRN-5, KRN-7, KRN-8, KEY-7

import (
	"math"
	"math/bits"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// knobView is a log that says what each case sets and nothing else: every
// key granted long ago unless ungranted, the step in flight unless idle.
type knobView struct {
	ungranted, idle bool
	ch              key.Changes
}

func (v knobView) Granted(key.ID) (int64, bool)                   { return -kernel.GrantHold, !v.ungranted }
func (knobView) Enrollments() ([]key.Enrollment, []key.PublicKey) { return nil, nil }
func (v knobView) ChangesView() *key.Changes                      { return &v.ch }
func (knobView) LedgerBefore(uint64) key.Ledger                   { return noUses{} }
func (v knobView) Dispatched(kernel.Request) (kernel.Dispatch, bool) {
	return kernel.Dispatch{}, !v.idle
}
func (knobView) OneOffLine(key.ID, int64) int64         { return 0 }
func (knobView) Task(string, int64) (kernel.Task, bool) { return kernel.Task{}, false }

// noUses is a ledger with nothing charged.
type noUses struct{}

func (noUses) Uses(key.ID) []key.Use { return nil }

// rig is one owner's mail root with its clerk key, and a world judging on
// the true clock now.
type rig struct {
	owner, holder keyPair
	ck            key.Key
	now           int64
	w             *world
}

func newRig(t *testing.T, verbs ...key.Verb) *rig {
	t.Helper()
	rng := rand.New(rand.NewPCG(5, 6))
	r := &rig{owner: gen(rng), holder: gen(rng), now: 10 * hour}
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: verbs, Serial: "w1"})
	ck, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	r.ck = ck
	r.w = &world{anchors: []key.PublicKey{r.owner.pk}, now: &r.now, reads: &[2]int64{math.MinInt64, math.MinInt64},
		done: map[string]bool{}, dead: map[key.ID]bool{}}
	return r
}

// req is plan id's one step, verb v to "alice", under k, signed by the home clerk.
func (r *rig) req(id string, k key.Key, v key.Verb) kernel.Request {
	st := kernel.PlanStep{Verb: v, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(v) {
		st.Args[n] = "alice"
	}
	return kernel.Request{Plan: kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{st}}, r.holder.priv)}
}

// The world's judge names each invariant an effect breaks, one planted at a
// time, and nothing for an effect that breaks none: the oracle the whole
// sweep rests on, shown to fire (KRN-5, KRN-7, KRN-8, KEY-7).
func TestTheWorldJudgesEachPlantedViolation(t *testing.T) {
	stranger := gen(rand.New(rand.NewPCG(7, 8)))
	for _, c := range []struct {
		name string
		want string // "" for no finding
		run  func(r *rig)
	}{
		{"a clean effect", "", func(r *rig) { r.w.judge(r.req("p", r.ck, key.Post), knobView{}) }},
		{"one request twice", "effect twice for ", func(r *rig) {
			q := r.req("p", r.ck, key.Trash)
			r.w.judge(q, knobView{})
			r.w.judge(q, knobView{})
		}},
		{"a widening the anchor never confirmed", "effect on a widening the anchor never confirmed", func(r *rig) {
			r.w.unconfirmed = true
			r.w.judge(r.req("p", r.ck, key.Post), knobView{})
		}},
		{"a key its submitter does not hold", "effect under an invalid key or one its submitter does not hold", func(r *rig) {
			q := r.req("p", r.ck, key.Post)
			q.Plan = kernel.SignPlan(q.Plan, stranger.priv)
			r.w.judge(q, knobView{})
			if len(r.w.effects) != 1 || r.w.effects[0].fp != "" || len(r.w.bad) != 1 {
				r.w.bad = append(r.w.bad, "an invalid key's effect must be recorded without a fingerprint, and judged no further")
			}
		}},
		{"the same irreversible effect in two plans within a day", "the same irreversible effect twice within a day, across plans", func(r *rig) {
			r.w.judge(r.req("p1", r.ck, key.Post), knobView{})
			r.now += key.DayMS - 1
			r.w.judge(r.req("p2", r.ck, key.Post), knobView{})
		}},
		{"the same irreversible effect a day apart", "", func(r *rig) {
			r.w.judge(r.req("p1", r.ck, key.Post), knobView{})
			r.now += key.DayMS
			r.w.judge(r.req("p2", r.ck, key.Post), knobView{})
		}},
		{"the same reversible effect in two plans", "", func(r *rig) {
			r.w.judge(r.req("p1", r.ck, key.Trash), knobView{})
			r.w.judge(r.req("p2", r.ck, key.Trash), knobView{})
		}},
		{"during STOP", "effect during STOP", func(r *rig) {
			r.w.judge(r.req("p", r.ck, key.Post), knobView{ch: key.Changes{Stopped: true}})
		}},
		{"under a revoked key", "effect under a revoked key", func(r *rig) {
			r.w.judge(r.req("p", r.ck, key.Post), knobView{ch: key.Changes{Revoked: map[key.ID]bool{r.ck.Tip(): true}}})
		}},
		{"under a grant cancelled with its phone", "effect under a grant cancelled with its cut-off phone", func(r *rig) {
			r.w.dead[r.ck.Tip()] = true
			r.w.judge(r.req("p", r.ck, key.Post), knobView{})
		}},
		{"under a key a cut-off phone narrowed", "effect under a key a cut-off phone narrowed", func(r *rig) {
			nk, err := key.Narrow(r.ck, r.owner.pass, key.LimitUses(1))
			if err != nil {
				panic(err)
			}
			r.w.cut = []key.PublicKey{r.owner.pk}
			r.w.judge(r.req("p", nk, key.Post), knobView{})
		}},
		{"under a grant not in the log", "effect under a grant not in the log or still in its hold", func(r *rig) {
			r.w.judge(r.req("p", r.ck, key.Post), knobView{ungranted: true})
		}},
		{"with a verb outside the key", "effect with a verb outside the key", func(r *rig) {
			r.w.judge(r.req("p", r.ck, key.Send), knobView{})
		}},
		{"for a step not in flight", "effect for a step the log does not have in flight", func(r *rig) {
			r.w.judge(r.req("p", r.ck, key.Post), knobView{idle: true})
		}},
		{"once a reading passed the key's expiry", "effect under a key once a reading passed its expiry", func(r *rig) {
			r.w.reads[1] = 1 << 40
			r.w.judge(r.req("p", r.ck, key.Post), knobView{})
		}},
	} {
		r := newRig(t, key.Post, key.Trash)
		c.run(r)
		switch {
		case c.want == "" && len(r.w.bad) != 0:
			t.Errorf("%s: judged %q, want nothing", c.name, r.w.bad)
		case c.want != "" && (len(r.w.bad) == 0 || !strings.HasPrefix(r.w.bad[len(r.w.bad)-1], c.want)):
			t.Errorf("%s: judged %q, want %q last", c.name, r.w.bad, c.want)
		}
	}
}

// script is a random source that answers each IntN in turn with the pick
// the test wrote for it, {n, k} for IntN(n) == k, and fails a draw it did
// not write: so a test fixes, and checks, every draw a step makes.
type script struct {
	t     *testing.T
	picks [][2]uint64
}

func (s *script) Uint64() uint64 {
	if len(s.picks) == 0 {
		s.t.Fatal("a draw the script did not write")
	}
	n, k := s.picks[0][0], s.picks[0][1]
	s.picks = s.picks[1:]
	if n&(n-1) == 0 {
		return k
	}
	q, _ := bits.Div64(k, 0, n) // the least x with x*n >= k<<64, less one
	return q + 1 + 1<<32
}

func (s *script) done() {
	if len(s.picks) != 0 {
		s.t.Errorf("%d scripted draws never made", len(s.picks))
	}
}

func scripted(t *testing.T, w *world, picks ...[2]uint64) *script {
	s := &script{t: t, picks: picks}
	w.rng = rand.New(s)
	return s
}

// Each twentieth draw is a refusal, a drop and a lost answer, one each, and
// the rest no fault (EVL-1's dropped and duplicated responses).
func TestTheWorldsFaultsAreOneTwentiethEach(t *testing.T) {
	w := &world{}
	for n := uint64(0); n < 20; n++ {
		want := clerk.FaultNone
		switch n {
		case 0:
			want = clerk.FaultFail
		case 1:
			want = clerk.FaultDrop
		case 2:
			want = clerk.FaultLostAck
		}
		s := scripted(t, w, [2]uint64{20, n})
		if got := w.fault("do"); got != want {
			t.Errorf("draw %d: fault %q, want %q", n, got, want)
		}
		s.done()
	}
}

// The transport delivers a request twice one time in ten: a clerk that
// forgets the keys it ran acts twice, and the world says so (KRN-8).
func TestTheWorldDeliversTwice(t *testing.T) {
	r := newRig(t, key.Post, key.Trash)
	r.w.mutant = MutantNoDedupe
	s := scripted(t, r.w, [2]uint64{20, 19}, [2]uint64{10, 0}, [2]uint64{20, 19})
	if res := r.w.Do(r.req("p", r.ck, key.Trash), knobView{}); res.Outcome != "ok" {
		t.Fatalf("got %+v", res)
	}
	s.done()
	if !slices.ContainsFunc(r.w.bad, func(b string) bool { return strings.HasPrefix(b, "effect twice for ") }) {
		t.Fatalf("judged %q, want the second effect", r.w.bad)
	}
}

// An old request redelivered out of order counts as turned away when the
// clerk answers it done already or refuses it on its check, not when a fault
// failed or dropped it; the world keeps the first 16 requests it saw to
// redeliver.
func TestTheWorldCountsTheStaleRequestsItTurnsAway(t *testing.T) {
	for _, c := range []struct {
		name  string
		bad   bool   // the old request's key is broken
		ran   bool   // the old request ran before
		fault uint64 // its fault draw when it runs now
		stale int
	}{
		{"done already", false, true, 0, 1},
		{"refused on its check", true, false, 0, 1},
		{"failed by a fault", false, false, 0, 0},
		{"dropped", false, false, 1, 0},
	} {
		r := newRig(t, key.Post, key.Trash)
		old := r.req("old", r.ck, key.Trash)
		if c.bad {
			old.Plan = kernel.SignPlan(old.Plan, gen(rand.New(rand.NewPCG(9, 9))).priv)
		}
		picks := [][2]uint64{{20, 19}, {10, 9}, {10, 0}, {1, 0}}
		if c.ran {
			s := scripted(t, r.w, [2]uint64{20, 19})
			r.w.mail = r.w.newMail()
			r.w.do(old, knobView{})
			s.done()
		} else if !c.bad {
			picks = append(picks, [2]uint64{20, c.fault})
		}
		s := scripted(t, r.w, picks...)
		if r.w.mail == nil {
			r.w.mail = r.w.newMail()
		}
		r.w.seen = []kernel.Request{old}
		r.w.Do(r.req("p", r.ck, key.Trash), knobView{})
		s.done()
		if r.w.stale != c.stale || len(r.w.seen) != 2 {
			t.Errorf("%s: %d stale and %d seen, want %d and 2", c.name, r.w.stale, len(r.w.seen), c.stale)
		}
	}
	r := newRig(t, key.Post, key.Trash)
	r.w.mail = r.w.newMail()
	for i := range 16 {
		r.w.seen = append(r.w.seen, r.req(string(rune('a'+i)), r.ck, key.Trash))
	}
	s := scripted(t, r.w, [2]uint64{20, 19}, [2]uint64{10, 9}, [2]uint64{10, 9})
	r.w.Do(r.req("p", r.ck, key.Trash), knobView{})
	s.done()
	if len(r.w.seen) != 16 {
		t.Errorf("%d seen, want the first 16 kept", len(r.w.seen))
	}
}

// The trusting mutant acts on the kernel's word alone: its world answers ok
// for a request the real clerk would refuse, and judges the effect.
func TestTheTrustingClerkActsOnTheKernelsWord(t *testing.T) {
	r := newRig(t, key.Post, key.Trash)
	r.w.mutant = MutantClerkTrusts
	r.w.mail = r.w.newMail()
	q := r.req("p", r.ck, key.Trash)
	q.Plan = kernel.SignPlan(q.Plan, gen(rand.New(rand.NewPCG(9, 9))).priv)
	s := scripted(t, r.w)
	if res := r.w.do(q, knobView{}); res.Outcome != "ok" || len(r.w.bad) != 1 {
		t.Fatalf("got %+v, judged %q", res, r.w.bad)
	}
	s.done()
}
