package loops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: LOOP-4, LOOP-6, CHG-1, OP-7
//
// Loop 1 on a real journal and change pipeline: owner outcomes become
// verdicts and held-out cases; the journal is mined for failures,
// corrections, slow and expensive steps, and repeated trajectories; a
// builder sees only the dev split and tasks with no held-out case; and the
// only way a candidate takes effect is through the pipeline.

type builder struct {
	mu     sync.Mutex
	briefs []Brief
	files  map[string][]byte
	err    error
}

func (b *builder) Build(_ context.Context, br Brief) (change.Candidate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.briefs = append(b.briefs, br)
	if b.err != nil {
		return change.Candidate{}, b.err
	}
	// A builder may claim anything; Loop 1 overrides what is the broker's.
	return change.Candidate{Source: change.Upstream, Origin: "builder", Public: true, Files: b.files}, nil
}

func (b *builder) got() []Brief {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Brief(nil), b.briefs...)
}

func (r *rig) harvester() *Harvester {
	return &Harvester{J: r.eng, Pipeline: r.p, Store: &change.MemStore{}}
}

// corrected journals a task in its own goal whose draft the owner edited
// from v1 to v2, and harvests it.
func (r *rig) corrected(h *Harvester, n int) {
	r.t.Helper()
	id := fmt.Sprintf("draft-%d", n)
	r.task(id, fmt.Sprintf("g%d", n), "mail", "draft", "private")
	must(r.t, h.Harvest(Outcome{Intent: id, Action: Edited, Input: []byte("procedures/mail"),
		Output: []byte("v1"), Correction: []byte("v2")}))
}

func TestOwnerOutcomesBecomeVerdictsAndCases(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	acts := []Action{Approved, Edited, Denied, Undone}
	for i, a := range acts {
		id := fmt.Sprintf("t%d", i)
		r.task(id, "g"+id, "mail", "send", "private")
		must(t, h.Harvest(Outcome{Intent: id, Action: a, Input: []byte("reply to Sam"), Output: []byte("ok"), Correction: []byte("fixed")}))
		st, err := r.eng.Get(id)
		must(t, err)
		want := journal.VerdictWrong
		if a == Approved {
			want = journal.VerdictGood
		}
		if st.Quality.Verdict != want || st.Quality.Source != "owner" {
			t.Fatalf("%s: quality %+v", a, st.Quality)
		}
	}
	ev, err := h.Evidence()
	must(t, err)
	if ev.HeldOut+len(ev.Dev) != len(acts) {
		t.Fatalf("held out %d + dev %d, want %d cases", ev.HeldOut, len(ev.Dev), len(acts))
	}
	for _, c := range ev.Dev {
		if c.Class != change.ClassTask {
			t.Fatalf("dev case class %s", c.Class)
		}
	}
	r.task("t9", "g9", "mail", "send", "private")
	if err := h.Harvest(Outcome{Intent: "t9", Action: Edited, Input: []byte("x"), Output: []byte("y")}); !errors.Is(err, ErrAction) {
		t.Fatalf("an edit with no correction: %v", err)
	}
	if err := h.Harvest(Outcome{Intent: "nope", Action: Approved, Input: []byte("x")}); err == nil {
		t.Fatal("outcome on an intent that does not exist")
	}
}

func TestMinerFindsTheLoop4Signals(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	// Failures: an effect that did not happen.
	r.tasks.out["pay-1"] = journal.ResultNotApplied
	r.task("pay-1", "f1", "bank", "pay", "private")
	// Slow steps, twice.
	r.tasks.delay["book-1"], r.tasks.delay["book-2"] = 5*time.Minute, 4*time.Minute
	r.task("book-1", "s1", "calendar", "book", "private")
	r.task("book-2", "s2", "calendar", "book", "private")
	// A repeated trajectory over three tasks.
	for i := 0; i < 3; i++ {
		g := fmt.Sprintf("rep%d", i)
		r.task(g+"-a", g, "mail", "search", "private")
		r.task(g+"-b", g, "mail", "label", "private")
	}
	// An owner correction.
	r.corrected(h, 1)
	cost := map[string]int64{"goal:f1": 100, "goal:s1": 100, "goal:s2": 100, "goal:rep0": 2000}
	l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h,
		Cost: func(k string) (int64, bool) { c, ok := cost[k]; return c, ok }})
	must(t, err)
	ev, err := h.Evidence()
	must(t, err)
	got := map[string]change.Class{}
	for _, hy := range l.mine(ev) {
		got[hy.Key] = hy.Class
		for _, k := range hy.Tasks {
			if ev.Held(k) {
				t.Fatalf("hypothesis %s cites held-out task %s", hy.Key, k)
			}
		}
	}
	want := map[string]change.Class{
		"failure:bank/pay":              change.ClassProcedure,
		"slow:calendar/book":            change.ClassSkill,
		"repeat:mail/search>mail/label": change.ClassSkill,
		"expensive:mail/search":         change.ClassContext,
	}
	if !ev.Held("goal:g1") {
		want["correction:mail/draft"] = change.ClassProcedure
	}
	for k, c := range want {
		if got[k] != c {
			t.Errorf("missing %s (%s); mined %v", k, c, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("mined %v, want %v", got, want)
	}
}

func TestLoop1WaitsForEvidenceThenAdoptsThroughThePipeline(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	b := &builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}
	l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h, Builder: b, Now: r.clk.now})
	must(t, err)
	r.restart(l)
	h.Wake = r.s.Wake

	n := 0
	for {
		ev, err := h.Evidence()
		must(t, err)
		if ev.HeldOut == 4 && len(ev.Dev) > 0 {
			break
		}
		n++
		r.corrected(h, n)
	}
	if ran, _ := r.s.Tick(context.Background()); ran {
		t.Fatal("Loop 1 proposed with 4 held-out cases")
	}
	if d := strings.Join(r.s.Digest(), "\n"); !strings.Contains(d, "waiting for more of your past tasks to test against (4/5)") {
		t.Fatalf("digest does not say Loop 1 is waiting: %q", d)
	}
	if r.ev.runs() != 0 {
		t.Fatal("evaluated while waiting for evidence")
	}
	for ev, _ := h.Evidence(); ev.HeldOut < 5; ev, _ = h.Evidence() {
		n++
		r.corrected(h, n)
	}
	if ran, _ := r.s.Tick(context.Background()); !ran {
		t.Fatal("Loop 1 did nothing with enough evidence")
	}
	if got := r.p.Files("procedures")["procedures/mail"]; string(got) != "v2" {
		t.Fatalf("procedure is %q after Loop 1's candidate", got)
	}
	ads := r.p.Adoptions()
	if len(ads) != 1 || ads[0].Basis != change.BasisStanding || ads[0].Origin != "loop1" || ads[0].Public || ads[0].Source != change.Local {
		t.Fatalf("adoption %+v", ads)
	}
	if sh := r.s.Share()[Improve]; sh != 1 {
		t.Fatalf("Loop 1's measured share %v after a gain", sh)
	}
	// Every brief held dev cases only and no held-out task.
	ev, _ := h.Evidence()
	for _, br := range b.got() {
		dev := map[string]bool{}
		for _, c := range ev.Dev {
			dev[c.ID] = true
		}
		for _, c := range br.Dev {
			if !dev[c.ID] || c.Expect == nil && c.Outcome == "" {
				t.Fatalf("brief carries non-dev case %s", c.ID)
			}
		}
		for _, s := range br.Hypothesis.Evidence {
			if ev.Held(TaskKey(s.Intent)) {
				t.Fatalf("brief carries held-out task %s", s.Intent.ID)
			}
		}
	}
	if len(b.got()) != 1 {
		t.Fatalf("%d builds, want 1", len(b.got()))
	}
	// The same hypothesis is not tried again until more evidence arrives.
	if ran, _ := r.s.Tick(context.Background()); ran {
		t.Fatal("tried the same hypothesis again with no new evidence")
	}
}

func TestCandidatesOutsideTheirClassNeverReachThePipeline(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	n := 0
	for _, files := range []map[string][]byte{
		{"budget/spare.json": []byte(`{"calls":5000}`)},
		{"suites/drop": []byte("x")},
		{"skills/greet": []byte("hello")}, // a procedure hypothesis may not write skills
	} {
		b := &builder{files: files}
		l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h, Builder: b, MinHeldOut: 1})
		must(t, err)
		for i := 0; i < 8; i++ {
			n++
			r.corrected(h, n)
		}
		job, ok := l.Next(context.Background(), true)
		if !ok {
			t.Fatal("no job offered")
		}
		res := job.Run(context.Background())
		if !errors.Is(res.Err, ErrOutOfClass) || res.Value != 0 {
			t.Fatalf("%v: result %+v", files, res)
		}
	}
	if r.ev.runs() != 0 || len(r.p.Adoptions()) != 0 {
		t.Fatalf("an out-of-class candidate was evaluated (%d runs)", r.ev.runs())
	}
}

// fakePipeline records what Loop 1 asks of the pipeline.
type fakePipeline struct {
	mu       sync.Mutex
	routing  int
	rechecks int
}

func (f *fakePipeline) Propose(context.Context, change.Candidate) (change.Report, error) {
	return change.Report{State: change.StateRejected}, nil
}
func (f *fakePipeline) ProposeRouting(context.Context, change.Router) (change.Report, bool, error) {
	f.mu.Lock()
	f.routing++
	f.mu.Unlock()
	return change.Report{State: change.StateAdopted, Score: change.Score{Passed: 6, BaselinePassed: 5}}, true, nil
}
func (f *fakePipeline) Adoptions() []change.Adoption {
	return []change.Adoption{{ID: "c1"}}
}
func (f *fakePipeline) Recheck(context.Context) ([]string, error) {
	f.mu.Lock()
	f.rechecks++
	f.mu.Unlock()
	return []string{"c1"}, nil
}

type router struct{ active, cand route.Rule }

func (r *router) Rule() route.Rule           { return r.active }
func (r *router) SetRule(x route.Rule) error { r.active = x; return nil }
func (r *router) Candidate() route.Rule      { return r.cand }

func TestRoutingCandidatesNeedLiveReplay(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	for i := 1; i <= 12; i++ {
		r.corrected(h, i)
	}
	fp := &fakePipeline{}
	rt := &router{active: route.Rule{"chat": {{Provider: "openai", Model: "a"}, {Provider: "anthropic", Model: "b"}}},
		cand: route.Rule{"chat": {{Provider: "anthropic", Model: "b"}, {Provider: "openai", Model: "a"}}}}
	cfg := LearnConfig{Pipeline: fp, Journal: r.eng, Harvest: h, Router: rt, RecheckCases: 1000, Now: r.clk.now}
	l, err := NewLearn(cfg)
	must(t, err)
	if job, ok := l.Next(context.Background(), true); ok {
		t.Fatalf("offline replay: offered %s", job.Name)
	}
	cfg.ModelWired = true
	l, err = NewLearn(cfg)
	must(t, err)
	if _, ok := l.Next(context.Background(), false); ok {
		t.Fatal("offered evaluation with no spare budget")
	}
	job, ok := l.Next(context.Background(), true)
	if !ok || job.Name != "routing" || !job.UsesModel {
		t.Fatalf("job %+v, %v", job, ok)
	}
	if res := job.Run(context.Background()); res.Value != 1.25 || fp.routing != 1 {
		t.Fatalf("routing result %+v, proposals %d", res, fp.routing)
	}
	if _, ok := l.Next(context.Background(), true); ok {
		t.Fatal("same routing rule offered again with no new evidence")
	}
}

func TestRecheckRunsWhenNewEvidenceArrives(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	fp := &fakePipeline{}
	l, err := NewLearn(LearnConfig{Pipeline: fp, Journal: r.eng, Harvest: h, Now: r.clk.now})
	must(t, err)
	n := 0
	held := func() int { ev, _ := h.Evidence(); return ev.HeldOut }
	for held() < 4 {
		n++
		r.corrected(h, n)
	}
	if _, ok := l.Next(context.Background(), true); ok {
		t.Fatal("recheck before 5 new held-out cases")
	}
	for held() < 5 {
		n++
		r.corrected(h, n)
	}
	job, ok := l.Next(context.Background(), true)
	if !ok || job.Name != "recheck" {
		t.Fatalf("job %+v, %v", job, ok)
	}
	if res := job.Run(context.Background()); res.Value != 1 || fp.rechecks != 1 {
		t.Fatalf("recheck result %+v", res)
	}
	if _, ok := l.Next(context.Background(), true); ok {
		t.Fatal("recheck offered again with no new evidence")
	}
	// One more case, and a week later, it runs again.
	for held() < 6 {
		n++
		r.corrected(h, n)
	}
	r.clk.add(8 * 24 * time.Hour)
	if job, ok := l.Next(context.Background(), true); !ok || job.Name != "recheck" {
		t.Fatal("weekly recheck not offered")
	}
}

// askPipeline answers every proposal with "waiting on the owner".
type askPipeline struct {
	fakePipeline
	proposals int
}

func (a *askPipeline) Propose(context.Context, change.Candidate) (change.Report, error) {
	a.mu.Lock()
	a.proposals++
	a.mu.Unlock()
	return change.Report{State: change.StateAwaitingOwner}, nil
}

func TestALapsedOwnerRequestBacksOffThenStops(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	n := 0
	more := func(k int) {
		for i := 0; i < k; i++ {
			n++
			r.corrected(h, n)
		}
	}
	more(12)
	ap := &askPipeline{}
	b := &builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}
	l, err := NewLearn(LearnConfig{Pipeline: ap, Journal: r.eng, Harvest: h, Builder: b, RecheckCases: 1000,
		RecheckEvery: 365 * 24 * time.Hour, Now: r.clk.now})
	must(t, err)
	run := func() bool {
		job, ok := l.Next(context.Background(), true)
		if ok {
			job.Run(context.Background())
		}
		return ok
	}
	if !run() || ap.proposals != 1 {
		t.Fatal("first proposal not made")
	}
	// New evidence, but the owner was just asked: wait for the backoff.
	more(4)
	if run() {
		t.Fatal("re-proposed inside the backoff")
	}
	r.clk.add(25 * time.Hour)
	if !run() || ap.proposals != 2 {
		t.Fatal("not re-proposed after the backoff")
	}
	// After two lapsed asks it is not proposed again, however long.
	more(4)
	r.clk.add(30 * 24 * time.Hour)
	if run() {
		t.Fatal("proposed a third time; it should wait in the digest")
	}
}

func TestBuildersAreChosenBySignal(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	for i := 1; i <= 12; i++ {
		r.corrected(h, i)
	}
	skills := &builder{files: map[string][]byte{"skills/x": []byte("y")}}
	l, err := NewLearn(LearnConfig{Pipeline: &fakePipeline{}, Journal: r.eng, Harvest: h, RecheckCases: 1000,
		Builder: BySignal{SignalRepeat: skills}})
	must(t, err)
	// Only correction hypotheses exist; the repeat-only builder gets none.
	if job, ok := l.Next(context.Background(), true); ok {
		t.Fatalf("offered %s with no builder for its signal", job.Name)
	}
	for i := 0; i < 3; i++ {
		g := fmt.Sprintf("rep%d", i)
		r.task(g+"-a", g, "mail", "search", "private")
		r.task(g+"-b", g, "mail", "label", "private")
	}
	job, ok := l.Next(context.Background(), true)
	if !ok {
		t.Fatal("repeat hypothesis not offered to its builder")
	}
	job.Run(context.Background())
	if got := skills.got(); len(got) != 1 || got[0].Hypothesis.Signal != SignalRepeat {
		t.Fatalf("briefs %+v", got)
	}
}
