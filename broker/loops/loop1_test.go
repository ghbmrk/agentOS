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
	"github.com/ghbmrk/agentos/broker/skill"
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
	if d := strings.Join(r.s.Digest(), "\n"); !strings.Contains(d, "waiting until there are 5 past tasks to test them on (4 so far)") {
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

// notReady is a builder whose evidence cannot yield a candidate yet.
type notReady struct {
	builder
	ready bool
}

func (b *notReady) Ready(Brief) bool { return b.ready }

// LOOP-3, L10: a builder that is not ready for a hypothesis gets no job, so
// nothing is measured against Loop 1 (no dry run toward parking); the
// hypothesis waits for more supporting tasks.
func TestNotReadyWaitsForMoreTasks(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	b := &notReady{builder: builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}}
	l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h, Builder: b, MinHeldOut: 1})
	must(t, err)
	n := 0
	for i := 0; i < 8; i++ {
		n++
		r.corrected(h, n)
	}
	if job, ok := l.Next(context.Background(), true); ok {
		t.Fatalf("offered %s while the builder was not ready", job.Name)
	}
	b.ready = true
	if _, ok := l.Next(context.Background(), true); ok {
		t.Fatal("offered again with no new supporting task")
	}
	// Held-out tasks never support a hypothesis, so add tasks until one
	// lands in its evidence.
	var job Job
	ok := false
	for i := 0; i < 20 && !ok; i++ {
		n++
		r.corrected(h, n)
		job, ok = l.Next(context.Background(), true)
	}
	if !ok || job.Name != "candidate" {
		t.Fatalf("no candidate after new supporting tasks: %v %v", job.Name, ok)
	}
	if len(b.got()) != 0 {
		t.Fatal("Build ran before the job")
	}
}

// skillFile is a valid one-step skill or procedure file for account,
// with the shape its content gives.
func skillFile(t *testing.T, kind skill.Kind, account string) (shape string, b []byte) {
	t.Helper()
	sk := &skill.Skill{Version: skill.Version, Kind: kind, ID: "k000000000000", Runs: 1,
		Slots: []skill.Slot{{Name: "to", Type: skill.Email, Max: 64}},
		Steps: []skill.Step{{Account: account, Action: "send", Recipients: []skill.Node{{Slot: "to"}}}}}
	shape = sk.Shape()
	sk.ID = "k" + shape
	if kind == skill.KindProcedure {
		sk.ID = "p" + shape
	}
	if err := sk.Validate(); err != nil {
		t.Fatal(err)
	}
	return shape, sk.Encode()
}

// CAP-5: a skill candidate may delete the procedure it replaces, but may
// not write there, and no other class may delete outside its namespace.
// "Replaces" is the shape the skill file's own steps give, not its name
// (P3-6e, security R1 on #74).
func TestSkillMaySupersedeItsProcedure(t *testing.T) {
	s1, b1 := skillFile(t, skill.KindSkill, "mail")
	s2, b2 := skillFile(t, skill.KindSkill, "chat")
	_, pb := skillFile(t, skill.KindProcedure, "mail")
	k := func(s string) string { return "skills/k" + s + ".json" }
	p := func(s string) string { return "procedures/p" + s + ".json" }
	ok := change.Candidate{Files: map[string][]byte{k(s1): b1}, Delete: []string{p(s1)}}
	if err := inClass(change.ClassSkill, ok); err != nil {
		t.Fatal(err)
	}
	sk := map[string][]byte{k(s1): b1}
	for name, c := range map[string]struct {
		class change.Class
		cand  change.Candidate
	}{
		"skill writes procedures": {change.ClassSkill, change.Candidate{Files: map[string][]byte{p(s1): pb}}},
		"skill deletes budget":    {change.ClassSkill, change.Candidate{Delete: []string{"budget/spare.json"}}},
		"other shape's procedure": {change.ClassSkill, change.Candidate{Files: sk, Delete: []string{p(s2)}}},
		"procedure with no skill": {change.ClassSkill, change.Candidate{Delete: []string{p(s1)}}},
		"two skills":              {change.ClassSkill, change.Candidate{Files: map[string][]byte{k(s1): b1, k(s2): b2}, Delete: []string{p(s1)}}},
		"procedure deletes skill": {change.ClassProcedure, change.Candidate{Delete: []string{k(s1)}}},
		// The builder names the file after s1's shape, but its steps are s2's.
		"skill renamed to another shape": {change.ClassSkill, change.Candidate{Files: map[string][]byte{k(s1): b2}, Delete: []string{p(s1)}}},
		"skill file not a skill":         {change.ClassSkill, change.Candidate{Files: map[string][]byte{k(s1): []byte("{}")}, Delete: []string{p(s1)}}},
		"procedure file under skills":    {change.ClassSkill, change.Candidate{Files: map[string][]byte{k(s1): pb}, Delete: []string{p(s1)}}},
	} {
		if err := inClass(c.class, c.cand); !errors.Is(err, ErrOutOfClass) {
			t.Errorf("%s: %v", name, err)
		}
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
	// (Thirteen tasks, so one lands in dev outside the next goal of a
	// held-out task, which mining also skips; the split is deterministic.)
	more(13)
	if run() {
		t.Fatal("re-proposed inside the backoff")
	}
	r.clk.add(25 * time.Hour)
	if !run() || ap.proposals != 2 {
		t.Fatal("not re-proposed after the backoff")
	}
	// After two lapsed asks it is not proposed again, however long, even
	// with new mined evidence (so the stop, not a lack of evidence, holds
	// it back).
	mined := func() int {
		ev, err := h.Evidence()
		must(t, err)
		n := 0
		for _, hy := range l.mine(ev) {
			if hy.Key == "correction:mail/draft" {
				n = len(hy.Tasks)
			}
		}
		return n
	}
	before := mined()
	for i := 0; i < 40 && mined() <= before; i++ {
		more(1)
	}
	if mined() <= before {
		t.Fatal("no new mined evidence for the third round")
	}
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

// cases captures what Harvest adds.
type cases struct{ got []change.Case }

func (c *cases) AddTaskCase(x change.Case) error { c.got = append(c.got, x); return nil }
func (c *cases) Dev(change.Class) []change.Case  { return nil }

func TestHarvestNeverWidensTheJournalLabel(t *testing.T) {
	r := newRig(t)
	cs := &cases{}
	h := &Harvester{J: r.eng, Pipeline: cs, Store: &change.MemStore{}}
	r.task("priv", "gp", "mail", "send", "private")
	r.task("pub", "gq", "mail", "send", "public")
	r.task("pub2", "gr", "mail", "send", "public")
	must(t, h.Harvest(Outcome{Intent: "priv", Action: Approved, Input: []byte("x"), Output: []byte("y"), Public: true}))
	must(t, h.Harvest(Outcome{Intent: "pub", Action: Approved, Input: []byte("x"), Output: []byte("y"), Public: true}))
	must(t, h.Harvest(Outcome{Intent: "pub2", Action: Approved, Input: []byte("x"), Output: []byte("y")}))
	want := map[string]bool{"priv": false, "pub": true, "pub2": false}
	for _, c := range cs.got {
		if c.Public != want[c.ID] {
			t.Fatalf("case %s public=%v", c.ID, c.Public)
		}
	}
	if len(cs.got) != 3 {
		t.Fatalf("%d cases", len(cs.got))
	}
}

// failSecond saves once, then fails: a crash between the harvester's two
// writes.
type failSecond struct {
	change.MemStore
	n int
}

func (f *failSecond) Save(b []byte) error {
	f.n++
	if f.n > 1 {
		return errors.New("disk gone")
	}
	return f.MemStore.Save(b)
}

func TestACrashMidHarvestStillKeepsTheTaskFromTheBuilder(t *testing.T) {
	r := newRig(t)
	st := &failSecond{}
	h := &Harvester{J: r.eng, Pipeline: r.p, Store: st}
	// Find a task whose case lands held out, so it must never be mined.
	var id string
	for i := 0; ; i++ {
		id = fmt.Sprintf("crash-%d", i)
		r.task(id, "gc"+id, "mail", "draft", "private")
		st.n = 0
		err := h.Harvest(Outcome{Intent: id, Action: Edited, Input: []byte("procedures/mail"), Output: []byte("v1"), Correction: []byte("v2")})
		if err == nil {
			t.Fatal("second save did not fail")
		}
		dev := false
		for _, c := range r.p.Dev(change.ClassTask) {
			dev = dev || c.ID == id
		}
		if !dev {
			break
		}
	}
	// The box restarts: a fresh harvester over what was saved.
	h2 := &Harvester{J: r.eng, Pipeline: r.p, Store: &st.MemStore}
	ev, err := h2.Evidence()
	must(t, err)
	if !ev.Held("goal:gc" + id) {
		t.Fatal("a held-out task the pipeline holds is not excluded from mining after a crash")
	}
	if ev.HeldOut != 0 {
		t.Fatalf("an unconfirmed case counted as evidence: %d", ev.HeldOut)
	}
	// Retrying the harvest completes it.
	must(t, h2.Harvest(Outcome{Intent: id, Action: Edited, Input: []byte("procedures/mail"), Output: []byte("v1"), Correction: []byte("v2")}))
	if ev, _ := h2.Evidence(); ev.HeldOut != 1 {
		t.Fatalf("after retry: held out %d", ev.HeldOut)
	}
}

// TestAHeldOutGoalsWorkIsNotMinedWhereverItLanded: a held-out task's work
// can land unstamped (the origin bucket), under a goal that ran while it
// was active, or under the goal that came after it (guest G14). None is
// mined; a goal that starts later is, so one held-out case does not stop
// Loop 1 on a one-guest box (#55 B2, arbitrator).
func TestAHeldOutGoalsWorkIsNotMinedWhereverItLanded(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	var id string
	for i := 0; ; i++ {
		id = fmt.Sprintf("held-%d", i)
		r.task(id, "owner:m"+id, "mail", "draft", "private")
		must(t, h.Harvest(Outcome{Intent: id, Action: Edited, Input: []byte("procedures/mail"), Output: []byte("v1"), Correction: []byte("v2")}))
		dev := false
		for _, c := range r.p.Dev(change.ClassTask) {
			dev = dev || c.ID == id
		}
		if !dev {
			break
		}
	}
	for _, x := range []struct{ id, goal, action string }{
		{"loose", "", "refund"},             // unstamped: the origin bucket
		{"during", "owner:mC", "send"},      // C runs inside A's span
		{"a-again", "owner:m" + id, "file"}, // A is still active
		{"trail", "owner:mB", "pay"},        // the goal after A: may be A's trailing work
		{"later", "owner:mD", "move"},       // starts after A's span and the goal after it
	} {
		r.tasks.out[x.id] = journal.ResultNotApplied
		r.task(x.id, x.goal, "bank", x.action, "private")
	}
	l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h})
	must(t, err)
	ev, err := h.Evidence()
	must(t, err)
	got := map[string]bool{}
	for _, hy := range l.mine(ev) {
		got[hy.Key] = true
	}
	if got["failure:bank/refund"] || got["failure:bank/pay"] || got["failure:bank/send"] || got["failure:bank/file"] {
		t.Fatalf("held-out work was mined: %v", got)
	}
	if !got["failure:bank/move"] {
		t.Fatalf("a later task of the lineage was not mined: %v", got)
	}
}

// heldCase journals intents of goal(i) until one lands held out and
// returns its ID.
func heldCase(t *testing.T, r *rig, h *Harvester, prefix string, goal func(i int) string) string {
	t.Helper()
	for i := 0; ; i++ {
		id := fmt.Sprintf("%s-%d", prefix, i)
		r.task(id, goal(i), "mail", "draft", "private")
		must(t, h.Harvest(Outcome{Intent: id, Action: Edited, Input: []byte("procedures/mail"), Output: []byte("v1"), Correction: []byte("v2")}))
		dev := false
		for _, c := range r.p.Dev(change.ClassTask) {
			dev = dev || c.ID == id
		}
		if !dev {
			return id
		}
	}
}

// failing journals a failed intent, so mining reports it if it is mined.
func (r *rig) failing(id, goal, action string) {
	r.tasks.out[id] = journal.ResultNotApplied
	r.task(id, goal, "bank", action, "private")
}

func minedKeys(t *testing.T, r *rig, h *Harvester) map[string]bool {
	t.Helper()
	l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h})
	must(t, err)
	ev, err := h.Evidence()
	must(t, err)
	got := map[string]bool{}
	for _, hy := range l.mine(ev) {
		got[hy.Key] = true
	}
	return got
}

// TestAHeldOutUnstampedCaseHoldsTheGoalsAroundIt: a held case with no goal
// (the guest held two messages open) may be the work of the goal stamped
// just before it or of the one stamped just after it (#55 L3 round 2).
func TestAHeldOutUnstampedCaseHoldsTheGoalsAroundIt(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	r.failing("x", "owner:mX", "refund")
	heldCase(t, r, h, "none", func(int) string { return "" })
	r.failing("y", "owner:mY", "pay")
	r.failing("z", "owner:mZ", "move")
	got := minedKeys(t, r, h)
	if got["failure:bank/refund"] || got["failure:bank/pay"] {
		t.Fatalf("a goal around a held unstamped case was mined: %v", got)
	}
	if !got["failure:bank/move"] {
		t.Fatalf("a later goal was not mined: %v", got)
	}
}

// TestAHeldGoalHoldsItsNeighboursInEveryLineageItReached: a goal's work
// can land in another lineage (a CAP-8 worker stamped with its creator's
// goal); the goal after it there is held too (#55 L3 round 3).
func TestAHeldGoalHoldsItsNeighboursInEveryLineageItReached(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	g := heldCase(t, r, h, "g", func(i int) string { return fmt.Sprintf("owner:mG%d", i) })
	goal := "owner:mG" + g[len("g-"):]
	for _, x := range []struct{ id, goal, action string }{
		{"w-g", goal, "label"},          // the held goal's work in the worker
		{"w-n", "owner:mN", "pay"},      // the worker's next goal: held
		{"w-later", "owner:mL", "move"}, // clear of it: mined
	} {
		r.tasks.out[x.id] = journal.ResultNotApplied
		in := journal.Intent{ID: x.id, GoalID: x.goal, Origin: "guest:worker", Account: "bank", Action: x.action,
			Executor: "task", Machine: "worker", Label: "private"}
		if _, err := r.eng.Submit(in); err != nil {
			t.Fatal(err)
		}
		r.eng.Authorize(context.Background(), x.id)
		r.eng.Dispatch(context.Background(), x.id)
	}
	got := minedKeys(t, r, h)
	if got["failure:bank/pay"] || got["failure:bank/label"] {
		t.Fatalf("the held goal's neighbour in the worker was mined: %v", got)
	}
	if !got["failure:bank/move"] {
		t.Fatalf("a later worker goal was not mined: %v", got)
	}
}

// TestSeveralHeldGoalsEachHoldTheirNeighbours: with two held goals and
// interleaved work, each holds the goals in its span and the first after
// it; goals clear of both are mined.
func TestSeveralHeldGoalsEachHoldTheirNeighbours(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	heldCase(t, r, h, "a", func(i int) string { return fmt.Sprintf("owner:mA%d", i) })
	r.failing("p", "owner:mP", "send") // first goal after A: held
	r.failing("q", "owner:mQ", "file") // clear of A: mined
	b := heldCase(t, r, h, "b", func(i int) string { return fmt.Sprintf("owner:mB%d", i) })
	r.failing("s", "owner:mS", "post") // inside B's span: held
	r.task(b+"-again", "owner:mB"+b[len("b-"):], "mail", "label", "private")
	r.failing("u", "owner:mU", "pay")  // first goal after B: held
	r.failing("v", "owner:mV", "move") // clear of B: mined
	got := minedKeys(t, r, h)
	for _, k := range []string{"failure:bank/send", "failure:bank/post", "failure:bank/pay"} {
		if got[k] {
			t.Errorf("%s mined: %v", k, got)
		}
	}
	for _, k := range []string{"failure:bank/file", "failure:bank/move"} {
		if !got[k] {
			t.Errorf("%s not mined: %v", k, got)
		}
	}
}

// TestAHeldOutGoalAlsoHoldsItsOriginsUnstampedWork: a guest's intents with
// no goal (two messages open, none fetched yet, or after the quiet window;
// guest G14) fall into its origin bucket, which may carry a held-out
// task's own effects. So a held-out case on a goal holds that origin's
// bucket too (#55 review B2).
func TestAHeldOutGoalAlsoHoldsItsOriginsUnstampedWork(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	var id string
	for i := 0; ; i++ {
		id = fmt.Sprintf("held-%d", i)
		r.task(id, "owner:m"+id, "mail", "draft", "private")
		must(t, h.Harvest(Outcome{Intent: id, Action: Edited, Input: []byte("procedures/mail"), Output: []byte("v1"), Correction: []byte("v2")}))
		dev := false
		for _, c := range r.p.Dev(change.ClassTask) {
			dev = dev || c.ID == id
		}
		if !dev {
			break
		}
	}
	ev, err := h.Evidence()
	must(t, err)
	if !ev.Held("goal:owner:m"+id) || !ev.Held("origin:guest:mail-agent") {
		t.Fatal("a held-out goal's origin bucket is still mined")
	}
	if ev.Held("origin:guest:other") {
		t.Fatal("another origin was held")
	}
}
