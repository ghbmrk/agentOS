package compile

// REQ: CAP-5, A10, CHG-1, CHG-6

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/skill"
)

var bg = context.Background()

// rig is a journal with a settable clock, an executor that succeeds, and a
// policy that allows task effects (denying actions named deny.*) and
// delegates change intents to the pipeline, asking a stand-in owner.
type rig struct {
	t     *testing.T
	eng   *journal.Engine
	now   time.Time
	p     *change.Pipeline
	dev   map[string]bool // tasks whose case is in the dev split (fake Cases)
	mu    sync.Mutex
	asked []string
}

func (r *rig) Check(ctx context.Context, ph journal.Phase, in journal.Intent) error {
	if in.Executor == change.Executor {
		err := r.p.Check(ctx, ph, in)
		if errors.Is(err, change.ErrNeedsOwner) {
			r.mu.Lock()
			r.asked = append(r.asked, in.ID)
			r.mu.Unlock()
			return errors.New("the owner said no")
		}
		return err
	}
	if strings.HasPrefix(in.Action, "deny.") {
		return errors.New("denied")
	}
	return nil
}

type ok struct{}

func (ok) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (ok) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), dev: map[string]bool{}}
	execs := map[string]journal.Executor{"task": ok{}}
	return r.open(execs)
}

func (r *rig) open(execs map[string]journal.Executor) *rig {
	eng, err := journal.Open(&journal.MemStore{}, r, execs, func(s string) string { return s },
		journal.WithClock(func() time.Time { return r.now }))
	if err != nil {
		r.t.Fatal(err)
	}
	r.eng = eng
	return r
}

// Dev is the fake pipeline's dev split: one case per dev task.
func (r *rig) Dev(class change.Class) []change.Case {
	if class != change.ClassSkill {
		return nil
	}
	var out []change.Case
	for task := range r.dev {
		out = append(out, change.Case{ID: "case-" + task, Class: class, Task: task})
	}
	return out
}

type step struct {
	account, action string
	params          map[string]any
	recips          []string
}

// task journals one task's effects gap apart, under goal, with the first
// intent's ID returned. Each intent runs to its outcome.
func (r *rig) task(goal, label string, gap time.Duration, steps ...step) string {
	r.t.Helper()
	var first string
	for i, s := range steps {
		if i > 0 {
			r.now = r.now.Add(gap)
		}
		id := fmt.Sprintf("guest-a/%s-%d", goal, i+1)
		r.effect(journal.Intent{ID: id, GoalID: goal, Origin: "guest:a", Account: s.account, Action: s.action,
			Params: s.params, Recipients: s.recips, Executor: "task", Label: label})
		if first == "" {
			first = id
		}
	}
	r.now = r.now.Add(time.Minute)
	return first
}

func (r *rig) effect(in journal.Intent) {
	r.t.Helper()
	if _, err := r.eng.Submit(in); err != nil {
		r.t.Fatal(err)
	}
	st, err := r.eng.Authorize(bg, in.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	if st.State == journal.Authorized {
		if _, err := r.eng.Dispatch(bg, in.ID); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *rig) judge(id string, v journal.Verdict, source string) {
	r.t.Helper()
	if _, err := r.eng.RecordQuality(id, journal.Quality{Verdict: v, Source: source}); err != nil {
		r.t.Fatal(err)
	}
}

// weekly is the recurring task: draft the weekly report to someone, then
// send it to them.
func weekly(to string, week int) []step {
	return []step{
		{"mail", "draft.create", map[string]any{"subject": "Weekly report", "to": to, "meta": map[string]any{"week": week}}, nil},
		{"mail", "message.send", nil, []string{to}},
	}
}

// accepted journals an owner-accepted weekly task in the dev split.
func (r *rig) accepted(goal, to string, week int) string {
	id := r.task(goal, "private", 30*time.Second, weekly(to, week)...)
	r.judge(id, journal.VerdictGood, "owner")
	r.dev[id] = true
	return id
}

func (r *rig) compiler() *Compiler {
	c, err := New(Config{Journal: r.eng, Cases: r})
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func only(t *testing.T, cs []change.Candidate) (string, *skill.Skill, change.Candidate) {
	t.Helper()
	if len(cs) != 1 || len(cs[0].Files) != 1 {
		t.Fatalf("candidates %+v", cs)
	}
	for p, b := range cs[0].Files {
		sk, err := skill.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		if p != sk.Path() {
			t.Fatalf("path %s for %s", p, sk.ID)
		}
		return p, sk, cs[0]
	}
	return "", nil, change.Candidate{}
}

// CAP-5: a recurring trajectory compiles into a skill. Values equal in
// every run are literals; the rest are typed inputs, one input per value
// that moves together (the address in the draft and the recipient). The
// candidate is local, from the compiler, and private when its inputs were.
func TestCompileSkillFromRepeatedRuns(t *testing.T) {
	r := newRig(t)
	r.accepted("g1", "ann@example.test", 40)
	r.accepted("g2", "bo@example.test", 41)
	r.accepted("g3", "cy@example.test", 42)
	p, sk, cand := only(t, r.compiler().Candidates(change.Tree{}))
	if !strings.HasPrefix(p, "skills/k") || sk.Kind != skill.KindSkill || sk.Runs != 3 {
		t.Fatalf("%s %+v", p, sk)
	}
	if cand.Source != change.Local || cand.Origin != Origin || cand.Public {
		t.Fatalf("candidate %+v", cand)
	}
	types := map[skill.SlotType]int{}
	for _, sl := range sk.Slots {
		types[sl.Type]++
	}
	if len(sk.Slots) != 2 || types[skill.Email] != 1 || types[skill.Number] != 1 {
		t.Fatalf("slots %+v", sk.Slots)
	}
	if string(sk.Steps[0].Params["subject"].Lit) != `"Weekly report"` {
		t.Fatalf("subject %+v", sk.Steps[0].Params["subject"])
	}
	to := sk.Steps[0].Params["to"].Slot
	if to == "" || sk.Steps[1].Recipients[0].Slot != to {
		t.Fatalf("the address and the recipient must share one input: %+v", sk.Steps)
	}
	if sk.Steps[0].Params["meta"].Obj["week"].Slot == "" {
		t.Fatal("week must be an input")
	}
}

// CHG-1, CAP-5: the compiler builds only from successful, owner-accepted
// tasks behind dev cases. A held-out task, a verdict from anyone but the
// owner, a failed or denied effect, a "wrong" on any effect, a redacted
// secret, or a one-effect task never feeds a skill.
func TestOnlyDevOwnerAcceptedSuccessfulRuns(t *testing.T) {
	for name, spoil := range map[string]func(r *rig){
		"held out": func(r *rig) {
			r.task("g3", "private", time.Second, weekly("cy@example.test", 42)...)
			r.judge("guest-a/g3-1", journal.VerdictGood, "owner") // a case, but not in dev
		},
		"agent verdict": func(r *rig) {
			id := r.task("g3", "private", time.Second, weekly("cy@example.test", 42)...)
			r.judge(id, journal.VerdictGood, "agent")
			r.dev[id] = true
		},
		"denied step": func(r *rig) {
			s := weekly("cy@example.test", 42)
			s[1].action = "deny.send"
			s = append(s[:1], s[1])
			id := r.task("g3", "private", time.Second, s...)
			r.judge(id, journal.VerdictGood, "owner")
			r.dev[id] = true
		},
		"wrong on a step": func(r *rig) {
			id := r.accepted("g3", "cy@example.test", 42)
			r.judge(strings.TrimSuffix(id, "-1")+"-2", journal.VerdictWrong, "owner")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.accepted("g1", "ann@example.test", 40)
			r.accepted("g2", "bo@example.test", 41)
			spoil(r)
			for _, c := range r.compiler().Candidates(change.Tree{}) {
				for p := range c.Files {
					if strings.HasPrefix(p, "skills/") {
						t.Fatalf("compiled a skill from a spoiled run: %s", p)
					}
				}
			}
		})
	}

	r := newRig(t)
	r.accepted("g1", "ann@example.test", 40)
	r.accepted("g2", "bo@example.test", 41)
	r.accepted("g3", "SECRET-REDACTED", 42)
	c, _ := New(Config{Journal: r.eng, Cases: r, Redacted: func(s string) bool { return strings.Contains(s, "REDACTED") }})
	for _, cand := range c.Candidates(change.Tree{}) {
		if _, has := cand.Files["skills/k"+shapeOf(t, r, "g1")+".json"]; has {
			t.Fatal("a trajectory with a redacted value compiled")
		}
	}

	r = newRig(t)
	for i := 0; i < 3; i++ {
		id := r.task(fmt.Sprintf("s%d", i), "private", time.Second, weekly("a@b.test", i)[1])
		r.judge(id, journal.VerdictGood, "owner")
		r.dev[id] = true
	}
	if cs := r.compiler().Candidates(change.Tree{}); len(cs) != 0 {
		t.Fatalf("one-effect tasks compiled: %+v", cs)
	}
}

func shapeOf(t *testing.T, r *rig, goal string) string {
	t.Helper()
	all := trajectories(r.eng, func(in journal.Intent) string { return in.GoalID }, "owner", nil)
	return Shape(all[goal])
}

// CAP-5: one accepted trajectory is recorded as a replayable procedure
// that carries no recorded value; once the task recurs it compiles into a
// skill that replaces the procedure. More runs alone make no new
// candidate.
func TestProcedureThenSkill(t *testing.T) {
	r := newRig(t)
	r.accepted("g1", "ann@example.test", 40)
	p, proc, cand := only(t, r.compiler().Candidates(change.Tree{}))
	if proc.Kind != skill.KindProcedure || !strings.HasPrefix(p, "procedures/p") {
		t.Fatalf("%s %+v", p, proc)
	}
	if bytes.Contains(cand.Files[p], []byte("ann@example.test")) || bytes.Contains(cand.Files[p], []byte("Weekly")) {
		t.Fatalf("a procedure must not carry recorded values: %s", cand.Files[p])
	}
	active := change.Tree{p: cand.Files[p]}
	if cs := r.compiler().Candidates(active); len(cs) != 0 {
		t.Fatalf("an adopted procedure was proposed again: %+v", cs)
	}

	r.accepted("g2", "bo@example.test", 41)
	r.accepted("g3", "cy@example.test", 42)
	sp, _, cand := only(t, r.compiler().Candidates(active))
	if len(cand.Delete) != 1 || cand.Delete[0] != p {
		t.Fatalf("the skill must replace the procedure: %+v", cand.Delete)
	}
	active = change.Tree{sp: cand.Files[sp]}
	r.accepted("g4", "di@example.test", 43)
	if cs := r.compiler().Candidates(active); len(cs) != 0 {
		t.Fatalf("a fourth run alone made a candidate: %+v", cs)
	}
	// A value that was constant now varies: the skill is regeneralized.
	r2 := newRig(t)
	for i, s := range []string{"Weekly report", "Weekly report", "Weekly report"} {
		id := r2.task(fmt.Sprintf("h%d", i), "private", time.Second, step{"mail", "draft.create", map[string]any{"subject": s, "to": "x@y.test"}, nil}, step{"mail", "message.send", nil, []string{"x@y.test"}})
		r2.judge(id, journal.VerdictGood, "owner")
		r2.dev[id] = true
	}
	sp2, _, c2 := only(t, r2.compiler().Candidates(change.Tree{}))
	id := r2.task("h9", "private", time.Second, step{"mail", "draft.create", map[string]any{"subject": "Monthly report", "to": "x@y.test"}, nil}, step{"mail", "message.send", nil, []string{"x@y.test"}})
	r2.judge(id, journal.VerdictGood, "owner")
	r2.dev[id] = true
	_, sk2, _ := only(t, r2.compiler().Candidates(change.Tree{sp2: c2.Files[sp2]}))
	if sk2.Steps[0].Params["subject"].Slot == "" {
		t.Fatalf("subject must become an input: %+v", sk2.Steps[0].Params)
	}
}

// zeros is a deterministic Rand, so the dev split is the same every run.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// echo is an evaluator that answers each probe with its input: every case
// passes on both sides, as a skill that neither helps nor hurts would.
type echo struct{}

func (echo) Run(_ context.Context, _ change.Tree, p change.Probe) ([]byte, error) {
	return p.Input, nil
}

// pipelineRig adds a real change pipeline whose dev split feeds the
// compiler, with n owner-accepted weekly tasks filed as skill cases.
func pipelineRig(t *testing.T, n int, to func(i int) string) *rig {
	r := newRig(t)
	p, err := change.New(change.Config{Store: &change.MemStore{}, Evaluator: echo{}, Rand: zeros{},
		Now: func() time.Time { return r.now }})
	if err != nil {
		t.Fatal(err)
	}
	r.p = p
	r.open(map[string]journal.Executor{"task": ok{}, change.Executor: p})
	p.Attach(r.eng)
	c := r.compiler()
	for i := 0; i < n; i++ {
		id := r.task(fmt.Sprintf("w%02d", i), "private", 30*time.Second, weekly(to(i), i)...)
		r.judge(id, journal.VerdictGood, "owner")
		if c.CaseClass(id) != change.ClassSkill {
			t.Fatalf("a two-effect task is a skill case")
		}
		if err := p.AddTaskCase(change.Case{ID: "case-" + id, Class: change.ClassSkill, Input: []byte("ok"),
			Expect: []byte("ok"), Outcome: change.Accepted, Task: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.AddSecurityCase(change.Case{ID: "sec-1", Class: change.ClassSkill, Input: []byte("refused"), Expect: []byte("refused")}); err != nil {
		t.Fatal(err)
	}
	return r
}

// CAP-5, CHG-6: compiled skills go through §11. With the real pipeline, a
// skill compiled from dev cases is evaluated on the held-out suite and,
// being authority-neutral with no regression, adopts under the standing
// grant and lands in the active tree.
func TestCompiledSkillAdoptsThroughPipeline(t *testing.T) {
	r := pipelineRig(t, 24, func(i int) string { return fmt.Sprintf("p%d@example.test", i) })
	c, _ := New(Config{Journal: r.eng, Cases: r.p})
	cs := c.Candidates(r.p.Files(skill.SkillsNS))
	path, _, cand := only(t, cs)
	rep, err := r.p.Propose(bg, cand)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != change.StateAdopted || rep.Basis != change.BasisStanding || !rep.Neutral || rep.HeldOut < 5 {
		t.Fatalf("report %+v", rep)
	}
	if _, ok := r.p.Files(skill.SkillsNS)[path]; !ok {
		t.Fatal("the adopted skill is not in the active tree")
	}
	if cs := c.Candidates(r.p.Files(skill.SkillsNS)); len(cs) != 0 {
		t.Fatalf("an adopted skill was proposed again: %+v", cs)
	}
}

// CAP-5, CHG-6: a skill whose literal is an address found nowhere in the
// active tree (the task always went to one person) is neutral but goes to
// the owner, with its held-out counts, instead of adopting unprompted.
func TestSkillWithFixedAddressAsksOwner(t *testing.T) {
	r := pipelineRig(t, 24, func(int) string { return "boss@example.test" })
	c, _ := New(Config{Journal: r.eng, Cases: r.p})
	_, sk, cand := only(t, c.Candidates(r.p.Files(skill.SkillsNS)))
	if string(sk.Steps[1].Recipients[0].Lit) != `"boss@example.test"` {
		t.Fatalf("recipient %+v", sk.Steps[1].Recipients)
	}
	rep, err := r.p.Propose(bg, cand)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Basis != change.BasisOwner || rep.HeldOut == 0 || len(r.asked) != 1 {
		t.Fatalf("report %+v, asked %v", rep, r.asked)
	}
}

// A10, CAP-5: the second-run speedup is measured from the journal: the
// median span of owner-accepted model runs of the skill's task against the
// median span of complete skill runs. A run that stopped (an assumption
// failed) is counted apart.
func TestMeasureSpeedup(t *testing.T) {
	r := newRig(t)
	for i, gap := range []time.Duration{40 * time.Second, 60 * time.Second, 80 * time.Second} {
		id := r.task(fmt.Sprintf("g%d", i), "private", gap, weekly(fmt.Sprintf("u%d@example.test", i), i)...)
		r.judge(id, journal.VerdictGood, "owner")
		r.dev[id] = true
	}
	c := r.compiler()
	path, sk, cand := only(t, c.Candidates(change.Tree{}))
	active := change.Tree{path: cand.Files[path]}

	run := func(runID string, second string) {
		vals := map[string]any{"to": "z@example.test", "week": 50}
		for i := range sk.Steps {
			params, recips, err := sk.Fill(i, vals)
			if err != nil {
				t.Fatal(err)
			}
			action := sk.Steps[i].Action
			if i == 1 && second != "" {
				action = second
			}
			r.effect(journal.Intent{ID: "guest-a/" + skill.RequestID(sk.ID, runID, i), Origin: "guest:a",
				Account: sk.Steps[i].Account, Action: action, Params: params, Recipients: recips, Executor: "task"})
			r.now = r.now.Add(2 * time.Second)
		}
	}
	run("r1", "")
	run("r2", "")
	run("r3", "deny.send")
	ms := c.Measure(active)
	if len(ms) != 1 {
		t.Fatalf("%+v", ms)
	}
	m := ms[0]
	if m.Skill != sk.ID || m.ModelRuns != 3 || m.ModelMedian != 60*time.Second || m.SkillRuns != 2 ||
		m.SkillMedian != 2*time.Second || m.Stopped != 1 || m.Ratio != 30 {
		t.Fatalf("speedup %+v", m)
	}
}

// CAP-5 (security review B1): a key that is data (an address used as a map
// key) never becomes structure, a slot name, or part of the tool schema.
// A nested object keyed by data is one input; params keyed by data are
// never compiled.
func TestDataKeysAreNotStructure(t *testing.T) {
	r := newRig(t)
	for i, who := range []string{"alice@example.test", "bob@example.test", "cy@example.test"} {
		id := r.task(fmt.Sprintf("g%d", i), "private", time.Second,
			step{"mail", "label.set", map[string]any{"labels": map[string]any{who: true}}, nil},
			step{"mail", "message.send", nil, []string{"team@example.test"}})
		r.judge(id, journal.VerdictGood, "owner")
		r.dev[id] = true
	}
	_, sk, cand := only(t, r.compiler().Candidates(change.Tree{}))
	for _, b := range cand.Files {
		if bytes.Contains(b, []byte("alice")) || bytes.Contains(b, []byte("bob@")) {
			t.Fatalf("a data key reached the skill: %s", b)
		}
	}
	if n := sk.Steps[0].Params["labels"]; n.Slot != "labels" || n.Obj != nil {
		t.Fatalf("labels must be one input: %+v", n)
	}

	r = newRig(t)
	for i, who := range []string{"alice@example.test", "bob@example.test", "cy@example.test"} {
		id := r.task(fmt.Sprintf("h%d", i), "private", time.Second,
			step{"mail", "label.set", map[string]any{who: true}, nil},
			step{"mail", "message.send", nil, []string{"team@example.test"}})
		r.judge(id, journal.VerdictGood, "owner")
		r.dev[id] = true
	}
	if cs := r.compiler().Candidates(change.Tree{}); len(cs) != 0 {
		t.Fatalf("params keyed by data compiled: %+v", cs)
	}
}

// CAP-5, CHG-1: Loop 1's repeat hypothesis hands the compiler only its
// brief's evidence (never a held-out task); BuildSkill compiles the
// largest repeated shape from it and writes only under skills/.
func TestBuildSkillFromEvidence(t *testing.T) {
	r := newRig(t)
	r.accepted("g1", "ann@example.test", 40)
	r.accepted("g2", "bo@example.test", 41)
	c := r.compiler()
	if _, err := c.BuildSkill(r.eng.List()); !errors.Is(err, ErrNoSkill) {
		t.Fatalf("two runs: %v", err)
	}
	r.accepted("g3", "cy@example.test", 42)
	cand, err := c.BuildSkill(r.eng.List())
	if err != nil {
		t.Fatal(err)
	}
	for p := range cand.Files {
		if !strings.HasPrefix(p, "skills/k") {
			t.Fatalf("wrote %s", p)
		}
	}
	// The same evidence without g3's statuses has too few runs: nothing
	// outside the evidence is read.
	var ev []journal.Status
	for _, s := range r.eng.List() {
		if s.Intent.GoalID != "g3" {
			ev = append(ev, s)
		}
	}
	if _, err := c.BuildSkill(ev); !errors.Is(err, ErrNoSkill) {
		t.Fatalf("read beyond the evidence: %v", err)
	}
}
