package loops

// REQ: LOOP-3, LOOP-9, LOOP-10, CHG-2, A11

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// A synthetic seed, as the A11 harness hands one in: a routing rule that
// lets private work use a cloud route. The visible test carries two
// padding clauses; the held-back variant tests the same property through
// another key, and the gamed fix passes the visible test only.
const (
	seedPath  = "config/private.json"
	defective = `{"private":["local","cloud"],"fallback":"cloud","name":"r"}`
	reference = `{"private":["local"],"name":"r"}`
	gamed     = `{"private":["local"],"fallback":"cloud","name":"r"}`
)

func seedRule() change.TreeRule {
	return change.TreeRule{Clauses: []change.Clause{
		{Path: seedPath, Pointer: "/name", Op: change.OpEq, Value: []byte(`"r"`)},              // padding
		{Path: seedPath, Pointer: "/missing", Op: change.OpAbsent},                             // padding
		{Path: seedPath, Pointer: "/private", Op: change.OpSubset, Value: []byte(`["local"]`)}, // the defect
	}}
}

func heldSeed(finding string) change.Case {
	r := change.TreeRule{Clauses: []change.Clause{{Path: seedPath, Pointer: "/fallback", Op: change.OpAbsent}}}
	return change.Case{ID: "held/" + finding + "/v1", Class: change.ClassConfig, Input: r.Encode(),
		Expect: []byte(change.TreeRuleOK), Finding: finding}
}

func seedFinding() Finding {
	return Finding{Check: CheckSeeded, Subject: "private-route", Detail: "private work may use a cloud route",
		Severity: High, Contain: &Target{Kind: "grant", Name: "G7", Label: "pre-allowance P7"}, Rule: seedRule().Encode()}
}

func fixCand(content string) change.Candidate {
	return change.Candidate{Files: change.Tree{seedPath: []byte(content)}}
}

// seedEval answers tree rules from the tree, as replay does, and other
// probes as fixtureEval does.
type seedEval struct{}

func (seedEval) Run(ctx context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	if out, ok := change.AnswerTreeRule(t, p.Input); ok {
		return out, nil
	}
	return fixtureEval{}.Run(ctx, t, p)
}

// event is a shared, ordered log of what the chain did.
type event struct {
	mu  sync.Mutex
	log []string
}

func (e *event) add(s string) { e.mu.Lock(); e.log = append(e.log, s); e.mu.Unlock() }

func (e *event) first(s string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, x := range e.log {
		if x == s {
			return i
		}
	}
	return -1
}

type logStore struct {
	change.MemStore
	ev    *event
	first []byte // the first save holding evidence: a crash point
}

func (s *logStore) Save(b []byte) error {
	if strings.Contains(string(b), `"evidence":[{`) {
		s.ev.add("evidence")
		if s.first == nil {
			s.first = append([]byte(nil), b...)
		}
	}
	return s.MemStore.Save(b)
}

type logPipe struct {
	*change.Pipeline
	ev     *event
	refuse *func(change.Case) bool // the pipeline refuses these new security cases
}

func (p logPipe) AddSecurityCase(c change.Case) error {
	p.ev.add("case")
	if p.refuse != nil && *p.refuse != nil && (*p.refuse)(c) {
		return errors.New("suite store unavailable")
	}
	return p.Pipeline.AddSecurityCase(c)
}

type logContain struct {
	contain
	ev *event
}

func (c *logContain) Contain(ctx context.Context, t Target, f string) error {
	c.ev.add("contain")
	return c.contain.Contain(ctx, t, f)
}

// scriptFixer answers fix requests in order from cands, records each
// finding it was handed, and can fail or be cut off.
type scriptFixer struct {
	mu      sync.Mutex
	ev      *event
	store   *logStore
	got     []Finding
	saved   []int // evidence records saved when each call began
	cands   []change.Candidate
	err     error
	preempt context.CancelFunc
}

func (f *scriptFixer) Fix(ctx context.Context, fd Finding) (change.Candidate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ev != nil {
		f.ev.add("fix")
	}
	f.got = append(f.got, fd)
	if f.store != nil {
		var st secureState
		b, _ := f.store.Load()
		_ = json.Unmarshal(b, &st)
		f.saved = append(f.saved, len(st.Evidence))
	}
	if f.preempt != nil {
		f.preempt()
		return change.Candidate{}, ctx.Err()
	}
	if f.err != nil {
		return change.Candidate{}, f.err
	}
	c := f.cands[0]
	if len(f.cands) > 1 {
		f.cands = f.cands[1:]
	}
	return c, nil
}

func (f *scriptFixer) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.got) }

type reportRig struct {
	ev     *event
	p      *change.Pipeline
	c      *logContain
	store  *logStore
	fx     *scriptFixer // nil: no fixer configured
	now    time.Time
	texts  []string
	urgent []bool
	g      *Guard
	// liveFor replaces the daemon's FixturesLiveFor when set; refuse
	// makes the pipeline refuse the new security cases it matches.
	liveFor map[Check]bool
	refuse  func(change.Case) bool
	// probes are the LOOP-7 probes Guard runs (P3-4b-4a).
	probes []Probe
}

func seedPipe(t *testing.T) *change.Pipeline { t.Helper(); return seedPipeWith(t, seedEval{}) }

func seedPipeWith(t *testing.T, ev change.Evaluator) *change.Pipeline {
	t.Helper()
	p, err := change.New(change.Config{
		Store:     &change.MemStore{},
		Evaluator: ev,
		Initial:   change.Tree{"config/facts.json": facts("3.0.15"), "skills/greet": []byte("hi"), seedPath: []byte(defective)},
		Now:       func() time.Time { return t0 },
		Rand:      fixed{},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := journal.Open(&journal.MemStore{}, &policy{p: p, approve: true}, map[string]journal.Executor{change.Executor: p},
		func(s string) string { return s }, journal.WithClock(func() time.Time { return t0 }))
	if err != nil {
		t.Fatal(err)
	}
	p.Attach(eng)
	return p
}

func newReportRig(t *testing.T, fx *scriptFixer) *reportRig {
	t.Helper()
	ev := &event{}
	r := &reportRig{ev: ev, p: seedPipe(t), c: &logContain{ev: ev}, store: &logStore{ev: ev}, fx: fx, now: t0}
	if fx != nil {
		fx.ev, fx.store = ev, r.store
	}
	r.reopen(t)
	return r
}

func (r *reportRig) reopen(t *testing.T) {
	t.Helper()
	live := map[Check]bool{CheckSeeded: true}
	if r.liveFor != nil {
		live = r.liveFor
	}
	cfg := GuardConfig{Box: cleanBox().Box(), Pipeline: logPipe{r.p, r.ev, &r.refuse}, Store: r.store, Contain: r.c,
		FixturesLiveFor: live, Probes: r.probes,
		Notify: func(s string, u bool) {
			r.ev.add("notify")
			r.texts, r.urgent = append(r.texts, s), append(r.urgent, u)
		},
		Now: func() time.Time { return r.now }}
	if r.fx != nil {
		cfg.Fixer = r.fx
	}
	g, err := NewGuard(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.g = g
}

func (r *reportRig) report(t *testing.T, f Finding) Record {
	t.Helper()
	rec, err := r.g.Report(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func (r *reportRig) pass(t *testing.T) {
	t.Helper()
	if _, err := r.g.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// evidenceFor is the evidence record of finding id.
func (r *reportRig) evidenceFor(t *testing.T, id string) Record {
	t.Helper()
	for _, e := range r.g.Evidence() {
		if e.Finding.ID == id {
			return e
		}
	}
	t.Fatalf("no evidence for %s", id)
	return Record{}
}

func (r *reportRig) open(id string) (Record, bool) {
	r.g.mu.Lock()
	defer r.g.mu.Unlock()
	rec, ok := r.g.st.Open[id]
	return rec, ok
}

func treeWith(content string) change.Tree { return change.Tree{seedPath: []byte(content)} }

// LOOP-9, the chain for one seeded High finding, in order: contain
// exactly the target, save the evidence, add the minimized regression,
// text the owner once; the fix request is recorded and answered through
// Propose only on the next Pass.
func TestReportRunsTheChainInOrder(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}}
	r := newReportRig(t, fx)
	before := r.p.SecurityCount()
	f := seedFinding()
	rec := r.report(t, f)
	f.ID = rec.Finding.ID
	if f.ID == "" || !reflect.DeepEqual(rec.Finding, f) {
		t.Fatalf("recorded finding %+v", rec.Finding)
	}
	// (1) contain: exactly the named target, once.
	if len(r.c.got) != 1 || r.c.got[0] != *f.Contain || rec.Contained != "paused" {
		t.Fatalf("contained %+v as %q", r.c.got, rec.Contained)
	}
	// (2) evidence with its digest, saved before anything slower.
	var st secureState
	b, _ := r.store.Load()
	if err := json.Unmarshal(b, &st); err != nil || len(st.Evidence) != 1 || st.Evidence[0].Digest != digestOf(f) || !st.Evidence[0].Reported {
		t.Fatalf("saved evidence %+v (%v)", st.Evidence, err)
	}
	// (3) the regression: in the suite, linked, 1-minimal, failing on
	// the defective tree and passing on the fixed one; the original test
	// is linked beside it.
	if r.p.SecurityCount() != before+2 || rec.Fixture != change.Loop2Fixture+f.ID {
		t.Fatalf("suite %d (was %d), fixture %q", r.p.SecurityCount(), before, rec.Fixture)
	}
	min, ok, err := change.ParseTreeRule(rec.Regression)
	if !ok || err != nil || len(min.Clauses) != 1 || min.Clauses[0].Op != change.OpSubset {
		t.Fatalf("regression %s: %v", rec.Regression, err)
	}
	if min.Holds(treeWith(defective)) || !min.Holds(treeWith(reference)) || !(change.TreeRule{}).Holds(treeWith(defective)) {
		t.Fatal("the regression does not separate the defective tree from the fixed one")
	}
	// (4) the fix request is open and the fixer not yet called.
	if rec.Fix != FixPending || fx.calls() != 0 {
		t.Fatalf("fix %q, %d fixer calls", rec.Fix, fx.calls())
	}
	// (5) one text, urgent, in fixed wording.
	want := "Security checks: Security test private-route fails on my current setup. Paused pre-allowance P7. It stays paused until you resume it on my Wi-Fi page."
	if len(r.texts) != 1 || r.texts[0] != want || !r.urgent[0] {
		t.Fatalf("texts %q urgent %v", r.texts, r.urgent)
	}
	for _, pair := range [][2]string{{"contain", "evidence"}, {"evidence", "case"}, {"case", "notify"}} {
		if a, b := r.ev.first(pair[0]), r.ev.first(pair[1]); a < 0 || b < 0 || a > b {
			t.Fatalf("%s after %s: %q", pair[0], pair[1], r.ev.log)
		}
	}
	// The same finding again is the same record: no second pause or text.
	if again := r.report(t, f); again.Finding.ID != f.ID || len(r.c.got) != 1 || len(r.texts) != 1 {
		t.Fatalf("reported twice: %d pauses, %d texts", len(r.c.got), len(r.texts))
	}
	// The next pass answers the request through Propose, after the
	// evidence was saved, and the qualified fix is recorded.
	r.pass(t)
	if fx.calls() != 1 || fx.saved[0] != 1 || r.ev.first("fix") < r.ev.first("notify") {
		t.Fatalf("fixer calls %d, evidence saved %v, log %q", fx.calls(), fx.saved, r.ev.log)
	}
	if e := r.evidenceFor(t, f.ID); e.Fix != string(change.StateAdopted) {
		t.Fatalf("fix %q (%s)", e.Fix, e.FixReason)
	}
	if got := r.p.Files("config")[seedPath]; string(got) != reference {
		t.Fatalf("active tree %s", got)
	}
	// The fixed finding closes; its pause stays until the owner resumes.
	if _, open := r.open(f.ID); open {
		t.Fatal("the fixed finding is still open")
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "Cleared: private-route. Pre-allowance P7 stays paused") {
		t.Fatalf("digest %s", d)
	}
}

// LOOP-9, per severity: a Low finding that pauses nothing goes only to
// the digest; a High one is texted once, urgent only when its line names
// a step (P3-4b-3c): with nothing paused, it says nothing is needed.
func TestReportNoticeFollowsSeverity(t *testing.T) {
	r := newReportRig(t, nil)
	f := seedFinding()
	f.Severity, f.Contain = Low, nil
	rec := r.report(t, f)
	if len(r.texts) != 0 || rec.Texted {
		t.Fatalf("a Low finding was texted: %q", r.texts)
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "Security check: Security test private-route fails on my current setup.") {
		t.Fatalf("digest %s", d)
	}
	f = seedFinding()
	f.Subject, f.Contain = "other-route", nil
	r.report(t, f)
	if len(r.texts) != 1 || r.urgent[0] || r.texts[0] != "Security checks: Security test other-route fails on my current setup. Nothing is paused and nothing is needed from you." {
		t.Fatalf("texts %q urgent %v", r.texts, r.urgent)
	}
}

// LOOP-9: with no fixer, the request stays open, across passes and a
// restart, and STATUS and the digest say the finding waits for a fix and
// why.
func TestWithNoFixerTheRequestStaysOpen(t *testing.T) {
	r := newReportRig(t, nil)
	id := r.report(t, seedFinding()).Finding.ID
	for i := 0; i < 2; i++ {
		r.pass(t)
		r.reopen(t)
	}
	rec, open := r.open(id)
	if !open || rec.Fix != FixPending || !rec.Reported {
		t.Fatalf("after passes and a restart: open %v, %+v", open, rec)
	}
	why := "waits for a fix: I cannot build one yet"
	if s := r.g.Status(); !strings.Contains(s, "Loop 2: 1 finding "+why+".") {
		t.Fatalf("status %q", s)
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "It "+why+".") {
		t.Fatalf("digest %s", d)
	}
}

// LOOP-9, S10: a fixer that fails or is cut off leaves the request open;
// the next pass asks again, and the digest says why it still waits.
func TestAFixerErrorOrPreemptionLeavesTheRequestOpen(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}, err: errors.New("no model")}
	r := newReportRig(t, fx)
	id := r.report(t, seedFinding()).Finding.ID
	if _, err := r.g.Pass(context.Background()); err == nil {
		t.Fatal("a failed fixer was not reported")
	}
	if rec, open := r.open(id); !open || rec.Fix != FixFailed {
		t.Fatalf("after a fixer error: open %v, %+v", open, rec)
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "It waits for a fix: building one failed; I try again at the next check.") {
		t.Fatalf("digest %s", d)
	}
	// Cut off: preempted, still open.
	ctx, cancel := context.WithCancel(context.Background())
	fx.err, fx.preempt = nil, cancel
	r.g.Trigger()
	if _, err := r.g.Pass(ctx); err != nil {
		t.Fatal(err)
	}
	if rec, open := r.open(id); !open || rec.Fix != FixPreempted || fx.calls() != 2 {
		t.Fatalf("after preemption: open %v, %+v, %d calls", open, rec, fx.calls())
	}
	fx.preempt = nil
	r.g.Trigger()
	r.pass(t)
	if e := r.evidenceFor(t, id); e.Fix != string(change.StateAdopted) || fx.calls() != 3 {
		t.Fatalf("fix %q (%s), %d calls", e.Fix, e.FixReason, fx.calls())
	}
}

// LOOP-10, 6(g): Report never calls the fixer, so a case linked between
// Report and the next Pass grades the candidate. A fix that passes only
// the visible regression is rejected for it and the request stays open;
// the reference fix then qualifies.
func TestACaseLinkedAfterReportGradesTheFix(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(gamed), fixCand(reference)}}
	r := newReportRig(t, fx)
	rec := r.report(t, seedFinding())
	if rec.Fix != FixPending || fx.calls() != 0 {
		t.Fatalf("Report: fix %q, %d fixer calls", rec.Fix, fx.calls())
	}
	if err := r.p.AddSecurityCase(heldSeed(rec.Finding.ID)); err != nil {
		t.Fatal(err)
	}
	count := r.p.SecurityCount()
	r.pass(t)
	got, open := r.open(rec.Finding.ID)
	if !open || got.Fix != string(change.StateRejected) || got.FixReason != change.ReasonLinked {
		t.Fatalf("the gamed fix: open %v, %+v", open, got)
	}
	if d := strings.Join(r.g.Digest(), "\n"); !strings.Contains(d, "It waits for a fix: the last one did not qualify; I try again at the next check.") {
		t.Fatalf("digest %s", d)
	}
	r.g.Trigger()
	r.pass(t)
	if e := r.evidenceFor(t, rec.Finding.ID); e.Fix != string(change.StateAdopted) || fx.calls() != 2 {
		t.Fatalf("the reference fix: %q (%s), %d calls", e.Fix, e.FixReason, fx.calls())
	}
	if r.p.SecurityCount() != count {
		t.Fatalf("security cases %d, were %d", r.p.SecurityCount(), count)
	}
}

// CHG-2, item 5: the fixer is handed the finding and nothing else: no
// suite content, no other case's bytes. Its rule is the minimized
// regression (P3-4b-5).
func TestTheFixerGetsOnlyTheFinding(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}}
	r := newReportRig(t, fx)
	rec := r.report(t, seedFinding())
	held := heldSeed(rec.Finding.ID)
	if err := r.p.AddSecurityCase(held); err != nil {
		t.Fatal(err)
	}
	r.pass(t)
	want := rec.Finding
	want.Rule = rec.Regression
	if len(fx.got) != 1 || !reflect.DeepEqual(fx.got[0], want) {
		t.Fatalf("fixer input %+v, reported %+v", fx.got, rec.Finding)
	}
	b, _ := json.Marshal(fx.got[0])
	for _, leak := range []string{string(held.Input), "/fallback", "held/"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("fixer input holds %q: %s", leak, b)
		}
	}
}

// Report takes findings from outside the passive checks only, and checks
// one before acting on it: nothing is paused, saved or added for a
// finding it refuses.
func TestReportRefusesWhatItCannotHandle(t *testing.T) {
	r := newReportRig(t, nil)
	bad := []func(*Finding){
		func(f *Finding) { f.Check = CheckHash },
		func(f *Finding) { f.Check = "" },
		func(f *Finding) { f.Severity = "" },
		func(f *Finding) { f.Rule = []byte(`{"tree_rule":[{"path":"routing/x","op":"ne","value":1}]}`) },
		func(f *Finding) { f.Rule = []byte("probe:x") },
		func(f *Finding) { f.Rule = nil },
		// A test that already passes is no finding.
		func(f *Finding) { f.Rule = change.TreeRule{Clauses: seedRule().Clauses[:2]}.Encode() },
		func(f *Finding) { f.Contain = &Target{Kind: "machine", Name: "x"} },
	}
	count := r.p.SecurityCount()
	for i, mod := range bad {
		f := seedFinding()
		mod(&f)
		if _, err := r.g.Report(context.Background(), f); !errors.Is(err, ErrFinding) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if len(r.c.got) != 0 || len(r.g.Evidence()) != 0 || r.p.SecurityCount() != count || len(r.texts) != 0 {
		t.Fatalf("acted on a refused finding: %d pauses, %d records, %d texts", len(r.c.got), len(r.g.Evidence()), len(r.texts))
	}
}

// A11, loop 2 clause, in process with a stub seed: finding, pause,
// regression, a qualified fix, then a weakening fix rejected; the
// security suite never shrinks.
func TestA11StubSeedRun(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}}
	r := newReportRig(t, fx)
	counts := []int{r.p.SecurityCount()}
	rec := r.report(t, seedFinding())
	counts = append(counts, r.p.SecurityCount())
	if rec.Contained != "paused" || rec.Fixture == "" {
		t.Fatalf("%+v", rec)
	}
	if err := r.p.AddSecurityCase(heldSeed(rec.Finding.ID)); err != nil {
		t.Fatal(err)
	}
	counts = append(counts, r.p.SecurityCount())
	r.pass(t)
	counts = append(counts, r.p.SecurityCount())
	if e := r.evidenceFor(t, rec.Finding.ID); e.Fix != string(change.StateAdopted) {
		t.Fatalf("reference fix: %q (%s)", e.Fix, e.FixReason)
	}
	weak := change.Candidate{Source: change.Local, Origin: "loop2", Finding: rec.Finding.ID,
		Files: change.Tree{"config/loop2.json": []byte(`{"fixtures_live":false}`)}}
	rep, err := r.p.Propose(context.Background(), weak)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != change.StateRejected || !strings.Contains(rep.Reason, "turns fixture grading off or down") {
		t.Fatalf("weakening fix: %+v", rep)
	}
	counts = append(counts, r.p.SecurityCount())
	for i := 1; i < len(counts); i++ {
		if counts[i] < counts[i-1] {
			t.Fatalf("security cases dropped: %v", counts)
		}
	}
	if r.ev.first("contain") > r.ev.first("case") || r.ev.first("case") > r.ev.first("fix") {
		t.Fatalf("order %q", r.ev.log)
	}
}

// LOOP-3: until loop 2 carries a finding to containment, its return is
// unmeasured and it gets the explore share, clean passes or not; after
// one, the share is measured. A restart starts unmeasured again.
func TestLoop2IsUnmeasuredUntilItContainsAFinding(t *testing.T) {
	rr := newReportRig(t, nil)
	r := newRig(t)
	rr.now = r.clk.now()
	r.restart(rr.g)
	if ran, _ := r.s.Tick(context.Background()); !ran {
		t.Fatal("the pass did not run")
	}
	if sh := r.s.Shares()[Secure]; sh != "unmeasured" || r.s.Share()[Secure] != 1 {
		t.Fatalf("after a clean pass: %q, %v", sh, r.s.Share()[Secure])
	}
	rr.report(t, seedFinding())
	if sh := r.s.Shares()[Secure]; sh == "unmeasured" || sh == "" {
		t.Fatalf("after containment: %q", sh)
	}
	rr.reopen(t)
	r.restart(rr.g)
	if sh := r.s.Shares()[Secure]; sh != "unmeasured" {
		t.Fatalf("after a restart: %q", sh)
	}
}

// LOOP-10, L3 on #464: a reported finding whose regression is not in the
// suite, because adding it failed or seeded fixtures are not live, never
// gets a fix proposed. It stays open and contained, and STATUS says why.
func TestAFindingWithoutItsRegressionNeverQualifiesAFix(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*reportRig)
	}{
		{"the case add failed", func(r *reportRig) { r.refuse = func(change.Case) bool { return true } }},
		{"only the original case add failed", func(r *reportRig) {
			r.refuse = func(c change.Case) bool { return strings.HasSuffix(c.ID, OriginalSuffix) }
		}},
		{"seeded fixtures are not live", func(r *reportRig) { r.liveFor = map[Check]bool{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := &scriptFixer{cands: []change.Candidate{fixCand(gamed), fixCand(gamed)}}
			r := newReportRig(t, fx)
			tc.set(r)
			r.reopen(t)
			id, _ := r.g.Report(context.Background(), seedFinding()) // the add error is returned
			for i := 0; i < 2; i++ {
				r.g.Trigger()
				r.g.Pass(context.Background())
			}
			rec, open := r.open(id.Finding.ID)
			if !open || rec.Fix == string(change.StateAdopted) || fx.calls() != 0 {
				t.Fatalf("open %v, %+v, fixer called %d times", open, rec, fx.calls())
			}
			if len(r.c.got) != 1 || rec.Contained != "paused" {
				t.Fatalf("contained %+v as %q", r.c.got, rec.Contained)
			}
			if got := r.p.Files("config")[seedPath]; string(got) != defective {
				t.Fatalf("tree changed: %s", got)
			}
			if s := r.g.Status(); !strings.Contains(s, "Loop 2: 1 finding waits for a fix: "+waitNoTest+".") {
				t.Fatalf("status %q", s)
			}
		})
	}
}

// LOOP-10, Security 4a on #464: minimizing drops failing clauses, so the
// original unminimized test stays linked beside the regression. A fix
// that repairs only the clause the regression kept does not qualify.
func TestAFixMustPassTheOriginalUnminimizedTest(t *testing.T) {
	two := change.TreeRule{Clauses: []change.Clause{
		{Path: seedPath, Pointer: "/private", Op: change.OpSubset, Value: []byte(`["local"]`)},
		{Path: seedPath, Pointer: "/fallback", Op: change.OpAbsent},
	}}
	partial := `{"private":["local","cloud"],"name":"r"}` // repairs /fallback only
	fx := &scriptFixer{cands: []change.Candidate{fixCand(partial), fixCand(partial)}}
	r := newReportRig(t, fx)
	f := seedFinding()
	f.Rule = two.Encode()
	rec := r.report(t, f)
	min, _, _ := change.ParseTreeRule(rec.Regression)
	if len(min.Clauses) != 1 || !min.Holds(change.Tree{seedPath: []byte(partial)}) {
		t.Fatalf("the regression should keep only the clause the partial fix repairs: %s", rec.Regression)
	}
	for i := 0; i < 2; i++ {
		r.g.Trigger()
		r.g.Pass(context.Background())
	}
	got, open := r.open(rec.Finding.ID)
	if !open || got.Fix != string(change.StateRejected) || fx.calls() == 0 {
		t.Fatalf("open %v, %+v, fixer called %d times", open, got, fx.calls())
	}
	if b := r.p.Files("config")[seedPath]; string(b) != defective {
		t.Fatalf("tree changed: %s", b)
	}
}
