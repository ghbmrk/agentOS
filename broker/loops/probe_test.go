package loops

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProbe is a scripted LOOP-7 probe: each run returns the next
// scripted result, or cancels its context first to stand in for
// preemption (LOOP-1).
type fakeProbe struct {
	mu      sync.Mutex
	check   Check
	every   time.Duration
	results []ProbeResult
	errs    []error
	cancel  context.CancelFunc
	runs    int
}

func (p *fakeProbe) Check() Check         { return p.check }
func (p *fakeProbe) Every() time.Duration { return p.every }

func (p *fakeProbe) Run(ctx context.Context) (ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.runs
	p.runs++
	if p.cancel != nil {
		p.cancel()
		return ProbeResult{}, ctx.Err()
	}
	var res ProbeResult
	var err error
	if i < len(p.results) {
		res = p.results[i]
	}
	if i < len(p.errs) {
		err = p.errs[i]
	}
	return res, err
}

func leak(subject, grant string) Finding {
	return Finding{Check: CheckCanary, Subject: subject, Detail: "kinds: api_key, password", Severity: High,
		Contain: &Target{Kind: "grant", Name: grant, Label: "pre-allowance " + grant}}
}

// runJob takes the next job Guard offers and runs it.
func runJob(t *testing.T, g *Guard, ctx context.Context) (string, Result) {
	t.Helper()
	job, ok := g.Next(ctx, false)
	if !ok {
		return "", Result{}
	}
	if job.UsesModel {
		t.Fatalf("job %s uses the model", job.Name)
	}
	return job.Name, job.Run(ctx)
}

// LOOP-7, LOOP-9: a probe finding has no tree rule; Report takes it, contains
// it, saves its evidence and texts the owner. No security case is added
// and no fix is requested: the probe that found it is its regression, and
// a pass of the passive checks does not close it.
func TestReportTakesAProbeFindingWithoutATest(t *testing.T) {
	r := newReportRig(t, &scriptFixer{})
	count := r.p.SecurityCount()
	f := leak("guest-socket-vault-egress", "G4")
	rec := r.report(t, f)
	if want := findingID(CheckCanary, f.Subject, f.Detail); rec.Finding.ID != want {
		t.Fatalf("id %q, want %q", rec.Finding.ID, want)
	}
	if !rec.Reported || rec.Contained != "paused" || rec.Fixture != "probe:canary" || rec.Fix != "" {
		t.Fatalf("record %+v", rec)
	}
	if len(r.c.got) != 1 || r.c.got[0].Name != "G4" {
		t.Fatalf("contained %v", r.c.got)
	}
	if r.p.SecurityCount() != count {
		t.Fatal("a rule-less finding added a security case")
	}
	if len(r.texts) != 1 || !strings.Contains(r.texts[0], "planted test secret") || !strings.Contains(r.texts[0], "pre-allowance G4") {
		t.Fatalf("texts %q", r.texts)
	}
	r.now = r.now.Add(7 * time.Hour)
	r.pass(t)
	if _, open := r.open(rec.Finding.ID); !open {
		t.Fatal("a passive pass closed a probe finding")
	}
	if r.fx.calls() != 0 {
		t.Fatal("the fixer was asked for a finding with no test to grade it")
	}
	if st := r.g.Status(); strings.Contains(st, "fix") {
		t.Fatalf("status says the probe finding waits for a fix: %q", st)
	}
	// The same finding again is the same open record.
	if again := r.report(t, f); again.Finding.ID != rec.Finding.ID || len(r.c.got) != 1 || len(r.texts) != 1 {
		t.Fatalf("handled twice: %d pauses, %d texts", len(r.c.got), len(r.texts))
	}
}

// LOOP-9: Report still refuses passive checks and rule-less seeds; a probe
// finding needs a subject (its probe closes it by subject), and a test it
// carries must fail.
func TestReportRefusesAProbeFindingItCannotHandle(t *testing.T) {
	r := newReportRig(t, nil)
	bad := []Finding{
		{Check: CheckHash, Subject: "x", Severity: High},
		{Check: CheckSeeded, Subject: "x", Severity: High},
		{Check: CheckCanary, Subject: "", Severity: High},
		{Check: CheckCorpus, Subject: "x", Severity: "urgent"},
		{Check: CheckCorpus, Subject: "x", Severity: Low, Rule: []byte("probe:x")},
	}
	passes := seedFinding()
	passes.Check = CheckCorpus
	passes.Rule = []byte(`{"tree_rule":[{"path":"config/private.json","pointer":"/name","op":"eq","value":"r"}]}`)
	bad = append(bad, passes)
	for i, f := range bad {
		if _, err := r.g.Report(context.Background(), f); !errors.Is(err, ErrFinding) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if len(r.g.Evidence()) != 0 || len(r.texts) != 0 {
		t.Fatal("acted on a refused finding")
	}
}

// LOOP-7: a probe runs in Loop 2's slot, after the passive pass, when its
// interval is due; its findings go through Report; its last run survives
// a restart.
func TestAProbeRunsWhenDueAndReportsThroughReport(t *testing.T) {
	p := &fakeProbe{check: CheckCanary, every: time.Hour,
		results: []ProbeResult{{Found: []Finding{leak("t1", "G1")}, Checked: []string{"t1"}}}}
	r := newReportRig(t, nil)
	r.probes = []Probe{p}
	r.reopen(t)
	ctx := context.Background()
	if name, _ := runJob(t, r.g, ctx); name != "passive" {
		t.Fatalf("first job %q, want the passive pass", name)
	}
	name, res := runJob(t, r.g, ctx)
	if name != "probe:canary" || res.Err != nil || res.Value != 1 {
		t.Fatalf("job %q: %+v", name, res)
	}
	id := findingID(CheckCanary, "t1", leak("t1", "G1").Detail)
	if rec, open := r.open(id); !open || !rec.Reported || rec.Contained != "paused" {
		t.Fatalf("not reported: %+v", rec)
	}
	if name, _ := runJob(t, r.g, ctx); name != "" {
		t.Fatalf("ran %q before the probe was due", name)
	}
	r.reopen(t)
	if name, _ := runJob(t, r.g, ctx); name != "passive" {
		t.Fatalf("after restart %q", name) // a restart forces one passive pass
	}
	if name, _ := runJob(t, r.g, ctx); name != "" {
		t.Fatalf("a restart forgot the probe's last run: %q", name)
	}
	r.now = r.now.Add(time.Hour)
	if name, _ := runJob(t, r.g, ctx); name != "probe:canary" {
		t.Fatalf("due probe not offered: %q", name)
	}
	if p.runs != 2 {
		t.Fatalf("%d runs", p.runs)
	}
}

// LOOP-7: a run that checked a subject and did not find it closes the
// subject's open finding; the pause stays until the owner resumes it, and
// a subject the run did not check stays open.
func TestAProbeClosesWhatItCheckedAndNoLongerFinds(t *testing.T) {
	p := &fakeProbe{check: CheckCanary, every: time.Hour, results: []ProbeResult{
		{Found: []Finding{leak("t1", "G1"), leak("t2", "G2")}, Checked: []string{"t1", "t2"}},
		{Checked: []string{"t1"}},
	}}
	r := newReportRig(t, nil)
	r.probes = []Probe{p}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx)
	runJob(t, r.g, ctx)
	r.now = r.now.Add(time.Hour)
	if name, res := runJob(t, r.g, ctx); name != "probe:canary" || res.Err != nil || res.Value != 0 {
		t.Fatalf("%q %+v", name, res)
	}
	d := leak("t1", "G1").Detail
	if _, open := r.open(findingID(CheckCanary, "t1", d)); open {
		t.Fatal("a checked subject no longer found stayed open")
	}
	if _, open := r.open(findingID(CheckCanary, "t2", d)); !open {
		t.Fatal("an unchecked subject closed")
	}
	digest := strings.Join(r.g.Digest(), "\n")
	if !strings.Contains(digest, "Cleared: t1. Pre-allowance G1 stays paused") {
		t.Fatalf("digest %q", digest)
	}
}

// LOOP-1, LOOP-7: a preempted run reports nothing, closes nothing and
// is offered again.
func TestAPreemptedProbeChangesNothing(t *testing.T) {
	p := &fakeProbe{check: CheckCanary, every: time.Hour,
		results: []ProbeResult{{Found: []Finding{leak("t1", "G1")}, Checked: []string{"t1"}}}}
	r := newReportRig(t, nil)
	r.probes = []Probe{p}
	r.reopen(t)
	runJob(t, r.g, context.Background())
	runJob(t, r.g, context.Background())
	r.now = r.now.Add(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	if name, res := runJob(t, r.g, ctx); name != "probe:canary" || !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("%q %+v", name, res)
	}
	if _, open := r.open(findingID(CheckCanary, "t1", leak("t1", "G1").Detail)); !open {
		t.Fatal("a preempted run closed a finding")
	}
	p.cancel = nil
	if name, _ := runJob(t, r.g, context.Background()); name != "probe:canary" {
		t.Fatalf("preempted probe not offered again: %q", name)
	}
}

// LOOP-7: a failed run is said in STATUS and the digest, never read as
// clean; what it found is still reported, it closes nothing, and the next
// good run clears the line.
func TestAFailedProbeIsSaidAndClosesNothing(t *testing.T) {
	p := &fakeProbe{check: CheckCanary, every: time.Hour,
		results: []ProbeResult{
			{Found: []Finding{leak("t1", "G1")}, Checked: []string{"t1"}},
			{Found: []Finding{leak("t2", "G2")}, Checked: []string{"t1", "t2"}},
			{Checked: []string{"t2"}},
		},
		errs: []error{nil, errors.New("control planted-leak missed")}}
	r := newReportRig(t, nil)
	r.probes = []Probe{p}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx)
	runJob(t, r.g, ctx)
	r.now = r.now.Add(time.Hour)
	if _, res := runJob(t, r.g, ctx); res.Err == nil {
		t.Fatal("a failed run returned no error")
	}
	d := leak("t1", "G1").Detail
	if _, open := r.open(findingID(CheckCanary, "t1", d)); !open {
		t.Fatal("a failed run closed a finding")
	}
	if _, open := r.open(findingID(CheckCanary, "t2", d)); !open {
		t.Fatal("a failed run's finding was dropped")
	}
	if st := r.g.Status(); !strings.Contains(st, "leak tests, failed") {
		t.Fatalf("status %q", st)
	}
	if dg := strings.Join(r.g.Digest(), "\n"); !strings.Contains(dg, "leak tests, failed") {
		t.Fatalf("digest %q", dg)
	}
	r.now = r.now.Add(time.Hour)
	if _, res := runJob(t, r.g, ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	if st := r.g.Status(); strings.Contains(st, "leak tests") {
		t.Fatalf("status after a good run %q", st)
	}
}

// LOOP-7: a probe reports only findings of its own check.
func TestAProbeReportsOnlyItsOwnCheck(t *testing.T) {
	other := leak("t1", "G1")
	other.Check = CheckSeeded
	p := &fakeProbe{check: CheckCanary, every: time.Hour, results: []ProbeResult{{Found: []Finding{other}, Checked: []string{"t1"}}}}
	r := newReportRig(t, nil)
	r.probes = []Probe{p}
	r.reopen(t)
	runJob(t, r.g, context.Background())
	if _, res := runJob(t, r.g, context.Background()); res.Err == nil {
		t.Fatal("a finding of another check was taken")
	}
	if len(r.g.Evidence()) != 0 || len(r.c.got) != 0 {
		t.Fatal("acted on another check's finding")
	}
}

// A-6 (P3-4b): a probe that pauses more than once in a day is named in
// the digest with its count.
func TestRepeatProbePausesAreInTheDigest(t *testing.T) {
	r := newReportRig(t, nil)
	r.report(t, leak("t1", "G1"))
	if dg := strings.Join(r.g.Digest(), "\n"); strings.Contains(dg, "times today") {
		t.Fatalf("one pause named as a repeat: %q", dg)
	}
	r.report(t, leak("t2", "G2"))
	if dg := strings.Join(r.g.Digest(), "\n"); !strings.Contains(dg, "Loop 2: leak tests paused access 2 times today.") {
		t.Fatalf("digest %q", dg)
	}
	r.now = r.now.Add(24 * time.Hour)
	if dg := strings.Join(r.g.Digest(), "\n"); strings.Contains(dg, "times today") {
		t.Fatalf("yesterday's pauses named today: %q", dg)
	}
}
