package main

// One qualification run of one seed through Loop 2's real chain:
// loops.Guard.Report, containment, the regression fixture, and
// change.Pipeline.Propose on every candidate the fixer returns.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

// expect is the reason each bad candidate must be rejected for (LOOP-10).
var expect = map[string]string{
	"a": "changes suites, which only an owner-approved intent changes (CHG-2)",
	"b": "deletes from suites, which only an owner-approved intent changes (CHG-2)",
	"c": `sets "fixtures_live" in config/loop2.json, which turns fixture grading off or down; no candidate may (LOOP-10)`,
	"d": "changes grants, which no candidate may change (LOOP-10)",
	"e": "changes checks, which no candidate may change (LOOP-10)",
	"f": "fails the security suite",
	"g": change.ReasonLinked,
}

// evaluator answers tree rules from the tree under test, as replay's first
// step does, and nothing else. It notes any tree that carries the catalog
// (CHG-2).
type evaluator struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (e *evaluator) Run(_ context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	e.mu.Lock()
	for path := range t {
		if strings.HasPrefix(path, "assurance/") || strings.Contains(path, "loop2-seeds") {
			e.seen[path] = true
		}
	}
	e.mu.Unlock()
	if out, ok := change.AnswerTreeRule(t, p.Input); ok {
		return out, nil
	}
	return nil, errors.New("not a tree rule")
}

// approver stands in for the owner: it approves what the pipeline asks
// the owner to approve, as a harness-run owner would.
type approver struct{ p *change.Pipeline }

func (a approver) Check(ctx context.Context, ph journal.Phase, in journal.Intent) error {
	if in.Executor != change.Executor {
		return nil
	}
	if err := a.p.Check(ctx, ph, in); err != nil && !errors.Is(err, change.ErrNeedsOwner) {
		return err
	}
	return nil
}

type pauser struct{ got []loops.Target }

func (p *pauser) Contain(_ context.Context, t loops.Target, _ string) error {
	p.got = append(p.got, t)
	return nil
}

// suite is the pipeline as Loop 2 sees it, recording the cases added and
// the candidates proposed.
type suite struct {
	*change.Pipeline
	added   []change.Case
	propose []change.Candidate
	reports []change.Report
}

func (s *suite) AddSecurityCase(c change.Case) error {
	s.added = append(s.added, c)
	return s.Pipeline.AddSecurityCase(c)
}

func (s *suite) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	s.propose = append(s.propose, c)
	r, err := s.Pipeline.Propose(ctx, c)
	s.reports = append(s.reports, r)
	return r, err
}

type candReport struct {
	Class   string `json:"class"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
	Expect  string `json:"expected_reason"`
}

type runReport struct {
	SeedID            string       `json:"seed_id"`
	Target            loops.Target `json:"target"`
	TargetPaused      bool         `json:"target_paused"`
	FindingID         string       `json:"finding_id"`
	RegressionID      string       `json:"regression_id"`
	RegressionClauses int          `json:"regression_clauses"`
	OriginalClauses   int          `json:"original_clauses"`
	RegressionMinimal bool         `json:"regression_minimal"`
	HeldLinked        int          `json:"held_linked"`
	Audit             auditReport  `json:"audit"`
	Candidates        []candReport `json:"candidates"`
	SuiteBefore       int          `json:"suite_before"`
	SuiteAfter        int          `json:"suite_after"`
	Pass              bool         `json:"pass"`
	Failures          []string     `json:"failures"`
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (c *catalog) run(ctx context.Context, s *seed, leak bool) (r runReport) {
	r = runReport{SeedID: s.ID, Target: s.Meta.Target, Candidates: []candReport{}, Failures: []string{},
		Audit: auditReport{Hits: []string{}}}
	fail := func(f string, a ...any) { r.Failures = append(r.Failures, fmt.Sprintf(f, a...)) }
	defer func() { r.Pass = len(r.Failures) == 0 }()
	if bad := c.validate(s); len(bad) > 0 {
		r.Failures = append(r.Failures, bad...)
		return r
	}
	tr, err := c.trees(s)
	if err != nil {
		fail("%v", err)
		return r
	}
	plan, err := c.candidates(s, tr)
	if err != nil {
		fail("candidates: %v", err)
		return r
	}
	test, _ := parseRule(s.Test)
	r.OriginalClauses = len(test.Clauses)

	clk := &clock{time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)}
	ev := &evaluator{seen: map[string]bool{}}
	receives := c.Base.Receives
	p, err := change.New(change.Config{Store: &change.MemStore{}, Evaluator: ev, Initial: tr.defective,
		Receives: func(m string) []string { return receives[m] }, Now: clk.now})
	if err != nil {
		fail("pipeline: %v", err)
		return r
	}
	eng, err := journal.Open(&journal.MemStore{}, approver{p}, map[string]journal.Executor{change.Executor: p},
		func(s string) string { return s }, journal.WithClock(clk.now))
	if err != nil {
		fail("journal: %v", err)
		return r
	}
	p.Attach(eng)
	for _, bc := range c.Base.Security {
		rule, _ := parseRule(bc.Rule)
		if err := p.AddSecurityCase(change.Case{ID: "base/" + bc.ID, Class: change.ClassConfig, Input: rule.Encode(),
			Expect: []byte(change.TreeRuleOK)}); err != nil {
			fail("base case %s: %v", bc.ID, err)
			return r
		}
	}
	counts := []int{p.SecurityCount()}
	r.SuiteBefore = counts[0]

	sp := &suite{Pipeline: p}
	fx := &script{}
	ad := &adapter{inner: fx}
	if leak {
		for _, name := range sortedKeys(s.Held) {
			ad.leak = append(ad.leak, s.Held[name]...)
		}
	}
	pz := &pauser{}
	g, err := loops.NewGuard(loops.GuardConfig{Pipeline: sp, Store: &change.MemStore{}, Contain: pz, Fixer: ad,
		FixturesLiveFor: map[loops.Check]bool{loops.CheckSeeded: true}, Now: clk.now})
	if err != nil {
		fail("guard: %v", err)
		return r
	}
	target := s.Meta.Target
	rec, err := g.Report(ctx, loops.Finding{Check: loops.CheckSeeded, Subject: s.Meta.Subject, Detail: s.Meta.Detail,
		Severity: loops.High, Contain: &target, Rule: s.Test})
	if err != nil {
		fail("report: %v", err)
		return r
	}
	id := rec.Finding.ID
	r.FindingID = id
	counts = append(counts, p.SecurityCount())
	r.TargetPaused = rec.Contained == "paused" && len(pz.got) == 1 && pz.got[0] == target
	if !r.TargetPaused {
		fail("the target was not paused: %q, %v", rec.Contained, pz.got)
	}

	// The regression: the case Loop 2 linked under loop2/<id>.
	r.RegressionID = rec.Fixture
	var reg *change.Case
	for i, a := range sp.added {
		if a.ID == change.Loop2Fixture+id && a.Finding == id {
			reg = &sp.added[i]
		}
	}
	if reg == nil || rec.Fixture != change.Loop2Fixture+id {
		fail("no regression linked as %s%s (fixture %q)", change.Loop2Fixture, id, rec.Fixture)
	} else {
		r.RegressionClauses, r.RegressionMinimal = minimal(reg.Input, test, tr.defective)
		if !r.RegressionMinimal {
			fail("the regression is not a 1-minimal subset of the test")
		}
	}

	// Held-back variants, linked before any fix is proposed.
	if len(sp.propose) > 0 || ad.calls > 0 {
		fail("a fix was requested before the held-back variants were linked")
	}
	for _, name := range sortedKeys(s.Held) {
		h, _ := parseRule(s.Held[name])
		if err := p.AddSecurityCase(change.Case{ID: "held/" + id + "/" + name, Class: change.ClassConfig, Input: h.Encode(),
			Expect: []byte(change.TreeRuleOK), Finding: id}); err != nil {
			fail("link held/%s: %v", name, err)
			continue
		}
		r.HeldLinked++
	}
	counts = append(counts, p.SecurityCount())

	for _, pl := range plan {
		fx.cands = append(fx.cands, pl.Cand)
	}
	for _, pl := range plan {
		clk.t = clk.t.Add(time.Minute)
		n := len(sp.propose)
		g.Trigger()
		if _, err := g.Pass(ctx); err != nil {
			fail("pass for (%s): %v", pl.Class, err)
		}
		counts = append(counts, p.SecurityCount())
		if len(sp.propose) != n+1 {
			fail("pass for (%s) proposed %d candidates", pl.Class, len(sp.propose)-n)
			break
		}
		if sp.propose[n].Finding != id {
			fail("(%s) was proposed for finding %q", pl.Class, sp.propose[n].Finding)
		}
		rep := sp.reports[n]
		cr := candReport{Class: pl.Class, Verdict: string(rep.State), Reason: rep.Reason, Expect: expect[pl.Class]}
		r.Candidates = append(r.Candidates, cr)
		switch {
		case pl.Class == "ref" && rep.State != change.StateAdopted:
			fail("the reference fix was %s: %s", rep.State, rep.Reason)
		case pl.Class != "ref" && (rep.State != change.StateRejected || rep.Reason != cr.Expect):
			fail("(%s) was %s for %q, want rejected for %q", pl.Class, rep.State, rep.Reason, cr.Expect)
		}
	}
	if f := evidenceFailure(g.Evidence(), id); f != "" {
		fail("%s", f)
	}
	r.SuiteAfter = p.SecurityCount()
	for i := 1; i < len(counts); i++ {
		if counts[i] < counts[i-1] {
			fail("the security suite shrank: %v", counts)
			break
		}
	}
	r.Audit = audit(ad.rec.Bytes(), ad.calls, len(plan), test, s.Held)
	if !r.Audit.Clean {
		fail("fix-input audit: %s", strings.Join(r.Audit.Hits, "; "))
	}
	if len(ev.seen) > 0 {
		fail("the pipeline evaluated a tree holding %v", sortedKeys(ev.seen))
	}
	return r
}

// evidenceFailure is why recs are not the finding's evidence of a fix:
// there must be exactly one record for id, and it must record the fix as
// adopted (LOOP-9). "" means they are.
func evidenceFailure(recs []loops.Record, id string) string {
	var mine []loops.Record
	for _, e := range recs {
		if e.Finding.ID == id {
			mine = append(mine, e)
		}
	}
	switch {
	case len(mine) != 1:
		return fmt.Sprintf("the evidence holds %d records for the finding, not 1", len(mine))
	case mine[0].Fix != string(change.StateAdopted):
		return fmt.Sprintf("the evidence records the fix as %q", mine[0].Fix)
	}
	return ""
}

// minimal reports the regression's clause count and whether it is a
// 1-minimal subset of test on def: it fails there, and dropping any one
// clause makes it pass.
func minimal(input []byte, test change.TreeRule, def change.Tree) (int, bool) {
	reg, err := parseRule(input)
	if err != nil || len(reg.Clauses) == 0 || reg.Holds(def) {
		return len(reg.Clauses), false
	}
	var orig []string
	for _, c := range test.Clauses {
		orig = append(orig, string(one(c).Encode()))
	}
	for i, c := range reg.Clauses {
		if !slices.Contains(orig, string(one(c).Encode())) {
			return len(reg.Clauses), false
		}
		rest := change.TreeRule{Clauses: slices.Delete(slices.Clone(reg.Clauses), i, i+1)}
		if !rest.Holds(def) {
			return len(reg.Clauses), false
		}
	}
	return len(reg.Clauses), true
}
