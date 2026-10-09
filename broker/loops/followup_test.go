package loops

// REQ: LOOP-3, LOOP-9, LOOP-10, CHG-2

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
)

// adoptOutside changes the active tree without Loop 2's fix, as an
// owner-approved intent or an update would.
func (r *reportRig) adoptOutside(t *testing.T, content string) {
	t.Helper()
	rep, err := r.p.Propose(context.Background(), change.Candidate{Source: change.Local, Origin: "test", Files: treeWith(content)})
	if err != nil || rep.State != change.StateAdopted {
		t.Fatalf("outside change: %+v %v", rep, err)
	}
}

func (r *reportRig) count(s string) int {
	n := 0
	for _, x := range r.texts {
		n += strings.Count(x, s)
	}
	return n
}

// P3-4b-1b item 1 (LOOP-9): a reported finding whose linked cases come to
// pass on the active tree without Loop 2's fix closes as cleared on the
// next Pass. The pause stays, the "waits for a fix" lines go, and the
// owner is told once in clearedLine's wording. One whose cases still fail
// stays open.
func TestAReportedFindingTheTreeComesToPassIsCleared(t *testing.T) {
	r := newReportRig(t, nil)
	rec := r.report(t, seedFinding())
	if err := r.p.AddSecurityCase(heldSeed(rec.Finding.ID)); err != nil {
		t.Fatal(err)
	}
	// A partial repair: the held variant passes, the seed's test fails.
	r.adoptOutside(t, `{"private":["local","cloud"],"name":"r"}`)
	r.g.Trigger()
	r.pass(t)
	if _, open := r.open(rec.Finding.ID); !open {
		t.Fatal("a finding whose cases still fail was closed")
	}
	if s := r.g.Status(); !strings.Contains(s, waitForAFixOf) {
		t.Fatalf("status %q", s)
	}
	r.adoptOutside(t, reference)
	r.g.Trigger()
	r.pass(t)
	if _, open := r.open(rec.Finding.ID); open {
		t.Fatal("a finding the tree passes stays open")
	}
	cleared := clearedLine(rec)
	if n := r.count(cleared); n != 1 {
		t.Fatalf("cleared line texted %d times: %q", n, r.texts)
	}
	if _, still := r.g.st.Paused[targetKey(*rec.Finding.Contain)]; !still {
		t.Fatal("the pause was lifted")
	}
	if s := r.g.Status(); strings.Contains(s, waitForAFixOf) {
		t.Fatalf("status still waits: %q", s)
	}
	for _, l := range r.g.Digest() {
		if strings.Contains(l, waitForAFixOf) {
			t.Fatalf("digest still waits: %q", l)
		}
	}
	r.g.Trigger()
	r.pass(t)
	if n := r.count(cleared); n != 1 {
		t.Fatalf("cleared line texted %d times after another pass", n)
	}
}

// P3-4b-1b item 1: a finding whose cases were never all linked is not
// cleared by the tree passing the ones that were; its original test is
// not in the suite to say so.
func TestAFindingMissingACaseIsNotClearedByTheOthers(t *testing.T) {
	r := newReportRig(t, nil)
	r.refuse = func(c change.Case) bool { return strings.HasSuffix(c.ID, OriginalSuffix) }
	rec, _ := r.g.Report(context.Background(), seedFinding())
	r.adoptOutside(t, reference)
	r.g.Trigger()
	r.g.Pass(context.Background()) // the refused add is retried and errs
	if _, open := r.open(rec.Finding.ID); !open {
		t.Fatal("cleared with its original test missing")
	}
}

// P3-4b-1b item 2 (CHG-2, LOOP-10): a finding reported as X/original
// holds the slot of finding X's original test. X's add of its original is
// refused as another finding's case, so X is not linked and no fix is
// requested for it. A re-report stays idempotent.
func TestAFindingIDCannotTakeAnothersOriginalSlot(t *testing.T) {
	two := change.TreeRule{Clauses: []change.Clause{
		{Path: seedPath, Pointer: "/private", Op: change.OpSubset, Value: []byte(`["local"]`)},
		{Path: seedPath, Pointer: "/fallback", Op: change.OpAbsent},
	}}
	partial := `{"private":["local","cloud"],"name":"r"}`
	fx := &scriptFixer{cands: []change.Candidate{fixCand(partial)}}
	r := newReportRig(t, fx)
	f := seedFinding()
	f.Rule, f.ID = two.Encode(), "seeded:X/original"
	first := r.report(t, f)
	before := r.p.SecurityCount()
	f.ID = "seeded:X"
	x, err := r.g.Report(context.Background(), f)
	if !errors.Is(err, change.ErrConflict) {
		t.Fatalf("the colliding add: %v", err)
	}
	if x.Fix != "" || x.Fixture != "" || r.p.SecurityCount() != before+1 {
		t.Fatalf("X linked: %+v, suite %d -> %d", x, before, r.p.SecurityCount())
	}
	for i := 0; i < 2; i++ {
		r.g.Trigger()
		r.g.Pass(context.Background())
	}
	for _, got := range fx.got {
		if got.ID == f.ID {
			t.Fatal("a fix was requested for the unlinked finding")
		}
	}
	if b := r.p.Files("config")[seedPath]; string(b) != defective {
		t.Fatalf("tree changed: %s", b)
	}
	// Re-reporting the linked one changes nothing.
	n, texts := r.p.SecurityCount(), len(r.texts)
	f.ID = first.Finding.ID
	again := r.report(t, f)
	if again.Finding.ID != first.Finding.ID || r.p.SecurityCount() != n || len(r.texts) != texts {
		t.Fatalf("re-report: %+v, suite %d -> %d, texts %d -> %d", again, n, r.p.SecurityCount(), texts, len(r.texts))
	}
}

// P3-4b-1b item 3 (LOOP-9): a crash right after handle's first save
// leaves an open reported record with no case, no request and no text
// sent. The next Pass, or a re-report, adds the cases, opens the request
// and sends the text, exactly once.
func TestAReportCutOffAfterItsFirstSaveResumes(t *testing.T) {
	for _, via := range []string{"pass", "report"} {
		t.Run(via, func(t *testing.T) {
			r := newReportRig(t, nil)
			before := r.p.SecurityCount()
			// The crash: nothing after the first save happened.
			r.refuse = func(change.Case) bool { return true }
			r.g.Report(context.Background(), seedFinding())
			r.refuse, r.texts = nil, nil
			if err := r.store.MemStore.Save(r.store.first); err != nil {
				t.Fatal(err)
			}
			r.reopen(t)
			id := seedFinding()
			rec, _ := r.open(r.g.Evidence()[0].Finding.ID)
			if rec.Fix != "" || !rec.Texted {
				t.Fatalf("crash point: %+v", rec)
			}
			id.ID = rec.Finding.ID
			for i := 0; i < 2; i++ {
				if via == "pass" {
					r.g.Trigger()
					r.pass(t)
				} else {
					r.report(t, id)
				}
			}
			got, _ := r.open(id.ID)
			if got.Fix != FixPending || r.p.SecurityCount() != before+2 {
				t.Fatalf("not repaired: %+v, suite %d -> %d", got, before, r.p.SecurityCount())
			}
			if e := r.evidenceFor(t, id.ID); e.Fix != FixPending || e.Fixture == "" {
				t.Fatalf("evidence %+v", e)
			}
			if n := r.count(ownerLine(got)); n != 1 {
				t.Fatalf("owner line sent %d times: %q", n, r.texts)
			}
		})
	}
}

// P3-4b-1b item 3: a case add that failed once with a store error is
// retried on the next Pass, and the finding is then repaired and fixed.
func TestAFailedCaseAddIsRetried(t *testing.T) {
	fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}}
	r := newReportRig(t, fx)
	once := true
	r.refuse = func(change.Case) bool { o := once; once = false; return o }
	rec, err := r.g.Report(context.Background(), seedFinding())
	if err == nil || rec.Fix != "" {
		t.Fatalf("the failed add: %+v %v", rec, err)
	}
	r.g.Trigger()
	r.pass(t)
	if _, open := r.open(rec.Finding.ID); open || fx.calls() != 1 {
		t.Fatalf("not repaired: open %v, fixer called %d times", open, fx.calls())
	}
	if b := r.p.Files("config")[seedPath]; string(b) != reference {
		t.Fatalf("tree %s", b)
	}
}

// P3-4b-1b item 4 (LOOP-3): the scan covers the daemon's loop2NotRun
// table, and a banned word planted in it fails the scan.
func TestTheWordingScanCoversLoop2NotRun(t *testing.T) {
	src, err := os.ReadFile(daemonLoop2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "var loop2NotRun = map[") || !contains(ownerTables, daemonLoop2) {
		t.Fatal("loop2NotRun is not in a scanned file")
	}
	planted := strings.Replace(string(src), `"needs the updater"`, `"needs the updater to detect it"`, 1)
	if planted == string(src) {
		t.Fatal("no loop2NotRun entry to plant in")
	}
	if bad := scanWording(t, daemonLoop2, planted); len(bad) != 1 || bad[0] != "needs the updater to detect it" {
		t.Fatalf("planted scan: %q", bad)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// configEval answers tree rules from the tree, and plain probes only on a
// tree whose config is the active one: like replay, it cannot run a
// changed configuration.
type configEval struct{}

const plainProbe = "probe:plain"

func (configEval) Run(ctx context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	if out, ok := change.AnswerTreeRule(t, p.Input); ok {
		return out, nil
	}
	if string(t[seedPath]) != defective {
		return nil, change.ErrNotEvaluated
	}
	if string(p.Input) == plainProbe {
		return []byte("ok"), nil
	}
	return seedEval{}.Run(ctx, t, p)
}

// P3-4b-1b item 5 (LOOP-10): a config fix whose plain security probes
// cannot be evaluated stays rejected even when every case linked to its
// finding passes (ASSUMPTIONS.md, L2-9: an untested change to the other
// security properties is never adopted). With no such probe the same fix
// qualifies on its linked cases. The security suite never shrinks.
func TestAConfigFixWithUnevaluablePlainProbes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plain bool
		want  change.State
	}{
		{"a plain probe the fix makes unevaluable", true, change.StateRejected},
		{"no plain probe", false, change.StateAdopted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := &scriptFixer{cands: []change.Candidate{fixCand(reference)}}
			r := newReportRig(t, fx)
			r.p = seedPipeWith(t, configEval{})
			r.reopen(t)
			if tc.plain {
				c := change.Case{ID: "plain/config", Class: change.ClassConfig, Input: []byte(plainProbe), Expect: []byte("ok")}
				if err := r.p.AddSecurityCase(c); err != nil {
					t.Fatal(err)
				}
			}
			rec := r.report(t, seedFinding())
			before := r.p.SecurityCount()
			r.g.Trigger()
			r.g.Pass(context.Background())
			ev := r.evidenceFor(t, rec.Finding.ID)
			if ev.Fix != string(tc.want) {
				t.Fatalf("fix %q (%s), want %q", ev.Fix, ev.FixReason, tc.want)
			}
			if r.p.SecurityCount() < before {
				t.Fatalf("suite %d -> %d", before, r.p.SecurityCount())
			}
			_, open := r.open(rec.Finding.ID)
			if open != (tc.want != change.StateAdopted) {
				t.Fatalf("open %v", open)
			}
		})
	}
}
