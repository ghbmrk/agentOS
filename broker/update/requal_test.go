package update

// REQ: UPD-5, HLD-3

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner answers from cand and base by suite, and counts calls.
type fakeRunner struct {
	cand, base map[string]Score
	err        error
	calls      int
}

func (r *fakeRunner) Run(_ context.Context, rel *Verified, suite string) (Score, error) {
	r.calls++
	if r.err != nil {
		return Score{}, r.err
	}
	if rel == nil {
		return r.base[suite], nil
	}
	return r.cand[suite], nil
}

func sc(suite string, cases, passed int) Score {
	return Score{Suite: suite, Digest: "d-" + suite, Cases: cases, Passed: passed}
}

// passing is a runner on which the candidate equals the baseline.
func passing() *fakeRunner {
	s := map[string]Score{
		SuiteHeldOut:  sc(SuiteHeldOut, 10, 8),
		SuiteReplay:   sc(SuiteReplay, 5, 5),
		SuiteSecurity: sc(SuiteSecurity, 40, 40),
	}
	b := map[string]Score{}
	for k, v := range s {
		b[k] = v
	}
	return &fakeRunner{cand: s, base: b}
}

func requalifier(t *testing.T, f *fixture, r Runner) *Requalifier {
	t.Helper()
	q, err := NewRequalifier(f.store, r, filepath.Join(f.dir, "requal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestNoRunnerHoldsTheRelease(t *testing.T) {
	f, v := ordinary(t, Options{})
	q := requalifier(t, f, nil)
	got, err := q.Requalify(context.Background(), v)
	if err != nil || got.Passed || got.Reason != RequalUnavailable {
		t.Fatalf("no runner: %+v, %v; want unavailable and not passed", got, err)
	}
	if got.Ref != v.Ref() {
		t.Fatalf("verdict names %+v, want %+v", got.Ref, v.Ref())
	}
}

func TestRequalifyPassesWithNoRegression(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	q := requalifier(t, f, r)
	got, err := q.Requalify(context.Background(), v)
	if err != nil || !got.Passed || got.Reason != "" || len(got.Scores) != 3 {
		t.Fatalf("got %+v, %v; want passed on three suites", got, err)
	}
	if r.calls != 6 {
		t.Fatalf("runner called %d times, want 6 (three suites, candidate and baseline)", r.calls)
	}
	// Nothing is kept: a second call runs every suite again.
	again, err := q.Requalify(context.Background(), v)
	if err != nil || !again.Passed || r.calls != 12 {
		t.Fatalf("second call: %+v, %v, %d calls", again, err, r.calls)
	}
}

func TestEmptyTaskSuitesPass(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	for _, s := range []string{SuiteHeldOut, SuiteReplay} {
		r.cand[s], r.base[s] = sc(s, 0, 0), sc(s, 0, 0)
	}
	got, err := requalifier(t, f, r).Requalify(context.Background(), v)
	if err != nil || !got.Passed {
		t.Fatalf("a new box with no past tasks: %+v, %v", got, err)
	}
}

func TestRequalifyFailures(t *testing.T) {
	for _, c := range []struct {
		name   string
		mod    func(r *fakeRunner)
		reason string
	}{
		{"held-out regresses", func(r *fakeRunner) { r.cand[SuiteHeldOut] = sc(SuiteHeldOut, 10, 7) }, SuiteHeldOut},
		{"replay regresses", func(r *fakeRunner) { r.cand[SuiteReplay] = sc(SuiteReplay, 5, 4) }, SuiteReplay},
		{"replay step not admitted", func(r *fakeRunner) {
			s := sc(SuiteReplay, 5, 5)
			s.Unadmitted = 1
			r.cand[SuiteReplay] = s
		}, SuiteReplay},
		{"security case fails", func(r *fakeRunner) { r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 37) }, SuiteSecurity},
		{"security suite empty", func(r *fakeRunner) {
			r.cand[SuiteSecurity], r.base[SuiteSecurity] = sc(SuiteSecurity, 0, 0), sc(SuiteSecurity, 0, 0)
		}, SuiteSecurity},
		{"different suite digest", func(r *fakeRunner) {
			s := sc(SuiteHeldOut, 10, 9)
			s.Digest = "other"
			r.cand[SuiteHeldOut] = s
		}, SuiteHeldOut},
		{"different case count", func(r *fakeRunner) { r.cand[SuiteHeldOut] = sc(SuiteHeldOut, 9, 9) }, SuiteHeldOut},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, v := ordinary(t, Options{})
			r := passing()
			c.mod(r)
			got, err := requalifier(t, f, r).Requalify(context.Background(), v)
			if err != nil || got.Passed || got.Reason != c.reason || got.Detail == "" {
				t.Fatalf("got %+v, %v; want failed on %s with a detail", got, err, c.reason)
			}
			if c.name == "security case fails" && got.Detail != "3 security cases fail" {
				t.Fatalf("detail %q, want the failing count", got.Detail)
			}
		})
	}
}

func TestSecuritySuiteOnlyGrows(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	q := requalifier(t, f, r)
	if got, err := q.Requalify(context.Background(), v); err != nil || !got.Passed {
		t.Fatalf("first: %+v, %v", got, err)
	}
	// The installed release changes and the suite now has fewer cases on
	// both sides: the floor of 40 fails it, across a new Requalifier on the
	// same record.
	f.must(f.store.writeInstalled(Installed{Version: 1, UsrRootHash: strings.Repeat("cd", 32)}))
	r.cand[SuiteSecurity], r.base[SuiteSecurity] = sc(SuiteSecurity, 30, 30), sc(SuiteSecurity, 30, 30)
	got, err := requalifier(t, f, r).Requalify(context.Background(), v)
	if err != nil || got.Passed || got.Reason != SuiteSecurity {
		t.Fatalf("shrunk suite: %+v, %v; want failed on security", got, err)
	}
}

// A pass is never reused: a security case added since (HLD-5) is run, and
// a release that fails it does not pass (#4033 L3 point 2).
func TestSuiteGrowthIsRunAgain(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	q := requalifier(t, f, r)
	if got, err := q.Requalify(context.Background(), v); err != nil || !got.Passed {
		t.Fatalf("first: %+v, %v", got, err)
	}
	r.base[SuiteSecurity] = Score{Suite: SuiteSecurity, Digest: "d2", Cases: 41, Passed: 41}
	r.cand[SuiteSecurity] = Score{Suite: SuiteSecurity, Digest: "d2", Cases: 41, Passed: 40}
	got, err := q.Requalify(context.Background(), v)
	if err != nil || got.Passed || got.Reason != SuiteSecurity {
		t.Fatalf("after the suite grew: %+v, %v; want failed on security", got, err)
	}
}

// A held-out failure is not kept: a run that passes later passes.
func TestFailureIsRunAgain(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	r.cand[SuiteHeldOut] = sc(SuiteHeldOut, 10, 7)
	q := requalifier(t, f, r)
	if got, err := q.Requalify(context.Background(), v); err != nil || got.Passed {
		t.Fatalf("first: %+v, %v; want failed", got, err)
	}
	r.cand[SuiteHeldOut] = sc(SuiteHeldOut, 10, 9)
	if got, err := q.Requalify(context.Background(), v); err != nil || !got.Passed {
		t.Fatalf("second: %+v, %v; want passed", got, err)
	}
}

// A security failure is final on that suite, across restarts: a later run
// that passes every case does not pass (#4033 Security delta point 1). A
// new suite digest runs it afresh, and another candidate is not affected.
func TestSecurityFailureIsFinalOnItsSuite(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 39)
	if got, err := requalifier(t, f, r).Requalify(context.Background(), v); err != nil || got.Passed {
		t.Fatalf("first: %+v, %v; want failed", got, err)
	}
	r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 40)
	got, err := requalifier(t, f, r).Requalify(context.Background(), v)
	if err != nil || got.Passed || got.Reason != SuiteSecurity {
		t.Fatalf("retry on the same suite: %+v, %v; want failed on security", got, err)
	}
	// Another candidate on the same suite is judged on its own.
	f.release(3, nil)
	f.publish(0, 1)
	res, err := f.check(Options{})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	if got, err := requalifier(t, f, r).Requalify(context.Background(), res.Release); err != nil || !got.Passed {
		t.Fatalf("another candidate: %+v, %v; want passed", got, err)
	}
	// A grown suite (new digest) runs the first candidate afresh.
	grown := Score{Suite: SuiteSecurity, Digest: "d2", Cases: 41, Passed: 41}
	r.cand[SuiteSecurity], r.base[SuiteSecurity] = grown, grown
	if got, err := requalifier(t, f, r).Requalify(context.Background(), v); err != nil || !got.Passed {
		t.Fatalf("new suite: %+v, %v; want passed", got, err)
	}
}

// baseErr fails the baseline's security run while err is set.
type baseErr struct {
	*fakeRunner
	err error
}

func (r *baseErr) Run(ctx context.Context, rel *Verified, suite string) (Score, error) {
	if rel == nil && suite == SuiteSecurity && r.err != nil {
		return Score{}, r.err
	}
	return r.fakeRunner.Run(ctx, rel, suite)
}

// hook calls before ahead of each Run.
type hook struct {
	*fakeRunner
	before func(rel *Verified, suite string)
}

func (h *hook) Run(ctx context.Context, rel *Verified, suite string) (Score, error) {
	h.before(rel, suite)
	return h.fakeRunner.Run(ctx, rel, suite)
}

// A candidate's security failure is saved before the baseline runs, so a
// baseline error afterwards does not let a clean retry pass it (#4033
// Security delta 2, point 1a).
func TestSecurityMarkSurvivesBaselineError(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := &baseErr{fakeRunner: passing(), err: errors.New("sandbox flake")}
	r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 39)
	if _, err := requalifier(t, f, r).Requalify(context.Background(), v); err == nil {
		t.Fatal("baseline error not reported")
	}
	r.err = nil
	r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 40)
	if got, err := requalifier(t, f, r).Requalify(context.Background(), v); err != nil || got.Passed {
		t.Fatalf("clean retry after a baseline error: %+v, %v; want not passed", got, err)
	}
}

// A mark whose save failed still holds in this process (point 1b).
func TestSecurityMarkHeldWhenSaveFails(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 39)
	path := filepath.Join(f.dir, "requal.json")
	// After load, a non-empty directory at the record path makes the save
	// fail: it is planted when the candidate's security run starts.
	q := requalifier(t, f, &hook{r, func(rel *Verified, suite string) {
		if rel != nil && suite == SuiteSecurity {
			f.must(os.MkdirAll(filepath.Join(path, "x"), 0o700))
		}
	}})
	if _, err := q.Requalify(context.Background(), v); err == nil {
		t.Fatal("failed save not reported")
	}
	f.must(os.RemoveAll(path))
	q.runner = r
	r.cand[SuiteSecurity] = sc(SuiteSecurity, 40, 40)
	if got, err := q.Requalify(context.Background(), v); err != nil || got.Passed {
		t.Fatalf("clean retry after a failed save: %+v, %v; want not passed", got, err)
	}
}

// The ship gate holds even on a record a runner once wrote (#4033 Security
// point 4).
func TestNoRunnerAfterAPassStillHolds(t *testing.T) {
	f, v := ordinary(t, Options{})
	if got, err := requalifier(t, f, passing()).Requalify(context.Background(), v); err != nil || !got.Passed {
		t.Fatalf("with a runner: %+v, %v", got, err)
	}
	got, err := requalifier(t, f, nil).Requalify(context.Background(), v)
	if err != nil || got.Passed || got.Reason != RequalUnavailable {
		t.Fatalf("no runner on the same record: %+v, %v; want unavailable", got, err)
	}
}

func TestRunnerErrorKeepsNothing(t *testing.T) {
	f, v := ordinary(t, Options{})
	r := passing()
	r.err = errors.New("sandbox did not boot")
	q := requalifier(t, f, r)
	if got, err := q.Requalify(context.Background(), v); err == nil || got.Passed {
		t.Fatalf("runner error: %+v, %v; want an error", got, err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "requal.json")); !os.IsNotExist(err) {
		t.Fatalf("a failed run saved a record: %v", err)
	}
	r.err = nil
	if got, err := q.Requalify(context.Background(), v); err != nil || !got.Passed {
		t.Fatalf("after the error clears: %+v, %v", got, err)
	}
}

func TestMalformedScoreFailsClosed(t *testing.T) {
	for _, c := range []struct {
		name string
		s    Score
	}{
		{"wrong suite", sc(SuiteReplay, 10, 8)},
		{"no digest", Score{Suite: SuiteHeldOut, Cases: 10, Passed: 8}},
		{"more passed than cases", sc(SuiteHeldOut, 10, 11)},
		{"negative", sc(SuiteHeldOut, -1, -1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, v := ordinary(t, Options{})
			r := passing()
			r.cand[SuiteHeldOut] = c.s
			if got, err := requalifier(t, f, r).Requalify(context.Background(), v); err == nil || got.Passed {
				t.Fatalf("got %+v, %v; want an error", got, err)
			}
		})
	}
}

func TestCorruptRecordFailsClosed(t *testing.T) {
	f, v := ordinary(t, Options{})
	f.must(os.WriteFile(filepath.Join(f.dir, "requal.json"), []byte("{"), 0o600))
	if got, err := requalifier(t, f, passing()).Requalify(context.Background(), v); err == nil || got.Passed {
		t.Fatalf("corrupt record: %+v, %v; want an error", got, err)
	}
}

func TestRequalifyRefusesUncheckedRelease(t *testing.T) {
	f := newFixture(t)
	if _, err := requalifier(t, f, passing()).Requalify(context.Background(), &Verified{}); !errors.Is(err, ErrNotChecked) {
		t.Fatalf("unchecked: %v", err)
	}
	if _, err := NewRequalifier(nil, nil, "x"); err == nil {
		t.Fatal("no store accepted")
	}
}
