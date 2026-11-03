package requal

// REQ: UPD-5, HLD-2, HLD-3

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// fakeSandbox answers each input with answer(candidate, input) and records
// what it was given.
type fakeSandbox struct {
	answer   func(cand bool, in []byte) ([]byte, error)
	startErr error
	closeErr func(cand bool) error
	starts   int
	closes   int
	inputs   [][]byte
}

type fakeSession struct {
	sb   *fakeSandbox
	cand bool
}

func (s *fakeSandbox) Start(_ context.Context, rel *update.Verified) (Session, error) {
	s.starts++
	if s.startErr != nil {
		return nil, s.startErr
	}
	return &fakeSession{s, rel != nil}, nil
}

func (s *fakeSession) Run(ctx context.Context, in []byte) ([]byte, error) {
	s.sb.inputs = append(s.sb.inputs, in)
	if s.sb.answer == nil {
		return in, nil
	}
	return s.sb.answer(s.cand, in)
}

func (s *fakeSession) Close() error {
	s.sb.closes++
	if s.sb.closeErr != nil {
		return s.sb.closeErr(s.cand)
	}
	return nil
}

type cases []Case

func (c cases) Cases(context.Context) ([]Case, error) { return c, nil }

// echo passes a case whose output equals its Expect.
func echo(c Case, out []byte) Grade { return Grade{Pass: bytes.Equal(out, c.Expect)} }

func three() cases {
	return cases{
		{ID: "a", Input: []byte("1"), Expect: []byte("1")},
		{ID: "b", Input: []byte("2"), Expect: []byte("2")},
		{ID: "c", Input: []byte("3"), Expect: []byte("x")},
	}
}

func allSuites(src Source, g Grader) map[string]Suite {
	return map[string]Suite{
		update.SuiteHeldOut:  {src, g},
		update.SuiteReplay:   {src, g},
		update.SuiteSecurity: {src, g},
	}
}

func runner(t *testing.T, sb Sandbox, suites map[string]Suite) *Runner {
	t.Helper()
	r, err := New(Config{Sandbox: sb, Suites: suites, CaseTimeout: time.Second, Budget: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func release(t *testing.T) *update.Verified {
	return updatetest.Release(t, 2, false, map[string][]byte{"host-image/usr.img": []byte("usr-2")})
}

func TestHostGradesWhatTheSandboxReturns(t *testing.T) {
	sb := &fakeSandbox{}
	r := runner(t, sb, allSuites(three(), echo))
	sc, err := r.Run(context.Background(), release(t), update.SuiteHeldOut)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Suite != update.SuiteHeldOut || sc.Cases != 3 || sc.Passed != 2 || sc.Digest == "" {
		t.Fatalf("score %+v, want 2 of 3 on held-out", sc)
	}
	if sb.starts != 1 {
		t.Fatalf("%d sandbox starts for one run, want 1", sb.starts)
	}
}

func TestOnlyTheInputReachesTheSandbox(t *testing.T) {
	sb := &fakeSandbox{}
	src := cases{{ID: "case-id-7", Input: []byte("in"), Expect: []byte("expected-answer")}}
	if _, err := runner(t, sb, allSuites(src, echo)).Run(context.Background(), release(t), update.SuiteSecurity); err != nil {
		t.Fatal(err)
	}
	if len(sb.inputs) != 1 || !bytes.Equal(sb.inputs[0], []byte("in")) {
		t.Fatalf("sandbox got %q, want only the input", sb.inputs)
	}
	// The sandbox's copy is its own: writing to it cannot change the case.
	sb.inputs[0][0] = 'X'
	if string(src[0].Input) != "in" {
		t.Fatal("the sandbox shares the case's input buffer")
	}
}

func TestSuiteWithoutSourceFailsClosed(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]map[string]Suite{
		"missing":   {update.SuiteHeldOut: {three(), echo}, update.SuiteReplay: {three(), echo}},
		"no source": {update.SuiteHeldOut: {three(), echo}, update.SuiteReplay: {three(), echo}, update.SuiteSecurity: {nil, echo}},
		"no grader": {update.SuiteHeldOut: {three(), echo}, update.SuiteReplay: {three(), echo}, update.SuiteSecurity: {three(), nil}},
	} {
		t.Run(name, func(t *testing.T) {
			sb := &fakeSandbox{}
			r := runner(t, sb, s)
			if _, err := r.Run(ctx, release(t), update.SuiteSecurity); !errors.Is(err, ErrNoSource) {
				t.Fatalf("err %v, want ErrNoSource", err)
			}
			// Through slice a's rule: an error, never a passed verdict.
			v, st := updatetest.Box(t, 2, false, map[string][]byte{"host-image/usr.img": []byte("usr-2")})
			q, err := update.NewRequalifier(st, r, filepath.Join(t.TempDir(), "requal.json"))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := q.Requalify(ctx, v); err == nil || got.Passed {
				t.Fatalf("Requalify = %+v, %v; want an error", got, err)
			}
		})
	}
}

func TestEmptySuiteBootsNothing(t *testing.T) {
	sb := &fakeSandbox{}
	r := runner(t, sb, allSuites(cases{}, echo))
	sc, err := r.Run(context.Background(), release(t), update.SuiteReplay)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Cases != 0 || sc.Passed != 0 || sc.Digest == "" || sb.starts != 0 {
		t.Fatalf("score %+v after %d starts, want 0 of 0 and no boot", sc, sb.starts)
	}
	// Through slice a's rule: empty held-out and replay suites pass, but an
	// empty security suite fails, so a fresh box holds its releases.
	v, st := updatetest.Box(t, 2, false, map[string][]byte{"host-image/usr.img": []byte("usr-2")})
	q, err := update.NewRequalifier(st, r, filepath.Join(t.TempDir(), "requal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := q.Requalify(context.Background(), v); err != nil || got.Passed || got.Reason != update.SuiteSecurity {
		t.Fatalf("Requalify = %+v, %v; want failed on security", got, err)
	}
}

// errSource answers its cases together with an error.
type errSource struct{ c cases }

var errCases = errors.New("cases unreadable")

func (s errSource) Cases(context.Context) ([]Case, error) { return s.c, errCases }

func TestSourceErrorIsAnError(t *testing.T) {
	ctx := context.Background()
	for name, src := range map[string]errSource{"no cases": {}, "with cases": {three()}} {
		t.Run(name, func(t *testing.T) {
			sb := &fakeSandbox{}
			// Security is whole and passing, so only the erring held-out
			// source stands between this candidate and a passed verdict.
			suites := allSuites(three(), echo)
			suites[update.SuiteHeldOut] = Suite{src, echo}
			suites[update.SuiteSecurity] = Suite{cases{{ID: "s1", Input: []byte("p"), Expect: []byte("p")}}, echo}
			r := runner(t, sb, suites)
			for _, rel := range []*update.Verified{nil, release(t)} {
				if _, err := r.Run(ctx, rel, update.SuiteHeldOut); !errors.Is(err, errCases) {
					t.Fatalf("err %v, want the source's error", err)
				}
			}
			if sb.starts != 0 {
				t.Fatalf("%d boots on a source error, want none", sb.starts)
			}
			v, st := updatetest.Box(t, 2, false, map[string][]byte{"host-image/usr.img": []byte("usr-2")})
			q, err := update.NewRequalifier(st, r, filepath.Join(t.TempDir(), "requal.json"))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := q.Requalify(ctx, v); err == nil || got.Passed {
				t.Fatalf("Requalify = %+v, %v; want an error", got, err)
			}
		})
	}
}

func TestDigestNamesTheCases(t *testing.T) {
	d := func(c cases) string {
		t.Helper()
		sc, err := runner(t, &fakeSandbox{}, allSuites(c, echo)).Run(context.Background(), nil, update.SuiteHeldOut)
		if err != nil {
			t.Fatal(err)
		}
		return sc.Digest
	}
	base := d(three())
	if d(three()) != base {
		t.Fatal("the same cases give two digests")
	}
	for name, mut := range map[string]func(c cases){
		"input":  func(c cases) { c[0].Input = []byte("9") },
		"expect": func(c cases) { c[2].Expect = []byte("y") },
		"id":     func(c cases) { c[1].ID = "z" },
		// Moving a byte between fields keeps the concatenation; the
		// length prefixes must still tell them apart.
		"split": func(c cases) { c[0].Input, c[0].Expect = []byte("11"), []byte("") },
	} {
		c := three()
		mut(c)
		if d(c) == base {
			t.Errorf("changing the %s keeps the digest", name)
		}
	}
	if d(three()[:2]) == base {
		t.Error("dropping a case keeps the digest")
	}
}

func TestDuplicateCaseIDsRefused(t *testing.T) {
	c := three()
	c[2].ID = "a"
	if _, err := runner(t, &fakeSandbox{}, allSuites(c, echo)).Run(context.Background(), release(t), update.SuiteHeldOut); err == nil {
		t.Fatal("duplicate case IDs scored")
	}
}

func TestCandidateErrorFailsTheCase(t *testing.T) {
	sb := &fakeSandbox{answer: func(cand bool, in []byte) ([]byte, error) {
		if string(in) == "2" {
			return nil, errors.New("candidate crashed")
		}
		return in, nil
	}}
	sc, err := runner(t, sb, allSuites(three(), echo)).Run(context.Background(), release(t), update.SuiteHeldOut)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Cases != 3 || sc.Passed != 1 {
		t.Fatalf("score %+v, want 1 of 3", sc)
	}
}

func TestBaselineErrorIsAnError(t *testing.T) {
	ctx := context.Background()
	crash := func(cand bool, in []byte) ([]byte, error) {
		if string(in) == "2" {
			return nil, errors.New("crashed")
		}
		return in, nil
	}
	sb := &fakeSandbox{answer: crash}
	if _, err := runner(t, sb, allSuites(three(), echo)).Run(ctx, nil, update.SuiteHeldOut); err == nil {
		t.Fatal("a baseline case error scored")
	}
	if sb.closes != 1 {
		t.Fatalf("the aborted baseline's session closed %d times, want 1", sb.closes)
	}
	if _, err := runner(t, &fakeSandbox{startErr: errors.New("no boot")}, allSuites(three(), echo)).Run(ctx, nil, update.SuiteHeldOut); err == nil {
		t.Fatal("a baseline start error scored")
	}
	// Start and close fail the run for the candidate too.
	if _, err := runner(t, &fakeSandbox{startErr: errors.New("no boot")}, allSuites(three(), echo)).Run(ctx, release(t), update.SuiteHeldOut); err == nil {
		t.Fatal("a candidate start error scored")
	}
	for _, cand := range []bool{false, true} {
		sb := &fakeSandbox{closeErr: func(bool) error { return errors.New("left running") }}
		var rel *update.Verified
		if cand {
			rel = release(t)
		}
		if _, err := runner(t, sb, allSuites(three(), echo)).Run(ctx, rel, update.SuiteHeldOut); err == nil {
			t.Fatalf("close error scored (candidate %v)", cand)
		}
	}
}

func TestBudgetSpentIsAnError(t *testing.T) {
	hang := &fakeSandbox{answer: func(cand bool, in []byte) ([]byte, error) {
		time.Sleep(30 * time.Millisecond)
		return in, nil
	}}
	r, err := New(Config{Sandbox: hang, Suites: allSuites(three(), echo), CaseTimeout: time.Second, Budget: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if sc, err := r.Run(context.Background(), release(t), update.SuiteHeldOut); err == nil {
		t.Fatalf("a run past its budget scored %+v", sc)
	}
}

func TestCaseTimeoutFailsACandidateCase(t *testing.T) {
	sb := &fakeSandbox{answer: func(cand bool, in []byte) ([]byte, error) { return in, nil }}
	slow := &slowSandbox{fakeSandbox: sb, slowOn: "1"}
	r, err := New(Config{Sandbox: slow, Suites: allSuites(three(), echo), CaseTimeout: 20 * time.Millisecond, Budget: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := r.Run(context.Background(), release(t), update.SuiteHeldOut)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Passed != 1 {
		t.Fatalf("score %+v, want the timed-out case failed", sc)
	}
}

// slowSandbox's sessions wait out the case's context on one input.
type slowSandbox struct {
	*fakeSandbox
	slowOn string
}

type slowSession struct {
	Session
	on string
}

func (s *slowSandbox) Start(ctx context.Context, rel *update.Verified) (Session, error) {
	sess, err := s.fakeSandbox.Start(ctx, rel)
	return slowSession{sess, s.slowOn}, err
}

func (s slowSession) Run(ctx context.Context, in []byte) ([]byte, error) {
	if string(in) == s.on {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.Session.Run(ctx, in)
}

func TestUnadmittedCountsOnReplayOnly(t *testing.T) {
	g := func(c Case, out []byte) Grade { return Grade{Pass: true, Unadmitted: 2} }
	r := runner(t, &fakeSandbox{}, allSuites(three(), g))
	for _, s := range []string{update.SuiteHeldOut, update.SuiteReplay, update.SuiteSecurity} {
		sc, err := r.Run(context.Background(), release(t), s)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if s == update.SuiteReplay {
			want = 6
		}
		if sc.Unadmitted != want {
			t.Errorf("%s: unadmitted %d, want %d", s, sc.Unadmitted, want)
		}
	}
}

func TestNegativeUnadmittedCountsAsNone(t *testing.T) {
	// A grader's negative count on one case must not cancel another case's
	// unadmitted steps, whether it comes first or last (a clamp on the
	// running total would pass only the first).
	for _, neg := range []string{"a", "c"} {
		g := func(c Case, out []byte) Grade {
			if c.ID == neg {
				return Grade{Pass: true, Unadmitted: -5}
			}
			return Grade{Pass: true, Unadmitted: 1}
		}
		sc, err := runner(t, &fakeSandbox{}, allSuites(three(), g)).Run(context.Background(), release(t), update.SuiteReplay)
		if err != nil {
			t.Fatal(err)
		}
		if sc.Unadmitted != 2 {
			t.Fatalf("negative on %s: unadmitted %d, want 2", neg, sc.Unadmitted)
		}
	}
}

func TestUncheckedReleaseRefused(t *testing.T) {
	sb := &fakeSandbox{}
	if _, err := runner(t, sb, allSuites(three(), echo)).Run(context.Background(), &update.Verified{}, update.SuiteHeldOut); err == nil {
		t.Fatal("an unchecked release ran")
	}
	if sb.starts != 0 {
		t.Fatal("an unchecked release booted")
	}
}

func TestNewRefusesMissingLimits(t *testing.T) {
	for _, c := range []Config{
		{Suites: allSuites(three(), echo), CaseTimeout: time.Second, Budget: time.Second},
		{Sandbox: &fakeSandbox{}, Budget: time.Second},
		{Sandbox: &fakeSandbox{}, CaseTimeout: time.Second},
	} {
		if _, err := New(c); err == nil {
			t.Errorf("New(%+v) accepted", c)
		}
	}
}

func TestRequalifyThroughTheRunner(t *testing.T) {
	ctx := context.Background()
	// The candidate answers "x" to input 3, so it passes held-out case c
	// that the baseline fails; regress makes it fail case a instead.
	for name, tc := range map[string]struct {
		answer func(cand bool, in []byte) ([]byte, error)
		pass   bool
		reason string
	}{
		"equal": {answer: nil, pass: true},
		"better": {answer: func(cand bool, in []byte) ([]byte, error) {
			if cand && string(in) == "3" {
				return []byte("x"), nil
			}
			return in, nil
		}, pass: true},
		"regress": {answer: func(cand bool, in []byte) ([]byte, error) {
			if cand && string(in) == "1" {
				return []byte("wrong"), nil
			}
			return in, nil
		}, reason: update.SuiteHeldOut},
	} {
		t.Run(name, func(t *testing.T) {
			sec := cases{{ID: "s1", Input: []byte("p"), Expect: []byte("p")}}
			suites := allSuites(three(), echo)
			suites[update.SuiteSecurity] = Suite{sec, echo}
			r := runner(t, &fakeSandbox{answer: tc.answer}, suites)
			v, st := updatetest.Box(t, 2, false, map[string][]byte{"host-image/usr.img": []byte("usr-2")})
			q, err := update.NewRequalifier(st, r, filepath.Join(t.TempDir(), "requal.json"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := q.Requalify(ctx, v)
			if err != nil {
				t.Fatal(err)
			}
			if got.Passed != tc.pass || got.Reason != tc.reason {
				t.Fatalf("verdict %+v, want passed %v reason %q", got, tc.pass, tc.reason)
			}
		})
	}
}
