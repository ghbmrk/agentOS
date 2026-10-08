package loops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: CAP-3, LOOP-3

// W3-forget-b2, potency C1: a forget that arrives while a builder machine
// works takes back only a build that read the forgotten task, and requeues
// it at once; work for other goals goes on.

// hookBuilder runs during inside each build, as a forget would arrive
// while the builder machine works, and ends the build if that cancelled
// it (loopbuild destroys the machine on ctx's end).
type hookBuilder struct {
	builder
	during func(Brief)
}

func (b *hookBuilder) Build(ctx context.Context, br Brief) (change.Candidate, error) {
	if b.during != nil {
		b.during(br)
	}
	if err := ctx.Err(); err != nil {
		return change.Candidate{}, err
	}
	return b.builder.Build(ctx, br)
}

// requeueRig is TestForgottenGoalsHypothesisIsTriedAgain's evidence: a
// refund hypothesis on goals mX1 and mX2, and a pay one on mY.
func requeueRig(t *testing.T) (*Learn, *hookBuilder) {
	t.Helper()
	r := newRig(t)
	h := r.harvester()
	for i := range 8 {
		r.corrected(h, i)
	}
	r.failing("x1", "owner:mX1", "refund")
	r.failing("x2", "owner:mX2", "refund")
	r.failing("y", "owner:mY", "pay")
	b := &hookBuilder{builder: builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}}
	l, err := NewLearn(LearnConfig{Pipeline: r.p, Journal: r.eng, Harvest: h, Builder: b, MinHeldOut: 1, Backoff: time.Hour})
	must(t, err)
	return l, b
}

const refundKey = "failure:bank/refund"

// nextBuild returns Loop 1's next candidate job and the key it builds.
func nextBuild(t *testing.T, l *Learn, b *hookBuilder) (Job, func() string) {
	t.Helper()
	job, ok := l.Next(context.Background(), true)
	if !ok || job.Name != "candidate" {
		t.Fatalf("no candidate job: %v %q", ok, job.Name)
	}
	n := len(b.got())
	return job, func() string {
		if bs := b.got(); len(bs) > n {
			return bs[len(bs)-1].Hypothesis.Key
		}
		return ""
	}
}

// The A/B test: the same refund build, with a forget of a goal it did not
// read (A) and of one it did (B), each arriving mid-build.
func TestAForgetMidBuildRequeuesOnlyTheBuildThatReadIt(t *testing.T) {
	for _, arm := range []struct {
		name, forget string
		requeued     bool
	}{
		{"A: another goal's task", "owner:mY", false},
		{"B: a task the build read", "owner:mX1", true},
	} {
		t.Run(arm.name, func(t *testing.T) {
			l, b := requeueRig(t)
			b.during = func(br Brief) {
				if br.Hypothesis.Key == refundKey {
					l.ForgetGoal(arm.forget)
				}
			}
			var res Result
			for range 5 { // the pay build may come first
				job, built := nextBuild(t, l, b)
				if res = job.Run(context.Background()); built() == refundKey {
					break
				}
			}
			b.during = nil
			if got := errors.Is(res.Err, ErrRequeued); got != arm.requeued {
				t.Fatalf("requeued %v (%v); want %v", got, res.Err, arm.requeued)
			}
			l.mu.Lock()
			tried, waits := l.tried[refundKey], !l.notBefore[refundKey].IsZero()
			l.mu.Unlock()
			if arm.requeued {
				// Taken back: not counted as tried, no backoff, offered
				// again on the very next turn.
				if tried != 0 || waits {
					t.Fatalf("a requeued build left tried=%d, backoff %v", tried, waits)
				}
				job, built := nextBuild(t, l, b)
				if job.Run(context.Background()); built() != refundKey {
					t.Fatal("the requeued build is not offered again at once")
				}
				return
			}
			// Kept: the build ran to its proposal and counts as tried.
			if tried == 0 {
				t.Fatal("a build that did not read the forgotten task was not kept")
			}
		})
	}
}

// The scheduler runs a requeued unit again at once, unmeasured, unlike an
// interrupted one, which waits Retry (PE3).
func TestARequeuedUnitRunsAgainAtOnceUnmeasured(t *testing.T) {
	r := newRig(t)
	src := &evalSource{run: func() Result { return Result{Err: ErrRequeued} }}
	r.restart(src)
	ran, wait := r.s.Tick(context.Background())
	if !ran || wait != 0 {
		t.Fatalf("requeued unit: ran %v, wait %v; want no wait", ran, wait)
	}
	r.s.mu.Lock()
	runs := r.s.loops[Improve].runs
	r.s.mu.Unlock()
	if runs != 0 {
		t.Fatalf("a requeued unit was measured (%d runs)", runs)
	}
}
