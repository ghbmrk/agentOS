package loops

import (
	"context"
	"errors"
	"slices"
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
	return requeueRigOn(t, nil)
}

// requeueRigOn is requeueRig with the pipeline wrap returns in place of
// the rig's own (nil: the rig's own).
func requeueRigOn(t *testing.T, wrap func(Pipeline) Pipeline) (*Learn, *hookBuilder) {
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
	var p Pipeline = r.p
	if wrap != nil {
		p = wrap(p)
	}
	l, err := NewLearn(LearnConfig{Pipeline: p, Journal: r.eng, Harvest: h, Builder: b, MinHeldOut: 1, Backoff: time.Hour})
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

// A forget that lands between Next and the build starting is not missed:
// the build is taken back as if it had landed mid-build (L3 on #321).
func TestAForgetBeforeTheBuildStartsRequeuesIt(t *testing.T) {
	// Where the refund build falls in the (deterministic) order.
	l, b := requeueRig(t)
	at := -1
	for i := range 5 {
		job, built := nextBuild(t, l, b)
		if job.Run(context.Background()); built() == refundKey {
			at = i
			break
		}
	}
	if at < 0 {
		t.Fatal("the refund build never came")
	}
	l, b = requeueRig(t)
	for range at {
		job, _ := nextBuild(t, l, b)
		job.Run(context.Background())
	}
	job, _ := nextBuild(t, l, b)
	l.ForgetGoal("owner:mX1")
	builds := 0
	b.during = func(Brief) { builds++ }
	if res := job.Run(context.Background()); !errors.Is(res.Err, ErrRequeued) {
		t.Fatalf("a forget before the build began: %v; want ErrRequeued", res.Err)
	}
	b.during = nil
	if builds != 0 {
		// W3-forget-b2 f2: a job that cancelled itself builds nothing.
		t.Fatalf("a requeued job still built (%d builds)", builds)
	}
	l.mu.Lock()
	tried, waits := l.tried[refundKey], !l.notBefore[refundKey].IsZero()
	l.mu.Unlock()
	if tried != 0 || waits {
		t.Fatalf("left tried=%d, backoff %v", tried, waits)
	}
	job, built := nextBuild(t, l, b)
	if job.Run(context.Background()); built() != refundKey {
		t.Fatal("the requeued build is not offered again at once")
	}
}

// refundBuild runs Loop 1's jobs until the refund build has begun, and
// returns its result; b.during sees each build as it begins.
func refundBuild(t *testing.T, l *Learn, b *hookBuilder, ctx func() context.Context) Result {
	t.Helper()
	during, began := b.during, ""
	defer func() { b.during = during }()
	b.during = func(br Brief) {
		began = br.Hypothesis.Key
		if during != nil {
			during(br)
		}
	}
	for range 5 { // the pay build may come first
		job, _ := nextBuild(t, l, b)
		if res := job.Run(ctx()); began == refundKey {
			return res
		}
	}
	t.Fatal("the refund build never came")
	return Result{}
}

// W3-forget-b2 f3: a build whose context ended for another reason (the
// scheduler preempted it) and whose goal is then forgotten is requeued
// too, though its cause is not ErrRequeued: the post-build check reads
// the forget itself.
func TestAForgetAfterAPreemptionStillRequeues(t *testing.T) {
	l, b := requeueRig(t)
	var stop context.CancelFunc
	b.during = func(br Brief) {
		if br.Hypothesis.Key == refundKey {
			stop() // preempted: the job's ctx ends first
			l.ForgetGoal("owner:mX1")
		}
	}
	res := refundBuild(t, l, b, func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		stop = cancel
		return ctx
	})
	b.during = nil
	if !errors.Is(res.Err, ErrRequeued) {
		t.Fatalf("preempted, then forgotten: %v; want ErrRequeued", res.Err)
	}
	l.mu.Lock()
	tried, asks := l.tried[refundKey], l.asks[refundKey]
	l.mu.Unlock()
	if tried != 0 || asks != 0 {
		t.Fatalf("left tried=%d asks=%d", tried, asks)
	}
}

// forgetOnPropose answers the refund candidate "waiting on the owner",
// and the owner forgets its goal just after it reached them.
type forgetOnPropose struct {
	Pipeline
	l     *Learn
	asked int
}

func (p *forgetOnPropose) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	if !slices.Contains(c.Goals, "owner:mX1") {
		return p.Pipeline.Propose(ctx, c)
	}
	p.asked++
	p.l.ForgetGoal("owner:mX1")
	return change.Report{State: change.StateAwaitingOwner}, nil
}

// W3-forget-b2 f1 (L3 on #321): a forget that lands after the proposal
// reached the owner, while the job still runs, requeues the rebuild at
// once, as a forget after the job does, and counts that ask the same way,
// so forgets never let a hypothesis ask more than MaxAsks times.
func TestAForgetAfterTheProposalReachedTheOwnerCountsTheAsk(t *testing.T) {
	fp := &forgetOnPropose{}
	l, b := requeueRigOn(t, func(p Pipeline) Pipeline { fp.Pipeline = p; return fp })
	fp.l = l
	if res := refundBuild(t, l, b, context.Background); !errors.Is(res.Err, ErrRequeued) {
		t.Fatalf("forgotten after the ask: %v; want ErrRequeued", res.Err)
	}
	l.mu.Lock()
	tried, asks, waits := l.tried[refundKey], l.asks[refundKey], !l.notBefore[refundKey].IsZero()
	l.mu.Unlock()
	if tried != 0 || waits || asks != 1 {
		t.Fatalf("tried=%d backoff %v asks=%d; want 0, false, 1", tried, waits, asks)
	}
	// Each further forget after an ask rebuilds at once, until MaxAsks.
	for range 4 {
		job, ok := l.Next(context.Background(), true)
		if !ok || job.Name != "candidate" {
			break
		}
		job.Run(context.Background())
	}
	if fp.asked != l.cfg.MaxAsks {
		t.Fatalf("the owner was asked %d times; MaxAsks is %d", fp.asked, l.cfg.MaxAsks)
	}
}
