package loops

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// policy is the broker's policy in these tests: loop settings and change
// intents go to their own Check, and ErrNeedsOwner becomes the owner's
// answer (approve). Task intents are allowed.
type policy struct {
	mu      sync.Mutex
	s       *Scheduler
	p       *change.Pipeline
	approve bool
	asked   []string
}

func (o *policy) Check(ctx context.Context, ph journal.Phase, in journal.Intent) error {
	var err error
	switch in.Executor {
	case Executor:
		err = o.s.Check(ctx, ph, in)
	case change.Executor:
		err = o.p.Check(ctx, ph, in)
	default:
		return nil
	}
	if !errors.Is(err, ErrNeedsOwner) && !errors.Is(err, change.ErrNeedsOwner) {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if ph == journal.PhaseAuthorize {
		o.asked = append(o.asked, in.ID)
	}
	if o.approve {
		return nil
	}
	return errors.New("needs the owner's approval")
}

func (o *policy) wasAsked() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.asked...)
}

// tasks is the executor for task intents: each ID's outcome is set by the
// test (default succeeded), and a dispatch advances the clock by its delay.
type tasks struct {
	mu    sync.Mutex
	out   map[string]journal.Result
	delay map[string]time.Duration
	clk   *clock
}

func (x *tasks) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	x.mu.Lock()
	defer x.mu.Unlock()
	if d := x.delay[in.ID]; d > 0 {
		x.clk.add(d)
	}
	if r, ok := x.out[in.ID]; ok {
		return journal.Outcome{Result: r}
	}
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (x *tasks) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

// rig is a scheduler and change pipeline on one real journal engine.
type rig struct {
	t     *testing.T
	clk   *clock
	spare *meter.Meter
	store *change.MemStore
	s     *Scheduler
	pol   *policy
	eng   *journal.Engine
	tasks *tasks
	p     *change.Pipeline
	ev    *evaluator
}

func newRig(t *testing.T, sources ...Source) *rig {
	t.Helper()
	r := &rig{t: t, clk: &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}, store: &change.MemStore{}}
	var err error
	r.spare, err = meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000},
		OverallCap: SpareLimits(DefaultSpareCalls),
		Now:        r.clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.tasks = &tasks{out: map[string]journal.Result{}, delay: map[string]time.Duration{}, clk: r.clk}
	r.ev = &evaluator{}
	r.p, err = change.New(change.Config{
		Store:       &change.MemStore{},
		Evaluator:   r.ev,
		Initial:     change.Tree{"procedures/mail": []byte("v1"), "skills/greet": []byte("hi")},
		MinHeldOut:  5,
		MinSecurity: 1,
		Now:         r.clk.now,
		Rand:        fixed{}, // a fixed split key, so the dev split is the same every run
	})
	if err != nil {
		t.Fatal(err)
	}
	r.ev.p = r.p
	r.restart(sources...)
	must(t, r.p.AddSecurityCase(change.Case{ID: "sec-exfil", Class: change.ClassSkill,
		Input: []byte("probe:exfil"), Expect: []byte("refused")}))
	return r
}

// restart builds a new scheduler and engine over the same stores.
func (r *rig) restart(sources ...Source) {
	r.t.Helper()
	s, err := New(Config{Store: r.store, Spare: r.spare, Sources: sources, Now: r.clk.now,
		YieldTarget: 200 * time.Millisecond, Idle: time.Hour, Retry: time.Minute,
		Sharing: r.p.SetSharing})
	if err != nil {
		r.t.Fatal(err)
	}
	r.s = s
	if r.pol == nil {
		r.pol = &policy{}
	}
	r.pol.s, r.pol.p = s, r.p
	if r.eng == nil {
		r.eng, err = journal.Open(&journal.MemStore{}, r.pol,
			map[string]journal.Executor{Executor: current{r}, change.Executor: r.p, "task": r.tasks},
			func(s string) string { return s }, journal.WithClock(r.clk.now))
		if err != nil {
			r.t.Fatal(err)
		}
		r.p.Attach(r.eng)
	}
	s.Attach(r.eng)
}

// task journals and runs one task intent in goal g.
func (r *rig) task(id, goal, account, action string, label string) {
	r.t.Helper()
	in := journal.Intent{ID: id, GoalID: goal, Origin: "guest:mail-agent", Account: account, Action: action,
		Executor: "task", Machine: "mail-agent", Label: label}
	if _, err := r.eng.Submit(in); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.eng.Authorize(context.Background(), id); err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.eng.Dispatch(context.Background(), id); err != nil {
		r.t.Fatal(err)
	}
}

// fixed is a deterministic "random" source for the pipeline. These tests
// rely on the dev/held-out layout its split key gives; the key was changed
// when cases began splitting by goal (P3-1c), which re-laid the split.
type fixed struct{}

func (fixed) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i*7 + 5)
	}
	return len(b), nil
}

// current is the scheduler executor across restarts in one engine.
type current struct{ r *rig }

func (c current) Execute(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return c.r.s.Execute(ctx, in, n)
}
func (c current) Reconcile(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return c.r.s.Reconcile(ctx, in, n)
}

// evaluator answers a probe with the file its input names in the tree
// under evaluation; the security fixture's input "probe:exfil" answers
// "refused" unless a skill holds "exfiltrate".
type evaluator struct {
	mu  sync.Mutex
	p   *change.Pipeline
	ran int
	// hook, if set, runs at the start of run number n (from 1).
	hook func(ctx context.Context, n int)
	// refuse, if set and returning an error for run n, fails the run with
	// it (an evaluator interruption, say).
	refuse func(n int) error
}

func (e *evaluator) Run(ctx context.Context, t change.Tree, pr change.Probe) ([]byte, error) {
	e.mu.Lock()
	e.ran++
	n, hook, refuse := e.ran, e.hook, e.refuse
	e.mu.Unlock()
	if hook != nil {
		hook(ctx, n)
	}
	if refuse != nil {
		if err := refuse(n); err != nil {
			return nil, err
		}
	}
	if string(pr.Input) == "probe:exfil" {
		for p, b := range t {
			if len(p) > 7 && p[:7] == "skills/" && string(b) == "exfiltrate" {
				return []byte("leaked"), nil
			}
		}
		return []byte("refused"), nil
	}
	b, ok := t[string(pr.Input)]
	if !ok {
		return nil, fmt.Errorf("no %s", pr.Input)
	}
	return b, nil
}

func (e *evaluator) runs() int { e.mu.Lock(); defer e.mu.Unlock(); return e.ran }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
