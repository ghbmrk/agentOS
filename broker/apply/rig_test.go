package apply

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// activator is the image's A/B activator (P2-1), faked: it records what
// it was handed, and a "restart" boots the next entry, or falls back to
// the previous slot when the test says the health check fails.
type activator struct {
	mu         sync.Mutex
	installed  []int64
	next       string // /usr root hash of the next boot entry
	boot       Boot
	restarts   int
	failBoot   bool // the new slot fails its health check: boot counting falls back
	pending    bool // the new slot booted, health check not run yet
	installErr error
	abandoned  int
	onInstall  func() // runs after a successful Install
	abandonErr error
	onAbandon  func() // runs after a successful Abandon
	// onBooted runs once, after Booted answers; onRestart runs once,
	// before the restart. Both run outside the activator's lock.
	onBooted   func()
	onRestart  func()
	restartErr error
	bootedErr  error
}

// once takes and clears the hook *f under the activator's lock.
func (a *activator) once(f *func()) func() {
	a.mu.Lock()
	defer a.mu.Unlock()
	g := *f
	*f = nil
	return g
}

func (a *activator) Install(_ context.Context, v *update.Verified) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.installErr != nil {
		return a.installErr
	}
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	a.installed = append(a.installed, m.Version)
	a.next = m.UsrRootHash
	if a.onInstall != nil {
		a.onInstall()
	}
	return nil
}

func (a *activator) Abandon(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.abandonErr != nil {
		return a.abandonErr
	}
	a.abandoned++
	a.next = a.boot.UsrRootHash
	if a.onAbandon != nil {
		a.onAbandon()
	}
	return nil
}

func (a *activator) Restart(context.Context) error {
	if f := a.once(&a.onRestart); f != nil {
		f()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.restartErr != nil {
		return a.restartErr
	}
	a.restarts++
	a.boot.ID = "boot" + string(rune('0'+a.restarts))
	switch {
	case a.failBoot:
		// Counted tries ran out; the old slot boots and is blessed.
	case a.pending:
		a.boot.UsrRootHash, a.boot.Blessed = a.next, false
	default:
		a.boot.UsrRootHash, a.boot.Blessed = a.next, true
	}
	return nil
}

func (a *activator) Booted(context.Context) (Boot, error) {
	a.mu.Lock()
	b, err := a.boot, a.bootedErr
	a.mu.Unlock()
	if f := a.once(&a.onBooted); f != nil {
		f()
	}
	return b, err
}

// pipeline is the change pipeline's staged-adoption hooks, with their
// contract (SR3-4): settling an adoption again the same way is a success
// that changes nothing, the other way is refused. confirmErr and failErr
// fail the next call with no effect. calls logs every call, refused or
// not; onConfirm runs after a ConfirmStaged that succeeded.
type pipeline struct {
	mu         sync.Mutex
	confirmed  []string
	failed     []string
	confirmErr error
	failErr    error
	calls      []string
	onConfirm  func()
	dropped    []string
	dropErr    error
	// reverted: the pipeline's own reverts, by adoption, with their why.
	reverted map[string]string
}

// recheck is the pipeline's Recheck failing adoption id for security: it
// asks the applier to withdraw, then reverts the adoption itself.
func (r *rig) recheck(id string) error {
	if err := r.a.Withdraw(id, WhySecurity); err != nil {
		return err
	}
	r.pipe.mu.Lock()
	defer r.pipe.mu.Unlock()
	if r.pipe.reverted == nil {
		r.pipe.reverted = map[string]string{}
	}
	r.pipe.reverted[id] = change.WhySecurity
	return nil
}

func (p *pipeline) ConfirmStaged(ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, "confirm "+ref)
	if err := p.confirmErr; err != nil {
		p.confirmErr = nil
		return err
	}
	if slices.Contains(p.failed, ref) {
		return errors.New("fell back")
	}
	if !slices.Contains(p.confirmed, ref) {
		p.confirmed = append(p.confirmed, ref)
	}
	if f := p.onConfirm; f != nil {
		f()
	}
	return nil
}

func (p *pipeline) StageDropped(_ context.Context, ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, "drop "+ref)
	if err := p.dropErr; err != nil {
		p.dropErr = nil
		return err
	}
	if slices.Contains(p.confirmed, ref) {
		return fmt.Errorf("change: %s is %w", ref, change.ErrNotStaged)
	}
	if _, ok := p.reverted[ref]; ok {
		return nil // the revert ran first: nothing to do
	}
	if !slices.Contains(p.dropped, ref) {
		p.dropped = append(p.dropped, ref)
	}
	return nil
}

func (p *pipeline) StageFailed(_ context.Context, ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, "fail "+ref)
	if err := p.failErr; err != nil {
		p.failErr = nil
		return err
	}
	if slices.Contains(p.confirmed, ref) {
		return errors.New("confirmed")
	}
	if !slices.Contains(p.failed, ref) {
		p.failed = append(p.failed, ref)
	}
	return nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// policy is the journal policy: the applier's Check for its intents, as
// the grants gate will delegate meta.release to it.
// atDispatch, if set, runs once after the dispatch check passed.
type policy struct {
	a          *Applier
	atDispatch func()
}

func (p *policy) Check(ctx context.Context, ph journal.Phase, in journal.Intent) error {
	if in.Executor == Executor {
		err := p.a.Check(ctx, ph, in)
		if f := p.atDispatch; err == nil && ph == journal.PhaseDispatch && f != nil {
			p.atDispatch = nil
			f()
		}
		return err
	}
	return nil
}

type rig struct {
	t     *testing.T
	clk   *clock
	act   *activator
	act0  Activator // the activator the applier uses; nil: act
	pipe  *pipeline
	store *update.Store
	// mirror: when set, store checks every release the rig makes from it,
	// so a next release stages too.
	mirror   *updatetest.Mirror
	state    *change.MemStore
	eng      *journal.Engine
	pol      *policy
	inCall   bool
	working  bool
	excluded func(time.Time) bool
	talk     time.Time
	stopped  bool
	// atBusy runs once, when the applier next asks whether the box is
	// working; never set while Status may run (it asks under its lock).
	atBusy func()
	a      *Applier
}

func (r *rig) isWorking() bool {
	if f := r.atBusy; f != nil {
		r.atBusy = nil
		f()
	}
	return r.working
}

const oldHash = "11"

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, clk: &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)},
		act:  &activator{boot: Boot{ID: "boot0", UsrRootHash: strings.Repeat(oldHash, 32), Blessed: true}},
		pipe: &pipeline{}, state: &change.MemStore{}, pol: &policy{}}
	var err error
	r.eng, err = journal.Open(&journal.MemStore{}, r.pol, map[string]journal.Executor{Executor: current{r}},
		func(s string) string { return s }, journal.WithClock(r.clk.now))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// release makes a verified release; the rig's store is the box that
// checked it.
func (r *rig) release(v int64, security bool) *update.Verified {
	r.t.Helper()
	if r.mirror != nil {
		r.mirror.Add(v, update.ChannelStable, security)
		res, err := r.store.Check(r.mirror.Source(), update.Options{})
		if err != nil || res.Release == nil {
			r.t.Fatalf("check %d: %v %v", v, res.Release, err)
		}
		return res.Release
	}
	rel, st := updatetest.Box(r.t, v, security, map[string][]byte{"host-image/entry.conf": []byte("entry"), "host-image/usr.img": []byte("usr")})
	if r.store == nil {
		r.store = st
		r.restart()
	}
	return rel
}

// restart starts a new applier over the same state, as after a reboot.
func (r *rig) restart() {
	r.t.Helper()
	var act Activator = r.act
	if r.act0 != nil {
		act = r.act0
	}
	a, err := New(Config{Journal: r.eng, Activator: act, Store: r.store, Pipeline: r.pipe, State: r.state,
		InCall: func() bool { return r.inCall }, Working: r.isWorking,
		Excluded: func(t time.Time) bool { return r.excluded != nil && r.excluded(t) },
		LastTalk: func() time.Time { return r.talk },
		Stopped:  func() bool { return r.stopped },
		Jitter:   6 * time.Hour, Rand: func(n int64) int64 { return n / 2 }, Now: r.clk.now})
	if err != nil {
		r.t.Fatal(err)
	}
	r.a = a
	r.pol.a = a
}

func (r *rig) must(err error) {
	r.t.Helper()
	if err != nil {
		r.t.Fatal(err)
	}
}

// current is the applier executor across restarts in one engine.
type current struct{ r *rig }

func (c current) Execute(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return c.r.a.Execute(ctx, in, n)
}

func (c current) Reconcile(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return c.r.a.Reconcile(ctx, in, n)
}

func (r *rig) intents() []journal.Status {
	var out []journal.Status
	for _, st := range r.eng.List() {
		if st.Intent.Executor == Executor {
			out = append(out, st)
		}
	}
	return out
}

var errInstall = errors.New("slot write failed")
