package apply

import (
	"context"
	"errors"
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
	return nil
}

func (a *activator) Abandon(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.abandoned++
	a.next = a.boot.UsrRootHash
	return nil
}

func (a *activator) Restart(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
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
	defer a.mu.Unlock()
	return a.boot, nil
}

// pipeline is the change pipeline's staged-adoption hooks.
type pipeline struct {
	mu        sync.Mutex
	confirmed []string
	failed    []string
}

func (p *pipeline) ConfirmStaged(ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.confirmed = append(p.confirmed, ref)
	return nil
}

func (p *pipeline) StageFailed(_ context.Context, ref string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failed = append(p.failed, ref)
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
	t        *testing.T
	clk      *clock
	act      *activator
	act0     Activator // the activator the applier uses; nil: act
	pipe     *pipeline
	store    *update.Store
	state    *change.MemStore
	eng      *journal.Engine
	pol      *policy
	inCall   bool
	working  bool
	excluded func(time.Time) bool
	talk     time.Time
	stopped  bool
	a        *Applier
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
		InCall: func() bool { return r.inCall }, Working: func() bool { return r.working },
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
