package loops

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/loops/loopstest"
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

// sharing records STOP SHARING and START SHARING, in place of the change
// pipeline's SetSharing.
type sharing struct {
	mu  sync.Mutex
	got []bool
	err error
}

func (x *sharing) set(_ context.Context, on bool) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.err != nil {
		return x.err
	}
	x.got = append(x.got, on)
	return nil
}

func (x *sharing) calls() []bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]bool(nil), x.got...)
}

// rig is a scheduler with its spare envelope on a kernel of its own and a
// settable clock. No journal: owner settings apply directly (HLD-4).
type rig struct {
	t       *testing.T
	clk     *clock
	spare   *Spare
	kern    *loopstest.Kernel
	store   *change.MemStore
	s       *Scheduler
	sharing *sharing
	// stopped is what Config.Stopped reports.
	stopped atomic.Bool
	// kmu serializes the kernel, which is not safe for concurrent use,
	// across widenings and revocations from racing budget changes.
	kmu sync.Mutex
}

func newRig(t *testing.T, sources ...Source) *rig {
	t.Helper()
	r := &rig{t: t, clk: &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}, store: &change.MemStore{}, sharing: &sharing{}}
	r.spare, r.kern = newSpare(t, r.clk.now)
	r.spare.Widen, r.spare.Revoke = r.widen, r.revoke
	r.restart(sources...)
	return r
}

// widen is the owner's passkey on the rig's kernel. Each widening is a
// millisecond later than the last, so two never grant the same key.
func (r *rig) widen(n int64) (key.Key, error) {
	r.kmu.Lock()
	defer r.kmu.Unlock()
	r.clk.add(time.Millisecond)
	return r.kern.Widen(n)
}

func (r *rig) revoke(id key.ID) error {
	r.kmu.Lock()
	defer r.kmu.Unlock()
	return r.kern.Revoke(id)
}

// widened is how many times the owner's passkey widened the envelope.
func (r *rig) widened() int {
	r.kmu.Lock()
	defer r.kmu.Unlock()
	return r.kern.Widened
}

// gateWiden makes Widen wait until release is closed; entered gets each cap
// asked, before the wait.
func (r *rig) gateWiden() (entered chan int64, release chan struct{}) {
	entered, release = make(chan int64, 64), make(chan struct{})
	r.spare.Widen = func(n int64) (key.Key, error) {
		entered <- n
		<-release
		return r.widen(n)
	}
	return entered, release
}

// restart builds a new scheduler over the same store and spare envelope.
func (r *rig) restart(sources ...Source) {
	r.t.Helper()
	s, err := New(Config{Store: r.store, Spare: r.spare, Sources: sources, Now: r.clk.now,
		YieldTarget: 200 * time.Millisecond, Idle: time.Hour, Retry: time.Minute,
		Stopped: r.stopped.Load, Sharing: r.sharing.set})
	if err != nil {
		r.t.Fatal(err)
	}
	r.s = s
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// newSpare is a spare envelope on a kernel of its own (loopstest).
func newSpare(t *testing.T, now func() time.Time) (*Spare, *loopstest.Kernel) {
	t.Helper()
	k := loopstest.New(t, now)
	return &Spare{State: k.State, Envelope: k.Envelope, Holder: k.Holder, Widen: k.Widen, Revoke: k.Revoke, OutPerM: loopstest.OutPerM}, k
}

// call is one spare call of amount minor units, charged to the spare key.
func (r *rig) call(amount int64) *key.Refusal {
	r.t.Helper()
	return r.kern.Call(r.spare.Key(), amount)
}
