package apply

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
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

// seedKey is a synthetic key from one seed byte.
func seedKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	b := make([]byte, ed25519.SeedSize)
	b[0] = seed
	k := ed25519.NewKeyFromSeed(b)
	return k.Public().(ed25519.PublicKey), k
}

// clerkSide is the update clerk across restarts under one kernel. When
// atDispatch is set, it runs once after the clerk's own checks passed and
// before it acts, as a change landing between the two would.
type clerkSide struct{ r *rig }

func (c clerkSide) Do(req kernel.Request, v kernel.View) kernel.Result {
	c.r.dos++
	f := c.r.atDispatch
	if f == nil {
		return c.r.a.Do(req, v)
	}
	if res, ok := c.r.a.done(req.Plan.ID); ok {
		return res
	}
	if rf := c.r.a.authorize(req, v); rf != "" {
		return kernel.Result{Outcome: "failed", Detail: rf}
	}
	c.r.atDispatch = nil
	f()
	return c.r.a.execute(context.Background(), req.Plan.ID)
}

func (c clerkSide) Probe(req kernel.Request, v kernel.View) kernel.Result { return c.r.a.Probe(req, v) }

// kern is the kernel as the daemon drives it: a submitted plan is decided
// and its step dispatched at once, unless hold is set.
type kern struct{ r *rig }

func (k kern) Submit(now int64, p kernel.Plan) error {
	if err := k.r.k.Submit(now, p); err != nil {
		return err
	}
	if ps := k.r.k.State().Plans[p.ID]; ps.Status == kernel.SRejected {
		k.r.t.Logf("kernel rejected %s: %s", p.ID, ps.Reject)
	}
	if k.r.hold {
		return nil
	}
	return k.r.k.Tick(now)
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
	mirror *updatetest.Mirror
	state  *change.MemStore
	k      *kernel.Kernel
	mem    *kernel.MemStore
	anc    *kernel.MemAnchor
	pinned key.PublicKey
	holder ed25519.PrivateKey
	upkey  key.Key
	// hold: the kernel does not dispatch a submitted plan until the test
	// ticks it; dos counts the clerk's dispatches.
	hold       bool
	dos        int
	atDispatch func()
	// saves: every state the applier saved, in order.
	saves    []state
	inCall   bool
	working  bool
	excluded func(time.Time) bool
	talk     time.Time
	stopped  bool
	paused   bool // the pinned channel
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
		pipe: &pipeline{}, state: &change.MemStore{}, mem: &kernel.MemStore{}, anc: &kernel.MemAnchor{}}
	// The image-pinned update key: a standing root for activate only
	// (decision 2 of brief #3423), granted in the log before the test.
	pub, priv := seedKey(40)
	r.pinned, r.holder = key.Ed25519(pub), priv
	r.upkey = key.Issue(key.Ed25519Signer(priv), key.Root{Clerk: Name, Verbs: []key.Verb{key.ChangeAccount}, Serial: "image"})
	r.bootKernel()
	_, opriv := seedKey(1)
	_, bpriv := seedKey(12)
	batch := []key.Key{r.upkey}
	cos := []key.Cosign{key.Approve(key.Ed25519Signer(opriv), kernel.BatchHash(batch...)), key.Approve(key.Ed25519Signer(bpriv), kernel.BatchHash(batch...))}
	if err := r.k.Issue(r.ms()-kernel.GrantHold, cos, batch...); err != nil {
		t.Fatal(err)
	}
	return r
}

// anchors are the kernel's in the rig: the owner's two hardware keys and
// the pinned update key.
//
// STAND-IN, NEVER WIRING: the pinned key is listed as an anchor only
// because the kernel has no other way yet to admit a root no owner signed;
// without it the kernel rejects every activate plan. An anchor signs
// enrollments and cosigns for every clerk, and the pinned key's holder
// ships in the image, so agentosd must never copy this list: #3677 gives
// the kernel a grant of the image-pinned root that is not an anchor, and
// this fixture moves to it then (ASSUMPTIONS MIG-4-adapters-e-1, A7).
func (r *rig) anchors() []key.PublicKey {
	opub, _ := seedKey(1)
	bpub, _ := seedKey(12)
	return []key.PublicKey{key.Ed25519(opub), key.Ed25519(bpub), r.pinned}
}

func (r *rig) ms() int64 { return r.clk.now().UnixMilli() }

// bootKernel (re)starts the kernel over the rig's log, as after a reboot:
// a step in flight is marked unknown, to be probed (KRN-8).
func (r *rig) bootKernel() {
	r.t.Helper()
	kpub, kpriv := seedKey(3)
	l, err := kernel.Open(kernel.Config{Store: r.mem, Anchor: r.anc, Pub: kpub, Sign: kpriv, Rand: mrand.NewChaCha8([32]byte{1})})
	if err != nil {
		r.t.Fatal(err)
	}
	if r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{Name: clerkSide{r}}, r.ms()); err != nil {
		r.t.Fatal(err)
	}
}

// nextDay moves past the kernel's 24-hour guard on an identical effect
// (KRN-8) and lets the kernel reconcile a step left unknown, as the
// daemon's kernel ticks would: the same release is activated again only
// by a later plan, or by the kernel's redo of one proven not done.
func (r *rig) nextDay() {
	r.t.Helper()
	r.clk.add(24 * time.Hour)
	r.tick()
}

// reconcile lets the kernel probe a step left unknown, ProbeEvery later.
func (r *rig) reconcile() {
	r.t.Helper()
	r.clk.add(kernel.ProbeEvery * time.Millisecond)
	r.tick()
}

// retried is the same boot's retry of an unrecorded handover: the next
// Tick abandons it, and the kernel, which admits no second plan for the
// release while the first is unknown (KRN-8), probes the first, finds it
// not done and redoes it; the Tick after that restarts into it.
func (r *rig) retried() (bool, error) {
	r.t.Helper()
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		return ok, fmt.Errorf("abandoning tick: %v", err)
	}
	r.reconcile()
	return r.a.Tick(context.Background())
}

// tick runs the kernel now: a held dispatch or a probe.
func (r *rig) tick() {
	r.t.Helper()
	r.must(r.k.Tick(r.ms()))
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
	a, err := New(Config{Kernel: kern{r}, Key: r.upkey, Holder: r.holder, Pinned: r.pinned, Activator: act, Store: r.store, Pipeline: r.pipe, State: savedState{r},
		InCall: func() bool { return r.inCall }, Working: r.isWorking,
		Excluded: func(t time.Time) bool { return r.excluded != nil && r.excluded(t) },
		LastTalk: func() time.Time { return r.talk },
		Stopped:  func() bool { return r.stopped },
		Paused:   func() bool { return r.paused },
		Jitter:   6 * time.Hour, Rand: func(n int64) int64 { return n / 2 }, Now: r.clk.now})
	if err != nil {
		r.t.Fatal(err)
	}
	r.a = a
}

func (r *rig) must(err error) {
	r.t.Helper()
	if err != nil {
		r.t.Fatal(err)
	}
}

// savedState is the rig's state store, recording each save.
type savedState struct{ r *rig }

func (s savedState) Load() ([]byte, error) { return s.r.state.Load() }

func (s savedState) Save(b []byte) error {
	if err := s.r.state.Save(b); err != nil {
		return err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	s.r.saves = append(s.r.saves, st)
	return nil
}

// plans is the update clerk's plans in the kernel's log, in order.
func (r *rig) plans() []*kernel.PlanState {
	var out []*kernel.PlanState
	for _, id := range r.k.State().Order {
		if p := r.k.State().Plans[id]; len(p.Plan.Steps) > 0 && p.Plan.Steps[0].Clerk == Name {
			out = append(out, p)
		}
	}
	return out
}

var errInstall = errors.New("slot write failed")
