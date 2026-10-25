package guest

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/sim"
)

// testKernel is the real kernel on broker/kernel/sim's disk, with one
// in-process clerk, "mail", that counts what it runs. The owner's two
// passkeys grant a clerk key for mail organize and trash to the planner host,
// which narrows it to each machine (KEY-3), as agentosd's Keys does.
type testKernel struct {
	t  testing.TB
	mu sync.Mutex
	k  *kernel.Kernel
	// runs counts the clerk's effects by plan ID.
	runs  map[string]int
	host  ed25519.PrivateKey // the planner host: the clerk key's holder
	clerk key.Key
	at    int64
	// lose, when set, makes Submit report a lost answer after the kernel
	// took the plan.
	lose bool
	// readErr, when set, makes Plan fail as a lost owner socket does.
	readErr bool
	// entered and hold, when set, make Submit signal entered and then wait
	// for hold, giving up if its context ends first.
	entered, hold chan struct{}
	// refuse, when set, makes Submit refuse every plan before logging it.
	refuse bool
}

func seedKey(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	return ed25519.NewKeyFromSeed(s)
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func newTestKernel(t testing.TB) *testKernel {
	t.Helper()
	owner, second, head := seedKey(1), seedKey(2), seedKey(3)
	tk := &testKernel{t: t, runs: map[string]int{}, host: seedKey(4), at: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC).UnixMilli()}
	l, err := kernel.Open(kernel.Config{Store: &sim.Disk{}, Anchor: &kernel.MemAnchor{},
		Pub: pub(head), Sign: head, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	if tk.k, err = kernel.Boot(l, []ed25519.PublicKey{pub(owner), pub(second)}, map[string]kernel.Clerk{"mail": tk}, tk.at); err != nil {
		t.Fatal(err)
	}
	root := key.Issue(owner, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Organize, key.Trash}, Serial: "guest-1"})
	setup := tk.at - kernel.GrantHold
	if tk.clerk, err = key.ClerkKey(root, owner, pub(tk.host), setup, 0); err != nil {
		t.Fatal(err)
	}
	h := kernel.BatchHash(root, tk.clerk)
	if err := tk.k.Issue(setup, []key.Cosign{key.Approve(owner, h), key.Approve(second, h)}, root, tk.clerk); err != nil {
		t.Fatal(err)
	}
	return tk
}

// keys narrows the clerk key to each machine, which then signs as its holder.
func (tk *testKernel) keys(machine string) (key.Key, ed25519.PrivateKey, bool) {
	m := seedKey(byte(10 + len(machine)))
	k, err := key.Derive(tk.clerk, tk.host, pub(m))
	if err != nil {
		tk.t.Error(err)
		return key.Key{}, nil, false
	}
	return k, m, true
}

func (tk *testKernel) Submit(ctx context.Context, p kernel.Plan) error {
	if tk.hold != nil {
		close(tk.entered)
		select {
		case <-tk.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	tk.mu.Lock()
	defer tk.mu.Unlock()
	if tk.refuse {
		return errors.New("kernel: malformed plan")
	}
	tk.at++
	if err := tk.k.Submit(tk.at, p); err != nil {
		return err
	}
	if err := tk.k.Tick(tk.at); err != nil {
		return err
	}
	if tk.lose {
		return context.DeadlineExceeded
	}
	return nil
}

func (tk *testKernel) Plan(_ context.Context, id string) (string, []string, bool, error) {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	if tk.readErr {
		return "", nil, false, errors.New("owner socket: connection reset")
	}
	// The kernel process runs its plans on its own clock; here each read
	// lets it.
	tk.at++
	if err := tk.k.Tick(tk.at); err != nil {
		return "", nil, false, err
	}
	p := tk.k.State().Plans[id]
	if p == nil {
		return "", nil, false, nil
	}
	var phases []string
	for _, st := range p.Steps {
		phases = append(phases, st.Phase)
	}
	return p.Status, phases, true, nil
}

// Do and Probe are the mail clerk: every step it is sent is done once.
func (tk *testKernel) Do(r kernel.Request, _ kernel.View) kernel.Result {
	tk.runs[r.Plan.ID]++
	return kernel.Result{Outcome: "ok"}
}

func (tk *testKernel) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "ok"}
}

// stop and resume are the owner's STOP and RESUME on the kernel.
func (tk *testKernel) stop() {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	tk.at++
	if err := tk.k.Stop(tk.at); err != nil {
		tk.t.Fatal(err)
	}
}

func (tk *testKernel) resume() {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	tk.at++
	if err := tk.k.Resume(tk.at); err != nil {
		tk.t.Fatal(err)
	}
}

func (tk *testKernel) ran(id string) int {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	return tk.runs[id]
}

func (tk *testKernel) plans() int {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	return len(tk.k.State().Plans)
}

// labels are the labels the kernel logged on plan id's first step.
func (tk *testKernel) labels(id string) []string {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	if p := tk.k.State().Plans[id]; p != nil && len(p.Plan.Steps) > 0 {
		return p.Plan.Steps[0].Labels
	}
	return nil
}
