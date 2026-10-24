// Package kernelproc is the kernel's process (MIG-4-run, #2682; option A;
// split from broker/clerk/run by KRN-2 split, #2892): it holds the log and
// reaches each clerk over that clerk's socket. It never holds a credential,
// and it links no clerk's code, so no mail or model parser is in the kernel
// process (SPEC KRN-2). The wire both sides speak (the call, the view and
// the socket helpers) lives here too, and broker/clerk/run, the clerks'
// processes, imports it.
package kernelproc

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// KernelConfig is what the kernel process starts from. The log key and the
// head key come from the sealed store (STO-2), which this slice does not
// read: until it lands, only tests start a kernel process.
type KernelConfig struct {
	Log     string        // the log file
	Anchor  kernel.Anchor // where signed heads go, off the log's disk (LOG-2)
	Key     [32]byte      // the log's AES-256-GCM key
	Pub     ed25519.PublicKey
	Sign    ed25519.PrivateKey
	Anchors []ed25519.PublicKey // the owner's hardware keys (D-146)
	Clerks  map[string]Remote   // every clerk the kernel runs, by name; a closed table
}

// Kernel is the kernel process's one kernel: every call to it goes through
// one lock, so the owner side, the planner side and the clock never
// interleave inside the kernel. Clerk calls run outside it (Tick), so STOP,
// a revoke or STATUS never waits on a clerk (KRN-7, OWN-18).
type Kernel struct {
	mu      sync.Mutex
	k       *kernel.Kernel
	store   *FileStore
	clerks  map[string]remote
	anchors []ed25519.PublicKey
}

// OpenKernel opens the log, replays it and boots the kernel at now: plans
// left undecided are decided, and steps left in flight are marked unknown,
// to be probed through their clerk (KRN-8).
func OpenKernel(cfg KernelConfig, now int64) (*Kernel, error) {
	if cfg.Anchor == nil || cfg.Sign == nil || len(cfg.Anchors) == 0 {
		return nil, errors.New("run: a kernel needs an anchor, the head key and the owner's anchors")
	}
	st, err := OpenFileStore(cfg.Log)
	if err != nil {
		return nil, err
	}
	l, err := kernel.Open(kernel.Config{Store: st, Anchor: cfg.Anchor, Key: cfg.Key, Pub: cfg.Pub, Sign: cfg.Sign, Rand: rand.Reader})
	if err != nil {
		st.Close()
		return nil, err
	}
	clerks, kc := map[string]remote{}, map[string]kernel.Clerk{}
	for name, r := range cfg.Clerks {
		clerks[name] = remote{r, cfg.Anchors}
		kc[name] = clerks[name]
	}
	k, err := kernel.Boot(l, cfg.Anchors, kc, now)
	if err != nil {
		st.Close()
		return nil, err
	}
	return &Kernel{k: k, store: st, clerks: clerks, anchors: cfg.Anchors}, nil
}

// Tick runs every plan as far as now allows. It takes the due calls under the
// lock, then for each one, under the lock again, makes the kernel's last
// check (kernel.Send) and takes the call's view, makes the call without the
// lock, and logs its answer under it. A STOP or revoke logged while an
// earlier call hangs stops every later one (KRN-7).
func (h *Kernel) Tick(now int64) error {
	for n := 0; n < 4*kernel.MaxSteps; n++ {
		var due []kernel.Call
		err := h.With(func(k *kernel.Kernel) (err error) {
			due, err = k.Calls(now)
			return err
		})
		if err != nil || len(due) == 0 {
			return err
		}
		for _, c := range due {
			var s snapshot
			ok := false
			err := h.With(func(k *kernel.Kernel) (err error) {
				if ok, err = k.Send(now, c); ok {
					s = view(k.State(), h.anchors, c.Req, now)
				}
				return err
			})
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			r := h.clerks[c.Clerk]
			var res kernel.Result
			if c.Kind == kernel.ActProbe {
				res = r.probe(c.Req, s)
			} else {
				res = r.do(c.Req, s)
			}
			if err := h.With(func(k *kernel.Kernel) error { return k.Answer(now, c, res) }); err != nil {
				return err
			}
		}
	}
	return nil
}

// With runs fn on the kernel under the lock. The owner and planner sides
// call the kernel's API (docs/LANES.md, the frozen seam) only through it.
func (h *Kernel) With(fn func(*kernel.Kernel) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.k == nil {
		return errors.New("run: kernel closed")
	}
	return fn(h.k)
}

// Close releases the log; the kernel is unusable after.
func (h *Kernel) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.k = nil
	return h.store.Close()
}
