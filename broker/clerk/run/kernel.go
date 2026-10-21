// Package run runs the kernel and each credentialed clerk as processes of
// their own (MIG-4-run, #2682; option A): the kernel's process holds the log
// and reaches each clerk over that clerk's socket, and each clerk's process,
// under its own uid, holds that one account's Secrets file and no other
// (CLK-1, STO-3). The kernel process never holds a credential, and a clerk
// process sees the log only through the view the kernel sends with each call.
package run

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
// one lock, the clerk calls inside Tick included, so the owner side, the
// planner side and the clock never interleave inside the kernel.
type Kernel struct {
	mu    sync.Mutex
	k     *kernel.Kernel
	store *FileStore
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
	clerks := map[string]kernel.Clerk{}
	for name, r := range cfg.Clerks {
		clerks[name] = remote{r, cfg.Anchors}
	}
	k, err := kernel.Boot(l, cfg.Anchors, clerks, now)
	if err != nil {
		st.Close()
		return nil, err
	}
	return &Kernel{k: k, store: st}, nil
}

// Tick runs every plan as far as now allows, calling clerks as it goes.
func (h *Kernel) Tick(now int64) error {
	return h.With(func(k *kernel.Kernel) error { return k.Tick(now) })
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
