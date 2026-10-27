// Package proc is the kernel's process (MIG-4-run, #2682; option A;
// split from broker/clerk/run by KRN-2 split, #2892): it holds the log and
// reaches each clerk over that clerk's socket. It never holds a credential,
// and it links no clerk's code, so no mail or model parser is in the kernel
// process (SPEC KRN-2). The wire both sides speak (the call, the view and
// the socket helpers) lives here too, and broker/clerk/run, the clerks'
// processes, imports it.
package proc

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// KernelConfig is what the kernel process starts from. The log key and the
// head key come from the unlock step (STO-2b, handoff.KernelKeys).
type KernelConfig struct {
	Log     string        // the log file
	Anchor  kernel.Anchor // where signed heads go, off the log's disk (LOG-2)
	Key     [32]byte      // the log's AES-256-GCM key
	Pub     ed25519.PublicKey
	Sign    ed25519.PrivateKey
	Anchors []key.PublicKey   // the owner's hardware keys (D-146); none starts setup-only
	Clerks  map[string]Remote // every clerk the kernel runs, by name; a closed table
	// KeyDir is the subject-key table's directory (FileKeys, sealed under
	// Key), opened at start so content opens (KRN-erase). "" keeps content
	// closed (kernel.ErrContentClosed); only tests start a kernel so.
	KeyDir string
	// BackupDir is where the kernel keeps its backups' records, sealed
	// under Key (MIG-4-recovery-e3); it needs a KeyDir. "" keeps backups
	// off; only tests start a kernel so.
	BackupDir string
	// Recipient is the backup recipient in its wire form
	// (handoff.KernelKeys.Recipient); none refuses every backup.
	Recipient []byte
	// PageCA is the page authority in pageca.Marshal's form
	// (handoff.KernelKeys.PageCA); none certifies no page key (Certify).
	PageCA []byte
}

// Kernel is the kernel process's one kernel: every call to it goes through
// one lock, so the owner side, the planner side and the clock never
// interleave inside the kernel. Clerk calls run outside it (Tick), so STOP,
// a revoke or STATUS never waits on a clerk (KRN-7, OWN-18).
type Kernel struct {
	mu     sync.Mutex
	k      *kernel.Kernel
	store  *FileStore
	clerks map[string]remote
	// content is what the start found in the key table.
	content kernel.ContentReport
	// bk is the backups (backup.go); nil with no BackupDir.
	bk *backups
	// reseals is every backup re-seal running (reseal).
	reseals sync.WaitGroup
	// page is the page authority (CH-9); nil when the store holds none.
	// Set at open and never changed, so it is read without the lock.
	page *pageca.Authority
}

// OpenKernel opens the log, replays it and boots the kernel at now: plans
// left undecided are decided, and steps left in flight are marked unknown,
// to be probed through their clerk (KRN-8). With no anchors from the store
// and none in the log, the kernel is setup-only (kernel.Setup): its sockets
// serve only the setup step until the owner's hardware keys are logged.
// With a KeyDir it then opens the subject-key table, which re-applies every
// logged erase to it; no content store exists yet, so an erase's stores
// stay unconfirmed and Tick retries them.
func OpenKernel(cfg KernelConfig, now int64) (*Kernel, error) {
	if cfg.Anchor == nil || cfg.Sign == nil {
		return nil, errors.New("run: a kernel needs an anchor and the head key")
	}
	var page *pageca.Authority
	if len(cfg.PageCA) > 0 {
		var err error
		if page, err = pageca.Unmarshal(cfg.PageCA); err != nil {
			return nil, fmt.Errorf("run: the page authority: %w", err)
		}
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
	// A clerk's view is verified against the state's anchors, which setup
	// may log after boot.
	var k *kernel.Kernel
	anchors := func() []key.PublicKey { return k.State().Anchors }
	clerks, kc := map[string]remote{}, map[string]kernel.Clerk{}
	for name, r := range cfg.Clerks {
		clerks[name] = remote{r, anchors}
		kc[name] = clerks[name]
	}
	if k, err = kernel.Boot(l, cfg.Anchors, kc, now); err != nil {
		st.Close()
		return nil, err
	}
	h := &Kernel{k: k, store: st, clerks: clerks, page: page}
	if cfg.KeyDir != "" {
		keys, err := OpenFileKeys(cfg.KeyDir, cfg.Key)
		if err == nil {
			h.content, err = k.OpenContent(keys, map[string]kernel.ContentStore{}, now)
		}
		if err != nil {
			st.Close()
			return nil, fmt.Errorf("run: the subject-key table: %w", err)
		}
		if cfg.BackupDir != "" {
			if h.bk, err = openBackups(cfg, keys, k.State()); err != nil {
				st.Close()
				return nil, fmt.Errorf("run: the backups: %w", err)
			}
			k.OpenBackups(h.bk.set)
		}
	} else if cfg.BackupDir != "" {
		st.Close()
		return nil, errors.New("run: backups need the subject-key table")
	}
	return h, nil
}

// Content is what the start found in the subject-key table: subjects whose
// key is missing, and keys no subject names.
func (h *Kernel) Content() kernel.ContentReport { return h.content }

// Tick starts the backup re-seals due (reseal) without waiting for them,
// then runs every plan as far as now allows. It takes the due calls under the
// lock, then for each one, under the lock again, makes the kernel's last
// check (kernel.Send) and takes the call's view, makes the call without the
// lock, and logs its answer under it. A STOP or revoke logged while an
// earlier call hangs stops every later one (KRN-7).
func (h *Kernel) Tick(now int64) error {
	// A backup that gives an erased subject's key is re-sealed here, and
	// one whose re-seal failed retried with its backoff: kernel.Tick,
	// which would, runs clerk calls under the lock and is not this
	// process's (#3311 L3 on 6e14b28).
	if _, err := h.reseal(now); err != nil {
		return err
	}
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
					s = view(k.State(), k.State().Anchors, c.Req, now)
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

// reseal hands out every backup re-seal due (kernel.Reseals) and runs each
// on its own goroutine: its I/O at the target without the lock, so a hung
// target holds only its own re-seal, never STOP or another backup (KRN-7,
// #3317), then its commit under the lock. The WaitGroup is done once they
// are.
func (h *Kernel) reseal(now int64) (*sync.WaitGroup, error) {
	var due []*kernel.Reseal
	if err := h.With(func(k *kernel.Kernel) error { due = k.Reseals(now); return nil }); err != nil {
		return nil, err
	}
	wg := new(sync.WaitGroup)
	for _, r := range due {
		h.reseals.Add(1)
		wg.Go(func() {
			defer h.reseals.Done()
			r.Run()
			h.With(func(k *kernel.Kernel) error { k.Resealed(now, r); return nil })
		})
	}
	return wg, nil
}

// Erase erases subject (kernel.Erase), then re-seals every backup that
// gave its key and waits for those re-seals, which run without the lock,
// so a hung target delays this reply but never STOP. It returns what the
// erase has reached then.
func (h *Kernel) Erase(now int64, subject string) (kernel.Confirmation, error) {
	var c kernel.Confirmation
	err := h.With(func(k *kernel.Kernel) (err error) { c, err = k.Erase(now, subject); return err })
	if c.Subject == "" {
		return c, err
	}
	wg, rerr := h.reseal(now)
	if rerr == nil {
		wg.Wait()
		rerr = h.With(func(k *kernel.Kernel) error { c = k.Confirm(c); return nil })
	}
	return c, errors.Join(err, rerr)
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
