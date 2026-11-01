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
	"slices"
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
	// Pinned is the image's pinned roots (kernel.State.Pin): granted from
	// the image, never anchors.
	Pinned []key.Key
	// Checker is the checker process's key, from the store's pins
	// (kernel.PinChecker); none approves no step on a code.
	Checker ed25519.PublicKey
	// KeyDir is the subject-key table's directory (FileKeys, sealed under
	// Key), opened at start so content opens (KRN-erase). "" keeps content
	// closed (kernel.ErrContentClosed); only tests start a kernel so.
	KeyDir string
	// ContentDir holds the content stores (FileContent), one directory
	// each: every one of Stores and every one already there
	// (OpenContentStores). It needs a KeyDir; "" opens no store, so Seal
	// refuses (kernel.ErrStore); only tests start a kernel so.
	ContentDir string
	Stores     []string // the content clerks' stores (ContentSide)
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
	// FirstEdge is the edge key the link port captured before the Owner
	// Card confirm (handoff.KernelKeys.FirstEdge), which setup logs as the
	// first edge key (Kernel.Setup); none logs none.
	FirstEdge ed25519.PublicKey
	// LinkKey is the core's link key (handoff.KernelKeys.LinkKey), which
	// only the kernel holds (HW-15); none on a box enrolled before it.
	LinkKey ed25519.PrivateKey
	// Clock is the kernel process's clock, read when a backup re-seal
	// finishes, so a failure backs off from then (#3339); nil reads the
	// time it was handed out.
	Clock func() int64
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
	// unlogged are the item files the start found in a store that no
	// entry names in that store.
	unlogged []string
	// bk is the backups (backup.go); nil with no BackupDir.
	bk *backups
	// reseals is every backup re-seal running (reseal), and running each
	// one's channel by its backup, closed once it is over, whether or not
	// its commit ran; guarded by mu.
	reseals sync.WaitGroup
	running map[string]chan struct{}
	// betweenWaits, for tests only, runs in Erase between its wait for the
	// re-seals running at the erase and its own.
	betweenWaits func()
	// page is the page authority (CH-9); nil when the store holds none.
	// Set at open and never changed, so it is read without the lock.
	page *pageca.Authority
	// firstEdge and link are KernelConfig's, set at open and never
	// changed, so link is read without the lock: only LinkSide's
	// linksign signs with it, and it never goes into a backup (BAK-1).
	firstEdge ed25519.PublicKey
	link      ed25519.PrivateKey
	clock     func() int64 // KernelConfig's
	// head is KernelConfig's Sign, the store's head key: it signs the
	// recovery-key approvals the root steps verify (handoff.Approval).
	// Set at open and never changed.
	head ed25519.PrivateKey
	// card is the recovery key a lost-card rotation made at this boot,
	// held until the owner confirms the new card (kernelmain.go).
	card recoveryCard
}

// OpenKernel opens the log, replays it and boots the kernel at now: plans
// left undecided are decided, and steps left in flight are marked unknown,
// to be probed through their clerk (KRN-8). With no anchors from the store
// and none in the log, the kernel is setup-only (kernel.Setup): its sockets
// serve only the setup step until the owner's hardware keys are logged.
// With a KeyDir it then opens the subject-key table and the content stores
// in ContentDir, and re-applies every logged erase to them; a store an
// erase names that is not there stays unconfirmed, and Tick retries it.
// Keys and items no entry names are kept and reported (Content, Unlogged).
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
		clerks[name] = remote{r, anchors, cfg.Pinned}
		kc[name] = clerks[name]
	}
	if k, err = kernel.Boot(l, cfg.Anchors, kc, now, cfg.Pinned...); err != nil {
		st.Close()
		return nil, err
	}
	k.PinChecker(cfg.Checker)
	h := &Kernel{k: k, store: st, clerks: clerks, page: page, firstEdge: cfg.FirstEdge, link: cfg.LinkKey, clock: cfg.Clock, head: cfg.Sign}
	if cfg.KeyDir != "" {
		keys, err := OpenFileKeys(cfg.KeyDir, cfg.Key)
		stores := map[string]kernel.ContentStore{}
		var found map[string][]kernel.Hash
		if err == nil && cfg.ContentDir != "" {
			if stores, found, err = OpenContentStores(cfg.ContentDir, cfg.Stores); err != nil {
				st.Close()
				return nil, fmt.Errorf("run: the content stores: %w", err)
			}
		}
		if err == nil {
			h.content, err = k.OpenContent(keys, stores, now)
			h.unlogged = unlogged(k.State(), found)
		}
		if err != nil {
			st.Close()
			return nil, fmt.Errorf("run: the subject-key table: %w", err)
		}
		if cfg.BackupDir != "" {
			if h.bk, err = openBackups(cfg, keys, k, now); err != nil {
				st.Close()
				return nil, fmt.Errorf("run: the backups: %w", err)
			}
			k.OpenBackups(h.bk.set)
		}
	} else if cfg.BackupDir != "" || cfg.ContentDir != "" {
		st.Close()
		return nil, errors.New("run: backups and content stores need the subject-key table")
	}
	return h, nil
}

// Content is what the start found in the subject-key table: subjects whose
// key is missing, and keys no subject names.
func (h *Kernel) Content() kernel.ContentReport { return h.content }

// Unlogged is every item file the start found in a content store that no
// entry names in that store, as store/hash.
func (h *Kernel) Unlogged() []string { return h.unlogged }

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
					s = view(k.State(), k.State().Anchors, k.State().Pinned(), c.Req, now)
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
// are. Each is in running until it is over; a commit that finds the kernel
// closed is dropped, but the re-seal is still over, so no erase waits on it
// after Close.
func (h *Kernel) reseal(now int64) (*sync.WaitGroup, error) {
	var due []*kernel.Reseal
	var over []chan struct{}
	err := h.With(func(k *kernel.Kernel) error {
		due = k.Reseals(now)
		if h.running == nil {
			h.running = map[string]chan struct{}{}
		}
		for _, r := range due {
			over = append(over, make(chan struct{}))
			h.running[r.Backup] = over[len(over)-1]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	wg := new(sync.WaitGroup)
	for i, r := range due {
		h.reseals.Add(1)
		wg.Go(func() {
			defer h.reseals.Done()
			r.Run()
			end := now
			if h.clock != nil {
				end = max(now, h.clock())
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.k != nil {
				h.k.Resealed(end, r)
			}
			delete(h.running, r.Backup)
			close(over[i])
		})
	}
	return wg, nil
}

// runningFor is the channel of each re-seal running of a backup in names.
// The caller holds mu.
func (h *Kernel) runningFor(names []string) []chan struct{} {
	var out []chan struct{}
	for _, b := range names {
		if ch, ok := h.running[b]; ok {
			out = append(out, ch)
		}
	}
	return out
}

// named is every backup c names.
func named(c kernel.Confirmation) []string {
	out := slices.Clone(c.Resealed)
	for _, b := range c.StillHeld {
		out = append(out, b.Backup)
	}
	return out
}

func waitAll(chs []chan struct{}) {
	for _, ch := range chs {
		<-ch
	}
}

// Erase erases subject (kernel.Erase) and replies once every backup that
// gave its key has had a re-seal prepared after the erase (#3338). It
// names each backup the Set lists with the subject, and each that a
// backup write whose snapshot holds the subject adds, once that write is
// over. It waits for a re-seal of a named backup running at the erase,
// whose table was prepared before it and so still gives the key, then
// re-seals every backup due, then waits for any re-seal of a named
// backup that a Tick took in between. Every wait is without the lock, so
// a hung target delays this reply but never STOP. It returns what the
// erase has reached then: a backup whose re-seal failed is StillHeld with
// the failure, and Tick retries it after its backoff.
func (h *Kernel) Erase(now int64, subject string) (kernel.Confirmation, error) {
	var (
		c     kernel.Confirmation
		waits []chan struct{}
		w     *backupWrite
	)
	err := h.With(func(k *kernel.Kernel) (err error) {
		c, err = k.Erase(now, subject)
		waits = h.runningFor(named(c))
		if h.bk != nil && h.bk.writing != nil && h.bk.writing.live[subject] {
			w = h.bk.writing
		}
		return err
	})
	if c.Subject == "" {
		return c, err
	}
	var rerr error
	if w != nil {
		<-w.done
		rerr = h.With(func(*kernel.Kernel) error {
			have := named(c)
			for _, id := range w.ids {
				if !slices.Contains(have, id) {
					c.StillHeld = append(c.StillHeld, kernel.BackupHold{Backup: id})
				}
			}
			waits = append(waits, h.runningFor(w.ids)...)
			return nil
		})
	}
	if rerr == nil {
		waitAll(waits)
		if h.betweenWaits != nil {
			h.betweenWaits()
		}
		var wg *sync.WaitGroup
		if wg, rerr = h.reseal(now); rerr == nil {
			wg.Wait()
			rerr = h.With(func(*kernel.Kernel) error { waits = h.runningFor(named(c)); return nil })
		}
	}
	if rerr == nil {
		waitAll(waits)
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

// Close releases the log; the kernel is unusable after. It does not wait
// for a backup re-seal still running: one hung at its target would only
// delay shutdown behind a dying drive. Such a re-seal loses only its
// commit, as a crash after its put does, and the next start recovers:
// Rewrap takes the highest listed generation, and Tick re-seals again
// (#3338). An erase waiting on it returns, the kernel closed.
func (h *Kernel) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.k = nil
	return h.store.Close()
}
