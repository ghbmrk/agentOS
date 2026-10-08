package recalltool

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/events"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recall"
)

// TombstoneAge is the broker's tombstone policy (K8): far beyond the
// bus's last retry and a restart's hook replay. PruneTombstones refuses
// anything under recall.MinTombstoneAge.
const TombstoneAge = 30 * 24 * time.Hour

// ServiceConfig configures OpenService.
type ServiceConfig struct {
	// Dir is the broker-held state directory (created 0700): the index in
	// recall/, the bus in bus.jsonl and seen.jsonl, the provenance record
	// in provenance.jsonl.
	Dir string
	// Key is the vault-held identity key (K5); at least 16 bytes.
	Key []byte
	// Labeler reads and raises machine labels (the VM manager). Nil:
	// searches for owner data are refused, public-only ones still work.
	Labeler recall.Labeler
	// Journal, Machines and Cases are where a deletion reaches beyond the
	// index (Reach). Nil ones are not reached.
	Journal  Journal
	Machines Machines
	Cases    Cases
	// Ask takes a rollback that would lose agent work to the owner first
	// (W10; the grants gate). Location is the owner's time zone.
	Ask      Asker
	Location *time.Location
	// Notify tells the owner an approved rollback is done (the owner
	// channel's Notify).
	Notify func(text string) error
	Logf   func(format string, args ...any)
}

// Service is recall wired for the broker: the index, the event bus that
// feeds it, the provenance record, and the guest tools.
type Service struct {
	Index *recall.Index
	Bus   *events.Bus
	Prov  *Provenance
	Tools *Tools
	Reach *Reach
	close []func() error
}

// OpenService opens the index under the vault-held key, the bus with the
// index's keyer and its recall trigger, and the provenance record, and
// connects deletion: the bus forgets deleted sources (CAP-3).
func OpenService(cfg ServiceConfig) (*Service, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	k, err := recall.NewKeyer(cfg.Key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	s := &Service{}
	fail := func(err error) (*Service, error) {
		s.Close()
		return nil, err
	}
	dir, err := recall.OpenDir(filepath.Join(cfg.Dir, "recall"))
	if err != nil {
		return fail(err)
	}
	s.close = append(s.close, dir.Close)
	opts := []recall.Option{recall.WithKeyer(k)}
	if cfg.Labeler != nil {
		opts = append(opts, recall.WithLabeler(cfg.Labeler))
	}
	if s.Index, err = recall.Open(dir, opts...); err != nil {
		return fail(err)
	}
	var stores []*recall.FileStore
	for _, name := range []string{"bus.jsonl", "seen.jsonl", "provenance.jsonl"} {
		st, err := recall.OpenFile(filepath.Join(cfg.Dir, name))
		if err != nil {
			return fail(err)
		}
		s.close = append(s.close, st.Close)
		stores = append(stores, st)
	}
	if s.Bus, err = events.Open(events.Config{Log: stores[0], Seen: stores[1], Keyer: s.Index.Keyer(),
		Triggers: []events.Trigger{events.IndexInto(s.Index)}}); err != nil {
		return fail(err)
	}
	if err := s.Index.OnDelete(s.Bus.ForgetSource); err != nil {
		cfg.Logf("recall: replaying deletions to the bus: %v", err)
	}
	if s.Prov, err = OpenProvenance(stores[2]); err != nil {
		return fail(err)
	}
	s.Reach = &Reach{Prov: s.Prov, Journal: cfg.Journal, Machines: cfg.Machines, Cases: cfg.Cases,
		Deleted: s.Index.Deleted, Ask: cfg.Ask, Notify: cfg.Notify, Location: cfg.Location, Logf: cfg.Logf}
	s.Index.KeepTombstones(s.Reach.Needed)
	// Registering replays every tombstone, so a reach a crash cut short
	// runs again (CAP-3).
	if err := s.Index.OnDelete(s.Reach.OnDelete); err != nil {
		cfg.Logf("recall: replaying deletions past the index: %v", err)
	}
	label := func(machine string) string {
		if cfg.Labeler != nil && cfg.Labeler.Label(machine) == recall.Public {
			return "public"
		}
		return "private"
	}
	if s.Tools, err = New(Config{Index: s.Index, Prov: s.Prov, Label: label, Logf: cfg.Logf}); err != nil {
		return fail(err)
	}
	return s, nil
}

// Run pumps the bus, retries pending deletion reach every minute, and
// prunes tombstones once a day by the 30-day policy (K8) until ctx is done.
func (s *Service) Run(ctx context.Context, logf func(string, ...any)) {
	go s.Bus.Run(ctx, time.Second)
	retry := time.NewTicker(time.Minute)
	defer retry.Stop()
	var pruned time.Time
	for {
		if time.Since(pruned) >= 24*time.Hour {
			pruned = time.Now()
			if _, err := s.Index.PruneTombstones(TombstoneAge); err != nil && logf != nil {
				logf("recall: pruning tombstones: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
			if s.Reach.Pending() > 0 || s.Reach.Owed() {
				s.Reach.Retry(ctx) // failures are logged by Reach
			}
		}
	}
}

// Close closes the stores.
func (s *Service) Close() error {
	var errs []error
	for i := len(s.close) - 1; i >= 0; i-- {
		errs = append(errs, s.close[i]())
	}
	s.close = nil
	return errors.Join(errs...)
}

// Late serves the recall tools once the service is open (after the owner
// unlocks the vault, K5) and a fixed answer before.
type Late struct{ s atomic.Pointer[Tools] }

// Set makes t live.
func (l *Late) Set(t *Tools) { l.s.Store(t) }

// List returns the tool definitions, also before the service is open.
func (l *Late) List() []map[string]any { return list }

// Call serves a recall tool, or answers that recall is not open yet.
func (l *Late) Call(ctx context.Context, machine, lineage, name string, args json.RawMessage) (string, bool, error) {
	if t := l.s.Load(); t != nil {
		return t.Call(ctx, machine, lineage, name, args)
	}
	for _, d := range list {
		if d["name"] == name {
			return "", true, errors.New("recall opens once the owner unlocks the box's vault")
		}
	}
	return "", false, nil
}

// LateExecutor is the journal executor for rollback intents (ExecutorName)
// before and after the service opens. An approved rollback that runs
// before recall is open is recorded as approved, machines not reset, so
// Retry carries it through once recall opens.
type LateExecutor struct {
	r      atomic.Pointer[Reach]
	off    atomic.Bool
	failed atomic.Bool
	mu     sync.Mutex
	onOpen []func()
}

// Off records that recall is not configured: there is no index, so no
// deletion can reach anything and nothing is contained.
func (l *LateExecutor) Off() { l.off.Store(true) }

// Failed records that recall is configured but did not open. Its
// tombstones were never replayed, so which lineages hold a deleted record
// is unknown: every one stays contained (fail closed, #59 L3 third
// review), and STATUS says so.
func (l *LateExecutor) Failed() { l.failed.Store(true) }

// Set makes r the executor.
func (l *LateExecutor) Set(r *Reach) {
	l.mu.Lock()
	l.r.Store(r)
	fs := l.onOpen
	l.onOpen = nil
	l.mu.Unlock()
	for _, f := range fs {
		f()
	}
}

// OnOpen runs f once recall is open: now if it is, else when Set is
// called (in Set's goroutine).
func (l *LateExecutor) OnOpen(f func()) {
	l.mu.Lock()
	if l.r.Load() == nil {
		l.onOpen = append(l.onOpen, f)
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()
	f()
}

// Execute runs an approved rollback.
func (l *LateExecutor) Execute(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	if r := l.r.Load(); r != nil {
		return r.Execute(ctx, in, n)
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: approvedOnly + "recall is not open yet"}
}

// Contained is Reach.Contained once recall is open. Before (the vault is
// still locked after a restart), which lineages hold a deleted record is
// not known yet, so every one is contained until the tombstone replay at
// open settles it (#59 L3 re-review 4); unless recall is Off.
func (l *LateExecutor) Contained(lineage string) bool {
	if r := l.r.Load(); r != nil {
		return r.Contained(lineage)
	}
	return !l.off.Load()
}

// Status is Reach.Status once recall is open, "" before, and a line
// saying agents are held back if it failed to open.
func (l *LateExecutor) Status() string {
	if r := l.r.Load(); r != nil {
		return r.Status()
	}
	if l.failed.Load() && !l.off.Load() {
		return "Memory did not open; agents cannot fork or merge"
	}
	return ""
}

// Work is Reach.Work once recall is open; ok false before.
func (l *LateExecutor) Work(lineage string, since time.Time) (worked, ok bool) {
	if r := l.r.Load(); r != nil {
		return r.Work(lineage, since)
	}
	return false, false
}

// Actions is Reach.Actions once recall is open; ok false before.
func (l *LateExecutor) Actions(lineage string, since time.Time) (n int, ok bool) {
	if r := l.r.Load(); r != nil {
		return r.Actions(lineage, since)
	}
	return 0, false
}

// Handled is Reach.Handled once recall is open; ok false before.
func (l *LateExecutor) Handled(since time.Time) (handled, ok bool) {
	if r := l.r.Load(); r != nil {
		return r.Handled(since)
	}
	return false, false
}

// TakeBack is Reach.TakeBack once recall is open; before, ErrNotOpen,
// and nothing is recorded.
func (l *LateExecutor) TakeBack(ctx context.Context, lineage string, since time.Time, approved bool) error {
	if r := l.r.Load(); r != nil {
		return r.TakeBack(ctx, lineage, since, approved)
	}
	return ErrNotOpen
}

// ErrNotOpen: recall is not open yet, so nothing can be taken back.
var ErrNotOpen = errors.New("recall: not open yet")

// Reconcile reports an interrupted rollback as approved, to be finished.
func (l *LateExecutor) Reconcile(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return (&Reach{}).Reconcile(ctx, in, n)
}
