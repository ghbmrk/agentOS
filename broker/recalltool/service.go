package recalltool

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/events"
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
	Logf    func(format string, args ...any)
}

// Service is recall wired for the broker: the index, the event bus that
// feeds it, the provenance record, and the guest tools.
type Service struct {
	Index *recall.Index
	Bus   *events.Bus
	Prov  *Provenance
	Tools *Tools
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

// Run pumps the bus and prunes tombstones once a day by the 30-day policy
// (K8) until ctx is done.
func (s *Service) Run(ctx context.Context, logf func(string, ...any)) {
	go s.Bus.Run(ctx, time.Second)
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if _, err := s.Index.PruneTombstones(TombstoneAge); err != nil && logf != nil {
			logf("recall: pruning tombstones: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
