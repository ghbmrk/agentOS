package bridgeattempt

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/changesource"
)

// The post-replacement cut conservatively models a caller seeing a save error
// after replacement. Actual FileStore durability succeeds before the injected
// error; this is not a power-cut/unsynced-directory or disk-controller emulator.
type crashStore struct {
	file         *change.FileStore
	nth, saves   int
	after, fired bool
}

func (s *crashStore) Load() ([]byte, error) { return s.file.Load() }
func (s *crashStore) Save(raw []byte) error {
	s.saves++
	cut := s.nth > 0 && s.saves == s.nth
	if cut && !s.after {
		s.fired = true
		return errors.New("synthetic pre-replacement failure")
	}
	if err := s.file.Save(raw); err != nil {
		return err
	}
	if cut {
		s.fired = true
		return errors.New("synthetic post-replacement failure")
	}
	return nil
}
func (s *crashStore) arm(n int, after bool) { s.nth, s.saves, s.after, s.fired = n, 0, after, false }

var crashLimits = digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}

func crashComponents(t *testing.T, ps, qs digestqueue.Store) (*change.Pipeline, *digestqueue.Queue, *changesource.Source, *digestqueue.Collector) {
	t.Helper()
	p, err := change.New(change.Config{Store: ps, Evaluator: noEvaluation{}})
	if err != nil {
		t.Fatal(err)
	}
	q, err := digestqueue.New(qs, crashLimits)
	if err != nil {
		t.Fatal(err)
	}
	src, err := changesource.New(p)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{changesource.ID: src})
	if err != nil {
		t.Fatal(err)
	}
	return p, q, src, collector
}

// REQ: CH-15, OP-1, OP-2
// Twelve actual-file cuts spanning six boundaries. Every reopen uses fresh
// component objects; no recovery observation depends on the old heap state.
func TestAssembledDigestRecoveryAcrossEveryDurableBoundary(t *testing.T) {
	for _, phase := range []string{"source-peek", "queue-admit", "source-ack", "queue-ack", "queue-begin", "queue-finish"} {
		for _, after := range []bool{false, true} {
			name := phase + "/before"
			if after {
				name = phase + "/after"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				pf := &change.FileStore{Path: filepath.Join(dir, "source.json")}
				qf := &change.FileStore{Path: filepath.Join(dir, "queue.json")}
				ps, qs := &crashStore{file: pf}, &crashStore{file: qf}
				p, q, src, collector := crashComponents(t, ps, qs)
				if err := p.Notice("original", "Original fixed notice."); err != nil {
					t.Fatal(err)
				}
				var cut *crashStore
				switch phase {
				case "source-peek":
					cut = ps
					ps.arm(1, after)
				case "queue-admit":
					cut = qs
					qs.arm(1, after)
				case "source-ack":
					cut = ps
					ps.arm(2, after)
				case "queue-ack":
					cut = qs
					qs.arm(2, after)
				}
				b, collectErr := collector.Collect(context.Background(), now, now.Add(time.Hour))
				n := &notice{}
				if strings.HasPrefix(phase, "queue-b") || phase == "queue-finish" {
					if collectErr != nil || b == nil {
						t.Fatal("initial collection", b, collectErr)
					}
					cut = qs
					index := 1
					if phase == "queue-finish" {
						index = 2
					}
					qs.arm(index, after)
					a, err := New(Config{Queue: q, Owner: n, Now: func() time.Time { return now }, Gate: func(context.Context, digestqueue.Batch) error { return nil }, Sources: map[string]Validator{changesource.ID: src.Validate}})
					if err != nil {
						t.Fatal(err)
					}
					if err = a.Send(context.Background(), b.ID); err == nil {
						t.Fatal("injected attempt failure hidden")
					}
				} else if collectErr == nil {
					t.Fatal("injected collection failure hidden")
				}
				if cut == nil || !cut.fired {
					t.Fatal("specified crash boundary not reached")
				}
				expectedCalls := 0
				if phase == "queue-finish" {
					expectedCalls = 1
				}
				if n.calls != expectedCalls {
					t.Fatal("wrong transport count", n.calls)
				}
				// Discard old source/queue heap state. Fresh FileStore objects have no
				// injected failure. Successful reopen saves re-establish durability.
				p, q, _, collector = crashComponents(t, &change.FileStore{Path: pf.Path}, &change.FileStore{Path: qf.Path})
				if err := collector.Recover(context.Background()); err != nil {
					t.Fatal("recover", err)
				}
				if _, err := collector.Collect(context.Background(), now, now.Add(time.Hour)); err != nil {
					t.Fatal("recover collection", err)
				}
				batches, err := q.List()
				if err != nil || len(batches) != 1 {
					t.Fatal("first source duplicated or lost", batches, err)
				}
				first := batches[0]
				want := digestqueue.Ready
				if phase == "queue-begin" && after || phase == "queue-finish" && !after {
					want = digestqueue.Unknown
				}
				if phase == "queue-finish" && after {
					want = digestqueue.Accepted
				}
				if first.State != want || len(first.Snapshots) != 1 || first.Snapshots[0].Generation != 1 || first.Snapshots[0].Lines[0] != "Original fixed notice." || !first.Acknowledged[0] {
					t.Fatal("wrong recovered association/state", first, "want", want)
				}
				if phase == "queue-begin" && after || phase == "queue-finish" {
					if first.Attempts != 1 {
						t.Fatal("lost attempt identity", first)
					}
				} else if first.Attempts != 0 {
					t.Fatal("manufactured attempt", first)
				}
				// A newer persisted source event must form its own generation even when
				// the earlier batch is Unknown. Collection alone cannot replay transport.
				if err = p.Notice("later", "Later fixed notice."); err != nil {
					t.Fatal(err)
				}
				next, err := collector.Collect(context.Background(), now.Add(time.Minute), now.Add(time.Hour))
				if err != nil || next == nil {
					t.Fatal("later event lost", next, err)
				}
				if next.ID == first.ID || next.Snapshots[0].Generation != 2 || next.Snapshots[0].Lines[0] != "Later fixed notice." || !next.Acknowledged[0] {
					t.Fatal("later association wrong", next)
				}
				if got := state(t, q, first.ID); got.State != want || got.Attempts != first.Attempts || got.Snapshots[0].Hash != first.Snapshots[0].Hash {
					t.Fatal("new collection changed prior outcome", got)
				}
				if pending, err := collector.Collect(context.Background(), now.Add(2*time.Minute), now.Add(time.Hour)); err != nil || pending != nil {
					t.Fatal("new generation duplicated", pending, err)
				}
				if n.calls != expectedCalls {
					t.Fatal("recovery replayed transport")
				}
			})
		}
	}
}
