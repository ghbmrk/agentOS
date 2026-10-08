package digestqueue

import (
	"errors"
	"fmt"
	"github.com/ghbmrk/agentos/broker/change"
	"path/filepath"
	"testing"
	"time"
)

// REQ: OP-1, OP-2
func TestSelectedCompactionPrechecksWholeSetAndKeepsHighWater(t *testing.T) {
	q, err := New(&change.MemStore{}, Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	s, _ := NewSnapshot("accepted", 1, []string{"accepted notice"}, nil)
	b, err := q.Enqueue([]Snapshot{s}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	q.Acknowledge(b.ID, s.Source, s.Generation, s.Hash)
	begun, _ := q.Begin(b.ID, now)
	q.Finish(b.ID, begun.Attempts, TransportAccepted, "accepted")
	u, _ := NewSnapshot("unknown", 1, []string{"unknown notice"}, nil)
	unknown, _ := q.Enqueue([]Snapshot{u}, now, now.Add(time.Hour))
	q.Acknowledge(unknown.ID, u.Source, u.Generation, u.Hash)
	q.Begin(unknown.ID, now)
	q.Finish(unknown.ID, 1, OutcomeUnknown, "")
	if err := q.CompactBatches([]uint64{b.ID, unknown.ID}); !errors.Is(err, ErrInFlight) {
		t.Fatal(err)
	}
	if _, err := q.Get(b.ID); err != nil {
		t.Fatal("partial removal", err)
	}
	if err := q.CompactBatches([]uint64{b.ID, b.ID}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := q.CompactBatches([]uint64{b.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue([]Snapshot{s}, now, now.Add(time.Hour)); !errors.Is(err, ErrRetired) {
		t.Fatal(err)
	}
	if _, err := q.Get(unknown.ID); err != nil {
		t.Fatal(err)
	}
}
func TestSelectedCompactionPreservesIncompleteAcknowledgments(t *testing.T) {
	q, err := New(&change.MemStore{}, Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s, _ := NewSnapshot("pending", 1, []string{"pending notice"}, nil)
	b, _ := q.Enqueue([]Snapshot{s}, now, now.Add(time.Minute))
	q.Expire(now.Add(time.Hour))
	if err := q.CompactBatches([]uint64{b.ID}); !errors.Is(err, ErrUnacknowledged) {
		t.Fatal(err)
	}
	if _, err := q.Get(b.ID); err != nil {
		t.Fatal(err)
	}
}

type compactCut struct {
	Store
	cut   bool
	after bool
	saves int
}

func (s *compactCut) Save(raw []byte) error {
	s.saves++
	if s.cut {
		if s.after {
			if err := s.Store.Save(raw); err != nil {
				return err
			}
		}
		return errors.New("synthetic compaction persistence cut")
	}
	return s.Store.Save(raw)
}

// REQ: OP-1, OP-2
func TestSelectedCompactionActualReplacementCutsDoNotRewindIdentity(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "queue")
			st := &compactCut{Store: &change.FileStore{Path: path}, after: after}
			limits := Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 3, MaxBytes: 65536}
			q, err := New(st, limits)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
			s, _ := NewSnapshot("history", 1, []string{"accepted notice"}, nil)
			b, _ := q.Enqueue([]Snapshot{s}, now, now.Add(time.Hour))
			q.Acknowledge(b.ID, s.Source, s.Generation, s.Hash)
			q.Begin(b.ID, now)
			q.Finish(b.ID, 1, TransportAccepted, "accepted")
			st.cut = true
			if err := q.CompactBatches([]uint64{b.ID}); !errors.Is(err, ErrRecovery) {
				t.Fatal(err)
			}
			saves := st.saves
			if err := q.CompactBatches(nil); !errors.Is(err, ErrRecovery) || st.saves != saves {
				t.Fatal("uncertain heap kept writing", err)
			}
			q, err = New(&change.FileStore{Path: path}, limits)
			if err != nil {
				t.Fatal(err)
			}
			old, err := q.Get(b.ID)
			if after {
				if !errors.Is(err, ErrMissing) {
					t.Fatal(old, err)
				}
			} else if err != nil || old.State != Accepted {
				t.Fatal(old, err)
			}
			replay, err := q.Enqueue([]Snapshot{s}, now, now.Add(time.Hour))
			if after {
				if !errors.Is(err, ErrRetired) {
					t.Fatal(replay, err)
				}
			} else if err != nil || replay.ID != b.ID {
				t.Fatal(replay, err)
			}
			next, _ := NewSnapshot("history", 2, []string{"new notice"}, nil)
			fresh, err := q.Enqueue([]Snapshot{next}, now.Add(time.Minute), now.Add(time.Hour))
			if err != nil || fresh.ID <= b.ID {
				t.Fatal(fresh, err)
			}
		})
	}
}
