package heartbeat

import (
	"bytes"
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func source(t *testing.T, st digestqueue.Store, clock func() (time.Time, error), zone string, minute int) *Source {
	t.Helper()
	s, err := New(Config{Store: st, Clock: clock, Zone: zone, Minute: minute, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// REQ: CH-15, TIM-1, OP-1, OP-2
func TestDailyHeartbeatDueSnapshotAndAckSurviveFileReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heartbeat.json")
	clock := func() (time.Time, error) { return testNow, nil }
	s := source(t, &change.FileStore{Path: path}, clock, "UTC", 12*60)
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Peek(t.Context())
	if err != nil || snap == nil || snap.Source != ID || len(snap.Lines) != 1 || snap.Lines[0] != "Box is running." {
		t.Fatal(snap, err)
	}
	s = source(t, &change.FileStore{Path: path}, clock, "UTC", 12*60)
	same, err := s.Peek(t.Context())
	if err != nil || same.Hash != snap.Hash {
		t.Fatal(same, err)
	}
	if err := s.Ack(t.Context(), *snap); err != nil {
		t.Fatal(err)
	}
	s = source(t, &change.FileStore{Path: path}, clock, "UTC", 12*60)
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if pending, err := s.Peek(t.Context()); err != nil || pending != nil {
		t.Fatal("same day was reissued", pending, err)
	}
	if err := s.Ack(t.Context(), *snap); err != nil {
		t.Fatal("old ack not idempotent", err)
	}
}
func TestHeartbeatDSTWallMinuteAndRepeatedHourDoNotIssueTwice(t *testing.T) {
	for _, tc := range []struct {
		name   string
		at     time.Time
		minute int
	}{
		{"spring-gap", time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC), 150},
		{"fall-first", time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC), 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := tc.at
			s := source(t, &change.MemStore{}, func() (time.Time, error) { return now, nil }, "America/New_York", tc.minute)
			if err := s.Plan(t.Context()); err != nil {
				t.Fatal(err)
			}
			snap, err := s.Peek(t.Context())
			if err != nil || snap == nil {
				t.Fatal(snap, err)
			}
			if err := s.Ack(t.Context(), *snap); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Hour)
			if err := s.Plan(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Peek(t.Context()); err != nil || got != nil {
				t.Fatal("same local day duplicated", got, err)
			}
		})
	}
}
func TestHeartbeatClockRestrictionRollbackAndStalePendingHold(t *testing.T) {
	now := testNow
	var clockErr error
	s := source(t, &change.MemStore{}, func() (time.Time, error) { return now, clockErr }, "UTC", 12*60)
	now = now.Add(-time.Minute)
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Peek(t.Context()); got != nil {
		t.Fatal("not due")
	}
	clockErr = errors.New("synthetic-private clock diagnostics")
	if err := s.Plan(t.Context()); err != ErrClock || strings.Contains(err.Error(), "synthetic-private") {
		t.Fatal(err)
	}
	clockErr = nil
	now = testNow
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Peek(t.Context())
	now = now.Add(24 * time.Hour)
	if err := s.Plan(t.Context()); err != ErrStale {
		t.Fatal("old pending heartbeat silently replaced", err)
	}
	if _, err := s.Peek(t.Context()); err != ErrStale {
		t.Fatal("stale alive assertion disclosed", err)
	}
	if err := s.Validate(t.Context(), *snap); err != ErrStale {
		t.Fatal(err)
	}
	// An already admitted exact source Ack remains recoverable when time is restricted.
	clockErr = errors.New("restricted")
	if err := s.Ack(t.Context(), *snap); err != nil {
		t.Fatal(err)
	}
	clockErr = nil
	now = testNow.Add(-24 * time.Hour)
	if err := s.Plan(t.Context()); err != ErrClock {
		t.Fatal("clock rollback reset cadence", err)
	}
}
func TestHeartbeatOldAckPreservesLaterDayAndReceiptForgeriesRefuse(t *testing.T) {
	now := testNow
	s := source(t, &change.MemStore{}, func() (time.Time, error) { return now, nil }, "UTC", 0)
	s.Plan(t.Context())
	old, _ := s.Peek(t.Context())
	if err := s.Ack(t.Context(), *old); err != nil {
		t.Fatal(err)
	}
	now = now.Add(24 * time.Hour)
	s.Plan(t.Context())
	next, _ := s.Peek(t.Context())
	if err := s.Ack(t.Context(), *old); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Peek(t.Context())
	if got.Hash != next.Hash || got.Generation != 2 {
		t.Fatal("old ack consumed later heartbeat", got)
	}
	forged, err := digestqueue.NewSnapshotWithReceipt(ID, next.Generation, []string{"Forged alive assertion."}, nil, next.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(t.Context(), forged); err != ErrInvalid {
		t.Fatal(err)
	}
	other := source(t, &change.MemStore{}, func() (time.Time, error) { return now, nil }, "UTC", 0)
	other.st.Key = bytes.Repeat([]byte{1}, 32)
	if err := other.Ack(t.Context(), *next); err != ErrInvalid {
		t.Fatal("foreign source accepted receipt", err)
	}
}

func TestHeartbeatReceiptEncodingCannotMintDifferentIssuedHash(t *testing.T) {
	s := source(t, &change.MemStore{}, func() (time.Time, error) { return testNow, nil }, "UTC", 0)
	s.Plan(t.Context())
	issued, _ := s.Peek(t.Context())
	reencoded, err := digestqueue.NewSnapshotWithReceipt(ID, issued.Generation, issued.Lines, nil, " "+issued.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(t.Context(), reencoded); err != ErrInvalid {
		t.Fatal("noncanonical receipt produced new eligible hash", err)
	}
}

type heartbeatFileCut struct {
	change.FileStore
	saves, failAt int
	after         bool
}

func (s *heartbeatFileCut) Save(raw []byte) error {
	s.saves++
	if s.saves == s.failAt && !s.after {
		return errors.New("synthetic before replacement")
	}
	if err := s.FileStore.Save(raw); err != nil {
		return err
	}
	if s.saves == s.failAt {
		return errors.New("synthetic after replacement")
	}
	return nil
}
func TestHeartbeatActualFilePlanAndAckFailureCuts(t *testing.T) {
	for _, phase := range []string{"plan", "ack"} {
		for _, after := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/before", true: "/after"}[after], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "heartbeat.json")
				failAt := 2
				if phase == "ack" {
					failAt = 3
				}
				store := &heartbeatFileCut{FileStore: change.FileStore{Path: path}, failAt: failAt, after: after}
				clock := func() (time.Time, error) { return testNow, nil }
				s := source(t, store, clock, "UTC", 0)
				if phase == "plan" {
					if err := s.Plan(t.Context()); !errors.Is(err, ErrRecovery) {
						t.Fatal(err)
					}
					if s.Health() != ErrRecovery {
						t.Fatal("uncertain source remained usable")
					}
					fresh := source(t, &change.FileStore{Path: path}, clock, "UTC", 0)
					if err := fresh.Plan(t.Context()); err != nil {
						t.Fatal(err)
					}
					snap, err := fresh.Peek(t.Context())
					if err != nil || snap == nil || snap.Generation != 1 {
						t.Fatal("same day restarted generation", snap, err)
					}
				} else {
					if err := s.Plan(t.Context()); err != nil {
						t.Fatal(err)
					}
					snap, _ := s.Peek(t.Context())
					if err := s.Ack(t.Context(), *snap); !errors.Is(err, ErrRecovery) {
						t.Fatal(err)
					}
					fresh := source(t, &change.FileStore{Path: path}, clock, "UTC", 0)
					pending, err := fresh.Peek(t.Context())
					if err != nil || (pending == nil) != after {
						t.Fatal("cut not observed", pending, err)
					}
					if err := fresh.Ack(t.Context(), *snap); err != nil {
						t.Fatal(err)
					}
					if err := fresh.Plan(t.Context()); err != nil {
						t.Fatal(err)
					}
					if pending, err := fresh.Peek(t.Context()); err != nil || pending != nil {
						t.Fatal("ack replay duplicated day", pending, err)
					}
				}
			})
		}
	}
}
func TestHeartbeatContextAndConfigRefusalDoNotOverwriteState(t *testing.T) {
	store := &change.MemStore{}
	calls := 0
	clock := func() (time.Time, error) { calls++; return testNow, nil }
	s := source(t, store, clock, "UTC", 0)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Plan(ctx); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(err, calls)
	}
	if err := s.Plan(nil); err != ErrInvalid {
		t.Fatal(err)
	}
	before, _ := store.Load()
	if _, err := New(Config{Store: store, Clock: clock, Zone: "UTC", Minute: 1}); err != ErrInvalid {
		t.Fatal("cadence changed on reopen", err)
	}
	after, _ := store.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("refused config rewrote state")
	}
	if _, err := New(Config{Store: &change.MemStore{}, Clock: clock, Zone: "Local"}); err != ErrInvalid {
		t.Fatal(err)
	}
}
func TestHeartbeatEmptyCollectorCreatesOneDurableReadyBatch(t *testing.T) {
	clock := func() (time.Time, error) { return testNow, nil }
	s := source(t, &change.MemStore{}, clock, "UTC", 0)
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	q, err := digestqueue.New(&change.MemStore{}, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	collect, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{ID: s})
	if err != nil {
		t.Fatal(err)
	}
	b, err := collect.Collect(t.Context(), testNow, testNow.Add(time.Hour))
	if err != nil || b == nil || b.State != digestqueue.Ready || b.Attempts != 0 || !b.Acknowledged[0] || b.Snapshots[0].Lines[0] != Line {
		t.Fatal(b, err)
	}
	if err := s.Plan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if next, err := collect.Collect(t.Context(), testNow, testNow.Add(time.Hour)); err != nil || next != nil {
		t.Fatal("same day duplicate admitted", next, err)
	}
}
