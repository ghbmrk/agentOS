package digestnotes_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	dn "github.com/ghbmrk/agentos/broker/digestnotes"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func source(t *testing.T, st dn.Store) *dn.Source {
	t.Helper()
	s, err := dn.New(dn.Config{Store: st, Location: time.UTC, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func peek(t *testing.T, s *dn.Source) *dn.Snapshot {
	t.Helper()
	snap, err := s.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return snap
}
func record(t *testing.T, s *dn.Source, e dn.Event) {
	t.Helper()
	if err := s.Record(e); err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-15, OP-1, OP-2
func TestNonconsumingSnapshotReopensWithExactPrivateReceipt(t *testing.T) {
	st := &change.FileStore{Path: filepath.Join(t.TempDir(), "owner-notes.json")}
	s := source(t, st)
	record(t, s, dn.Event{Dropped: true, Silent: true, WrongAt: now})
	a := peek(t, s)
	if a == nil || a.Generation != 1 || len(a.Lines) != 3 || !strings.Contains(a.Lines[0], "1 code messages") {
		t.Fatal(a)
	}
	b := peek(t, source(t, st))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("snapshot changed on reopen", a, b)
	}
	if err := s.Validate(*b); err != nil {
		t.Fatal(err)
	}
}
func TestAckPreservesLaterCountsAndTimestampPrefix(t *testing.T) {
	s := source(t, &change.MemStore{})
	record(t, s, dn.Event{Dropped: true, Counted: true, WrongAt: now})
	a := peek(t, s)
	record(t, s, dn.Event{Dropped: true, Challenge: true, WrongAt: now.Add(time.Minute)})
	if err := s.Ack(context.Background(), *a); err != nil {
		t.Fatal(err)
	}
	b := peek(t, s)
	if b == nil || b.Generation != 2 || b.Counts.Dropped != 1 || b.Counts.Counted != 0 || b.Counts.Challenge != 1 || len(b.Wrong) != 1 || !b.Wrong[0].Equal(now.Add(time.Minute)) {
		t.Fatal("later events lost", b)
	}
	if err := s.Ack(context.Background(), *a); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(peek(t, s), b) {
		t.Fatal("old ack consumed new snapshot")
	}
	if err := s.Ack(context.Background(), *b); err != nil {
		t.Fatal(err)
	}
	if peek(t, s) != nil {
		t.Fatal("ack did not consume captured events")
	}
}
func TestForgedAndCrossSourceReceiptsCannotConsume(t *testing.T) {
	s := source(t, &change.MemStore{})
	record(t, s, dn.Event{Dropped: true})
	a := peek(t, s)
	for _, mutate := range []func(*dn.Snapshot){func(s *dn.Snapshot) { s.Counts.Dropped++ }, func(s *dn.Snapshot) { s.Generation++ }, func(s *dn.Snapshot) { s.Lines[0] = "Forged." }} {
		fake := *a
		fake.Lines = append([]string(nil), a.Lines...)
		mutate(&fake)
		if err := s.Ack(context.Background(), fake); err == nil {
			t.Fatal("forged receipt accepted")
		}
		if !reflect.DeepEqual(peek(t, s), a) {
			t.Fatal("forged ack mutated source")
		}
	}
	other, err := dn.New(dn.Config{Store: &change.MemStore{}, Location: time.UTC, Rand: bytes.NewReader(bytes.Repeat([]byte{1}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	record(t, other, dn.Event{Dropped: true})
	if err = other.Ack(context.Background(), *a); err == nil {
		t.Fatal("different source key accepted receipt")
	}
}
func TestBoundedWrongTimesRetainOverflowAndLaterEvents(t *testing.T) {
	s := source(t, &change.MemStore{})
	for i := 0; i < dn.MaxWrong; i++ {
		record(t, s, dn.Event{WrongAt: now.Add(time.Duration(i) * time.Second)})
	}
	a := peek(t, s)
	record(t, s, dn.Event{WrongAt: now.Add(time.Hour)})
	if err := s.Ack(context.Background(), *a); err != nil {
		t.Fatal(err)
	}
	b := peek(t, s)
	if b == nil || len(b.Wrong) != 0 || b.Overflow != 1 || !strings.Contains(strings.Join(b.Lines, " "), "not individually listed") {
		t.Fatal("overflow event lost", b)
	}
}
func TestReturnedSnapshotsOwnTheirArrays(t *testing.T) {
	s := source(t, &change.MemStore{})
	record(t, s, dn.Event{WrongAt: now})
	a := peek(t, s)
	a.Lines[0] = "mutated"
	a.Wrong[0] = now.Add(time.Hour)
	b := peek(t, s)
	if b.Lines[0] == "mutated" || !b.Wrong[0].Equal(now) {
		t.Fatal("snapshot aliases state")
	}
}

type failingStore struct {
	change.MemStore
	fail  bool
	after bool
}

func (s *failingStore) Save(raw []byte) error {
	if s.fail && !s.after {
		return errors.New("synthetic pre-write error")
	}
	if err := s.MemStore.Save(raw); err != nil {
		return err
	}
	if s.fail {
		return errors.New("synthetic post-write error")
	}
	return nil
}
func TestFailedEventSaveQuarantinesUntilDurableReopen(t *testing.T) {
	for _, after := range []bool{false, true} {
		st := &failingStore{after: after}
		s := source(t, st)
		st.fail = true
		if err := s.Record(dn.Event{Dropped: true}); err == nil {
			t.Fatal("save failure ignored")
		}
		if _, err := s.Peek(context.Background()); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal(err)
		}
		if s.Health() == nil {
			t.Fatal("missing failure status")
		}
		st.fail = false
		s = source(t, st)
		a := peek(t, s)
		if after != (a != nil) {
			t.Fatal("wrong recovered replacement", after, a)
		}
	}
}
func TestFailedAckCannotContinueFromOldHeap(t *testing.T) {
	st := &failingStore{}
	s := source(t, st)
	record(t, s, dn.Event{Dropped: true})
	a := peek(t, s)
	st.fail = true
	if err := s.Ack(context.Background(), *a); err == nil {
		t.Fatal("failed ack reported success")
	}
	if err := s.Validate(*a); !errors.Is(err, dn.ErrRecovery) {
		t.Fatal("failed source remained usable", err)
	}
	st.fail = false
	s = source(t, st)
	if err := s.Ack(context.Background(), *a); err != nil {
		t.Fatal(err)
	}
	if peek(t, s) != nil {
		t.Fatal("authentic recovery ack not consumed")
	}
}
func TestInvalidStateAndTimezoneDriftRefused(t *testing.T) {
	st := &change.MemStore{}
	source(t, st)
	if _, err := dn.New(dn.Config{Store: st, Location: time.FixedZone("other", 3600)}); err == nil {
		t.Fatal("timezone changed silently")
	}
	if err := st.Save([]byte(`{"schema":99}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := dn.New(dn.Config{Store: st, Location: time.UTC}); err == nil {
		t.Fatal("invalid state accepted")
	}
}
func TestCancelledOrNilContextCannotConsume(t *testing.T) {
	s := source(t, &change.MemStore{})
	record(t, s, dn.Event{Dropped: true})
	a := peek(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Ack(ctx, *a); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Peek(nil); err == nil {
		t.Fatal("nil peek context")
	}
	if err := s.Ack(nil, *a); err == nil {
		t.Fatal("nil ack context")
	}
	if !reflect.DeepEqual(peek(t, s), a) {
		t.Fatal("cancel consumed")
	}
}
func TestEmptyEventRefusedAndIdlePeekCreatesNoGeneration(t *testing.T) {
	s := source(t, &change.MemStore{})
	if err := s.Record(dn.Event{}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal(err)
	}
	if peek(t, s) != nil {
		t.Fatal("empty source snapshot")
	}
	record(t, s, dn.Event{Dropped: true})
	if peek(t, s).Generation != 1 {
		t.Fatal("idle peek spent generation")
	}
}

func TestPendingAndRepeatedAckSaveFailuresRequireReopen(t *testing.T) {
	st := &failingStore{}
	s := source(t, st)
	record(t, s, dn.Event{Dropped: true})
	st.fail = true
	if _, err := s.Peek(context.Background()); !errors.Is(err, dn.ErrRecovery) {
		t.Fatal("pending save failure", err)
	}
	st.fail = false
	s = source(t, st)
	a := peek(t, s)
	if err := s.Ack(context.Background(), *a); err != nil {
		t.Fatal(err)
	}
	st.fail = true
	if err := s.Ack(context.Background(), *a); !errors.Is(err, dn.ErrRecovery) {
		t.Fatal("old ack did not confirm durability", err)
	}
	st.fail = false
	s = source(t, st)
	if err := s.Ack(context.Background(), *a); err != nil {
		t.Fatal(err)
	}
}
func TestCorruptPendingReceiptRejectedOnReopen(t *testing.T) {
	st := &change.MemStore{}
	s := source(t, st)
	record(t, s, dn.Event{Dropped: true})
	peek(t, s)
	raw, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("1 code messages"), []byte("2 code messages"), 1)
	if err = st.Save(raw); err != nil {
		t.Fatal(err)
	}
	if _, err = dn.New(dn.Config{Store: st, Location: time.UTC}); err == nil {
		t.Fatal("corrupt pending receipt loaded")
	}
}
