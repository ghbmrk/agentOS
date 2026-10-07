package digestnotes_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	dn "github.com/ghbmrk/agentos/broker/digestnotes"
)

// REQ: OP-1, OP-2, CH-15
func TestOrderedRecordReplaySurvivesAckAndFileReopen(t *testing.T) {
	st := &change.FileStore{Path: filepath.Join(t.TempDir(), "notes.json")}
	s := source(t, st)
	event := dn.Event{Dropped: true, WrongAt: now}
	if err := s.RecordOnce(1, event); err != nil {
		t.Fatal(err)
	}
	a := peek(t, s)
	if err := s.RecordOnce(1, event); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, peek(t, s)) {
		t.Fatal("replay altered pending receipt")
	}
	if err := s.Ack(t.Context(), *a); err != nil {
		t.Fatal(err)
	}
	s = source(t, st)
	// Equal instants in a different timezone bind the same event.
	event.WrongAt = event.WrongAt.In(time.FixedZone("synthetic", 3600))
	if err := s.RecordOnce(1, event); err != nil {
		t.Fatal(err)
	}
	if peek(t, s) != nil {
		t.Fatal("replay restored acknowledged counts")
	}
	if err := s.RecordOnce(2, dn.Event{Silent: true}); err != nil {
		t.Fatal(err)
	}
	b := peek(t, s)
	if b.Counts.Silent != 1 || b.Counts.Dropped != 0 {
		t.Fatal(b)
	}
	if err := s.RecordOnce(1, event); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("stale ID", err)
	}
	if !reflect.DeepEqual(b, peek(t, s)) {
		t.Fatal("stale replay changed later event")
	}
}

func TestOrderedRecordsRejectChangedPayloadGapsAndMixedModes(t *testing.T) {
	s := source(t, &change.MemStore{})
	for _, id := range []uint64{0, 2, 99} {
		if err := s.RecordOnce(id, dn.Event{Dropped: true}); !errors.Is(err, dn.ErrInvalid) {
			t.Fatal(id, err)
		}
	}
	if err := s.RecordOnce(1, dn.Event{}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal(err)
	}
	if err := s.RecordOnce(1, dn.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	a := peek(t, s)
	for _, e := range []dn.Event{{Silent: true}, {Dropped: true, WrongAt: now}} {
		if err := s.RecordOnce(1, e); !errors.Is(err, dn.ErrInvalid) {
			t.Fatal("changed payload", err)
		}
	}
	if err := s.Record(dn.Event{Dropped: true}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("mixed anonymous record", err)
	}
	if !reflect.DeepEqual(a, peek(t, s)) {
		t.Fatal("rejection changed pending")
	}
	legacy := source(t, &change.MemStore{})
	record(t, legacy, dn.Event{Dropped: true})
	if err := legacy.RecordOnce(1, dn.Event{Dropped: true}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("legacy conversion", err)
	}
	old := peek(t, legacy)
	if err := legacy.Ack(t.Context(), *old); err != nil {
		t.Fatal(err)
	}
	if err := legacy.RecordOnce(1, dn.Event{Dropped: true}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("acked legacy conversion", err)
	}
}

func TestOrderedReplayRecoversBothSaveUncertainties(t *testing.T) {
	for _, after := range []bool{false, true} {
		st := &failingStore{after: after}
		s := source(t, st)
		st.fail = true
		if err := s.RecordOnce(1, dn.Event{Challenge: true}); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal(err)
		}
		if err := s.RecordOnce(1, dn.Event{Challenge: true}); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal("old heap remained usable", err)
		}
		st.fail = false
		s = source(t, st)
		if err := s.RecordOnce(1, dn.Event{Challenge: true}); err != nil {
			t.Fatal(err)
		}
		a := peek(t, s)
		if a == nil || a.Counts.Challenge != 1 {
			t.Fatal("lost or duplicated recovery event", after, a)
		}
		// Retry success also requires durable confirmation, never a heap-only answer.
		st.fail = true
		if err := s.RecordOnce(1, dn.Event{Challenge: true}); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal(err)
		}
		st.fail = false
		s = source(t, st)
		if err := s.RecordOnce(1, dn.Event{Challenge: true}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, peek(t, s)) {
			t.Fatal("retry failure changed snapshot")
		}
	}
}

func TestConcurrentEqualProducerRetriesCountOnce(t *testing.T) {
	s := source(t, &change.MemStore{})
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.RecordOnce(1, dn.Event{Dropped: true}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if a := peek(t, s); a == nil || a.Counts.Dropped != 1 {
		t.Fatal(a)
	}
}

func TestMalformedProducerHighWaterRefusesReopen(t *testing.T) {
	for _, fields := range []map[string]any{
		{"record_seq": 1}, {"record_hash": "abcd"}, {"record_seq": 1, "record_hash": "not-hex-at-all"},
	} {
		st := &change.MemStore{}
		source(t, st)
		raw, err := st.Load()
		if err != nil {
			t.Fatal(err)
		}
		var state map[string]any
		if err = json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		for k, v := range fields {
			state[k] = v
		}
		raw, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err = st.Save(raw); err != nil {
			t.Fatal(err)
		}
		if _, err = dn.New(dn.Config{Store: st}); !errors.Is(err, dn.ErrInvalid) {
			t.Fatal("corrupt producer state", err)
		}
	}
}

// The replacement cut uses the actual atomic file store, then independent
// objects; it models caller uncertainty, not hardware/media durability.
func TestOrderedRecordFileReplacementRecovery(t *testing.T) {
	for _, after := range []bool{false, true} {
		st := &recordFileCut{file: &change.FileStore{Path: filepath.Join(t.TempDir(), "notes.json")}, after: after}
		s := source(t, st)
		st.fail = true
		event := dn.Event{Dropped: true, Counted: true, WrongAt: now}
		if err := s.RecordOnce(1, event); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal(err)
		}
		// Fresh file-store and source objects never use the failed instance's heap.
		fresh := &change.FileStore{Path: st.file.Path}
		s = source(t, fresh)
		if err := s.RecordOnce(1, event); err != nil {
			t.Fatal(err)
		}
		a := peek(t, s)
		if a == nil || a.Counts.Dropped != 1 || a.Counts.Counted != 1 || len(a.Wrong) != 1 {
			t.Fatal(after, a)
		}
		if err := s.Ack(t.Context(), *a); err != nil {
			t.Fatal(err)
		}
		s = source(t, &change.FileStore{Path: st.file.Path})
		if err := s.RecordOnce(1, event); err != nil {
			t.Fatal(err)
		}
		if peek(t, s) != nil {
			t.Fatal("replayed event reappeared after acknowledgment")
		}
	}
}

type recordFileCut struct {
	file        *change.FileStore
	fail, after bool
}

func (s *recordFileCut) Load() ([]byte, error) { return s.file.Load() }
func (s *recordFileCut) Save(raw []byte) error {
	if s.fail && !s.after {
		return errors.New("synthetic before-replacement cut")
	}
	if err := s.file.Save(raw); err != nil {
		return err
	}
	if s.fail {
		return errors.New("synthetic after-replacement cut")
	}
	return nil
}
