package digestnotes_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	dn "github.com/ghbmrk/agentos/broker/digestnotes"
)

// REQ: OP-1, OP-2, CH-15
func TestProducerClaimPersistsExclusionAndPrivateBinding(t *testing.T) {
	st := &change.FileStore{Path: filepath.Join(t.TempDir(), "notes.json")}
	s := source(t, st)
	if _, err := s.ProducerCheckpoint(); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("unclaimed producer", err)
	}
	p, err := s.ClaimProducer()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Binding) != 64 || p.Sequence != 0 || p.Hash != "" {
		t.Fatal(p)
	}
	s = source(t, st)
	q, err := s.ProducerCheckpoint()
	if err != nil || !reflect.DeepEqual(p, q) {
		t.Fatal("claim lost on reopen", q, err)
	}
	if err := s.Record(dn.Event{Dropped: true}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("anonymous writer entered claimed source", err)
	}
	if err := s.RecordOnce(1, dn.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	q, err = s.ProducerCheckpoint()
	if err != nil || q.Sequence != 1 || len(q.Hash) != 64 || q.Binding != p.Binding {
		t.Fatal(q, err)
	}
	a := peek(t, s)
	if err := s.Ack(t.Context(), *a); err != nil {
		t.Fatal(err)
	}
	r, err := source(t, st).ProducerCheckpoint()
	if err != nil || !reflect.DeepEqual(q, r) {
		t.Fatal("digest acknowledgment reset producer", r, err)
	}
	other, err := dn.New(dn.Config{Store: &change.MemStore{}, Rand: bytes.NewReader(bytes.Repeat([]byte{7}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	otherP, err := other.ClaimProducer()
	if err != nil || otherP.Binding == p.Binding {
		t.Fatal("reset/source substitution invisible", otherP, err)
	}
}

func TestClaimCannotAdoptAnonymousHistory(t *testing.T) {
	for _, acked := range []bool{false, true} {
		s := source(t, &change.MemStore{})
		record(t, s, dn.Event{Dropped: true})
		if acked {
			a := peek(t, s)
			if err := s.Ack(t.Context(), *a); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.ClaimProducer(); !errors.Is(err, dn.ErrInvalid) {
			t.Fatal("anonymous history claimed", acked, err)
		}
		if err := s.Record(dn.Event{Silent: true}); err != nil {
			t.Fatal("refusal changed anonymous mode", err)
		}
	}
}
func TestUncertainClaimRequiresReopenAndConfirmation(t *testing.T) {
	for _, after := range []bool{false, true} {
		st := &failingStore{after: after}
		s := source(t, st)
		st.fail = true
		if _, err := s.ClaimProducer(); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal(err)
		}
		if _, err := s.ProducerCheckpoint(); !errors.Is(err, dn.ErrRecovery) {
			t.Fatal("failed claim disclosed usable checkpoint", err)
		}
		st.fail = false
		s = source(t, st)
		p, err := s.ClaimProducer()
		if err != nil || p.Sequence != 0 {
			t.Fatal(p, err)
		}
		if err := s.Record(dn.Event{Dropped: true}); !errors.Is(err, dn.ErrInvalid) {
			t.Fatal(err)
		}
	}
}
func TestPreviousOrderedStateCanBeClaimedWithoutReset(t *testing.T) {
	st := &change.MemStore{}
	s := source(t, st)
	if err := s.RecordOnce(1, dn.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ProducerCheckpoint()
	raw, _ := st.Load()
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "ordered")
	raw, _ = json.Marshal(legacy)
	if err := st.Save(raw); err != nil {
		t.Fatal(err)
	}
	s = source(t, st)
	after, err := s.ClaimProducer()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal(after, err)
	}
	if err := s.RecordOnce(1, dn.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	if a := peek(t, s); a == nil || a.Counts.Dropped != 1 {
		t.Fatal(a)
	}
}
func TestCanonicalEventHashRejectsDisguisedZeroAndMatchesInstants(t *testing.T) {
	disguised := time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("synthetic-zero", 0))
	if !disguised.IsZero() {
		t.Fatal("bad fixture")
	}
	for _, ordered := range []bool{false, true} {
		s := source(t, &change.MemStore{})
		var err error
		if ordered {
			err = s.RecordOnce(1, dn.Event{WrongAt: disguised})
		} else {
			err = s.Record(dn.Event{WrongAt: disguised})
		}
		if !errors.Is(err, dn.ErrInvalid) {
			t.Fatal("empty disguised event accepted", ordered, err)
		}
	}
	a, err := dn.EventHash(dn.Event{Dropped: true, WrongAt: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := dn.EventHash(dn.Event{Dropped: true, WrongAt: now.In(time.FixedZone("west", -3600))})
	if err != nil || a != b {
		t.Fatal("equal instants mismatch", err)
	}
	c, err := dn.EventHash(dn.Event{Dropped: true, WrongAt: disguised})
	if err != nil {
		t.Fatal(err)
	}
	d, err := dn.EventHash(dn.Event{Dropped: true})
	if err != nil || c != d {
		t.Fatal("absent timestamps mismatch", err)
	}
	if _, err := dn.EventHash(dn.Event{}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal(err)
	}
}
