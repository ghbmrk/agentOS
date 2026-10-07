package owner_test

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
	own "github.com/ghbmrk/agentos/broker/owner"
)

var guardAt = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func guardSource(t *testing.T, store dn.Store) *dn.Source {
	t.Helper()
	s, err := dn.New(dn.Config{Store: store, Location: time.UTC, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func guardOpen(t *testing.T, store own.Store, source *dn.Source) *own.DigestOutbox {
	t.Helper()
	o, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func guardState(t *testing.T, o *own.DigestOutbox) own.State {
	t.Helper()
	s, err := o.State()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func guardPeek(t *testing.T, s *dn.Source) *dn.Snapshot {
	t.Helper()
	a, err := s.Peek(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func challengeChange(s *own.State) {
	s.Challenged = true
	s.LowLocked = true
	s.UnlockedUntil = time.Time{}
	s.Wrong = append(s.Wrong, guardAt)
}

type guardAuthorityCut struct {
	file        own.FileStore
	fail, after bool
}

func (s *guardAuthorityCut) Load() (own.State, error) { return s.file.Load() }
func (s *guardAuthorityCut) Save(st own.State) error {
	if s.fail && !s.after {
		return errors.New("synthetic before authority replacement")
	}
	if err := s.file.Save(st); err != nil {
		return err
	}
	if s.fail {
		return errors.New("synthetic after authority replacement")
	}
	return nil
}

type guardNoteCut struct {
	file        change.FileStore
	fail, after bool
}

func (s *guardNoteCut) Load() ([]byte, error) { return s.file.Load() }
func (s *guardNoteCut) Save(raw []byte) error {
	if s.fail && !s.after {
		return errors.New("synthetic before note replacement")
	}
	if err := s.file.Save(raw); err != nil {
		return err
	}
	if s.fail {
		return errors.New("synthetic after note replacement")
	}
	return nil
}

// REQ: OP-1, OP-2, CH-15, CH-18
func TestGuardAndNoteShareOneAuthorityFileTransaction(t *testing.T) {
	for _, after := range []bool{false, true} {
		dir := t.TempDir()
		auth := &guardAuthorityCut{file: own.FileStore{Path: filepath.Join(dir, "owner.json")}, after: after}
		note := &change.FileStore{Path: filepath.Join(dir, "notes.json")}
		source := guardSource(t, note)
		out := guardOpen(t, auth, source)
		auth.fail = true
		if err := out.Commit(dn.Event{Challenge: true}, challengeChange); !errors.Is(err, own.ErrDigestRecovery) {
			t.Fatal(err)
		}
		if _, err := out.State(); !errors.Is(err, own.ErrDigestRecovery) {
			t.Fatal("uncertain heap still usable", err)
		}
		if err := out.Update(func(s *own.State) { s.LastStep = 99 }); !errors.Is(err, own.ErrDigestRecovery) {
			t.Fatal("uncertain authority granted", err)
		}
		freshAuth := own.FileStore{Path: auth.file.Path}
		saved, err := freshAuth.Load()
		if err != nil {
			t.Fatal(err)
		}
		if saved.Challenged != after || saved.LowLocked != after || (len(saved.DigestOutbox.Pending) == 1) != after {
			t.Fatal("torn authority/event transaction", after, saved)
		}
		freshSource := guardSource(t, &change.FileStore{Path: note.Path})
		fresh := guardOpen(t, freshAuth, freshSource)
		if err := fresh.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
		a := guardPeek(t, freshSource)
		if after {
			if a == nil || a.Counts.Challenge != 1 {
				t.Fatal(a)
			}
		} else if a != nil {
			t.Fatal("event invented before transaction committed", a)
		}
	}
}
func TestSourceAndOutboxAckCutsRecoverWithoutDuplicateCounts(t *testing.T) {
	for _, cut := range []string{"note-record", "owner-retire"} {
		for _, after := range []bool{false, true} {
			t.Run(cut+map[bool]string{false: "-before", true: "-after"}[after], func(t *testing.T) {
				dir := t.TempDir()
				auth := &guardAuthorityCut{file: own.FileStore{Path: filepath.Join(dir, "owner.json")}, after: after}
				note := &guardNoteCut{file: change.FileStore{Path: filepath.Join(dir, "notes.json")}, after: after}
				source := guardSource(t, note)
				out := guardOpen(t, auth, source)
				if err := out.Commit(dn.Event{Challenge: true, WrongAt: guardAt}, challengeChange); err != nil {
					t.Fatal(err)
				}
				if cut == "note-record" {
					note.fail = true
				} else {
					auth.fail = true
				}
				if err := out.Flush(t.Context()); err == nil {
					t.Fatal("cut reported confirmed success")
				}
				// Neither side of an uncertain retirement can weaken the stored guard.
				authSaved, err := auth.Load()
				if err != nil || !authSaved.Challenged || !authSaved.LowLocked || len(authSaved.Wrong) != 1 {
					t.Fatal(authSaved, err)
				}
				freshSource := guardSource(t, &change.FileStore{Path: note.file.Path})
				fresh := guardOpen(t, own.FileStore{Path: auth.file.Path}, freshSource)
				if err := fresh.Flush(t.Context()); err != nil {
					t.Fatal(err)
				}
				a := guardPeek(t, freshSource)
				if a == nil || a.Counts.Challenge != 1 || len(a.Wrong) != 1 {
					t.Fatal("lost or duplicated guard note", a)
				}
				st := guardState(t, fresh)
				if st.DigestOutbox.Acked != 1 || st.DigestOutbox.Produced != 1 || len(st.DigestOutbox.Pending) != 0 {
					t.Fatal(st.DigestOutbox)
				}
				if err := fresh.Flush(t.Context()); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(a, guardPeek(t, freshSource)) {
					t.Fatal("repeat flush changed receipt")
				}
			})
		}
	}
}
func TestDigestAckBeforeUncertainOutboxRetirementDoesNotResurrectNote(t *testing.T) {
	dir := t.TempDir()
	auth := &guardAuthorityCut{file: own.FileStore{Path: filepath.Join(dir, "owner.json")}}
	sourceStore := &change.FileStore{Path: filepath.Join(dir, "notes.json")}
	source := guardSource(t, sourceStore)
	out := guardOpen(t, auth, source)
	if err := out.Commit(dn.Event{Dropped: true}, nil); err != nil {
		t.Fatal(err)
	}
	auth.fail = true
	if err := out.Flush(t.Context()); !errors.Is(err, own.ErrDigestRecovery) {
		t.Fatal(err)
	}
	a := guardPeek(t, source)
	if err := source.Ack(t.Context(), *a); err != nil {
		t.Fatal(err)
	}
	source = guardSource(t, &change.FileStore{Path: sourceStore.Path})
	fresh := guardOpen(t, own.FileStore{Path: auth.file.Path}, source)
	if err := fresh.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if guardPeek(t, source) != nil {
		t.Fatal("outbox replay resurrected a consumed digest")
	}
	if err := fresh.Commit(dn.Event{Dropped: true}, nil); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	b := guardPeek(t, source)
	if b == nil || b.Generation != 2 || b.Counts.Dropped != 1 {
		t.Fatal("later event not isolated", b)
	}
}
func TestSourceBindingAndBackupSkewRequireExplicitRecovery(t *testing.T) {
	store := &own.MemStore{}
	source := guardSource(t, &change.MemStore{})
	out := guardOpen(t, store, source)
	initial, _ := store.Load()
	for i := 0; i < 2; i++ {
		if err := out.Commit(dn.Event{Dropped: true}, nil); err != nil {
			t.Fatal(err)
		}
		if err := out.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	final, _ := store.Load()
	freshKey, err := dn.New(dn.Config{Store: &change.MemStore{}, Rand: bytes.NewReader(bytes.Repeat([]byte{9}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: store, Source: freshKey}); !errors.Is(err, own.ErrDigestMismatch) {
		t.Fatal("source replacement adopted", err)
	}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: store, Source: source}); !errors.Is(err, own.ErrDigestMismatch) {
		t.Fatal("source more than one event ahead", err)
	}
	if err := store.Save(final); err != nil {
		t.Fatal(err)
	}
	resetSameKey := guardSource(t, &change.MemStore{})
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: store, Source: resetSameKey}); !errors.Is(err, own.ErrDigestMismatch) {
		t.Fatal("source behind durable floor", err)
	}
	final.DigestOutbox.LastHash = strings.Repeat("0", 64)
	if err := store.Save(final); err != nil {
		t.Fatal(err)
	}
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: store, Source: source}); !errors.Is(err, own.ErrDigestMismatch) {
		t.Fatal("floor hash mismatch", err)
	}
}
func TestBoundedBacklogAndOwnedStateCopies(t *testing.T) {
	store := &own.MemStore{}
	source := guardSource(t, &change.MemStore{})
	out := guardOpen(t, store, source)
	for i := 0; i < own.MaxDigestOutbox; i++ {
		if err := out.Commit(dn.Event{Dropped: true}, func(s *own.State) { s.LastStep++ }); err != nil {
			t.Fatal(err)
		}
	}
	called := false
	if err := out.Commit(dn.Event{Dropped: true}, func(s *own.State) { called = true; s.LastStep++ }); !errors.Is(err, own.ErrDigestFull) {
		t.Fatal(err)
	}
	if called {
		t.Fatal("capacity refusal invoked authority mutation")
	}
	st := guardState(t, out)
	if st.LastStep != own.MaxDigestOutbox || len(st.DigestOutbox.Pending) != own.MaxDigestOutbox {
		t.Fatal(st)
	}
	st.DigestOutbox.Pending[0].Event.Dropped = false
	st.DigestOutbox.Binding = "changed"
	loaded, _ := store.Load()
	loaded.DigestOutbox.Pending[0].Event.Dropped = false
	if a := guardState(t, out); !a.DigestOutbox.Pending[0].Event.Dropped {
		t.Fatal("state alias escaped")
	}
	if err := out.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a := guardPeek(t, source); a == nil || a.Counts.Dropped != own.MaxDigestOutbox {
		t.Fatal(a)
	}
	if err := out.Commit(dn.Event{Dropped: true}, nil); err != nil {
		t.Fatal("drained capacity unusable", err)
	}
}
func TestMutationCannotRewriteOutboxAndCancelledFlushCannotRetire(t *testing.T) {
	store := &own.MemStore{}
	source := guardSource(t, &change.MemStore{})
	out := guardOpen(t, store, source)
	if err := out.Commit(dn.Event{Dropped: true}, func(s *own.State) { s.LastStep = 8; s.DigestOutbox = nil }); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
	if st := guardState(t, out); st.LastStep != 0 || st.DigestOutbox.Produced != 0 {
		t.Fatal("invalid transaction leaked", st)
	}
	if err := out.Commit(dn.Event{Dropped: true}, nil); err != nil {
		t.Fatal(err)
	}
	before := guardState(t, out)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := out.Flush(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := out.Flush(nil); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, guardState(t, out)) {
		t.Fatal("cancelled flush retired event")
	}
}
func TestMalformedOutboxAndExistingAnonymousSourceRefused(t *testing.T) {
	store := &own.MemStore{}
	source := guardSource(t, &change.MemStore{})
	out := guardOpen(t, store, source)
	if err := out.Commit(dn.Event{Dropped: true}, nil); err != nil {
		t.Fatal(err)
	}
	saved, _ := store.Load()
	saved.DigestOutbox.Pending[0].ID = 7
	if err := store.Save(saved); err != nil {
		t.Fatal(err)
	}
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: store, Source: source}); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
	anonymous := guardSource(t, &change.MemStore{})
	if err := anonymous.Record(dn.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{Store: &own.MemStore{}, Source: anonymous}); !errors.Is(err, dn.ErrInvalid) {
		t.Fatal("anonymous source adopted", err)
	}
	if _, err := own.NewDigestOutbox(own.DigestOutboxConfig{}); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
}

func TestSourceOutageRetainsLaterAuthorityTransactions(t *testing.T) {
	dir := t.TempDir()
	auth := own.FileStore{Path: filepath.Join(dir, "owner.json")}
	note := &guardNoteCut{file: change.FileStore{Path: filepath.Join(dir, "notes.json")}}
	source := guardSource(t, note)
	out := guardOpen(t, auth, source)
	if err := out.Commit(dn.Event{Challenge: true}, challengeChange); err != nil {
		t.Fatal(err)
	}
	note.fail = true
	if err := out.Flush(t.Context()); !errors.Is(err, dn.ErrRecovery) {
		t.Fatal(err)
	}
	if out.Health() == nil {
		t.Fatal("source outage not visible")
	}
	if err := out.Commit(dn.Event{Dropped: true}, func(s *own.State) { s.LastStep = 77 }); err != nil {
		t.Fatal("source outage prevented durable capture", err)
	}
	saved, err := auth.Load()
	if err != nil || saved.LastStep != 77 || !saved.Challenged || len(saved.DigestOutbox.Pending) != 2 {
		t.Fatal(saved, err)
	}
	source = guardSource(t, &change.FileStore{Path: note.file.Path})
	fresh := guardOpen(t, own.FileStore{Path: auth.Path}, source)
	if err := fresh.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	a := guardPeek(t, source)
	if a == nil || a.Counts.Challenge != 1 || a.Counts.Dropped != 1 {
		t.Fatal("outage lost later transaction", a)
	}
}
func TestUnexpectedProducerQuarantinesCoordinator(t *testing.T) {
	store := &own.MemStore{}
	source := guardSource(t, &change.MemStore{})
	out := guardOpen(t, store, source)
	if err := out.Commit(dn.Event{Dropped: true}, nil); err != nil {
		t.Fatal(err)
	}
	if err := source.RecordOnce(1, dn.Event{Silent: true}); err != nil {
		t.Fatal(err)
	}
	if err := out.Flush(t.Context()); !errors.Is(err, own.ErrDigestRecovery) || !errors.Is(err, own.ErrDigestMismatch) {
		t.Fatal(err)
	}
	called := false
	if err := out.Update(func(s *own.State) { called = true; s.LastStep = 44 }); !errors.Is(err, own.ErrDigestRecovery) {
		t.Fatal(err)
	}
	saved, _ := store.Load()
	if called || saved.LastStep != 0 || len(saved.DigestOutbox.Pending) != 1 {
		t.Fatal("mismatch allowed authority transaction", saved)
	}
}
func TestAuthorityOnlyUpdatePreservesDigestMetadata(t *testing.T) {
	store := &own.MemStore{}
	source := guardSource(t, &change.MemStore{})
	out := guardOpen(t, store, source)
	before := guardState(t, out)
	if err := out.Update(func(s *own.State) { s.LastStep = 44 }); err != nil {
		t.Fatal(err)
	}
	after := guardState(t, out)
	if after.LastStep != 44 || !reflect.DeepEqual(before.DigestOutbox, after.DigestOutbox) {
		t.Fatal(after)
	}
	if err := out.Update(func(s *own.State) { s.DigestOutbox.Binding = "rewritten" }); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
	if err := out.Update(nil); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
	if err := out.Commit(dn.Event{}, nil); !errors.Is(err, own.ErrDigestInvalid) {
		t.Fatal(err)
	}
}
