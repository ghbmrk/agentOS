package ownersource

import (
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/owner"
	"path/filepath"
	"testing"
	"time"
)

const transactionalOwner = "+15550000999"

func transactionalChannel(t *testing.T, st owner.Store, n *digestnotes.Source) *owner.Channel {
	t.Helper()
	c, err := owner.NewTransactional(owner.Config{Owner: transactionalOwner, Store: st, Engine: noControl{}, Now: func() time.Time { return now }, Location: time.UTC}, n)
	if err != nil || c == nil {
		t.Fatal(err)
	}
	if err := c.OwnerStateHealth(); err != nil {
		t.Fatal(err)
	}
	return c
}
func transactionalWrong(t *testing.T, c *owner.Channel) {
	t.Helper()
	if _, err := c.LocalSignIn("100000"); !errors.Is(err, owner.ErrWrongCode) {
		t.Fatal(err)
	}
}
func queuedOnly(t *testing.T, b *digestqueue.Batch) {
	t.Helper()
	if b == nil || b.State != digestqueue.Ready || b.Attempts != 0 || b.Evidence != "" || len(b.Snapshots) != 1 || len(b.Acknowledged) != 1 || !b.Acknowledged[0] {
		t.Fatal("admission became transport/visibility evidence", b)
	}
}

type transactionalRetirementCut struct {
	owner.FileStore
	after bool
	hook  func()
}

func (s *transactionalRetirementCut) Save(st owner.State) error {
	if s.hook == nil || st.DigestOutbox == nil || st.DigestOutbox.Acked == 0 {
		return s.FileStore.Save(st)
	}
	hook := s.hook
	s.hook = nil
	hook() // real collection/ack interleaved after source ingestion
	if s.after {
		if err := s.FileStore.Save(st); err != nil {
			return err
		}
	}
	return errors.New("synthetic owner retirement uncertainty")
}

// REQ: CH-15, CH-18, OP-1, OP-2
func TestTransactionalQueueConsumptionBeforeUncertainOwnerRetirementDoesNotResurrect(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			dir := t.TempDir()
			auth := &transactionalRetirementCut{FileStore: owner.FileStore{Path: filepath.Join(dir, "owner.json")}, after: after}
			notePath, queuePath := filepath.Join(dir, "notes.json"), filepath.Join(dir, "queue.json")
			n := notes(t, &change.FileStore{Path: notePath})
			c := transactionalChannel(t, auth, n)
			q, err := digestqueue.New(&change.FileStore{Path: queuePath}, limits)
			if err != nil {
				t.Fatal(err)
			}
			collect := collector(t, q, adapter(t, n))
			var first *digestqueue.Batch
			transactionalWrong(t, c)
			auth.hook = func() {
				var err error
				first, err = collect.Collect(t.Context(), now, now.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				queuedOnly(t, first)
			}
			if err := c.FlushDigestNotes(t.Context()); !errors.Is(err, owner.ErrDigestRecovery) {
				t.Fatal(err)
			}
			if pending, err := n.Peek(t.Context()); err != nil || pending != nil {
				t.Fatal("collector did not consume source", pending, err)
			}
			// Reconstruct all three file-backed components, not just their in-memory views.
			n = notes(t, &change.FileStore{Path: notePath})
			c = transactionalChannel(t, owner.FileStore{Path: auth.Path}, n)
			if err := c.FlushDigestNotes(t.Context()); err != nil {
				t.Fatal(err)
			}
			if pending, err := n.Peek(t.Context()); err != nil || pending != nil {
				t.Fatal("producer replay restored consumed counts", pending, err)
			}
			q, err = digestqueue.New(&change.FileStore{Path: queuePath}, limits)
			if err != nil {
				t.Fatal(err)
			}
			collect = collector(t, q, adapter(t, n))
			old, err := q.Get(first.ID)
			if err != nil {
				t.Fatal(err)
			}
			queuedOnly(t, &old)
			if old.Snapshots[0].Hash != first.Snapshots[0].Hash {
				t.Fatal("old association changed")
			}
			transactionalWrong(t, c)
			if err := c.FlushDigestNotes(t.Context()); err != nil {
				t.Fatal(err)
			}
			later, err := collect.Collect(t.Context(), now.Add(time.Minute), now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			queuedOnly(t, later)
			if later.ID == old.ID || later.Snapshots[0].Generation != 2 {
				t.Fatal("later event lost/deduplicated", later)
			}
			st, err := (owner.FileStore{Path: auth.Path}).Load()
			if err != nil || len(st.Wrong) != 2 || st.LocalUsed != 2 || st.DigestOutbox.Produced != 2 || st.DigestOutbox.Acked != 2 || len(st.DigestOutbox.Pending) != 0 {
				t.Fatal("authority/producer floor changed", st, err)
			}
		})
	}
}

type transactionalQueueBitCut struct {
	change.FileStore
	writes int
	after  bool
}

func (s *transactionalQueueBitCut) Save(b []byte) error {
	s.writes++
	if s.writes != 3 {
		return s.FileStore.Save(b)
	} // open, enqueue, ack bitmap
	if s.after {
		if err := s.FileStore.Save(b); err != nil {
			return err
		}
	}
	return errors.New("synthetic queue bitmap uncertainty")
}
func TestTransactionalQueueBitmapReopenPreservesLaterRealOwnerEvent(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			dir := t.TempDir()
			auth := owner.FileStore{Path: filepath.Join(dir, "owner.json")}
			notePath := filepath.Join(dir, "notes.json")
			queueStore := &transactionalQueueBitCut{FileStore: change.FileStore{Path: filepath.Join(dir, "queue.json")}, after: after}
			n := notes(t, &change.FileStore{Path: notePath})
			c := transactionalChannel(t, auth, n)
			// Two actual producer events form one source snapshot: producer IDs
			// and digest generations must not be treated as the same cursor.
			transactionalWrong(t, c)
			transactionalWrong(t, c)
			if err := c.FlushDigestNotes(t.Context()); err != nil {
				t.Fatal(err)
			}
			q, err := digestqueue.New(queueStore, limits)
			if err != nil {
				t.Fatal(err)
			}
			collect := collector(t, q, adapter(t, n))
			if _, err := collect.Collect(t.Context(), now, now.Add(time.Hour)); !errors.Is(err, digestqueue.ErrRecovery) {
				t.Fatal(err)
			}
			if pending, err := n.Peek(t.Context()); err != nil || pending != nil {
				t.Fatal("source ack not committed", pending, err)
			}
			n = notes(t, &change.FileStore{Path: notePath})
			c = transactionalChannel(t, owner.FileStore{Path: auth.Path}, n)
			transactionalWrong(t, c)
			if err := c.FlushDigestNotes(t.Context()); err != nil {
				t.Fatal(err)
			}
			q, err = digestqueue.New(&change.FileStore{Path: queueStore.Path}, limits)
			if err != nil {
				t.Fatal(err)
			}
			collect = collector(t, q, adapter(t, n))
			before, err := q.Get(1)
			if err != nil || before.Acknowledged[0] != after {
				t.Fatal("queue cut not exercised", before, err)
			}
			hash := before.Snapshots[0].Hash
			if err := collect.Recover(t.Context()); err != nil {
				t.Fatal(err)
			}
			old, err := q.Get(1)
			if err != nil {
				t.Fatal(err)
			}
			queuedOnly(t, &old)
			if old.Snapshots[0].Hash != hash {
				t.Fatal("old receipt changed")
			}
			later, err := collect.Collect(t.Context(), now.Add(time.Minute), now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			queuedOnly(t, later)
			if later.ID != 2 || later.Snapshots[0].Generation != 2 {
				t.Fatal("old source-ack replay consumed later note", later)
			}
			st, err := auth.Load()
			if err != nil || len(st.Wrong) != 3 || st.LocalUsed != 3 || st.DigestOutbox.Produced != 3 || st.DigestOutbox.Acked != 3 {
				t.Fatal(st, err)
			}
		})
	}
}
