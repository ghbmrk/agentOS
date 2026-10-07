package ownersource

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/changesource"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
var limits = digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}

type noControl struct{}

func (noControl) Stop(context.Context) (journal.StopReport, error) { panic("unexpected control") }
func (noControl) Resume() error                                    { panic("unexpected control") }
func (noControl) Stopped() bool                                    { return false }
func (noControl) List() []journal.Status                           { return nil }
func notes(t *testing.T, st digestnotes.Store) *digestnotes.Source {
	t.Helper()
	n, err := digestnotes.New(digestnotes.Config{Store: st, Location: time.UTC, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func adapter(t *testing.T, n *digestnotes.Source) *Source {
	t.Helper()
	s, err := New(n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func collector(t *testing.T, q *digestqueue.Queue, s *Source) *digestqueue.Collector {
	t.Helper()
	c, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{ID: s})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func channel(t *testing.T, st owner.Store, n *digestnotes.Source) *owner.Channel {
	t.Helper()
	ch, err := owner.New(owner.Config{Owner: "+15550000999", Store: st, Engine: noControl{}, DigestNotes: n, Now: func() time.Time { return now }, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// REQ: CH-15, OP-1, OP-2
func TestActualOwnerSourceAndQueueReopenAfterSourceAckBeforeQueueBit(t *testing.T) {
	dir := t.TempDir()
	auth := owner.FileStore{Path: filepath.Join(dir, "owner.json")}
	if err := auth.Save(owner.State{Challenged: true}); err != nil {
		t.Fatal(err)
	}
	ns := &change.FileStore{Path: filepath.Join(dir, "notes.json")}
	qs := &change.FileStore{Path: filepath.Join(dir, "queue.json")}
	n := notes(t, ns)
	ch := channel(t, auth, n)
	ch.Handle(context.Background(), "+15550000999", "100000") // synthetic code-shaped challenge drop
	s := adapter(t, n)
	snap, err := s.Peek(context.Background())
	if err != nil || snap == nil || snap.Source != ID || len(snap.References) != 0 || len(snap.Lines) != 1 {
		t.Fatal(snap, err)
	}
	q, err := digestqueue.New(qs, limits)
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Enqueue([]digestqueue.Snapshot{*snap}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Ack(context.Background(), *snap); err != nil {
		t.Fatal(err)
	} // crash before queue Acknowledge
	if pending, err := n.Peek(context.Background()); err != nil || pending != nil {
		t.Fatal("source ack not durable", pending, err)
	}
	n = notes(t, &change.FileStore{Path: ns.Path})
	ch = channel(t, owner.FileStore{Path: auth.Path}, n)
	ch.Handle(context.Background(), "+15550000999", "100001") // later real owner event, not fixture injection
	q, err = digestqueue.New(&change.FileStore{Path: qs.Path}, limits)
	if err != nil {
		t.Fatal(err)
	}
	s = adapter(t, n)
	c := collector(t, q, s)
	if err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := q.Get(b.ID)
	if err != nil || !first.Acknowledged[0] || first.Snapshots[0].Hash != snap.Hash {
		t.Fatal("exact association not recovered", first, err)
	}
	next, err := c.Collect(context.Background(), now.Add(time.Minute), now.Add(time.Hour))
	if err != nil || next == nil || next.ID == b.ID || next.Snapshots[0].Generation != 2 || !next.Acknowledged[0] {
		t.Fatal("later event lost", next, err)
	}
	if next.Snapshots[0].Lines[0] != "1 code messages without the current challenge were ignored." {
		t.Fatal(next)
	}
	if err = s.Validate(context.Background(), *snap); err != nil {
		t.Fatal("valid old receipt lost", err)
	}
	if pending, err := c.Collect(context.Background(), now.Add(2*time.Minute), now.Add(time.Hour)); err != nil || pending != nil {
		t.Fatal("duplicate collection", pending, err)
	}
	state, err := auth.Load()
	if err != nil || len(state.Wrong) != 0 || state.BoundUsed != 0 {
		t.Fatal("digest event changed code authority", state, err)
	}
	if ch.TakeDigestNotes() != nil {
		t.Fatal("legacy consumer active")
	}
}
func TestRehashedReceiptCannotChangePrivateSourcePayload(t *testing.T) {
	n := notes(t, &change.MemStore{})
	if err := n.Record(digestnotes.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	s := adapter(t, n)
	snap, err := s.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, which := range []string{"lines", "receipt", "references"} {
		lines, receipt, refs := snap.Lines, snap.Receipt, snap.References
		switch which {
		case "lines":
			lines = []string{"Forged fixed notice."}
		case "receipt":
			receipt = strings.Replace(receipt, "1 code messages", "2 code messages", 1)
		case "references":
			refs = []string{"owner:g1"}
		}
		forged, err := digestqueue.NewSnapshotWithReceipt(ID, snap.Generation, lines, refs, receipt)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Ack(context.Background(), forged); err == nil {
			t.Fatal("forged association accepted", which)
		}
		if pending, err := n.Peek(context.Background()); err != nil || pending == nil || pending.Generation != 1 {
			t.Fatal("forgery consumed source", pending, err)
		}
	}
}
func TestFullQueueDoesNotAcknowledgeOwnerNotes(t *testing.T) {
	n := notes(t, &change.MemStore{})
	if err := n.Record(digestnotes.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	small := limits
	small.MaxBytes = 512
	q, err := digestqueue.New(&change.MemStore{}, small)
	if err != nil {
		t.Fatal(err)
	}
	s := adapter(t, n)
	if _, err = collector(t, q, s).Collect(context.Background(), now, now.Add(time.Hour)); !errors.Is(err, digestqueue.ErrFull) {
		t.Fatal(err)
	}
	if pending, err := n.Peek(context.Background()); err != nil || pending == nil {
		t.Fatal("failed admission consumed source", pending, err)
	}
}
func TestCancelledAndNilContextsRefused(t *testing.T) {
	n := notes(t, &change.MemStore{})
	s := adapter(t, n)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Peek(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Peek(nil); err == nil {
		t.Fatal("nil peek")
	}
	if err := s.Ack(nil, digestqueue.Snapshot{}); err == nil {
		t.Fatal("nil ack")
	}
	if err := s.Validate(ctx, digestqueue.Snapshot{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := New(nil); err == nil {
		t.Fatal("nil source")
	}
}

type noEvaluation struct{}

func (noEvaluation) Run(context.Context, change.Tree, change.Probe) ([]byte, error) {
	return nil, errors.New("unexpected model evaluation")
}

type cutStore struct {
	change.MemStore
	saves, failAt int
}

func (s *cutStore) Save(raw []byte) error {
	s.saves++
	if s.saves == s.failAt {
		return errors.New("synthetic owner source Ack cut")
	}
	return s.MemStore.Save(raw)
}
func TestMixedProductionSourcesRecoverPartialAcknowledgment(t *testing.T) {
	ps := &change.MemStore{}
	p, err := change.New(change.Config{Store: ps, Evaluator: noEvaluation{}})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Notice("original", "Original change notice."); err != nil {
		t.Fatal(err)
	}
	changeSource, err := changesource.New(p)
	if err != nil {
		t.Fatal(err)
	}
	ns := &cutStore{}
	n := notes(t, ns)
	if err = n.Record(digestnotes.Event{Dropped: true}); err != nil {
		t.Fatal(err)
	}
	ns.failAt = ns.saves + 2 // Peek succeeds, source Ack fails
	q, err := digestqueue.New(&change.MemStore{}, limits)
	if err != nil {
		t.Fatal(err)
	}
	c, err := digestqueue.NewCollector(q, map[string]digestqueue.Source{changesource.ID: changeSource, ID: adapter(t, n)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Collect(context.Background(), now, now.Add(time.Hour)); err == nil {
		t.Fatal("partial acknowledgment failure hidden")
	}
	batches, err := q.List()
	if err != nil || len(batches) != 1 || len(batches[0].Acknowledged) != 2 || !batches[0].Acknowledged[0] || batches[0].Acknowledged[1] {
		t.Fatal("wrong partial state", batches, err)
	}
	original := batches[0]
	if err = p.Notice("later", "Later change notice."); err != nil {
		t.Fatal(err)
	}
	ns.failAt = 0
	n = notes(t, ns)
	c, err = digestqueue.NewCollector(q, map[string]digestqueue.Source{changesource.ID: changeSource, ID: adapter(t, n)})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := q.Get(original.ID)
	if err != nil || !recovered.Acknowledged[0] || !recovered.Acknowledged[1] || recovered.Snapshots[0].Hash != original.Snapshots[0].Hash || recovered.Snapshots[1].Hash != original.Snapshots[1].Hash {
		t.Fatal("recovery changed associations", recovered, err)
	}
	next, err := c.Collect(context.Background(), now.Add(time.Minute), now.Add(time.Hour))
	if err != nil || next == nil || len(next.Snapshots) != 1 || next.Snapshots[0].Source != changesource.ID || next.Snapshots[0].Generation != 2 || next.Snapshots[0].Lines[0] != "Later change notice." {
		t.Fatal("later change lost or owner note repeated", next, err)
	}
}
