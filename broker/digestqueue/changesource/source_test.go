package changesource

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestqueue"
)

var now = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
var policy = digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}

type noEvaluation struct{}

func (noEvaluation) Run(context.Context, change.Tree, change.Probe) ([]byte, error) {
	return nil, errors.New("unexpected evaluation")
}
func pipeline(t *testing.T, store change.Store) *change.Pipeline {
	t.Helper()
	p, err := change.New(change.Config{Store: store, Evaluator: noEvaluation{}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func adapter(t *testing.T, p *change.Pipeline) *Source {
	t.Helper()
	s, err := New(p)
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

// REQ: CH-15, OP-1
func TestRealPipelineFeedsCollectorWithoutDestructiveRead(t *testing.T) {
	st := &change.MemStore{}
	p := pipeline(t, st)
	if err := p.Notice("fixed-notice", "Fixed broker notice."); err != nil {
		t.Fatal(err)
	}
	src := adapter(t, p)
	q, err := digestqueue.New(&change.MemStore{}, policy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := collector(t, q, src).Collect(context.Background(), now, now.Add(time.Hour))
	if err != nil || b == nil || !b.Acknowledged[0] || b.Snapshots[0].Lines[0] != "Fixed broker notice." {
		t.Fatal(b, err)
	}
	if pending, err := p.PeekDigest(); err != nil || pending != nil {
		t.Fatal("source not consumed after admission", pending, err)
	}
	if next, err := collector(t, q, src).Collect(context.Background(), now.Add(time.Minute), now.Add(time.Hour)); err != nil || next != nil {
		t.Fatal("source duplicated", next, err)
	}
}
func TestAdapterAckRejectsRehashedChangedQueuePayload(t *testing.T) {
	p := pipeline(t, &change.MemStore{})
	_ = p.Notice("note", "Original.")
	src := adapter(t, p)
	snap, err := src.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := digestqueue.NewSnapshotWithReceipt(ID, snap.Generation, []string{"Changed."}, snap.References, snap.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err = src.Ack(context.Background(), forged); err == nil {
		t.Fatal("queue payload differed from source receipt")
	}
	pending, err := p.PeekDigest()
	if err != nil || pending == nil {
		t.Fatal("forgery consumed source", pending, err)
	}
}
func TestAdapterAckRejectsRehashedChangedSourceReceipt(t *testing.T) {
	p := pipeline(t, &change.MemStore{})
	_ = p.Notice("note", "Original.")
	src := adapter(t, p)
	snap, _ := src.Peek(context.Background())
	var receipt change.DigestSnapshot
	_ = json.Unmarshal([]byte(snap.Receipt), &receipt)
	receipt.Marks[0].ID = "different"
	raw, _ := json.Marshal(receipt)
	forged, err := digestqueue.NewSnapshotWithReceipt(ID, snap.Generation, snap.Lines, snap.References, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err = src.Ack(context.Background(), forged); !errors.Is(err, change.ErrDigestSnapshot) {
		t.Fatal(err)
	}
}

// REQ: OP-2
func TestRealPipelineAndQueueReopenAfterPartialAcknowledgment(t *testing.T) {
	dir := t.TempDir()
	ps := change.FileStore{Path: filepath.Join(dir, "pipeline.json")}
	p := pipeline(t, ps)
	_ = p.Notice("note", "Fixed notice.")
	src := adapter(t, p)
	snap, err := src.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	qs := change.FileStore{Path: filepath.Join(dir, "queue.json")}
	q, err := digestqueue.New(qs, policy)
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Enqueue([]digestqueue.Snapshot{*snap}, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = src.Ack(context.Background(), *snap); err != nil {
		t.Fatal(err)
	} // Crash before queue acknowledgment bit.
	p2 := pipeline(t, change.FileStore{Path: ps.Path})
	q2, err := digestqueue.New(change.FileStore{Path: qs.Path}, policy)
	if err != nil {
		t.Fatal(err)
	}
	c := collector(t, q2, adapter(t, p2))
	if err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if !got.Acknowledged[0] {
		t.Fatal(got)
	}
	if next, err := c.Collect(context.Background(), now.Add(time.Minute), now.Add(time.Hour)); err != nil || next != nil {
		t.Fatal("duplicate from real source restart", next, err)
	}
}
func TestLaterRealPipelineNoticeSurvivesOldAck(t *testing.T) {
	p := pipeline(t, &change.MemStore{})
	_ = p.Notice("old", "Old.")
	src := adapter(t, p)
	old, _ := src.Peek(context.Background())
	_ = p.Notice("new", "New.")
	if err := src.Ack(context.Background(), *old); err != nil {
		t.Fatal(err)
	}
	next, err := src.Peek(context.Background())
	if err != nil || next == nil || next.Generation <= old.Generation || next.Lines[0] != "New." {
		t.Fatal(next, err)
	}
}
func TestMalformedOrForeignSourceRefused(t *testing.T) {
	p := pipeline(t, &change.MemStore{})
	src := adapter(t, p)
	for _, receipt := range []string{"{", `{} {}`, `{"unexpected":true}`} {
		snap, err := digestqueue.NewSnapshotWithReceipt(ID, 1, []string{"Note."}, nil, receipt)
		if err != nil {
			t.Fatal(err)
		}
		if err = src.Ack(context.Background(), snap); err == nil {
			t.Fatal(receipt)
		}
	}
	foreign, _ := digestqueue.NewSnapshotWithReceipt("owner", 1, []string{"Note."}, nil, `{}`)
	if err := src.Ack(context.Background(), foreign); err == nil {
		t.Fatal("foreign source accepted")
	}
}
func TestCancelledAdapterCallDoesNotConsume(t *testing.T) {
	p := pipeline(t, &change.MemStore{})
	_ = p.Notice("note", "Note.")
	src := adapter(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Peek(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	snap, _ := src.Peek(context.Background())
	if err := src.Ack(ctx, *snap); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if pending, err := p.PeekDigest(); err != nil || pending == nil {
		t.Fatal(pending, err)
	}
}
func TestOldReceiptRemainsIdempotentAfterNewerGeneration(t *testing.T) {
	p := pipeline(t, &change.MemStore{})
	src := adapter(t, p)
	_ = p.Notice("first", "First.")
	old, _ := src.Peek(context.Background())
	if err := src.Ack(context.Background(), *old); err != nil {
		t.Fatal(err)
	}
	_ = p.Notice("second", "Second.")
	next, _ := src.Peek(context.Background())
	if err := src.Ack(context.Background(), *next); err != nil {
		t.Fatal(err)
	}
	if err := src.Ack(context.Background(), *old); err != nil {
		t.Fatal(err)
	}
}
