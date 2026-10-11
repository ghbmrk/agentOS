package digestqueue

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// syntheticSource models a source whose Ack survives coordinator restart. It
// can append a later generation while the old one is queued/being acknowledged.
type syntheticSource struct {
	mu           sync.Mutex
	pending      *Snapshot
	acknowledged map[uint64]string
	calls        int
	fail         error
	peekFail     error
	afterAck     func()
}

func source(s Snapshot) *syntheticSource {
	return &syntheticSource{pending: &s, acknowledged: map[uint64]string{}}
}
func (s *syntheticSource) Peek(ctx context.Context) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peekFail != nil {
		return nil, s.peekFail
	}
	if s.pending == nil {
		return nil, nil
	}
	v := clone(*s.pending)
	return &v, nil
}
func (s *syntheticSource) Ack(ctx context.Context, snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		return s.fail
	}
	if h, ok := s.acknowledged[snap.Generation]; ok {
		if h != snap.Hash {
			return ErrConflict
		}
		return nil
	}
	if s.pending == nil || s.pending.Generation < snap.Generation {
		return ErrConflict
	}
	if s.pending.Generation == snap.Generation && s.pending.Hash != snap.Hash {
		return ErrConflict
	}
	s.acknowledged[snap.Generation] = snap.Hash
	if s.pending.Generation == snap.Generation {
		s.pending = nil
	}
	if s.afterAck != nil {
		s.afterAck()
	}
	return nil
}
func collect(t *testing.T, q *Queue, sources map[string]Source) *Collector {
	t.Helper()
	c, err := NewCollector(q, sources)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// REQ: OP-1
func TestCollectionDurablyQueuesBeforeAcknowledging(t *testing.T) {
	q, st := queue(t)
	src := source(snapshot(t, "change", 1, "Fixed note."))
	src.afterAck = func() {
		raw, _ := st.Load()
		var saved state
		_ = json.Unmarshal(raw, &saved)
		if len(saved.Batches) != 1 {
			t.Error("source ack preceded durable batch")
		}
	}
	c := collect(t, q, map[string]Source{"change": src})
	b, err := c.Collect(context.Background(), at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || !b.Acknowledged[0] {
		t.Fatal(b)
	}
	next, err := c.Collect(context.Background(), at.Add(time.Minute), at.Add(time.Hour))
	if err != nil || next != nil {
		t.Fatal("duplicated consumed source", next, err)
	}
}
func TestAdmissionFailureNeverCallsSourceAck(t *testing.T) {
	q, st := queue(t)
	src := source(snapshot(t, "change", 1, "Note."))
	c := collect(t, q, map[string]Source{"change": src})
	st.Fail = errors.New("disk full")
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); err == nil {
		t.Fatal("accepted failed save")
	}
	if src.calls != 0 || src.pending == nil {
		t.Fatal("consumed unqueued source")
	}
}

// REQ: OP-2
func TestRestartAfterSourceAckBeforeQueueBitmapSave(t *testing.T) {
	q, st := queue(t)
	src := source(snapshot(t, "change", 1, "Note."))
	src.afterAck = func() { st.Fail = errors.New("bitmap save failed") }
	c := collect(t, q, map[string]Source{"change": src})
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	if src.pending != nil {
		t.Fatal("test never consumed source")
	}
	st.Fail = nil
	src.afterAck = nil
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	c2 := collect(t, q2, map[string]Source{"change": src})
	if err = c2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := q2.Get(1)
	if !b.Acknowledged[0] || src.calls != 2 {
		t.Fatal(b, src.calls)
	}
	all, _ := q2.List()
	if len(all) != 1 {
		t.Fatal("duplicate batch on recovery")
	}
}
func TestPartialAcknowledgmentRecoveredBeforeNewPeek(t *testing.T) {
	q, _ := queue(t)
	a := source(snapshot(t, "change", 1, "Change."))
	z := source(snapshot(t, "owner", 1, "Owner."))
	z.fail = errors.New("source store failed")
	c := collect(t, q, map[string]Source{"change": a, "owner": z})
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); err == nil {
		t.Fatal("lost ack failure")
	}
	b, _ := q.Get(1)
	if !b.Acknowledged[0] || b.Acknowledged[1] {
		t.Fatal(b)
	}
	a.pending = &Snapshot{} // A new peek would fail; recovery must not peek sources.
	z.fail = nil
	if err := c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ = q.Get(1)
	if !b.Acknowledged[1] {
		t.Fatal("partial ack not recovered")
	}
}
func TestNewerGenerationSurvivesOlderRecoveryAck(t *testing.T) {
	q, _ := queue(t)
	old := snapshot(t, "change", 1, "Old note.")
	b, err := q.Enqueue([]Snapshot{old}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	src := source(snapshot(t, "change", 2, "New note."))
	c := collect(t, q, map[string]Source{"change": src})
	if err = c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if src.pending == nil || src.pending.Generation != 2 {
		t.Fatal("old ack erased newer source")
	}
	got, _ := q.Get(b.ID)
	if !got.Acknowledged[0] {
		t.Fatal(got)
	}
}
func TestWrongSourceIdentityRejectedBeforeAdmission(t *testing.T) {
	q, _ := queue(t)
	src := source(snapshot(t, "owner", 1, "Note."))
	c := collect(t, q, map[string]Source{"change": src})
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	all, _ := q.List()
	if len(all) != 0 || src.calls != 0 {
		t.Fatal("admitted wrong source")
	}
}
func TestMissingSourceBlocksRecoveryBeforeNewCollection(t *testing.T) {
	q, _ := queue(t)
	enqueue(t, q, "change", 1)
	src := source(snapshot(t, "owner", 1, "Owner note."))
	c := collect(t, q, map[string]Source{"owner": src})
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatal(err)
	}
	if src.calls != 0 {
		t.Fatal("new source bypassed missing recovery source")
	}
}

// REQ: OP-1 (W5-Db DB-6)
// W5-Da expected ErrExpired here; recover now skips expired batches.
func TestRecoverSkipsExpired(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	if err := q.Expire(at.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	src := source(b.Snapshots[0])
	c := collect(t, q, map[string]Source{"change": src})
	if err := c.Recover(context.Background()); err != nil {
		t.Fatal("recover blocked on an expired batch:", err)
	}
	if src.calls != 0 || src.pending == nil {
		t.Fatal("expired notice consumed source")
	}
}
func TestPeekFailureLeavesAllSourcesPending(t *testing.T) {
	q, _ := queue(t)
	a := source(snapshot(t, "change", 1, "Note."))
	b := source(snapshot(t, "owner", 1, "Note."))
	b.peekFail = errors.New("cannot snapshot")
	c := collect(t, q, map[string]Source{"change": a, "owner": b})
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); err == nil {
		t.Fatal("ignored peek failure")
	}
	if a.calls != 0 || b.calls != 0 {
		t.Fatal("partially consumed unadmitted collection")
	}
}
func TestCancelledContextPerformsNoSourceMutation(t *testing.T) {
	q, _ := queue(t)
	src := source(snapshot(t, "change", 1, "Note."))
	c := collect(t, q, map[string]Source{"change": src})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Collect(ctx, at, at.Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if src.calls != 0 {
		t.Fatal("cancelled collection consumed source")
	}
}
func TestCallerCannotReplaceConfiguredSource(t *testing.T) {
	q, _ := queue(t)
	src := source(snapshot(t, "change", 1, "Note."))
	configured := map[string]Source{"change": src}
	c := collect(t, q, configured)
	configured["change"] = source(snapshot(t, "owner", 1, "Wrong source."))
	if _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}
func TestConcurrentCollectorsOnOneCoordinatorDoNotDuplicate(t *testing.T) {
	q, _ := queue(t)
	src := source(snapshot(t, "change", 1, "Note."))
	c := collect(t, q, map[string]Source{"change": src})
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := c.Collect(context.Background(), at, at.Add(time.Hour)); errs <- err }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	all, _ := q.List()
	if len(all) != 1 || src.calls != 1 {
		t.Fatal(len(all), src.calls)
	}
}

// fileSource is a synthetic persisted source, not a production owner/change
// adapter. Its generation and acknowledgment ledger are separately durable.
type sourceState struct {
	Pending *Snapshot         `json:"pending,omitempty"`
	Done    map[uint64]string `json:"done"`
}
type fileSource struct {
	store     change.FileStore
	afterSave func()
}

func (s *fileSource) load() (sourceState, error) {
	var st sourceState
	raw, err := s.store.Load()
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(raw, &st)
	return st, err
}
func (s *fileSource) Peek(ctx context.Context) (*Snapshot, error) {
	st, err := s.load()
	return st.Pending, err
}
func (s *fileSource) Ack(ctx context.Context, snap Snapshot) error {
	st, err := s.load()
	if err != nil {
		return err
	}
	if hash, ok := st.Done[snap.Generation]; ok {
		if hash != snap.Hash {
			return ErrConflict
		}
		return nil
	}
	if st.Pending == nil || st.Pending.Generation != snap.Generation || st.Pending.Hash != snap.Hash {
		return ErrConflict
	}
	st.Done[snap.Generation] = snap.Hash
	st.Pending = nil
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err = s.store.Save(raw); err != nil {
		return err
	}
	if s.afterSave != nil {
		s.afterSave()
	}
	return nil
}

type failingFileStore struct {
	change.FileStore
	fail bool
}

func (s *failingFileStore) Save(raw []byte) error {
	if s.fail {
		return errors.New("queue bitmap write failed")
	}
	return s.FileStore.Save(raw)
}
func TestDistinctFileStoresRecoverAcrossBothReopens(t *testing.T) {
	dir := t.TempDir()
	queueStore := &failingFileStore{FileStore: change.FileStore{Path: filepath.Join(dir, "queue.json")}}
	sourceStore := change.FileStore{Path: filepath.Join(dir, "source.json")}
	initial := snapshot(t, "change", 1, "Synthetic fixed notice.")
	raw, _ := json.Marshal(sourceState{Pending: &initial, Done: map[uint64]string{}})
	if err := sourceStore.Save(raw); err != nil {
		t.Fatal(err)
	}
	q, err := New(queueStore, limits)
	if err != nil {
		t.Fatal(err)
	}
	src := &fileSource{store: sourceStore, afterSave: func() { queueStore.fail = true }}
	c := collect(t, q, map[string]Source{"change": src})
	if _, err = c.Collect(context.Background(), at, at.Add(time.Hour)); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	// Reopen both independently: source Ack is durable, queue bitmap is not.
	q2, err := New(change.FileStore{Path: queueStore.Path}, limits)
	if err != nil {
		t.Fatal(err)
	}
	source2 := &fileSource{store: change.FileStore{Path: sourceStore.Path}}
	c2 := collect(t, q2, map[string]Source{"change": source2})
	if err = c2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := q2.Get(1)
	if err != nil || !b.Acknowledged[0] {
		t.Fatal(b, err)
	}
	if next, err := c2.Collect(context.Background(), at.Add(time.Minute), at.Add(time.Hour)); err != nil || next != nil {
		t.Fatal("duplicate after persisted recovery", next, err)
	}
}

// REQ: OP-1 (W5-Db DB-6)
// Replaces W5-Da's TestCompactedExpiredBatchStillBlocksRatherThanWedgingSource:
// an expired batch no longer blocks its source; its lines are re-offered.
func TestExpiredGenerationReofferedInNewBatch(t *testing.T) {
	st := &change.MemStore{}
	q, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	src := source(snapshot(t, "change", 1, "Fixed broker notice."))
	c := collect(t, q, map[string]Source{"change": src})
	src.fail = errors.New("source down")
	if _, err = c.Collect(context.Background(), at, at.Add(time.Hour)); err == nil {
		t.Fatal("collect with a failing source ack")
	}
	src.fail = nil
	if err = q.Expire(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if old, _ := q.Get(1); old.State != Expired {
		t.Fatal(old.State)
	}
	if err = q.Compact(); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Get(1); err != nil {
		t.Fatal("expired batch the ledger points to was compacted:", err)
	}
	b, err := c.Collect(context.Background(), at.Add(time.Hour), at.Add(2*time.Hour))
	if err != nil || b == nil || b.ID == 1 || b.State != Ready || !b.Acknowledged[0] || b.Snapshots[0].Lines[0] != "Fixed broker notice." {
		t.Fatal(b, err)
	}
	if src.pending != nil {
		t.Fatal("re-offered generation not consumed")
	}
	if _, err = New(st, limits); err != nil {
		t.Fatal("re-offer left an invalid state:", err)
	}
	if again, err := c.Collect(context.Background(), at.Add(time.Hour), at.Add(2*time.Hour)); err != nil || again != nil {
		t.Fatal("duplicate after re-offer", again, err)
	}
}

// REQ: OP-2
func TestFullQueueLeavesSourcePendingUnacknowledged(t *testing.T) {
	small := limits
	small.MaxBatches = 1
	q, err := New(&change.MemStore{}, small)
	if err != nil {
		t.Fatal(err)
	}
	full := enqueue(t, q, "owner", 1)
	ack(t, q, full)
	src := source(snapshot(t, "change", 1, "Fixed broker notice."))
	c := collect(t, q, map[string]Source{"change": src})
	if _, err = c.Collect(context.Background(), at, at.Add(time.Hour)); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	batches, _ := q.List()
	if src.calls != 0 || src.pending == nil || src.pending.Generation != 1 || len(batches) != 1 {
		t.Fatal(src.calls, src.pending, len(batches))
	}
}
