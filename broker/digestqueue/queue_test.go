package digestqueue

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

var at = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
var limits = Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20}

func snapshot(t *testing.T, source string, gen uint64, text string) Snapshot {
	t.Helper()
	s, err := NewSnapshot(source, gen, []string{text}, []string{"task-1"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func queue(t *testing.T) (*Queue, *change.MemStore) {
	t.Helper()
	st := &change.MemStore{}
	q, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	return q, st
}
func enqueue(t *testing.T, q *Queue, source string, gen uint64) Batch {
	t.Helper()
	b, err := q.Enqueue([]Snapshot{snapshot(t, source, gen, "Fixed broker notice.")}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func ack(t *testing.T, q *Queue, b Batch) {
	t.Helper()
	for _, s := range b.Snapshots {
		if err := q.Acknowledge(b.ID, s.Source, s.Generation, s.Hash); err != nil {
			t.Fatal(err)
		}
	}
}
func start(t *testing.T, q *Queue, b Batch) Batch {
	t.Helper()
	ack(t, q, b)
	v, err := q.Begin(b.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// REQ: OP-1
func TestEnqueueIsDurableAndIdempotent(t *testing.T) {
	q, st := queue(t)
	b := enqueue(t, q, "change", 1)
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	again := enqueue(t, q2, "change", 1)
	if b.ID != again.ID {
		t.Fatal("duplicate batch")
	}
	s := snapshot(t, "change", 1, "Different notice.")
	if _, err = q2.Enqueue([]Snapshot{s}, at, at.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}
func TestSaveFailureNeverReturnsQueueAdmission(t *testing.T) {
	q, st := queue(t)
	st.Fail = errors.New("save denied")
	if _, err := q.Enqueue([]Snapshot{snapshot(t, "change", 1, "Notice.")}, at, at.Add(time.Hour)); err == nil {
		t.Fatal("admitted failed save")
	}
	st.Fail = nil
	if _, err := q.Enqueue([]Snapshot{snapshot(t, "change", 1, "Notice.")}, at, at.Add(time.Hour)); !errors.Is(err, ErrRecovery) {
		t.Fatal("did not quarantine uncertain store", err)
	}
	recovered, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	enqueue(t, recovered, "change", 1)
}
func TestOnlyExactSourceAcknowledgmentsAllowDispatch(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	if _, err := q.Begin(b.ID, at); !errors.Is(err, ErrUnacknowledged) {
		t.Fatal(err)
	}
	s := b.Snapshots[0]
	if err := q.Acknowledge(b.ID, s.Source, s.Generation, "wrong"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	ack(t, q, b)
	ack(t, q, b)
	if _, err := q.Begin(b.ID, at); err != nil {
		t.Fatal(err)
	}
}
func TestAllSourcesMustBeAcknowledged(t *testing.T) {
	q, _ := queue(t)
	b, err := q.Enqueue([]Snapshot{snapshot(t, "owner", 1, "Owner note."), snapshot(t, "change", 1, "Change note.")}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := b.Snapshots[0]
	if err = q.Acknowledge(b.ID, s.Source, s.Generation, s.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Begin(b.ID, at); !errors.Is(err, ErrUnacknowledged) {
		t.Fatal(err)
	}
	ack(t, q, b)
	if _, err = q.Begin(b.ID, at); err != nil {
		t.Fatal(err)
	}
}
func TestNewGenerationDoesNotChangeOlderAcknowledgment(t *testing.T) {
	q, _ := queue(t)
	old := enqueue(t, q, "change", 1)
	newer := enqueue(t, q, "change", 2)
	ack(t, q, old)
	v, err := q.Get(newer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.Acknowledged[0] {
		t.Fatal("older ack consumed newer source")
	}
}

// REQ: OP-2
func TestRestartOfSendingIsUnknownAndNeverRedispatched(t *testing.T) {
	q, st := queue(t)
	b := start(t, q, enqueue(t, q, "change", 1))
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := q2.Get(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Unknown {
		t.Fatal(got.State)
	}
	if _, err = q2.Begin(b.ID, at); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if err = q2.Expire(at.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = q2.Get(b.ID)
	if got.State != Unknown {
		t.Fatal("expiry hid unresolved send")
	}
}
func TestUnknownRequiresExplicitNotSentEvidenceBeforeRetry(t *testing.T) {
	q, _ := queue(t)
	b := start(t, q, enqueue(t, q, "change", 1))
	if err := q.Finish(b.ID, b.Attempts, OutcomeUnknown, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Begin(b.ID, at); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	if err := q.Finish(b.ID, b.Attempts, NotSent, ""); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty evidence enabled retry", err)
	}
	if err := q.Finish(b.ID, b.Attempts, NotSent, "adapter-proof-1"); err != nil {
		t.Fatal(err)
	}
	retry, err := q.Begin(b.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Attempts != 2 {
		t.Fatal(retry.Attempts)
	}
	if err = q.Finish(b.ID, b.Attempts, TransportAccepted, "stale-receipt"); !errors.Is(err, ErrState) {
		t.Fatal("old attempt resolved new send", err)
	}
}
func TestAcceptedIsTerminalAndDoesNotClaimVisibility(t *testing.T) {
	q, st := queue(t)
	b := start(t, q, enqueue(t, q, "change", 1))
	if err := q.Finish(b.ID, b.Attempts, TransportAccepted, "transport-1"); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if got.State != Accepted {
		t.Fatal(got.State)
	}
	if _, err = q2.Begin(b.ID, at); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if _, ok := fields["owner_visible"]; ok {
		t.Fatal("manufactured visibility")
	}
}
func TestRetryLimitPersists(t *testing.T) {
	q, st := queue(t)
	b := start(t, q, enqueue(t, q, "change", 1))
	if err := q.Finish(b.ID, 1, NotSent, "not-sent-1"); err != nil {
		t.Fatal(err)
	}
	b, err := q.Begin(b.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Finish(b.ID, b.Attempts, NotSent, "not-sent-2"); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if got.State != Failed {
		t.Fatal(got.State)
	}
	if _, err = q2.Begin(b.ID, at); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
}
func TestCapacityLeavesNewSourcesUnacknowledged(t *testing.T) {
	st := &change.MemStore{}
	small := limits
	small.MaxBatches = 1
	q, err := New(st, small)
	if err != nil {
		t.Fatal(err)
	}
	enqueue(t, q, "change", 1)
	if _, err = q.Enqueue([]Snapshot{snapshot(t, "owner", 1, "Owner note.")}, at, at.Add(time.Hour)); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	raw, _ := st.Load()
	if string(raw) == "" {
		t.Fatal("existing state gone")
	}
}
func TestSourceLedgerBound(t *testing.T) {
	small := limits
	small.MaxSources = 1
	q, err := New(&change.MemStore{}, small)
	if err != nil {
		t.Fatal(err)
	}
	enqueue(t, q, "change", 1)
	if _, err = q.Enqueue([]Snapshot{snapshot(t, "owner", 1, "Owner note.")}, at, at.Add(time.Hour)); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
}
func TestExpiryPreventsSending(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	if _, err := q.Begin(b.ID, at.Add(time.Hour)); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if err := q.Expire(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Get(b.ID)
	if got.State != Expired {
		t.Fatal(got.State)
	}
}
func TestForgetPurgesPendingPayload(t *testing.T) {
	q, st := queue(t)
	b := enqueue(t, q, "change", 1)
	if err := q.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if got.State != Cancelled || len(got.Snapshots) != 0 {
		t.Fatal(got)
	}
	if _, err = q2.Begin(b.ID, at); !errors.Is(err, ErrState) {
		t.Fatal(err)
	}
	raw, _ := st.Load()
	if contains(raw, []byte("Fixed broker notice.")) || contains(raw, []byte("task-1")) {
		t.Fatal("forgotten text persisted")
	}
}
func TestForgetFailsBeforeMutatingAnyInFlightReference(t *testing.T) {
	q, _ := queue(t)
	pending := enqueue(t, q, "change", 1)
	start(t, q, enqueue(t, q, "owner", 1))
	if err := q.Forget("task-1"); !errors.Is(err, ErrInFlight) {
		t.Fatal(err)
	}
	got, _ := q.Get(pending.ID)
	if got.State != Ready {
		t.Fatal("partial forget", got.State)
	}
}
func TestCompactionKeepsDedupeAndSequence(t *testing.T) {
	q, st := queue(t)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	started, _ := q.Begin(b.ID, at)
	if err := q.Finish(b.ID, started.Attempts, TransportAccepted, "receipt-1"); err != nil {
		t.Fatal(err)
	}
	if err := q.Compact(); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q2.Enqueue([]Snapshot{snapshot(t, "change", 1, "Fixed broker notice.")}, at, at.Add(time.Hour)); !errors.Is(err, ErrRetired) {
		t.Fatal("resurrected compacted generation", err)
	}
	next := enqueue(t, q2, "change", 2)
	if next.ID <= b.ID {
		t.Fatal("sequence reused")
	}
}
func TestSnapshotsAndReadsAreOwnedCopies(t *testing.T) {
	q, _ := queue(t)
	s := snapshot(t, "change", 1, "Notice.")
	b, err := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.Lines[0] = "corrupted"
	b.Snapshots[0].Lines[0] = "corrupted"
	got, _ := q.Get(b.ID)
	if got.Snapshots[0].Lines[0] != "Notice." {
		t.Fatal("caller mutated queue")
	}
}
func TestConcurrentCollectionCreatesOneBatch(t *testing.T) {
	q, _ := queue(t)
	s := snapshot(t, "change", 1, "Notice.")
	var wg sync.WaitGroup
	ids := make(chan uint64, 20)
	errs := make(chan error, 20)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour))
			if err != nil {
				errs <- err
			} else {
				ids <- b.ID
			}
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for id := range ids {
		if id != 1 {
			t.Fatal(id)
		}
	}
}
func TestTamperedSnapshotRejected(t *testing.T) {
	q, _ := queue(t)
	s := snapshot(t, "change", 1, "Notice.")
	s.Lines[0] = "Different notice."
	if _, err := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
func TestMixedDuplicateAndNewAssociationsRejected(t *testing.T) {
	q, _ := queue(t)
	b := enqueue(t, q, "change", 1)
	s := snapshot(t, "owner", 1, "New notice.")
	if _, err := q.Enqueue(append(b.Snapshots, s), at, at.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}
func TestInvalidParametersRejected(t *testing.T) {
	for _, l := range []Limits{{}, {MaxBatches: 1, MaxSources: 1, MaxAttempts: 0, MaxBytes: 1000}} {
		if _, err := New(&change.MemStore{}, l); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	q, _ := queue(t)
	for _, s := range []Snapshot{{}, {Source: "../source", Generation: 1}, {Source: "source", Generation: 0}} {
		if _, err := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour)); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if _, err := q.Enqueue([]Snapshot{snapshot(t, "change", 1, "Notice.")}, at, at); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
func TestMalformedAndOldStateFailClosed(t *testing.T) {
	for _, raw := range []string{"{", `{"schema":0}`, `{"schema":1,"unexpected":true}`} {
		st := &change.MemStore{}
		_ = st.Save([]byte(raw))
		if _, err := New(st, limits); err == nil {
			t.Fatal(raw)
		}
	}
	q, st := queue(t)
	enqueue(t, q, "change", 1)
	changed := limits
	changed.MaxAttempts = 3
	if _, err := New(st, changed); !errors.Is(err, ErrInvalid) {
		t.Fatal("policy changed on reopen", err)
	}
}
func TestRestartRecoverySaveFailureRefusesOpen(t *testing.T) {
	q, st := queue(t)
	start(t, q, enqueue(t, q, "change", 1))
	st.Fail = errors.New("disk full")
	if _, err := New(st, limits); err == nil {
		t.Fatal("recovery not durable")
	}
}
func TestByteLimit(t *testing.T) {
	small := limits
	small.MaxBytes = 600
	q, err := New(&change.MemStore{}, small)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Enqueue([]Snapshot{snapshot(t, "change", 1, fmt.Sprintf("%0500d", 1))}, at, at.Add(time.Hour)); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
}
func contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

// commitErrorStore models rename succeeding before the directory sync fails.
// Load sees the replacement, but the caller cannot claim durable admission.
type commitErrorStore struct {
	change.MemStore
	fail  bool
	saves int
}

func (s *commitErrorStore) Save(b []byte) error {
	s.saves++
	if err := s.MemStore.Save(b); err != nil {
		return err
	}
	if s.fail {
		return errors.New("directory sync failed after rename")
	}
	return nil
}
func TestPostCommitErrorQuarantinesUntilDurableReopen(t *testing.T) {
	st := &commitErrorStore{}
	q, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	st.fail = true
	if _, err = q.Enqueue([]Snapshot{snapshot(t, "change", 1, "Notice.")}, at, at.Add(time.Hour)); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	if _, err = q.List(); !errors.Is(err, ErrRecovery) {
		t.Fatal("read allowed uncertain store", err)
	}
	if _, err = New(st, limits); !errors.Is(err, ErrRecovery) {
		t.Fatal("reopen did not reestablish durable state", err)
	}
	st.fail = false
	before := st.saves
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	if st.saves != before+1 {
		t.Fatal("reopen did not sync observed state")
	}
	b, err := q2.Enqueue([]Snapshot{snapshot(t, "change", 1, "Notice.")}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != 1 {
		t.Fatal("second batch created")
	}
}
func TestInvalidPersistedStatesRejected(t *testing.T) {
	q, st := queue(t)
	enqueue(t, q, "change", 1)
	raw, _ := st.Load()
	mutations := map[string]func(*state){
		"duplicate batch":     func(s *state) { s.Batches = append(s.Batches, s.Batches[0]) },
		"invalid state":       func(s *state) { s.Batches[0].State = "delivered" },
		"unacknowledged send": func(s *state) { s.Batches[0].State = Sending; s.Batches[0].Attempts = 1 },
		"missing latest":      func(s *state) { delete(s.Latest, "change") },
		"changed source text": func(s *state) { s.Batches[0].Snapshots[0].Lines[0] = "changed" },
		"redacted ready": func(s *state) {
			s.Batches[0].Redacted = true
			s.Batches[0].Snapshots = nil
			s.Batches[0].Acknowledged = nil
		},
		"sequence rollback": func(s *state) { s.Seq = 0 },
		"attempt limit":     func(s *state) { s.Batches[0].Attempts = limits.MaxAttempts + 1 },
	}
	for label, mutate := range mutations {
		t.Run(label, func(t *testing.T) {
			var s state
			_ = json.Unmarshal(raw, &s)
			mutate(&s)
			b, _ := json.Marshal(s)
			bad := &change.MemStore{}
			_ = bad.Save(b)
			if _, err := New(bad, limits); err == nil {
				t.Fatal("corrupt state opened")
			}
		})
	}
	for _, suffix := range []string{`{}`, ` true`} {
		bad := &change.MemStore{}
		_ = bad.Save(append(append([]byte(nil), raw...), []byte(suffix)...))
		if _, err := New(bad, limits); err == nil {
			t.Fatal("trailing JSON accepted")
		}
	}
}
func FuzzLoadState(f *testing.F) {
	f.Add([]byte(`{"schema":0}`))
	f.Add([]byte("{"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			t.Skip()
		}
		st := &change.MemStore{}
		_ = st.Save(raw)
		q, err := New(st, limits)
		if err == nil {
			if _, err = q.List(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestExistingFileStoreRestartsWithPrivateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "digest.json")
	store := change.FileStore{Path: path}
	q, err := New(store, limits)
	if err != nil {
		t.Fatal(err)
	}
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	started, err := q.Begin(b.ID, at)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := New(store, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := q2.Get(b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Unknown || got.Attempts != started.Attempts {
		t.Fatal(got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}
