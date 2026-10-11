package digestqueue

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// later is when the next batch is made: past every fixture batch's expiry.
var later = at.Add(3 * time.Hour)

// unknownBatch admits one snapshot of source at gen, sends it and records an
// unknown outcome, so the batch can never be sent again.
func unknownBatch(t *testing.T, q *Queue, source string, gen uint64, line string) Batch {
	t.Helper()
	b, err := q.Enqueue([]Snapshot{snap(t, source, gen, line, "task-1")}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := start(t, q, b)
	if err = q.finish(s.ID, s.Attempts, OutcomeUnknown, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Get(b.ID)
	return got
}

// lateBatch admits one snapshot, consumes its source and re-arms it once with
// Late until until; once until passes it is held again for good.
func lateBatch(t *testing.T, q *Queue, source string, gen uint64, until time.Time) Batch {
	t.Helper()
	b, err := q.Enqueue([]Snapshot{snap(t, source, gen, "Late line.", "task-1")}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ack(t, q, b)
	if err = q.Late(b.ID, at.Add(time.Hour), until); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Get(b.ID)
	return got
}

func ids(t *testing.T, q *Queue) []uint64 {
	t.Helper()
	bs, err := q.List()
	if err != nil {
		t.Fatal(err)
	}
	var out []uint64
	for _, b := range bs {
		out = append(out, b.ID)
	}
	return out
}

func sized(n int) Limits { l := limits; l.MaxBatches, l.MaxSources = n, 256; return l }

func open(t *testing.T, l Limits) (*Queue, *change.MemStore) {
	t.Helper()
	st := &change.MemStore{}
	q, err := New(st, l)
	if err != nil {
		t.Fatal(err)
	}
	return q, st
}

// A queue full of batches that can never be sent again still takes today's
// digest: the oldest dead batch makes room, the others stay as they are.
// REQ: CH-15 (W5-Dc-r9 QC-1)
func TestFullQueueOfDeadBatchesAdmits(t *testing.T) {
	for _, kind := range []string{"unknown", "late", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			q, _ := open(t, sized(128))
			for i := uint64(1); i <= 128; i++ {
				src := fmt.Sprintf("s%d", i)
				if kind == "unknown" || (kind == "mixed" && i%2 == 1) {
					unknownBatch(t, q, src, 1, "Unknown line.")
				} else {
					lateBatch(t, q, src, 1, at.Add(2*time.Hour))
				}
			}
			before, _ := q.List()
			b, err := q.Enqueue([]Snapshot{snap(t, "today", 1, "Today line.")}, later, later.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			after, _ := q.List()
			if len(after) != 128 || after[0].ID != 2 || after[127].ID != b.ID || b.ID != 129 {
				t.Fatal("oldest dead batch not the one evicted", ids(t, q))
			}
			for i, a := range after[:127] {
				if a.State != before[i+1].State || a.Late != before[i+1].Late || a.Attempts != before[i+1].Attempts {
					t.Fatal("a kept batch changed", a, before[i+1])
				}
			}
		})
	}
}

// With room left nothing is evicted, so every dead batch keeps its STATUS
// line and its digest line while it can.
// REQ: OP-9 (W5-Dc-r9 QC-2)
func TestDeadBatchesStayWhileThereIsRoom(t *testing.T) {
	q, _ := open(t, sized(4))
	unknownBatch(t, q, "a", 1, "Unknown line.")
	lateBatch(t, q, "b", 1, at.Add(2*time.Hour))
	unknownBatch(t, q, "c", 1, "Unknown line.")
	if _, err := q.Enqueue([]Snapshot{snap(t, "today", 1, "Today line.")}, later, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, q); !slices.Equal(got, []uint64{1, 2, 3, 4}) {
		t.Fatal("evicted with room left", got)
	}
}

// Only dead batches are evicted, oldest first; a queue whose other batches
// may still be sent or are still owed is full, and nothing changes.
// REQ: OP-9 (W5-Dc-r9 QC-2)
func TestLiveBatchesAreNeverEvicted(t *testing.T) {
	q, st := open(t, sized(6))
	// Ready and past expiry with one source consumed: held, not yet late.
	if _, err := q.Enqueue([]Snapshot{snap(t, "a", 1, "Held line."), snap(t, "a2", 1, "Other line.")}, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.Acknowledge(1, "a", 1, snap(t, "a", 1, "Held line.").Hash); err != nil {
		t.Fatal(err)
	}
	start(t, q, enqueue(t, q, "b", 1))                                                                            // Sending.
	lateBatch(t, q, "c", 1, later.Add(time.Hour))                                                                 // Late, not yet past its new expiry.
	if _, err := q.Enqueue([]Snapshot{snap(t, "d", 1, "Fresh line.")}, later, later.Add(time.Hour)); err != nil { // Ready.
		t.Fatal(err)
	}
	// Late and sending when its new expiry passes: still in flight.
	f := lateBatch(t, q, "f", 1, at.Add(2*time.Hour))
	if _, err := q.begin(f.ID, at.Add(90*time.Minute)); err != nil {
		t.Fatal(err)
	}
	unknownBatch(t, q, "e", 1, "Unknown line.")
	fresh := func() error {
		_, err := q.Enqueue([]Snapshot{snap(t, "today", 1, "Today line.")}, later, later.Add(time.Hour))
		return err
	}
	if err := fresh(); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, q); !slices.Equal(got, []uint64{1, 2, 3, 4, 5, 7}) {
		t.Fatal("not the dead batch evicted", got)
	}
	raw, _ := st.Load()
	_, err := q.Enqueue([]Snapshot{snap(t, "tomorrow", 1, "Tomorrow line.")}, later, later.Add(time.Hour))
	if !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if after, _ := st.Load(); string(after) != string(raw) {
		t.Fatal("a refused admission changed the store")
	}
}

// An evicted batch leaves no text, keeps its ledger entry and the sequence,
// and its exact snapshot is refused if offered again: never revived or resent.
// REQ: CAP-3 (W5-Dc-r9 QC-3)
func TestEvictedBatchIsNeverRevived(t *testing.T) {
	q, st := open(t, sized(2))
	gone := unknownBatch(t, q, "change", 1, "Evicted line.")
	if err := q.Forget("task-1"); err != nil { // Redacted Unknown batches are evicted too.
		t.Fatal(err)
	}
	lateBatch(t, q, "owner", 1, at.Add(2*time.Hour))
	unknownBatch(t, q, "mail", 1, "Third line.")
	if got := ids(t, q); !slices.Equal(got, []uint64{2, 3}) {
		t.Fatal(got)
	}
	_, err := q.Enqueue([]Snapshot{snap(t, "today", 1, "Today line.")}, later, later.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(t, q); !slices.Equal(got, []uint64{3, 4}) {
		t.Fatal(got)
	}
	raw, _ := st.Load()
	for _, s := range []string{"Evicted line.", "Late line."} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("%q still stored", s)
		}
	}
	if _, err = q.Enqueue([]Snapshot{snap(t, "owner", 1, "Late line.", "task-1")}, later, later.Add(time.Hour)); !errors.Is(err, ErrRetired) {
		t.Fatal("evicted held batch re-admitted", err)
	}
	if _, err = q.Enqueue(gone.Snapshots, later, later.Add(time.Hour)); err == nil {
		t.Fatal("evicted unknown batch re-admitted")
	}
	q2, err := New(st, sized(2))
	if err != nil {
		t.Fatal(err)
	}
	b, err := q2.Enqueue([]Snapshot{snap(t, "tomorrow", 1, "Tomorrow line.")}, later, later.Add(time.Hour))
	if err != nil || b.ID != 5 {
		t.Fatal("sequence rewound", b.ID, err)
	}
	if got := ids(t, q2); !slices.Equal(got, []uint64{4, 5}) {
		t.Fatal(got)
	}
}

// The byte bound evicts dead batches too, and refuses once none are left.
// REQ: CH-15 (W5-Dc-r9 QC-4)
func TestByteBoundEvictsDeadBatches(t *testing.T) {
	small := sized(8)
	small.MaxBytes = 2400
	q, st := open(t, small)
	long := func(c byte) string { return strings.Repeat(string(c), 600) }
	unknownBatch(t, q, "a", 1, long('a'))
	unknownBatch(t, q, "b", 1, long('b'))
	if _, err := q.Enqueue([]Snapshot{snap(t, "c", 1, long('c'))}, later, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, q); len(got) >= 3 || got[len(got)-1] != 3 {
		t.Fatal("byte bound not met by eviction", got)
	}
	if _, err := q.Enqueue([]Snapshot{snap(t, "d", 1, long('d'))}, later, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := ids(t, q); !slices.Equal(got, []uint64{3, 4}) {
		t.Fatal(got)
	}
	raw, _ := st.Load()
	if _, err := q.Enqueue([]Snapshot{snap(t, "e", 1, long('e'))}, later, later.Add(time.Hour)); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if after, _ := st.Load(); string(after) != string(raw) {
		t.Fatal("a refused admission changed the store")
	}
}
