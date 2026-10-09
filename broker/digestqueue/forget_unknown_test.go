package digestqueue

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// unknownWith enqueues a two-snapshot batch, sends it and records an unknown
// outcome with evidence, so the batch is Unknown and holds "task-1" and "note-1".
func unknownWith(t *testing.T, q *Queue) Batch {
	t.Helper()
	b, err := q.Enqueue([]Snapshot{snap(t, "change", 1, "Forgotten change line.", "task-1"), snap(t, "owner", 1, "Kept owner line.", "note-1")}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s := start(t, q, b)
	if err = q.finish(s.ID, s.Attempts, OutcomeUnknown, "lost-1"); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Get(s.ID)
	return got
}

// forgetUnknown is UF-1's forget of one reference an Unknown batch holds.
func forgetUnknown(t *testing.T) (*Queue, *change.MemStore, Batch) {
	t.Helper()
	q, st := queue(t)
	b := unknownWith(t, q)
	if err := q.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	return q, st, b
}

func redactedUnknown(t *testing.T, q *Queue, was Batch) {
	t.Helper()
	got, err := q.Get(was.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Unknown || !got.Redacted || len(got.Snapshots) != 0 || len(got.Acknowledged) != 0 {
		t.Fatal("unknown batch not redacted whole", got)
	}
	if got.Attempts != was.Attempts || !got.Created.Equal(was.Created) || !got.Expires.Equal(was.Expires) || got.Evidence != was.Evidence || got.Late != was.Late {
		t.Fatal("redaction changed the batch's state or evidence", got, was)
	}
}

// REQ: CAP-3 (W5-Dc-r7 UF-1)
func TestForgetRedactsAnUnknownBatch(t *testing.T) {
	q, st, was := forgetUnknown(t)
	redactedUnknown(t, q, was)
	raw, _ := st.Load()
	for _, s := range []string{"Forgotten change line.", "task-1", "Kept owner line.", "note-1"} {
		if contains(raw, []byte(s)) {
			t.Fatalf("%q still in the store after the forget", s)
		}
	}
	if !contains(raw, []byte("lost-1")) {
		t.Fatal("evidence dropped")
	}
	if err := q.Forget("task-1"); err != nil {
		t.Fatal("repeat forget", err)
	}
}

// REQ: CAP-3 (W5-Dc-r7 UF-1)
func TestForgetStillRefusesWhileSending(t *testing.T) {
	q, st := queue(t)
	unknown := unknownWith(t, q)
	sending := start(t, q, enqueue(t, q, "mail", 1))
	before, _ := st.Load()
	if err := q.Forget("task-1"); !errors.Is(err, ErrInFlight) {
		t.Fatal(err)
	}
	after, _ := st.Load()
	if string(before) != string(after) {
		t.Fatal("refused forget changed the store")
	}
	if got, _ := q.Get(unknown.ID); got.Redacted || len(got.Snapshots) != 2 {
		t.Fatal("unknown batch redacted by a refused forget", got)
	}
	if got, _ := q.Get(sending.ID); got.State != Sending || got.Redacted {
		t.Fatal("sending batch changed", got)
	}
}

// REQ: CAP-3 (W5-Dc-r7 UF-2)
func TestRedactedUnknownSurvivesReopenAndCompact(t *testing.T) {
	q, st, was := forgetUnknown(t)
	if err := q.Compact(); err != nil {
		t.Fatal(err)
	}
	redactedUnknown(t, q, was)
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal("reopen refused the redacted unknown batch", err)
	}
	redactedUnknown(t, q2, was)
	if err = validate(q2.st, limits); err != nil {
		t.Fatal(err)
	}
	if _, err = q2.begin(was.ID, at); !errors.Is(err, ErrState) {
		t.Fatal("redacted unknown batch resent", err)
	}
}

// REQ: CAP-3 (W5-Dc-r7 UF-2)
func TestFinishRefusesARedactedUnknownBatch(t *testing.T) {
	q, st, was := forgetUnknown(t)
	before, _ := st.Load()
	for _, o := range []Outcome{NotSent, OutcomeUnknown, TransportAccepted} {
		if err := q.finish(was.ID, was.Attempts, o, "late-1"); !errors.Is(err, ErrState) {
			t.Fatal(o, err)
		}
	}
	after, _ := st.Load()
	if string(before) != string(after) {
		t.Fatal("refused finish changed the store")
	}
	redactedUnknown(t, q, was)
	if _, err := q.Enqueue([]Snapshot{snap(t, "mail", 1, "Next line.", "mail-1")}, at, at.Add(time.Hour)); err != nil {
		t.Fatal("queue broken after refused finish", err)
	}
}

// REQ: CAP-3 (W5-Dc-r7 UF-2)
func TestReofferOfARedactedUnknownGenerationConflicts(t *testing.T) {
	q, _, _ := forgetUnknown(t)
	if _, err := q.Enqueue([]Snapshot{snap(t, "change", 1, "Forgotten change line.", "task-1")}, at, at.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatal("forgotten generation re-admitted from an unknown batch", err)
	}
	if _, err := q.Enqueue([]Snapshot{snap(t, "change", 2, "Next change line.", "task-2")}, at, at.Add(time.Hour)); err != nil {
		t.Fatal("higher generation refused", err)
	}
}
