package digestqueue

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

func snap(t *testing.T, source string, gen uint64, line string, refs ...string) Snapshot {
	t.Helper()
	s, err := NewSnapshot(source, gen, []string{line}, refs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// held enqueues a two-source batch, consumes only its first source, and
// leaves it past expiry: Expire keeps it ready and Held reports it.
func held(t *testing.T, q *Queue, change, owner Snapshot) Batch {
	t.Helper()
	b, err := q.Enqueue([]Snapshot{change, owner}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Acknowledge(b.ID, change.Source, change.Generation, change.Hash); err != nil {
		t.Fatal(err)
	}
	if err = q.Expire(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	h, err := q.Held(at.Add(time.Hour))
	if err != nil || !slices.ContainsFunc(h, func(v Batch) bool { return v.ID == b.ID }) {
		t.Fatal(h, err)
	}
	return b
}

// REQ: OP-2 (W5-Db DB-4)
func TestRecoverFinishesHeldBatch(t *testing.T) {
	q, st := queue(t)
	ch := snap(t, "change", 1, "Change line.", "task-1")
	ow := snap(t, "owner", 1, "Owner line.", "note-1")
	chSrc, owSrc := source(ch), source(ow)
	chSrc.pending, chSrc.acknowledged[1] = nil, ch.Hash
	b := held(t, q, ch, ow)
	c := collect(t, q, map[string]Source{"change": chSrc, "owner": owSrc})
	if err := c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if owSrc.calls != 1 || owSrc.pending != nil {
		t.Fatal("held batch's remaining source not acknowledged", owSrc.calls)
	}
	now := at.Add(time.Hour)
	if err := q.Late(b.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var rendered Batch
	tr := &fakeTransport{outcome: TransportAccepted, evidence: "item-1"}
	s, _ := NewSender(q, tr, func(v Batch) (string, error) { rendered = v; return "Late digest.", nil }, fixedNow(now))
	if o, err := s.Send(context.Background(), b.ID); err != nil || o != TransportAccepted {
		t.Fatal(o, err)
	}
	if !rendered.Late || len(rendered.Snapshots) != 2 {
		t.Fatal("render did not see the late batch", rendered)
	}
	if _, err := New(st, limits); err != nil {
		t.Fatal(err)
	}
}

// REQ: OP-2 (W5-Db DB-4)
func TestLateRearmsHeldOnce(t *testing.T) {
	q, st := queue(t)
	b := enqueue(t, q, "change", 1)
	ack(t, q, b)
	now := at.Add(time.Hour)
	if _, err := q.begin(b.ID, now); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if err := q.Late(b.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if !got.Late || !got.Expires.Equal(now.Add(time.Hour)) || got.State != Ready || got.Attempts != 0 {
		t.Fatal("late not persisted", got)
	}
	// Not sent before the new expiry: held again, never re-armed, never expired.
	again := now.Add(time.Hour)
	if err = q2.Expire(again); err != nil {
		t.Fatal(err)
	}
	h, _ := q2.Held(again)
	if len(h) != 1 || h[0].ID != b.ID || !h[0].Late {
		t.Fatal("late batch not held again", h)
	}
	if err = q2.Late(b.ID, again, again.Add(time.Hour)); !errors.Is(err, ErrState) {
		t.Fatal("late twice", err)
	}
	if _, err = q2.begin(b.ID, again); !errors.Is(err, ErrExpired) {
		t.Fatal("begin's expiry check relaxed", err)
	}
}

// REQ: OP-2 (W5-Db DB-4)
func TestLateRefusedOnFreshOrLateBatch(t *testing.T) {
	q, _ := queue(t)
	now := at.Add(time.Hour)
	fresh := enqueue(t, q, "change", 1)
	ack(t, q, fresh)
	if err := q.Late(fresh.ID, at, now); !errors.Is(err, ErrState) {
		t.Fatal("fresh", err)
	}
	partial := held(t, q, snap(t, "owner", 1, "Owner line."), snap(t, "question", 1, "Question line."))
	if err := q.Late(partial.ID, now, now.Add(time.Hour)); !errors.Is(err, ErrState) {
		t.Fatal("unacknowledged", err)
	}
	if err := q.Late(fresh.ID, now, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("expiry not after now", err)
	}
	if err := q.Late(fresh.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.Late(fresh.ID, now, now.Add(2*time.Hour)); !errors.Is(err, ErrState) {
		t.Fatal("late", err)
	}
	sent := enqueue(t, q, "mail", 1)
	b := start(t, q, sent)
	if err := q.finish(b.ID, b.Attempts, TransportAccepted, "item-1"); err != nil {
		t.Fatal(err)
	}
	if err := q.Late(sent.ID, now, now.Add(time.Hour)); !errors.Is(err, ErrState) {
		t.Fatal("accepted", err)
	}
	if err := q.Late(99, now, now.Add(time.Hour)); !errors.Is(err, ErrMissing) {
		t.Fatal("missing", err)
	}
}

// REQ: OP-2 (W5-Db DB-5)
func TestForgetRemovesOnlyMatchingSnapshots(t *testing.T) {
	q, st := queue(t)
	ch := snap(t, "change", 1, "Forgotten change line.", "task-1")
	ow := snap(t, "owner", 1, "Kept owner line.", "note-1")
	b, err := q.Enqueue([]Snapshot{ch, ow}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Acknowledge(b.ID, ow.Source, ow.Generation, ow.Hash); err != nil {
		t.Fatal(err)
	}
	accepted := snap(t, "mail", 1, "Sent mail line.", "task-1")
	a, _ := q.Enqueue([]Snapshot{accepted}, at, at.Add(time.Hour))
	a = start(t, q, a)
	if err = q.finish(a.ID, a.Attempts, TransportAccepted, "item-1"); err != nil {
		t.Fatal(err)
	}
	if err = q.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := q2.Get(b.ID)
	if got.State != Ready || got.Redacted || len(got.Snapshots) != 1 || got.Snapshots[0].Source != "owner" || len(got.Acknowledged) != 1 || !got.Acknowledged[0] {
		t.Fatal(got)
	}
	if done, _ := q2.Get(a.ID); done.State != Accepted || !done.Redacted || done.Evidence != "item-1" {
		t.Fatal("accepted batch not redacted whole", done)
	}
	raw, _ := st.Load()
	if contains(raw, []byte("Forgotten change line.")) || contains(raw, []byte("Sent mail line.")) || contains(raw, []byte("task-1")) {
		t.Fatal("forgotten text persisted")
	}
	if !contains(raw, []byte("Kept owner line.")) {
		t.Fatal("unaffected line lost")
	}
	if v, err := q2.begin(b.ID, at); err != nil || len(v.Snapshots) != 1 {
		t.Fatal("remaining snapshot not sendable", v, err)
	}
}

// REQ: OP-1 (W5-Db DB-5)
func TestForgetKeepsUnaffectedSourceCollectable(t *testing.T) {
	q, _ := queue(t)
	ch := snap(t, "change", 1, "Change line.", "task-1")
	ow := snap(t, "owner", 1, "Owner line.", "note-1")
	chSrc, owSrc := source(ch), source(ow)
	c := collect(t, q, map[string]Source{"change": chSrc, "owner": owSrc})
	if _, err := q.Enqueue([]Snapshot{ch, ow}, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	// Source-side duty: drop the forgotten reference; never re-offer it.
	chSrc.pending = nil
	if b, err := c.Collect(context.Background(), at, at.Add(time.Hour)); err != nil || b != nil {
		t.Fatal("unaffected source wedged by forget", b, err)
	}
	if owSrc.pending != nil {
		t.Fatal("unaffected generation not consumed")
	}
	owSrc.pending = &[]Snapshot{snap(t, "owner", 2, "Later owner line.")}[0]
	b, err := c.Collect(context.Background(), at, at.Add(time.Hour))
	if err != nil || b == nil || b.Snapshots[0].Generation != 2 {
		t.Fatal("later collect failed", b, err)
	}
}

// REQ: OP-2 (W5-Db DB-5)
func TestForgetLastSnapshotCancels(t *testing.T) {
	q, st := queue(t)
	ready := enqueue(t, q, "change", 1)
	expired, _ := q.Enqueue([]Snapshot{snap(t, "owner", 1, "Owner line.", "task-1")}, at, at.Add(time.Minute))
	if err := q.Expire(at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := q.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	q2, err := New(st, limits)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := q2.Get(ready.ID); got.State != Cancelled || !got.Redacted {
		t.Fatal(got)
	}
	if got, _ := q2.Get(expired.ID); got.State != Expired || !got.Redacted {
		t.Fatal(got)
	}
}

// REQ: OP-1 (W5-Db DB-5, DB-6)
// A source that re-offers a forgotten generation is refused visibly, from a
// ready or an expired batch alike.
func TestForgottenGenerationNeverReadmitted(t *testing.T) {
	q, _ := queue(t)
	ch := snap(t, "change", 1, "Change line.", "task-1")
	ow := snap(t, "owner", 1, "Owner line.", "note-1")
	if _, err := q.Enqueue([]Snapshot{ch, ow}, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.Expire(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	later := at.Add(time.Hour)
	if _, err := q.Enqueue([]Snapshot{ch}, later, later.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatal("forgotten generation re-admitted from an expired batch", err)
	}
	b, err := q.Enqueue([]Snapshot{ow}, later, later.Add(time.Hour))
	if err != nil || b.State != Ready {
		t.Fatal("unaffected expired line not re-offered", b, err)
	}
	q2, _ := queue(t)
	if _, err := q2.Enqueue([]Snapshot{ch, ow}, at, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q2.Forget("task-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := q2.Enqueue([]Snapshot{ch}, later, later.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatal("forgotten generation re-admitted from a ready batch", err)
	}
}

// REQ: OP-2 (W5-Db DB-5), CAP-3 (W5-Dc-r7 UF-1)
// The in-flight batch is Sending: an Unknown one is now redacted (W5-Dc-r7).
func TestForgetInFlightRefusesBeforeMutation(t *testing.T) {
	q, st := queue(t)
	pending, _ := q.Enqueue([]Snapshot{snap(t, "change", 1, "Change line.", "task-1"), snap(t, "owner", 1, "Owner line.", "note-1")}, at, at.Add(time.Hour))
	start(t, q, enqueue(t, q, "mail", 1))
	before, _ := st.Load()
	if err := q.Forget("task-1"); !errors.Is(err, ErrInFlight) {
		t.Fatal(err)
	}
	after, _ := st.Load()
	got, _ := q.Get(pending.ID)
	if string(before) != string(after) || len(got.Snapshots) != 2 {
		t.Fatal("partial forget", got)
	}
}

// REQ: OP-1 (W5-Db DB-6)
func TestCompactDropsSupersededExpired(t *testing.T) {
	q, st := queue(t)
	s := snapshot(t, "change", 1, "Fixed broker notice.")
	old, _ := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour))
	keep, _ := q.Enqueue([]Snapshot{snapshot(t, "owner", 1, "Owner notice.")}, at, at.Add(time.Hour))
	if err := q.Expire(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := q.Compact(); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Get(old.ID); err != nil {
		t.Fatal("expired batch still in the ledger was compacted", err)
	}
	later := at.Add(time.Hour)
	next, err := q.Enqueue([]Snapshot{s}, later, later.Add(time.Hour))
	if err != nil || next.ID == old.ID {
		t.Fatal(next, err)
	}
	if err = q.Compact(); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Get(old.ID); !errors.Is(err, ErrMissing) {
		t.Fatal("superseded expired batch kept", err)
	}
	if _, err = q.Get(keep.ID); err != nil {
		t.Fatal("unsuperseded expired batch dropped", err)
	}
	if _, err = New(st, limits); err != nil {
		t.Fatal(err)
	}
	// The ledger still dedupes the re-offered generation.
	if again, err := q.Enqueue([]Snapshot{s}, later, later.Add(time.Hour)); err != nil || again.ID != next.ID {
		t.Fatal(again, err)
	}
}

// REQ: OP-1 (W5-Db DB-6)
// Against any batch that is not expired, the same source, generation and
// hash return the existing batch and a different hash conflicts (W5-Da).
func TestSameParamsNonExpiredStillIdempotent(t *testing.T) {
	for _, state := range []State{Ready, Sending, Unknown, Accepted} {
		q, _ := queue(t)
		s := snapshot(t, "change", 1, "Fixed broker notice.")
		b, _ := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour))
		if state != Ready {
			v := start(t, q, b)
			switch state {
			case Unknown:
				_ = q.finish(v.ID, v.Attempts, OutcomeUnknown, "")
			case Accepted:
				_ = q.finish(v.ID, v.Attempts, TransportAccepted, "item-1")
			}
		}
		if got, _ := q.Get(b.ID); got.State != state {
			t.Fatal(state, got.State)
		}
		again, err := q.Enqueue([]Snapshot{s}, at, at.Add(time.Hour))
		if err != nil || again.ID != b.ID {
			t.Fatal(state, again, err)
		}
		later := at.Add(time.Hour)
		if _, err = q.Enqueue([]Snapshot{s}, later, later.Add(time.Hour)); !errors.Is(err, ErrConflict) {
			t.Fatal(state, "new intent admitted against a live batch", err)
		}
		other := snapshot(t, "change", 1, "Different text.")
		if _, err = q.Enqueue([]Snapshot{other}, at, at.Add(time.Hour)); !errors.Is(err, ErrConflict) {
			t.Fatal(state, err)
		}
		if batches, _ := q.List(); len(batches) != 1 {
			t.Fatal(state, len(batches))
		}
	}
}

// REQ: OP-1 (W5-Db DB-6)
// A re-offered generation's new batch can expire in turn and be re-offered
// again; every intermediate state reopens.
func TestRepeatedExpiryReoffersAgain(t *testing.T) {
	st := &change.MemStore{}
	q, _ := New(st, limits)
	s := snapshot(t, "change", 1, "Fixed broker notice.")
	ids := map[uint64]bool{}
	for i := 0; i < 3; i++ {
		from := at.Add(time.Duration(i) * time.Hour)
		b, err := q.Enqueue([]Snapshot{s}, from, from.Add(time.Hour))
		if err != nil || ids[b.ID] {
			t.Fatal(i, b, err)
		}
		ids[b.ID] = true
		if err = q.Expire(from.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if q, err = New(st, limits); err != nil {
			t.Fatal(i, err)
		}
	}
}
