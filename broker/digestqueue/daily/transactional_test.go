package daily

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/digestqueue/ownersource"
	"github.com/ghbmrk/agentos/broker/owner"
	"path/filepath"
	"testing"
	"time"
)

// REQ: CH-15, CH-18, OP-1, OP-2
func TestFourFileTransactionalDailyComposition(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	clock := func() (time.Time, error) { return now, nil }
	r := &recipient{}
	var w *Workflow
	var c *owner.Channel
	var q *dq.Queue
	var notes *digestnotes.Source
	open := func() {
		t.Helper()
		var err error
		notes, err = digestnotes.New(digestnotes.Config{Store: &change.FileStore{Path: filepath.Join(dir, "notes")}, Location: time.UTC})
		if err != nil {
			t.Fatal(err)
		}
		q, err = dq.New(&change.FileStore{Path: filepath.Join(dir, "queue")}, dq.Limits{MaxBatches: 8, MaxSources: 4, MaxAttempts: 2, MaxBytes: 65536})
		if err != nil {
			t.Fatal(err)
		}
		hb, err := heartbeat.New(heartbeat.Config{Store: &change.FileStore{Path: filepath.Join(dir, "heartbeat")}, Clock: clock, Zone: "UTC", Minute: 720})
		if err != nil {
			t.Fatal(err)
		}
		adapter, err := ownersource.New(notes)
		if err != nil {
			t.Fatal(err)
		}
		w, err = New(Config{Queue: q, Heartbeat: hb, Sources: map[string]dq.Source{ownersource.ID: adapter}, Validators: map[string]Validator{ownersource.ID: adapter.Validate}, Owner: r, Clock: clock, TTL: time.Hour, Flush: func(ctx context.Context) error {
			if err := c.OwnerStateHealth(); err != nil {
				return err
			}
			return c.FlushDigestNotes(ctx)
		}, Gate: func(context.Context, dq.Batch) error { return c.OwnerStateHealth() }})
		if err != nil {
			t.Fatal(err)
		}
		e, err := w.WrapEngine(&testEngine{})
		if err != nil {
			t.Fatal(err)
		}
		c, err = owner.NewTransactional(owner.Config{Owner: "+15550000999", Store: owner.FileStore{Path: filepath.Join(dir, "owner")}, Engine: e, Now: func() time.Time { return now }, Location: time.UTC}, notes)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.OwnerStateHealth(); err != nil {
			t.Fatal(err)
		}
		if err := w.Activate(); err != nil {
			t.Fatal(err)
		}
	}
	wrong := func() {
		t.Helper()
		if _, err := c.LocalSignIn("100000"); !errors.Is(err, owner.ErrWrongCode) {
			t.Fatal(err)
		}
	}
	open()
	wrong()
	first, err := w.Step(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Get(first)
	if err != nil || len(b.Snapshots) != 2 || b.State != dq.Accepted || r.calls != 1 {
		t.Fatal(b, err)
	}
	wrong()
	again, err := w.Step(t.Context())
	if err != nil || again != first || r.calls != 1 {
		t.Fatal(again, err)
	}
	pending, err := notes.Peek(t.Context())
	if err != nil || pending == nil {
		t.Fatal("later activity consumed", pending, err)
	}
	open()
	again, err = w.Step(t.Context())
	if err != nil || again != first || r.calls != 1 {
		t.Fatal("restart reissued", again, err)
	}
	now = now.Add(24 * time.Hour)
	second, err := w.Step(t.Context())
	if err != nil || second == first || r.calls != 2 {
		t.Fatal(second, err)
	}
	b, err = q.Get(second)
	if err != nil || len(b.Snapshots) != 2 {
		t.Fatal(b, err)
	}
	st, err := (owner.FileStore{Path: filepath.Join(dir, "owner")}).Load()
	if err != nil || st.DigestOutbox.Produced != 2 || st.DigestOutbox.Acked != 2 || len(st.DigestOutbox.Pending) != 0 {
		t.Fatal(st, err)
	}
	if pending, err := notes.Peek(t.Context()); err != nil || pending != nil {
		t.Fatal(pending, err)
	}
	// Real public local STOP routes through the workflow wrapper. Normal engine
	// resume does not silently reactivate notifications.
	if err := c.LocalStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Step(t.Context()); !errors.Is(err, ErrHeld) {
		t.Fatal("local STOP bypassed daily containment", err)
	}
}
