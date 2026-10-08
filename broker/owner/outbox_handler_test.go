package owner

import (
	"errors"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	"testing"
	"time"
)

func handlerOutbox(t *testing.T) (*Channel, *MemStore, *digestnotes.Source) {
	t.Helper()
	store := &MemStore{}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c, err := New(Config{Owner: ownerNum, Engine: &fakeEngine{}, Store: store, Secrets: testSecrets, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	source := noteSource(t, &noteStore{})
	out, err := NewDigestOutbox(DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	// Replace the unused fixture backend with a fresh one; no production constructor selects it.
	c.codes = codes{sec: testSecrets, rand: c.cfg.Rand}
	if err := c.codes.bindDigestOutbox(out); err != nil {
		t.Fatal(err)
	}
	return c, store, source
}

// REQ: CH-15, CH-18, OP-1, OP-2, CH-2
func TestHandlerLocalWrongCodesAndChallengeCapturedOnce(t *testing.T) {
	c, store, source := handlerOutbox(t)
	for i := 0; i < WrongToChallenge; i++ {
		if _, err := c.LocalSignIn("000000"); !errors.Is(err, ErrWrongCode) {
			t.Fatal(err)
		}
	}
	st, _ := store.Load()
	if len(st.Wrong) != WrongToChallenge || len(st.DigestOutbox.Pending) != WrongToChallenge {
		t.Fatal("authority and events not paired", st)
	}
	for i, e := range st.DigestOutbox.Pending {
		if !e.Event.WrongAt.Equal(c.cfg.Now()) || e.Event.Challenge != (i == WrongToChallenge-1) {
			t.Fatal("wrong origin or duplicate transition", e)
		}
	}
	if got := c.TakeDigestNotes(); len(got) != 0 {
		t.Fatal("ephemeral fallback", got)
	}
	if err := c.FlushDigestNotes(t.Context()); err != nil {
		t.Fatal(err)
	}
	snap := notePeek(t, source)
	if snap == nil || snap.Counts.Challenge != 1 || len(snap.Wrong) != WrongToChallenge {
		t.Fatal(snap)
	}
}
func TestHandlerPageCheckPropagatesLocalOrigin(t *testing.T) {
	c, store, _ := handlerOutbox(t)
	c.mu.Lock()
	ok, _, msg := c.checkOriginLocked("", "000000", c.cfg.Now(), true)
	c.mu.Unlock()
	st, _ := store.Load()
	if ok || msg != "" || len(st.DigestOutbox.Pending) != 1 || st.DigestOutbox.Pending[0].Event.WrongAt.IsZero() {
		t.Fatal(ok, msg, st)
	}
}
func TestHandlerDropAndVaultFlagsHaveNoAnonymousFallback(t *testing.T) {
	c, store, source := handlerOutbox(t)
	c.mu.Lock()
	c.dropLocked(c.cfg.Now())
	c.codes.pausedSilent, c.codes.pausedCounted = true, true
	c.floodLocked(c.cfg.Now())
	c.floodLocked(c.cfg.Now())
	c.mu.Unlock()
	st, _ := store.Load()
	if len(st.DigestOutbox.Pending) != 2 || !st.DigestOutbox.Pending[0].Event.Dropped || !st.DigestOutbox.Pending[1].Event.Silent || !st.DigestOutbox.Pending[1].Event.Counted {
		t.Fatal(st)
	}
	if len(c.TakeDigestNotes()) != 0 {
		t.Fatal("ephemeral fallback")
	}
	if err := c.FlushDigestNotes(t.Context()); err != nil {
		t.Fatal(err)
	}
	snap := notePeek(t, source)
	if snap == nil || snap.Counts.Dropped != 1 || snap.Counts.Silent != 1 || snap.Counts.Counted != 1 {
		t.Fatal(snap)
	}
}
func TestHandlerCaptureFailureIsVisibleAndCannotResume(t *testing.T) {
	c, _, _ := handlerOutbox(t)
	c.codes.outboxBlocked = ErrDigestRecovery
	c.mu.Lock()
	c.dropLocked(c.cfg.Now())
	c.mu.Unlock()
	if c.OwnerDigestStatus() == "" {
		t.Fatal("capture failure hidden")
	}
	if _, err := c.LocalResume(); !errors.Is(err, ErrDigestRecovery) {
		t.Fatal(err)
	}
	if err := c.LocalStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(c.TakeDigestNotes()) != 0 {
		t.Fatal("held handler fell back")
	}
}

func TestHandlerLocalAnswerStagesWrongTimestampAtCodeCheck(t *testing.T) {
	c, store, _ := handlerOutbox(t)
	r := &request{id: "K1", local: true, tier: High, items: []Item{highItem("synthetic")}, done: []bool{false}, expires: c.cfg.Now().Add(time.Hour)}
	c.open[r.id] = r
	if _, err := c.LocalAnswer(r.id, requestSum(r), true, "000000"); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	st, _ := store.Load()
	if st.LocalUsed != 1 || len(st.Wrong) != 1 || len(st.DigestOutbox.Pending) != 1 || !st.DigestOutbox.Pending[0].Event.WrongAt.Equal(c.cfg.Now()) {
		t.Fatal(st)
	}
}

type handlerBlockedNotes struct {
	noteStore
	block            bool
	started, release chan struct{}
}

func (s *handlerBlockedNotes) Save(b []byte) error {
	if s.block {
		select {
		case s.started <- struct{}{}:
		default:
		}
		<-s.release
	}
	return s.noteStore.Save(b)
}
func TestHandlerTextAndLocalStopBypassBlockedOutboxFlush(t *testing.T) {
	c, store, _ := handlerOutbox(t)
	// Build a separate fresh fixture rather than replacing a live producer.
	c.codes = codes{sec: testSecrets, rand: c.cfg.Rand}
	store = &MemStore{}
	notes := &handlerBlockedNotes{started: make(chan struct{}, 1), release: make(chan struct{})}
	source, err := digestnotes.New(digestnotes.Config{Store: notes, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	out, err := NewDigestOutbox(DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.codes.bindDigestOutbox(out); err != nil {
		t.Fatal(err)
	}
	if err := out.Commit(digestnotes.Event{Dropped: true}, nil); err != nil {
		t.Fatal(err)
	}
	notes.block = true
	done := make(chan error, 1)
	go func() { done <- c.FlushDigestNotes(t.Context()) }()
	defer close(notes.release)
	select {
	case <-notes.started:
	case <-time.After(time.Second):
		t.Fatal("flush did not reach source store")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- c.LocalStop(t.Context()) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("local STOP waited for flush")
	}
	text := make(chan []string, 1)
	go func() { text <- c.Handle(t.Context(), ownerNum, "STOP") }()
	select {
	case <-text:
	case <-time.After(time.Second):
		t.Fatal("text STOP waited for flush")
	}
	// Release and join to ensure no worker survives the test.
	notes.release <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("flush did not finish")
	}
}
