package owner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestnotes"
)

// REQ: OP-1, CH-15, CH-18, CH-2
func TestLegacyChannelCannotOpenTransactionalOwnerState(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	source := noteSource(t, &noteStore{})
	out, err := NewDigestOutbox(DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Commit(digestnotes.Event{Challenge: true}, func(s *State) { s.Challenged = true; s.LowLocked = true }); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := New(Config{Owner: ownerNum, Engine: &fakeEngine{}, Store: store})
	if ch != nil || !errors.Is(err, ErrDigestComposition) {
		t.Fatal("legacy handler opened transactional authority state", ch, err)
	}
	after, _ := os.ReadFile(store.Path)
	if !bytes.Equal(before, after) {
		t.Fatal("composition refusal modified authority state")
	}
}
func TestAnonymousHandlerCannotOpenKnownOrderedSource(t *testing.T) {
	for _, claimed := range []bool{false, true} {
		source := noteSource(t, &noteStore{})
		if claimed {
			if _, err := source.ClaimProducer(); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := source.RecordOnce(1, digestnotes.Event{Dropped: true}); err != nil {
				t.Fatal(err)
			}
		}
		ch, err := New(Config{Owner: ownerNum, Engine: &fakeEngine{}, Store: &MemStore{}, DigestNotes: source})
		if ch != nil || !errors.Is(err, ErrDigestComposition) {
			t.Fatal("anonymous producer opened ordered source", claimed, ch, err)
		}
	}
}
func TestLateProducerClaimIsVisibleAndCannotAlterCodeOrStop(t *testing.T) {
	r := newRig(t, nil)
	source := noteSource(t, &noteStore{})
	saved, err := r.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	saved.Challenged = true
	if err := r.store.Save(saved); err != nil {
		t.Fatal(err)
	}
	r.edit = func(cfg *Config) { cfg.DigestNotes = source }
	r.ch = r.open()
	if _, err := source.ClaimProducer(); err != nil {
		t.Fatal(err)
	}
	r.say(wrongCode(83))
	if len(r.ch.codes.st.Wrong) != 0 || r.ch.codes.st.BoundUsed != 0 {
		t.Fatal("note error changed code authority")
	}
	if source.Health() != nil {
		t.Fatal("fixture did not exercise healthy-source mode refusal")
	}
	if !strings.Contains(r.ch.OwnerDigestStatus(), "Owner digest notes paused") {
		t.Fatal("capture refusal invisible")
	}
	if r.ch.TakeDigestNotes() != nil {
		t.Fatal("capture error reenabled destructive reader")
	}
	if err := r.ch.LocalStop(context.Background()); err != nil || !r.eng.Stopped() {
		t.Fatal("note mismatch blocked STOP", err)
	}
}
func TestAnonymousSourceRecoveryStillAllowsOwnerChannelAndStop(t *testing.T) {
	r := newRig(t, nil)
	store := &noteStore{}
	source := noteSource(t, store)
	store.fail = true
	if err := source.Record(digestnotes.Event{Dropped: true}); err == nil {
		t.Fatal("fixture did not fail")
	}
	r.edit = func(cfg *Config) { cfg.DigestNotes = source }
	r.ch = r.open()
	if !strings.Contains(r.ch.OwnerDigestStatus(), "paused") {
		t.Fatal("source recovery status missing")
	}
	if _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal("anonymous source outage changed code authority", err)
	}
	r.say("STOP")
	if !r.eng.Stopped() {
		t.Fatal("source recovery blocked text STOP")
	}
}
func TestHealthySourceInputErrorIsReportedAsCaptureFailure(t *testing.T) {
	r, _, source := noteRig(t)
	r.ch.mu.Lock()
	r.ch.wrongLocalLocked(time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 3600)))
	r.ch.mu.Unlock()
	if source.Health() != nil {
		t.Fatal("input refusal should leave source healthy")
	}
	if !strings.Contains(r.ch.OwnerDigestStatus(), "paused") {
		t.Fatal("healthy-source capture error invisible")
	}
	if len(r.ch.codes.st.Wrong) != 0 {
		t.Fatal("notification failure changed wrong-code accounting")
	}
}
