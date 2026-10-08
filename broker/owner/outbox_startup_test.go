package owner

import (
	"bytes"
	"errors"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func startupConfig(store Store) Config {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	return Config{Owner: ownerNum, Engine: &fakeEngine{}, Store: store, Secrets: testSecrets, Now: func() time.Time { return now }}
}

// REQ: CH-2, CH-15, CH-18, OP-1, OP-2
func TestTransactionalConstructorRoutesAndReopensAuthority(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	notes := &noteStore{}
	cfg := startupConfig(store)
	c, err := NewTransactional(cfg, noteSource(t, notes))
	if err != nil {
		t.Fatal(err)
	}
	if c.OwnerStateHealth() != nil {
		t.Fatal("healthy composition held")
	}
	if c.codes.outbox == nil || c.codes.store != nil {
		t.Fatal("unbound constructor")
	}
	if _, err := c.LocalSignIn("000000"); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	if err := c.FlushDigestNotes(t.Context()); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewTransactional(cfg, noteSource(t, notes))
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.codes.st.Wrong) != 1 || reopened.codes.st.LocalUsed != 1 || reopened.codes.st.DigestOutbox.Acked != 1 {
		t.Fatal(reopened.codes.st)
	}
	if _, err := New(cfg); !errors.Is(err, ErrDigestComposition) {
		t.Fatal("legacy silently downgraded", err)
	}
}
func assertRecoveryChannel(t *testing.T, c *Channel) {
	t.Helper()
	if c == nil {
		t.Fatal("recovery removed control channel")
	}
	if c.OwnerStateHealth() != ErrDigestRecovery {
		t.Fatal("missing fixed authority health")
	}
	v := &backendVerifier{}
	c.codes.verify = v
	if _, err := c.LocalSignIn("123456"); !errors.Is(err, ErrDigestRecovery) || v.calls != 0 {
		t.Fatal("held sign-in checked", err, v.calls)
	}
	if c.SessionUnlocked(c.cfg.Now()) {
		t.Fatal("held session grants")
	}
	if _, err := c.LocalResume(); !errors.Is(err, ErrDigestRecovery) {
		t.Fatal(err)
	}
	text := strings.Join(c.Handle(t.Context(), ownerNum, "STATUS"), " ")
	if !strings.Contains(text, "recovery") || strings.Contains(text, "synthetic-private") {
		t.Fatal("missing or leaking recovery status", text)
	}
	if out := c.Handle(t.Context(), stranger, "STATUS"); len(out) != 0 {
		t.Fatal("stranger read status", out)
	}
	if len(c.TakeDigestNotes()) != 0 {
		t.Fatal("held mode fell back")
	}
	if err := c.RequireUnlock(); !errors.Is(err, ErrDigestRecovery) {
		t.Fatal("held state write allowed", err)
	}
	if err := c.LocalStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if out := c.Handle(t.Context(), ownerNum, "STOP"); len(out) == 0 || !c.cfg.Engine.Stopped() {
		t.Fatal("text STOP unavailable", out)
	}
}
func TestTransactionalStartupOwnerReplacementUncertaintyKeepsControl(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			store := &backendFileCut{FileStore: FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}, fail: true, after: after}
			cfg := startupConfig(store)
			reissued := 0
			cfg.Reissue = func([]Carried) { reissued++ }
			c, err := NewTransactional(cfg, noteSource(t, &noteStore{}))
			if err != nil {
				t.Fatal(err)
			}
			assertRecoveryChannel(t, c)
			c.Boot()
			if reissued != 0 {
				t.Fatal("held startup reissued")
			}
			persisted, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if (persisted.DigestOutbox != nil) != after {
				t.Fatal("unexpected replacement", persisted)
			}
		})
	}
}

type startupLoadFailure struct{ saves int }

func (s *startupLoadFailure) Load() (State, error) {
	return State{}, errors.New("synthetic-private/owner.json")
}
func (s *startupLoadFailure) Save(State) error { s.saves++; return nil }
func TestTransactionalStartupLoadFailureNeverInventsAuthority(t *testing.T) {
	store := &startupLoadFailure{}
	c, err := NewTransactional(startupConfig(store), noteSource(t, &noteStore{}))
	if err != nil {
		t.Fatal(err)
	}
	assertRecoveryChannel(t, c)
	if store.saves != 0 {
		t.Fatal("unread state overwritten")
	}
}
func TestTransactionalStartupPairMismatchPreservesRetainedState(t *testing.T) {
	store := &MemStore{}
	cfg := startupConfig(store)
	c, err := NewTransactional(cfg, noteSource(t, &noteStore{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LocalSignIn("000000"); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	before, _ := store.Load()
	other, err := digestnotes.New(digestnotes.Config{Store: &noteStore{}, Location: time.UTC, Rand: bytes.NewReader(bytes.Repeat([]byte{1}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	held, err := NewTransactional(cfg, other)
	if err != nil {
		t.Fatal(err)
	}
	assertRecoveryChannel(t, held)
	after, _ := store.Load()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("pair mismatch rewrote state")
	}
}
func TestTransactionalConstructorRejectsDualSourceBeforeClaim(t *testing.T) {
	source := noteSource(t, &noteStore{})
	cfg := startupConfig(&MemStore{})
	cfg.DigestNotes = source
	if _, err := NewTransactional(cfg, source); !errors.Is(err, ErrDigestComposition) {
		t.Fatal(err)
	}
	if source.UsesOrderedProducer() {
		t.Fatal("invalid composition claimed source")
	}
	if _, err := NewTransactional(startupConfig(&MemStore{}), nil); !errors.Is(err, ErrDigestInvalid) {
		t.Fatal(err)
	}
}
func TestTransactionalStartupSourceOutageKeepsStopAndRetainedOutbox(t *testing.T) {
	notes := &noteStore{}
	source := noteSource(t, notes)
	store := &MemStore{}
	cfg := startupConfig(store)
	c, err := NewTransactional(cfg, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LocalSignIn("000000"); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	notes.fail = true
	if err := c.FlushDigestNotes(t.Context()); err == nil {
		t.Fatal("missing outage")
	}
	before, _ := store.Load()
	held, err := NewTransactional(cfg, source)
	if err != nil {
		t.Fatal(err)
	}
	assertRecoveryChannel(t, held)
	after, _ := store.Load()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("outage erased retained outbox")
	}
}
