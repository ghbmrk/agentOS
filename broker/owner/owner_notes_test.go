package owner

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestnotes"
)

type noteStore struct {
	mu             sync.Mutex
	raw            []byte
	fail           bool
	block, entered chan struct{}
	once           sync.Once
}

func (s *noteStore) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.raw...), nil
}
func (s *noteStore) Save(raw []byte) error {
	if s.block != nil {
		s.once.Do(func() { close(s.entered) })
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("synthetic note save failed")
	}
	s.raw = append([]byte(nil), raw...)
	return nil
}
func noteSource(t *testing.T, st *noteStore) *digestnotes.Source {
	t.Helper()
	n, err := digestnotes.New(digestnotes.Config{Store: st, Location: time.UTC, Rand: bytes.NewReader(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func noteRig(t *testing.T) (*rig, *noteStore, *digestnotes.Source) {
	t.Helper()
	r := newRig(t, nil)
	st := &noteStore{}
	n := noteSource(t, st)
	r.edit = func(cfg *Config) { cfg.DigestNotes = n }
	r.ch = r.open()
	return r, st, n
}
func notePeek(t *testing.T, n *digestnotes.Source) *digestnotes.Snapshot {
	t.Helper()
	s, err := n.Peek(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// REQ: CH-15, CH-18, CH-2
func TestConfiguredOwnerNotesSurviveSourceAndChannelReopen(t *testing.T) {
	r, st, n := noteRig(t)
	enterChallenge(t, r)
	wrongBefore := len(r.ch.codes.st.Wrong)
	r.say(wrongCode(71))
	r.say(wrongCode(72))
	if len(r.ch.codes.st.Wrong) != wrongBefore {
		t.Fatal("challenge drops changed code accounting")
	}
	if _, err := r.ch.LocalSignIn(wrongCode(90)); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	a := notePeek(t, n)
	if a == nil || a.Counts.Dropped != 2 || a.Counts.Challenge != 1 || len(a.Wrong) != 1 {
		t.Fatal("guard events not captured", a)
	}
	if r.ch.TakeDigestNotes() != nil {
		t.Fatal("destructive reader active alongside source")
	}
	fresh := noteSource(t, st)
	r.edit = func(cfg *Config) { cfg.DigestNotes = fresh }
	r.ch = r.open()
	if b := notePeek(t, fresh); !reflect.DeepEqual(a, b) {
		t.Fatal("source changed on actual channel reopen", a, b)
	}
}
func TestOwnerNoteFailureDoesNotChangeCodeChecksOrStop(t *testing.T) {
	r, st, n := noteRig(t)
	st.fail = true
	if _, err := r.ch.LocalSignIn(wrongCode(91)); !errors.Is(err, ErrWrongCode) {
		t.Fatal(err)
	}
	if r.ch.codes.st.LocalUsed != 1 || len(r.ch.codes.st.Wrong) != 1 {
		t.Fatal("notification failure altered counted attempt")
	}
	if n.Health() == nil || !strings.Contains(r.ch.LocalStatusLines(), "Owner digest notes paused") {
		t.Fatal("note failure invisible")
	}
	if _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal("source failure blocked valid generator code", err)
	}
	if err := r.ch.LocalStop(context.Background()); err != nil || !r.eng.Stopped() {
		t.Fatal("source failure blocked containment", err)
	}
}
func TestOwnerNoteFailureCannotFallBackToDestructiveDigest(t *testing.T) {
	r, st, n := noteRig(t)
	st.fail = true
	r.ch.mu.Lock()
	r.ch.dropLocked(r.clock())
	r.ch.mu.Unlock()
	if r.ch.TakeDigestNotes() != nil {
		t.Fatal("failed source used legacy reader")
	}
	if _, err := n.Peek(context.Background()); !errors.Is(err, digestnotes.ErrRecovery) {
		t.Fatal(err)
	}
	if !strings.Contains(r.ch.OwnerDigestStatus(), "paused") {
		t.Fatal("missing fixed source status")
	}
}
func TestBlockedNoteStoreDoesNotDelayTextOrLocalStop(t *testing.T) {
	r, st, _ := noteRig(t)
	st.block = make(chan struct{})
	st.entered = make(chan struct{})
	defer close(st.block)
	signed := make(chan error, 1)
	go func() { _, err := r.ch.LocalSignIn(wrongCode(92)); signed <- err }()
	select {
	case <-st.entered:
	case <-time.After(time.Second):
		t.Fatal("no blocked note save")
	}
	text := make(chan []string, 1)
	local := make(chan error, 1)
	go func() { text <- r.ch.Handle(context.Background(), ownerNum, "STOP") }()
	go func() { local <- r.ch.LocalStop(context.Background()) }()
	select {
	case out := <-text:
		if len(out) == 0 || !strings.HasPrefix(out[0], "Stopped.") {
			t.Fatal(out)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("text STOP waited for note storage")
	}
	select {
	case err := <-local:
		if err != nil || !r.eng.Stopped() {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("local STOP waited for note storage")
	}
}
func TestOwnerVaultFloodFlagsProduceClosedCountOnlyEvents(t *testing.T) {
	r, _, n := noteRig(t)
	r.ch.mu.Lock()
	r.ch.codes.pausedSilent = true
	r.ch.codes.pausedCounted = true
	r.ch.codes.justChallenged = true
	r.ch.floodLocked(r.clock())
	r.ch.mu.Unlock()
	s := notePeek(t, n)
	if s == nil || s.Counts.Silent != 1 || s.Counts.Counted != 1 || s.Counts.Challenge != 1 || len(s.Wrong) != 0 {
		t.Fatal(s)
	}
}
func TestDefaultOwnerDigestBehaviorAndStatusRemainCompatible(t *testing.T) {
	r := newRig(t, nil)
	r.ch.mu.Lock()
	r.ch.dropLocked(r.clock())
	r.ch.mu.Unlock()
	if notes := r.ch.TakeDigestNotes(); len(notes) != 1 {
		t.Fatal(notes)
	}
	if r.ch.OwnerDigestStatus() != "" {
		t.Fatal("unconfigured source produced status")
	}
}
