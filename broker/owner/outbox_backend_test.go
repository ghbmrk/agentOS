package owner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/digestnotes"
)

func backendCodes(t *testing.T, store Store) (*codes, *DigestOutbox, *digestnotes.Source) {
	t.Helper()
	source := noteSource(t, &noteStore{})
	out, err := NewDigestOutbox(DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	c := &codes{sec: testSecrets, store: store}
	if err := c.bindDigestOutbox(out); err != nil {
		t.Fatal(err)
	}
	return c, out, source
}

// REQ: CH-18, CH-15, OP-1, OP-2, CH-2
func TestCodeBackendCapturesChallengeAtTheActualWrongCodeTransaction(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	c, out, source := backendCodes(t, store)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for i := 0; i < WrongToChallenge; i++ {
		if _, err := c.wrong(now.Add(time.Duration(i) * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Challenged || !saved.LowLocked || len(saved.Wrong) != WrongToChallenge || len(saved.DigestOutbox.Pending) != 1 || !saved.DigestOutbox.Pending[0].Event.Challenge {
		t.Fatal("challenge not atomic with authority", saved)
	}
	if err := out.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	snap := notePeek(t, source)
	if snap == nil || snap.Counts.Challenge != 1 {
		t.Fatal(snap)
	}
	// Ordinary authority-only commits must preserve the coordinator's newer ack.
	if err := c.commit(func(s *State) { s.Pending = append(s.Pending, PendingRef{ID: "synthetic"}) }); err != nil {
		t.Fatal(err)
	}
	if c.st.DigestOutbox.Acked != 1 || len(c.st.DigestOutbox.Pending) != 0 || !c.st.Challenged {
		t.Fatal("stale code view rewrote outbox floor", c.st)
	}
}
func TestLocalOriginWrongStrongCheckCommitsTimestampWithWrongCounter(t *testing.T) {
	store := &MemStore{}
	c, _, _ := backendCodes(t, store)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	wrong := "999999"
	if wrong == totpAt(testSecrets.TOTPSeed, now.Unix()) {
		wrong = "888888"
	}
	res, _, err := c.checkStrong(wrong, now, strongOpts{count: true, local: true})
	if err != nil || res != strongWrong {
		t.Fatal(res, err)
	}
	saved, _ := store.Load()
	if len(saved.Wrong) != 1 || len(saved.DigestOutbox.Pending) != 1 || !saved.DigestOutbox.Pending[0].Event.WrongAt.Equal(now) {
		t.Fatal("local note not atomic with code state", saved)
	}
}

type backendFileCut struct {
	FileStore
	fail, after bool
}

func (s *backendFileCut) Save(st State) error {
	if s.fail && !s.after {
		return errors.New("synthetic before code-state replacement")
	}
	if err := s.FileStore.Save(st); err != nil {
		return err
	}
	if s.fail {
		return errors.New("synthetic after code-state replacement")
	}
	return nil
}
func TestCodeBackendSaveUncertaintyNeverGrantsAndKeepsStricterMemory(t *testing.T) {
	for _, after := range []bool{false, true} {
		store := &backendFileCut{FileStore: FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}, after: after}
		c, _, _ := backendCodes(t, store)
		now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
		for i := 0; i < WrongToChallenge-1; i++ {
			if _, err := c.wrong(now.Add(time.Duration(i) * time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		store.fail = true
		if _, err := c.wrong(now.Add(time.Minute)); !errors.Is(err, ErrDigestRecovery) {
			t.Fatal(err)
		}
		if !c.st.Challenged || !c.st.LowLocked || !c.justChallenged || c.unlocked(now) {
			t.Fatal("save failure weakened current containment", c.st)
		}
		persisted, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if persisted.Challenged != after || (len(persisted.DigestOutbox.Pending) == 1) != after {
			t.Fatal("authority/event replacement tore", after, persisted)
		}
		v := &backendVerifier{}
		c.verify = v
		if res, _, err := c.checkStrong("123456", now, strongOpts{unlock: time.Hour, count: true}); res != strongWrong || !errors.Is(err, ErrDigestRecovery) || v.calls != 0 {
			t.Fatal("held backend invoked verifier or granted", res, err, v.calls)
		}
		ch := &Channel{codes: *c, cfg: Config{Engine: &fakeEngine{stopped: true}}}
		if ok, _, msg := ch.checkLocked("123456", "123456", now); ok || msg == "" {
			t.Fatal("texted code bypassed held backend", ok, msg)
		}
		if _, err := ch.LocalResume(); !errors.Is(err, ErrDigestRecovery) || !ch.cfg.Engine.Stopped() {
			t.Fatal("signed-in local resume bypassed held backend", err)
		}
		if err := ch.LocalStop(context.Background()); err != nil {
			t.Fatal("held backend blocked STOP", err)
		}
	}
}

type backendVerifier struct{ calls int }

func (v *backendVerifier) VerifyTOTP(_ string, _ int64, _ bool) (int64, bool, error) {
	v.calls++
	return 12345, true, nil
}
func TestFullCodeBackendRefusesBeforeAnyVerificationOrUnlock(t *testing.T) {
	c, out, _ := backendCodes(t, &MemStore{})
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	if err := c.commit(func(s *State) { s.UnlockedUntil = now.Add(time.Hour) }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxDigestOutbox; i++ {
		if err := out.Commit(digestnotes.Event{Dropped: true}, nil); err != nil {
			t.Fatal(err)
		}
	}
	v := &backendVerifier{}
	c.verify = v
	if res, _, err := c.checkStrong("123456", now, strongOpts{unlock: time.Hour, count: true}); res != strongWrong || !errors.Is(err, ErrDigestFull) || v.calls != 0 {
		t.Fatal(res, err, v.calls)
	}
	if c.unlocked(now) {
		t.Fatal("full backend allowed session authority")
	}
	if err := out.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if c.unlocked(now) {
		t.Fatal("drain silently cleared conservative hold")
	}
}
func TestBackendBindingRefusesASecondLiveAuthorityView(t *testing.T) {
	c, out, _ := backendCodes(t, &MemStore{})
	if err := c.bindDigestOutbox(out); !errors.Is(err, ErrDigestComposition) {
		t.Fatal("live backend rebound", err)
	}
	c2 := &codes{st: State{LastStep: 1}}
	if err := c2.bindDigestOutbox(out); !errors.Is(err, ErrDigestComposition) {
		t.Fatal("nonempty authority view replaced", err)
	}
	if err := (&codes{}).bindDigestOutbox(nil); !errors.Is(err, ErrDigestInvalid) {
		t.Fatal(err)
	}
}
func TestUncertainStrongSuccessCannotAdvanceLiveAuthority(t *testing.T) {
	store := &backendFileCut{FileStore: FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}, after: true}
	c, _, _ := backendCodes(t, store)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	store.fail = true
	res, _, err := c.checkStrong(totpAt(testSecrets.TOTPSeed, now.Unix()), now, strongOpts{unlock: time.Hour, count: true})
	if res != strongWrong || !errors.Is(err, ErrDigestRecovery) || !c.st.UnlockedUntil.IsZero() {
		t.Fatal("uncertain success granted", res, err, c.st)
	}
	raw, err := os.ReadFile(store.Path)
	if err != nil || !strings.Contains(string(raw), "last_step") {
		t.Fatal(err)
	}
	if c.unlocked(now) {
		t.Fatal("uncertain backend grants from heap")
	}
}

func TestBackendSourceOutageRetainsNotesWithoutBlockingValidStrongCode(t *testing.T) {
	store := &MemStore{}
	notes := &noteStore{}
	source := noteSource(t, notes)
	out, err := NewDigestOutbox(DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	c := &codes{sec: testSecrets}
	if err := c.bindDigestOutbox(out); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	if _, err := c.wrongOrigin(now, true); err != nil {
		t.Fatal(err)
	}
	notes.fail = true
	if err := out.Flush(t.Context()); !errors.Is(err, digestnotes.ErrRecovery) {
		t.Fatal(err)
	}
	code := totpAt(testSecrets.TOTPSeed, now.Unix())
	if res, _, err := c.checkStrong(code, now, strongOpts{unlock: time.Hour, count: true}); err != nil || res != strongOK || !c.unlocked(now) {
		t.Fatal("note-source outage changed valid strong-code authority", res, err)
	}
	saved, _ := store.Load()
	if saved.LastStep == 0 || len(saved.DigestOutbox.Pending) != 1 || len(saved.Wrong) != 1 {
		t.Fatal("delegated update lost retained note/counter", saved)
	}
}
func TestDelegatedStrongCodeUseSurvivesReopenAndCannotReplay(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}
	notes := &noteStore{}
	source := noteSource(t, notes)
	out, err := NewDigestOutbox(DigestOutboxConfig{Store: store, Source: source})
	if err != nil {
		t.Fatal(err)
	}
	c := &codes{sec: testSecrets}
	if err := c.bindDigestOutbox(out); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	code := totpAt(testSecrets.TOTPSeed, now.Unix())
	if res, _, err := c.checkStrong(code, now, strongOpts{unlock: time.Hour, count: true}); res != strongOK || err != nil {
		t.Fatal(res, err)
	}
	freshOut, err := NewDigestOutbox(DigestOutboxConfig{Store: FileStore{Path: store.Path}, Source: noteSource(t, notes)})
	if err != nil {
		t.Fatal(err)
	}
	fresh := &codes{sec: testSecrets}
	if err := fresh.bindDigestOutbox(freshOut); err != nil {
		t.Fatal(err)
	}
	if res, _, err := fresh.checkStrong(code, now, strongOpts{count: true}); res != strongWrong || err != nil || len(fresh.st.Wrong) != 1 {
		t.Fatal("used generator code replayed after reopen", res, err, fresh.st)
	}
}

func TestHeldBackendLocalReplyDoesNotRevealStorageDetails(t *testing.T) {
	c, _, _ := backendCodes(t, &MemStore{})
	c.outboxBlocked = errors.Join(ErrDigestRecovery, errors.New("synthetic-private/owner-state.json"))
	ch := &Channel{codes: *c, cfg: Config{Engine: &fakeEngine{}}}
	msg, err := ch.LocalResume()
	if err != ErrDigestRecovery || strings.Contains(msg+err.Error(), "synthetic-private") || strings.Contains(msg, "Still stopped") {
		t.Fatal("held reply leaked details or invented containment", msg, err)
	}
}
