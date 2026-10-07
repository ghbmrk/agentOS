package owner

import (
	"errors"
	"github.com/ghbmrk/agentos/broker/digestnotes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type replyFileFault struct {
	FileStore
	writes, failAt int
	after          bool
}

func (s *replyFileFault) Save(st State) error {
	s.writes++
	fail := s.writes == s.failAt
	if fail && !s.after {
		return errors.New("synthetic-private/owner-state.json")
	}
	if err := s.FileStore.Save(st); err != nil {
		return err
	}
	if fail {
		return errors.New("synthetic-private/owner-state.json")
	}
	return nil
}

// REQ: CH-18, CH-19, CH-2, OP-1
func TestTransactionalLocalErrorsHideStoreDetailsAndRequireRecovery(t *testing.T) {
	for _, page := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			for _, save := range []int{2, 3} {
				t.Run(strings.Join([]string{map[bool]string{false: "signin", true: "approval"}[page], map[bool]string{false: "before", true: "after"}[after], map[int]string{2: "attempt", 3: "wrong"}[save]}, "/"), func(t *testing.T) {
					store := &replyFileFault{FileStore: FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}, failAt: save, after: after}
					c, err := NewTransactional(startupConfig(store), noteSource(t, &noteStore{}))
					if err != nil {
						t.Fatal(err)
					}
					var public error
					if page {
						r := &request{id: "K1", local: true, tier: High, items: []Item{highItem("synthetic")}, done: []bool{false}, expires: c.cfg.Now().Add(time.Hour)}
						c.open[r.id] = r
						_, public = c.LocalAnswer(r.id, requestSum(r), true, "000000")
					} else {
						_, public = c.LocalSignIn("000000")
					}
					if public != ErrDigestRecovery || strings.Contains(public.Error(), "synthetic-private") {
						t.Fatal("public error leaked or obscured recovery", public)
					}
					v := &backendVerifier{}
					c.codes.verify = v
					writes := store.writes
					if _, err := c.LocalSignIn("123456"); err != ErrDigestRecovery || v.calls != 0 || store.writes != writes {
						t.Fatal("held retry verified, wrote or leaked", err, v.calls, store.writes)
					}
					reply := strings.Join(c.Handle(t.Context(), ownerNum, "123456"), " ")
					if !strings.Contains(reply, "recovery") || strings.Contains(reply, "Try again") || strings.Contains(reply, "synthetic-private") {
						t.Fatal("misleading held reply", reply)
					}
					if err := c.LocalStop(t.Context()); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
func TestTransactionalFullBacklogReplyDescribesHold(t *testing.T) {
	c, _, _ := handlerOutbox(t)
	for i := 0; i < MaxDigestOutbox; i++ {
		if err := c.codes.outbox.Commit(digestnotes.Event{Dropped: true}, nil); err != nil {
			t.Fatal(err)
		}
	}
	text := strings.Join(c.Handle(t.Context(), ownerNum, "123456"), " ")
	if !strings.Contains(text, "backlog is full") || strings.Contains(text, "Try again") {
		t.Fatal(text)
	}
	if _, err := c.LocalSignIn("123456"); err != ErrDigestFull {
		t.Fatal(err)
	}
}

func TestTransactionalSignInNotificationSaveFailureDoesNotReturnNewAuthority(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			store := &replyFileFault{FileStore: FileStore{Path: filepath.Join(t.TempDir(), "owner.json")}, failAt: 4, after: after}
			cfg := startupConfig(store)
			c, err := NewTransactional(cfg, noteSource(t, &noteStore{}))
			if err != nil {
				t.Fatal(err)
			}
			until, err := c.LocalSignIn(totpAt(testSecrets.TOTPSeed, cfg.Now().Unix()))
			if err != ErrDigestRecovery || !until.IsZero() || c.SessionUnlocked(cfg.Now()) {
				t.Fatal("failed notification save returned authority", until, err)
			}
			persisted, err := store.Load()
			if err != nil || persisted.LastStep == 0 {
				t.Fatal("successful proof not spent", persisted, err)
			}
			if (len(persisted.LocalSignIns) == 1) != after {
				t.Fatal("file replacement cut not exercised", persisted)
			}
		})
	}
}

type replyUnavailableVerifier struct{}

func (replyUnavailableVerifier) VerifyTOTP(string, int64, bool) (int64, bool, error) {
	return 0, false, &VerifyError{Kind: VaultDown}
}
func TestTransactionalVerifierFailureKeepsItsExistingErrorClass(t *testing.T) {
	c, err := NewTransactional(startupConfig(&MemStore{}), noteSource(t, &noteStore{}))
	if err != nil {
		t.Fatal(err)
	}
	c.codes.verify = replyUnavailableVerifier{}
	_, err = c.LocalSignIn("123456")
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Kind != VaultDown || c.OwnerStateHealth() != nil {
		t.Fatal("verifier failure became a storage hold", err)
	}
}
