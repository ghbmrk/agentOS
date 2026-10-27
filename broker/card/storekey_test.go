package card

import (
	"bytes"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// REQ: REC-1, REC-4, BAK-1
// MIG-4-recovery-len (#3406): the recovery key a card prints opens the
// sealed store's recovery slot and derives the backups' recipient, typed
// back in any case and spacing the card's normalisation forgives.
func TestCardRecoveryKeyOpensStoreSlot(t *testing.T) {
	c := mustGen(t, 7)
	rk, err := StoreRecoveryKey(c.RecoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(rk) != seal.RecoveryLen {
		t.Fatalf("store recovery key is %d bytes, the slot takes %d", len(rk), seal.RecoveryLen)
	}
	path := filepath.Join(t.TempDir(), "store")
	st, err := seal.Create(path, seal.Recovery{Key: rk})
	if err != nil {
		t.Fatal(err)
	}
	want, err := backup.RecipientFor(rk)
	if err != nil {
		t.Fatal(err)
	}
	typed := strings.ToLower(strings.ReplaceAll(c.RecoveryKey, "-", " "))
	again, err := StoreRecoveryKey(typed)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := seal.Unlock(path, seal.Recovery{Key: again})
	if err != nil {
		t.Fatalf("the typed card key does not open the recovery slot: %v", err)
	}
	if !bytes.Equal(opened.ID(), st.ID()) {
		t.Fatal("opened a different store")
	}
	got, err := backup.RecipientFor(again)
	if err != nil || got.ID() != want.ID() {
		t.Fatalf("typed card key derives another backup recipient: %v", err)
	}
	other, err := StoreRecoveryKey(mustGen(t, 8).RecoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.Unlock(path, seal.Recovery{Key: other}); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("another card's key: %v, want ErrWrongFactor", err)
	}
}

// The derivation is pinned: a change would orphan every store and backup
// already sealed to a card's key.
func TestStoreRecoveryKeyVector(t *testing.T) {
	var b [recoveryKeyBytes]byte
	for i := range b {
		b[i] = byte(i*37 + 11)
	}
	rk, err := StoreRecoveryKey(RecoveryKeyText(b))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(rk); got != storeKeyVector {
		t.Fatalf("store recovery key %s", got)
	}
}

// A mistyped, short, long or foreign key is refused, never derived.
func TestStoreRecoveryKeyRefuses(t *testing.T) {
	key := mustGen(t, 9).RecoveryKey
	bad := []byte(key)
	if bad[7] == 'A' {
		bad[7] = 'B'
	} else {
		bad[7] = 'A'
	}
	for _, s := range []string{"", string(bad), key[:len(key)-6], key + "-AAAAA", strings.Repeat("0", 40),
		hex.EncodeToString(make([]byte, seal.RecoveryLen))} {
		if rk, err := StoreRecoveryKey(s); err == nil || rk != nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

// storeKeyVector was computed outside Go (Python hmac, RFC 5869 with an
// empty salt) from the bytes i*37+11, the same key as the card's text vector.
const storeKeyVector = "a59068f49ad9f69f7175d32b71649f85a7bf5afbc7fc61ba5f3e18a3334de7b1"
