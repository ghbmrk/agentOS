package recovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests pin the recovery key's checks, its derivations and the
// reserved vault entries line by line (OWN-page-session mutants part 4,
// #5849): each fails if one statement or comparison they name is removed
// or turned.

func TestAWrongRecoveryKeyIsRefusedEvenWithACodeAndTheLocalPage(t *testing.T) {
	x := newBox(t)
	a := Auth{Code: true, Local: true, Recovery: mustKey(t)}
	if err := a.check(x.b); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("a wrong recovery key beside a code and the local page: %v", err)
	}
	if err := (Auth{Code: true, Local: true}).check(x.b); err != nil {
		t.Fatalf("code and local page: %v", err)
	}
}

func TestNoBackupKeyDerivesFromAnEmptyRecoveryKey(t *testing.T) {
	if _, err := backupPrivate(RecoveryKey{}); err == nil {
		t.Fatal("backupPrivate of no key")
	}
	if _, err := backupPublic(RecoveryKey{}); err == nil {
		t.Fatal("backupPublic of no key")
	}
}

func TestAnEmptyRecoveryKeyEnrollsNoSlot(t *testing.T) {
	s, kek, err := Factor(RecoveryKey{}).Enroll()
	if err == nil || kek != nil || s.Kind != "" || s.Sealed != nil {
		t.Fatalf("Enroll of no key: %+v, %x, %v", s, kek, err)
	}
}

func TestTheRecoverySlotKEKNeedsABareThirtyTwoByteSalt(t *testing.T) {
	rk := mustKey(t)
	good, _, err := Factor(rk).Enroll()
	must(t, err)
	if kek, err := Factor(rk).KEK(good); err != nil || len(kek) == 0 {
		t.Fatalf("a well-formed slot: %x, %v", kek, err)
	}
	withKDF := good
	must(t, json.Unmarshal([]byte(`{"kdf":{}}`), &withKDF))
	short, long, none := good, good, good
	short.Sealed = good.Sealed[:31]
	long.Sealed = append(append([]byte(nil), good.Sealed...), 0)
	none.Sealed = nil
	for name, kek := range map[string]func() ([]byte, error){
		"kdf":     func() ([]byte, error) { return Factor(rk).KEK(withKDF) },
		"short":   func() ([]byte, error) { return Factor(rk).KEK(short) },
		"long":    func() ([]byte, error) { return Factor(rk).KEK(long) },
		"no-salt": func() ([]byte, error) { return Factor(rk).KEK(none) },
		"no-key":  func() ([]byte, error) { return Factor(RecoveryKey{}).KEK(good) },
	} {
		if k, err := kek(); err == nil || k != nil {
			t.Errorf("%s: %x, %v", name, k, err)
		}
	}
}

func TestStoreBackupKeyNeedsAKeyASlotFileAndItsOwnKind(t *testing.T) {
	x := newBox(t)
	before, _, err := reserved(x.b.V, BackupKeyName, KindBackupKey)
	must(t, err)
	if err := storeBackupKey(x.b, RecoveryKey{}); err == nil {
		t.Fatal("stored a backup key for no recovery key")
	}
	gone := &Box{VaultPath: x.b.VaultPath, KeysPath: filepath.Join(t.TempDir(), "missing.keys"), V: x.b.V}
	if err := storeBackupKey(gone, x.rk); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing slot file: %v", err)
	}
	after, _, err := reserved(x.b.V, BackupKeyName, KindBackupKey)
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("a failed storeBackupKey changed the backup key")
	}
	must(t, x.b.V.Put(BackupKeyName, otherKind, []byte("sk-synthetic-not-a-backup-key")))
	if err := storeBackupKey(x.b, x.rk); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("wrong-kind entry: %v", err)
	}
	if k, _ := entryKind(x.b.V, BackupKeyName); k != otherKind {
		t.Fatalf("the entry of another kind was overwritten: %q", k)
	}
}

func TestEnsureMACKeyKeepsTheKeyItHasAndRefusesAnotherKind(t *testing.T) {
	x := newBox(t)
	k1, err := macKey(x.b.V)
	must(t, err)
	must(t, ensureMACKey(x.b.V))
	k2, err := macKey(x.b.V)
	must(t, err)
	if !bytes.Equal(k1, k2) {
		t.Fatal("ensureMACKey replaced an existing MAC key")
	}
	must(t, x.b.V.Put(MACKeyName, otherKind, []byte("sk-synthetic-not-a-mac-key")))
	if err := ensureMACKey(x.b.V); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("ensureMACKey over another kind: %v", err)
	}
	if err := rotateMACKey(x.b.V); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("rotateMACKey over another kind: %v", err)
	}
	if k, _ := entryKind(x.b.V, MACKeyName); k != otherKind {
		t.Fatalf("the entry of another kind was overwritten: %q", k)
	}
}

func TestAnEmptyRecoveryKeyPrintsNothing(t *testing.T) {
	if s := (RecoveryKey{}).Text(); s != "" {
		t.Fatalf("Text of no key = %q", s)
	}
}

// RFC 5869 appendix A.1 (SHA-256, 42 bytes: two blocks).
func TestHKDFMatchesRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(hkdf(ikm, salt, string(info), 42)); got != want {
		t.Fatalf("hkdf = %s\nwant   %s", got, want)
	}
}

func readKeys(t *testing.T, path string) keysFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	must(t, err)
	var kf keysFile
	must(t, json.Unmarshal(raw, &kf))
	return kf
}

func TestKeySlotsNeedATwelveByteNonceAndAWrappedKey(t *testing.T) {
	x := newBox(t)
	for name, bad := range map[string]func(*keysSlot){
		"nonce":   func(s *keysSlot) { s.Nonce = s.Nonce[:11] },
		"wrapped": func(s *keysSlot) { s.Wrapped = s.Wrapped[:len(s.Wrapped)-1] },
	} {
		kf := readKeys(t, x.b.KeysPath)
		bad(&kf.Slots[0])
		raw, err := json.Marshal(kf)
		must(t, err)
		if err := CheckKeys(raw); err == nil {
			t.Errorf("%s: a malformed slot passed", name)
		}
	}
}

func TestRecoverySlotIDIsTheDomainSeparatedSaltHash(t *testing.T) {
	x := newBox(t)
	var salt []byte
	for _, s := range readKeys(t, x.b.KeysPath).Slots {
		if s.Kind == Factor(x.rk).Kind() {
			salt = s.Sealed
		}
	}
	want := sha256.Sum256(append([]byte("agentos-recovery-slot-id/v2\x00"), salt...))
	got, err := recoverySlotID(x.b.KeysPath)
	must(t, err)
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("slot id %x, want %x", got, want)
	}
	if _, err := recoverySlotID(filepath.Join(t.TempDir(), "none")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.keys")
	must(t, os.WriteFile(bad, []byte(`{"magic":"agentos-vault-keys","version":2,"slots":[]}`), 0o600))
	if _, err := recoverySlotID(bad); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("unreadable file: %v", err)
	}
}

// The forget log's header and chain start are MACs of a fixed layout, so a
// log a later build reads verifies; each field is bound into the header.
func TestForgetLogHeaderAndChainStartLayout(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	l := forgetLog{Format: forgetLogFmt, ID: bytes.Repeat([]byte{1}, 16), Host: "pc-a", Base: 7, AnchorSeq: 3}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("agentos-forget-header-v1\x00" + l.Format + "\x00"))
	m.Write(l.ID)
	m.Write([]byte("\x00pc-a\x00"))
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], 7)
	binary.BigEndian.PutUint64(n[8:], 3)
	m.Write(n[:])
	if got, want := l.headerMAC(key), hex.EncodeToString(m.Sum(nil)); got != want {
		t.Fatalf("header MAC %s, want %s", got, want)
	}
	c := hmac.New(sha256.New, key)
	c.Write([]byte("agentos-forget-chain-v1\x00"))
	c.Write(l.ID)
	if got, want := chainStart(key, l.ID), hex.EncodeToString(c.Sum(nil)); got != want {
		t.Fatalf("chain start %s, want %s", got, want)
	}
}

func TestEnsureForgetLogStopsOnAMalformedKeyOrLog(t *testing.T) {
	for _, name := range []string{ForgetKeyName, ForgetLogName} {
		x := newBox(t)
		kind := map[string]string{ForgetKeyName: KindForgetKey, ForgetLogName: KindForgetLog}[name]
		junk := []byte(`{"format":"not-this-one"}`)
		must(t, x.b.V.Put(name, kind, junk))
		if err := ensureForgetLog(x.b.V, x.rk, nil); err == nil {
			t.Errorf("%s: a malformed entry was replaced", name)
		}
		got, _, err := reserved(x.b.V, name, kind)
		must(t, err)
		if !bytes.Equal(got, junk) {
			t.Errorf("%s: the malformed entry changed", name)
		}
	}
}

func TestSaveForgetLogReportsAnEntryItCannotEncode(t *testing.T) {
	x := newBox(t)
	l := forgetLog{Format: forgetLogFmt, ID: bytes.Repeat([]byte{1}, 16),
		Entries: []ForgetEntry{{Seq: 1, Goal: "g", At: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	var me *json.MarshalerError
	if err := saveForgetLog(x.b.V, l); !errors.As(err, &me) {
		t.Fatalf("err = %v, want the encoding error", err)
	}
}

func TestProvisionStopsAtABadKeyOrAFactorThatOpensNothing(t *testing.T) {
	x := newBox(t)
	bad := x.card
	bad.RecoveryKey = "not a recovery key"
	_, perr := ParseRecoveryKey(bad.RecoveryKey)
	if err := Provision(x.b, bad, Factor(x.rk)); err == nil || err.Error() != perr.Error() {
		t.Fatalf("Provision with an unreadable key: %v, want %v", err, perr)
	}
	// The vault's own refusal of a factor that opens no slot, for comparison.
	none := x.b.V.Rekey(Factor(mustKey(t)), Factor(mustKey(t)))
	if none == nil {
		t.Fatal("a stray recovery key opened the vault")
	}
	if err := Provision(x.b, x.card, Factor(mustKey(t))); !errors.Is(err, none) {
		t.Fatalf("Provision with a factor that opens nothing: %v", err)
	}
}

func TestStoreCardChecksEachEntryKindAndTheSecretLength(t *testing.T) {
	x := newBox(t)
	c := x.card
	// The shortest value the vault stores.
	n := 1
	for ; x.b.V.Put("test-probe", otherKind, bytes.Repeat([]byte{'p'}, n)) != nil; n++ {
		if n > 256 {
			t.Fatal("the vault stores no value up to 256 bytes")
		}
	}
	c.SetupSecret = strings.Repeat("S", n)
	must(t, storeCard(x.b, c))
	c.SetupSecret = c.SetupSecret[1:]
	if err := storeCard(x.b, c); err == nil || !strings.Contains(err.Error(), "card setup too short") {
		t.Fatalf("short setup secret: %v", err)
	}
	for _, name := range []string{CardName, CardName + "-setup"} {
		y := newBox(t)
		must(t, y.b.V.Put(name, otherKind, []byte("sk-synthetic-not-a-card")))
		if err := storeCard(y.b, y.card); !errors.Is(err, ErrWrongKind) {
			t.Errorf("%s of another kind: %v", name, err)
		}
		if k, _ := entryKind(y.b.V, name); k != otherKind {
			t.Errorf("%s: the entry of another kind was overwritten: %q", name, k)
		}
	}
}

// A key whose last symbol is not zero prints and reads back whole: the
// last five bits are a symbol of their own.
func TestARecoveryKeyPrintsItsLastSymbol(t *testing.T) {
	k, err := NewRecoveryKey(bytes.NewReader(bytes.Repeat([]byte{0xff}, 64)))
	must(t, err)
	txt := k.Text()
	groups := strings.Split(txt, "-")
	if last := groups[len(groups)-1]; last[:4] != strings.Repeat(string(Alphabet[31]), 4) {
		t.Fatalf("last group %q of %q", last, txt)
	}
	back, err := ParseRecoveryKey(txt)
	must(t, err)
	if !bytes.Equal(back.b[:], k.b[:]) {
		t.Fatalf("read back %x, printed %x", back.b[:], k.b[:])
	}
}

// withFailingDraw makes the next crypto/rand draw fail and later ones
// succeed. No test in this package is parallel, so the failure lands on
// the first draw the code under test makes.
func withFailingDraw(t *testing.T) {
	t.Helper()
	real := rand.Reader
	failed := false
	rand.Reader = readerFunc(func(p []byte) (int, error) {
		if !failed {
			failed = true
			return 0, errShort
		}
		return real.Read(p)
	})
	t.Cleanup(func() { rand.Reader = real })
}

type readerFunc func([]byte) (int, error)

func (r readerFunc) Read(p []byte) (int, error) { return r(p) }

func TestNewEntriesStopWhenTheirRandomDrawFails(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Delete(MACKeyName))
	withFailingDraw(t)
	if err := ensureMACKey(x.b.V); !errors.Is(err, errShort) {
		t.Fatalf("ensureMACKey: %v", err)
	}
	if _, ok := entryKind(x.b.V, MACKeyName); ok {
		t.Fatal("a MAC key was stored from a failed draw")
	}
	// No forget key: the draw for its counter authorization fails.
	y := newBox(t)
	must(t, y.b.V.Delete(ForgetKeyName))
	withFailingDraw(t)
	if err := ensureForgetLog(y.b.V, y.rk, nil); !errors.Is(err, errShort) {
		t.Fatalf("no forget key: %v", err)
	}
	if _, ok := entryKind(y.b.V, ForgetKeyName); ok {
		t.Fatal("a forget key was stored from a failed draw")
	}
	// No log: the draw for its ID fails.
	z := newBox(t)
	must(t, z.b.V.Delete(ForgetLogName))
	withFailingDraw(t)
	if err := ensureForgetLog(z.b.V, z.rk, nil); !errors.Is(err, errShort) {
		t.Fatalf("no forget log: %v", err)
	}
	if _, ok := entryKind(z.b.V, ForgetLogName); ok {
		t.Fatal("a forget log was stored from a failed draw")
	}
}
