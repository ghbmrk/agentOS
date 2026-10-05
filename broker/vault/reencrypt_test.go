package vault

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// REQ: CRED-8, CRED-9

const newPass = "violet harbor kettle summit ribbon falcon meadow"

// recoveryish stands in for P2-8's recovery-key factor.
type recoveryish struct{ kek []byte }

func (recoveryish) Kind() string { return SlotRecovery }
func (r recoveryish) Enroll() (Slot, []byte, error) {
	return Slot{Kind: SlotRecovery, Sealed: []byte("salt")}, append([]byte(nil), r.kek...), nil
}
func (r recoveryish) KEK(Slot) ([]byte, error) { return append([]byte(nil), r.kek...), nil }

func dataKey(t *testing.T, kp string, f Factor, vp string) []byte {
	t.Helper()
	kf, err := readKeys(kp)
	if err != nil {
		t.Fatal(err)
	}
	id, err := fileKeyID(vp)
	if err != nil {
		t.Fatal(err)
	}
	k, err := kf.unwrap(f, id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func readBytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// R10a: the card is lost together with an earlier keys file. Replacing the
// passphrase alone (Rekey) leaves the old data key opening later copies;
// after Reencrypt the old key and the old keys file open nothing written
// since, and the new passphrase opens everything.
func TestReencryptShutsOutTheOldKey(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	oldKeys := readBytes(t, kp)
	oldKey := dataKey(t, kp, Passphrase(testPass), vp)

	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, "anthropic", "sk-canary-after-rekey")
	if w, err := Open(vp, oldKey); err != nil {
		t.Fatalf("precondition: Rekey alone should leave the old key working: %v", err)
	} else {
		w.Close()
	}

	if n, err := v.Reencrypt(Passphrase(newPass)); err != nil || n != 0 {
		t.Fatalf("Reencrypt: %d, %v", n, err)
	}
	mustPut(t, v, "openai", "sk-canary-after-reenc")
	v.Close()

	if _, err := Open(vp, oldKey); err == nil {
		t.Fatal("old data key opens the re-encrypted vault")
	}
	stale := kp + ".old"
	if err := os.WriteFile(stale, oldKeys, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealed(vp, stale, Passphrase(testPass)); err == nil {
		t.Fatal("old card and old keys file open the re-encrypted vault")
	}
	w, err := OpenSealed(vp, kp, Passphrase(newPass))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, n := range []string{"openai", "anthropic"} {
		if _, ok := w.Secret(n); !ok {
			t.Fatalf("%s lost in re-encryption", n)
		}
	}
	if bytes.Equal(dataKey(t, kp, Passphrase(newPass), vp), oldKey) {
		t.Fatal("data key unchanged")
	}
}

// Every slot is rewrapped under its own key-encryption key: the recovery
// slot and this PC's trusted-host slot keep opening; another PC's slot,
// which no factor here can prove, is dropped and counted.
func TestReencryptRewrapsProvenSlots(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	rec := recoveryish{bytes.Repeat([]byte{9}, KeySize)}
	if err := v.Rekey(Passphrase(testPass), rec); err != nil {
		t.Fatal(err)
	}
	if err := v.Rekey(rec, Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	alpha, beta := newHost("alpha"), newHost("beta")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	if err := v.AddSlot(beta, sameHost(beta)); err != nil {
		t.Fatal(err)
	}
	n, err := v.Reencrypt(Passphrase(testPass), rec, alpha)
	if err != nil || n != 1 {
		t.Fatalf("Reencrypt: dropped %d, %v; want 1 (beta)", n, err)
	}
	v.Close()
	for name, f := range map[string]Factor{"passphrase": Passphrase(testPass), "recovery": rec, "alpha": alpha} {
		w, err := OpenSealed(vp, kp, f)
		if err != nil {
			t.Fatalf("%s after Reencrypt: %v", name, err)
		}
		w.Close()
	}
	if _, err := OpenSealed(vp, kp, beta); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("dropped PC: %v", err)
	}
}

// An owner slot no factor proves refuses the call, with nothing changed: a
// wrong passphrase, or a recovery slot whose key was not given.
func TestReencryptNeedsEveryOwnerSlot(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	defer v.Close()
	rec := recoveryish{bytes.Repeat([]byte{9}, KeySize)}
	if err := v.Rekey(Passphrase(testPass), rec); err != nil {
		t.Fatal(err)
	}
	keys, vault := readBytes(t, kp), readBytes(t, vp)
	for name, fs := range map[string][]Factor{
		"recovery missing": {Passphrase(testPass)},
		"wrong passphrase": {Passphrase(newPass), rec},
		"wrong recovery":   {Passphrase(testPass), recoveryish{bytes.Repeat([]byte{8}, KeySize)}},
	} {
		if _, err := v.Reencrypt(fs...); !errors.Is(err, ErrSlotNotProven) {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(keys, readBytes(t, kp)) || !bytes.Equal(vault, readBytes(t, vp)) {
			t.Fatalf("%s: files changed", name)
		}
	}
	mustPut(t, v, "openai", "sk-canary-still-open")
}

// A crash at either point between Reencrypt's writes leaves a vault the
// card opens; the next OpenSealed drops the slots for the key the file is
// not under, after which Rekey works again.
func TestReencryptCrashSafety(t *testing.T) {
	for _, step := range []int{1, 2} {
		v, vp, kp := openWithPassphrase(t)
		crashPoint = func(s int) error {
			if s == step {
				return errors.New("crash")
			}
			return nil
		}
		_, err := v.Reencrypt(Passphrase(testPass))
		crashPoint = func(int) error { return nil }
		if err == nil {
			t.Fatal("no crash")
		}
		if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); !errors.Is(err, ErrReencryptPending) {
			t.Fatalf("step %d: Rekey with two keys' slots: %v", step, err)
		}
		v.Close()
		w, err := OpenSealed(vp, kp, Passphrase(testPass))
		if err != nil {
			t.Fatalf("step %d: card no longer opens: %v", step, err)
		}
		if _, ok := w.Secret("openai"); !ok {
			t.Fatalf("step %d: entry lost", step)
		}
		slots, _ := ReadSlots(kp)
		if len(slots) != 1 {
			t.Fatalf("step %d: %d slots after recovery, want 1", step, len(slots))
		}
		if err := w.Rekey(Passphrase(testPass), Passphrase(newPass)); err != nil {
			t.Fatalf("step %d: Rekey after recovery: %v", step, err)
		}
		w.Close()
		w, err = OpenSealed(vp, kp, Passphrase(newPass))
		if err != nil {
			t.Fatalf("step %d: new passphrase: %v", step, err)
		}
		w.Close()
	}
}

// A rollback counter bound to the vault advances with the re-encrypting
// write, and the re-encrypted file binds afterwards.
func TestReencryptKeepsTheRollbackBinding(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	pc := newPC("alpha")
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Reencrypt(Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	v.Close()
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Bind(pc); err != nil {
		t.Fatalf("re-encrypted vault: %v", err)
	}
	w.Close()
}
