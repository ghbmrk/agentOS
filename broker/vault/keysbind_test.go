package vault

import (
	"errors"
	"os"
	"testing"
)

// REQ: CRED-8, CRED-9

func putFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// F1: an earlier keys file put back beside the current vault would bring
// back a removed trusted-host slot. The vault records the keys file it goes
// with, so every factor is refused with that file instead.
func TestOldKeysFileIsRefused(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	alpha := newHost("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	withAlpha := readBytes(t, kp)
	if n, err := v.RemoveSlots(SlotTPM, sameHost(alpha)); err != nil || n != 1 {
		t.Fatalf("RemoveSlots: %d, %v", n, err)
	}
	v.Close()

	putFile(t, kp, withAlpha)
	for name, f := range map[string]Factor{"removed host": alpha, "passphrase": Passphrase(testPass)} {
		if _, err := OpenSealed(vp, kp, f); !errors.Is(err, ErrRolledBack) {
			t.Fatalf("%s with the earlier keys file: %v", name, err)
		}
	}
}

// Every slot change is a vault write, so on an anchored PC it advances the
// counter: the earlier vault with its own earlier keys file is caught by
// Bind.
func TestSlotChangeAdvancesTheCounter(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	pc := newPC("beta")
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	alpha := newHost("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	oldVault, oldKeys := readBytes(t, vp), readBytes(t, kp)
	if _, err := v.RemoveSlots(SlotTPM, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	v.Close()

	putFile(t, vp, oldVault)
	putFile(t, kp, oldKeys)
	w, err := OpenSealed(vp, kp, alpha)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("pair from before the slot removal: %v", err)
	}
}

// A crash inside a slot change leaves the vault accepting both keys files;
// OpenSealed keeps whichever is on the drive and accepts only it after.
func TestInterruptedSlotChange(t *testing.T) {
	for _, keysWritten := range []bool{false, true} {
		v, vp, kp := openWithPassphrase(t)
		cur := readBytes(t, kp)
		alpha := newHost("alpha")
		if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
			t.Fatal(err)
		}
		next := readBytes(t, kp)
		// Back to the first step of the change: the vault accepts both.
		v.mu.Lock()
		v.keysOK = [][]byte{keysHash(cur), keysHash(next)}
		if err := v.save(); err != nil {
			t.Fatal(err)
		}
		v.mu.Unlock()
		v.Close()
		onDrive, other := cur, next
		if keysWritten {
			onDrive, other = next, cur
		}
		putFile(t, kp, onDrive)

		w, err := OpenSealed(vp, kp, Passphrase(testPass))
		if err != nil {
			t.Fatalf("written=%v: %v", keysWritten, err)
		}
		w.Close()
		putFile(t, kp, other)
		if _, err := OpenSealed(vp, kp, Passphrase(testPass)); !errors.Is(err, ErrRolledBack) {
			t.Fatalf("written=%v: the file not kept still opens: %v", keysWritten, err)
		}
	}
}
