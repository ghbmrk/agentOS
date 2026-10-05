package vault

import (
	"bytes"
	"encoding/json"
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

// crashAt makes the n-th sealed-next-keys step crash (crashKeysSealed),
// for the rest of the test.
func crashAt(t *testing.T, n int) {
	seen := 0
	crashPoint = func(s int) error {
		if s == crashKeysSealed {
			if seen++; seen == n {
				return errors.New("crash")
			}
		}
		return nil
	}
	t.Cleanup(func() { crashPoint = func(int) error { return nil } })
}

// A crash after a slot change sealed the next keys file rolls forward at
// the next OpenSealed, whichever keys file is on the drive.
func TestInterruptedSlotChange(t *testing.T) {
	for _, onDrive := range []string{"before", "after"} {
		v, vp, kp := openWithPassphrase(t)
		cur := readBytes(t, kp)
		alpha := newHost("alpha")
		crashAt(t, 1)
		if err := v.AddSlot(alpha, sameHost(alpha)); err == nil {
			t.Fatal("no crash")
		}
		next := v.nextKeys
		v.Close()
		crashPoint = func(int) error { return nil }
		if onDrive == "after" {
			// The keys file write landed; the last vault write did not.
			putFile(t, kp, next)
		}
		w, err := OpenSealed(vp, kp, Passphrase(testPass))
		if err != nil {
			t.Fatalf("%s: %v", onDrive, err)
		}
		w.Close()
		if _, err := OpenSealed(vp, kp, alpha); err != nil {
			t.Fatalf("%s: added slot after roll-forward: %v", onDrive, err)
		}
		putFile(t, kp, cur)
		if _, err := OpenSealed(vp, kp, Passphrase(testPass)); !errors.Is(err, ErrRolledBack) {
			t.Fatalf("%s: the file before still opens: %v", onDrive, err)
		}
	}
}

// L3 round 2: a crash after the next keys file was written but before the
// vault recorded it must not let the file before back in. A removed
// trusted-host slot, put back with that file, opens nothing, and any
// other unlock rolls forward to the file without it.
func TestRemovedSlotCannotReturnMidChange(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	alpha := newHost("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	withAlpha := readBytes(t, kp)
	// Crash after step 2: the keys file without alpha is on the drive.
	v.mu.Lock()
	kf, err := v.slotsForChange()
	if err != nil {
		t.Fatal(err)
	}
	var keep []Slot
	for _, s := range kf.Slots {
		if s.Kind != SlotTPM {
			keep = append(keep, s)
		}
	}
	next, _ := json.Marshal(&keyFile{Magic: kf.Magic, Version: kf.Version, Slots: keep})
	v.nextKeys = next
	if err := v.save(); err != nil {
		t.Fatal(err)
	}
	v.mu.Unlock()
	v.Close()
	putFile(t, kp, next)

	putFile(t, kp, withAlpha) // the attacker's copy
	if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("removed slot with the file before: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if !bytes.Equal(readBytes(t, kp), next) {
		t.Fatal("did not roll forward to the file without the removed slot")
	}
	putFile(t, kp, withAlpha)
	if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("after roll-forward: %v", err)
	}
}

// The same for re-encryption: a crash after the new-slots-only file was
// sealed leaves nothing an old keys file can open, and the card rolls
// forward to the new key's slots.
func TestReencryptCrashBeforeLastKeysWrite(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	alpha := newHost("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	old := readBytes(t, kp)
	crashAt(t, 2) // 1: both sets; 2: new slots only
	if _, err := v.Reencrypt(Passphrase(testPass)); err == nil {
		t.Fatal("no crash")
	}
	v.Close()
	crashPoint = func(int) error { return nil }

	putFile(t, kp, old)
	for name, f := range map[string]Factor{"dropped host": alpha, "old card slot": Passphrase(testPass)} {
		if _, err := OpenSealed(vp, kp, f); !errors.Is(err, ErrNoSlotOpens) && !errors.Is(err, ErrRolledBack) {
			t.Fatalf("%s with the keys file before re-encryption: %v", name, err)
		}
	}
}
