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
	staged := readBytes(t, kp+nextSuffix)
	os.Remove(kp + nextSuffix)
	for name, f := range map[string]Factor{"dropped host": alpha, "old card slot": Passphrase(testPass)} {
		if _, err := OpenSealed(vp, kp, f); !errors.Is(err, ErrNoSlotOpens) && !errors.Is(err, ErrRolledBack) {
			t.Fatalf("%s with the keys file before re-encryption: %v", name, err)
		}
	}
	// With the staged next file beside it, the dropped host still opens
	// nothing; the card opens through the staged file and rolls forward.
	putFile(t, kp+nextSuffix, staged)
	if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("dropped host with the staged file: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatalf("card with the staged file: %v", err)
	}
	w.Close()
	if !bytes.Equal(readBytes(t, kp), staged) {
		t.Fatal("did not roll forward to the staged file")
	}
}

// Defect P2-4d: a passphrase Rekey that crashed right after sealing the
// next keys file left the old file on the drive. The old passphrase's slot
// is not in the next file and the new one's slot was in no file on the
// drive, so neither opened the vault. The next file is now staged beside
// the keys file before the seal, and the new passphrase opens from it.
func TestRekeyCrashAfterSealOpensWithNewPassphrase(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	before := readBytes(t, kp)
	crashAt(t, 1)
	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err == nil {
		t.Fatal("no crash")
	}
	v.Close()
	crashPoint = func(int) error { return nil }
	if !bytes.Equal(readBytes(t, kp), before) {
		t.Fatal("keys file changed before the crash point")
	}

	if _, err := OpenSealed(vp, kp, Passphrase(testPass)); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("old passphrase after the change was decided: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(newPass))
	if err != nil {
		t.Fatalf("new passphrase: %v", err)
	}
	if _, ok := w.Secret("openai"); !ok {
		t.Fatal("entry lost")
	}
	w.Close()
	if _, err := os.Stat(kp + nextSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file left after roll-forward: %v", err)
	}
	w, err = OpenSealed(vp, kp, Passphrase(newPass))
	if err != nil {
		t.Fatalf("new passphrase from the keys file: %v", err)
	}
	w.Close()
}

// The staged file opens nothing unless it is the next file the vault
// sealed: a stale one from a finished change, or one planted beside the
// keys file, is refused.
func TestStagedKeysFileMustMatchTheSeal(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	before := readBytes(t, kp)
	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err != nil {
		t.Fatal(err)
	}
	after := readBytes(t, kp)
	v.Close()

	// The finished change's file staged again, with the file before on
	// the drive: the vault records no change under way.
	putFile(t, kp, before)
	putFile(t, kp+nextSuffix, after)
	if _, err := OpenSealed(vp, kp, Passphrase(newPass)); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("stale staged file: %v", err)
	}

	// Mid-change, a staged file other than the sealed one.
	putFile(t, kp, after)
	os.Remove(kp + nextSuffix)
	w, err := OpenSealed(vp, kp, Passphrase(newPass))
	if err != nil {
		t.Fatal(err)
	}
	crashAt(t, 1)
	if err := w.Rekey(Passphrase(newPass), Passphrase(testPass)); err == nil {
		t.Fatal("no crash")
	}
	staged := readBytes(t, kp+nextSuffix)
	w.Close()
	crashPoint = func(int) error { return nil }
	var kf keyFile
	if err := json.Unmarshal(staged, &kf); err != nil {
		t.Fatal(err)
	}
	kf.Slots = append(kf.Slots, kf.Slots[0])
	planted, _ := json.Marshal(&kf)
	putFile(t, kp+nextSuffix, planted)
	if _, err := OpenSealed(vp, kp, Passphrase(testPass)); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("planted staged file: %v", err)
	}
	putFile(t, kp+nextSuffix, staged)
	if w, err = OpenSealed(vp, kp, Passphrase(testPass)); err != nil {
		t.Fatalf("sealed staged file: %v", err)
	}
	w.Close()
}

// Re-encryption's last slot change, interrupted after its seal, leaves the
// keys file holding both slot sets on the drive. The card opens the new
// key's slot there and rolls forward to the file with only the new slots.
func TestReencryptRollsForwardFromBothSlotSets(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	crashAt(t, 2) // 1: both sets; 2: new slots only
	if _, err := v.Reencrypt(Passphrase(testPass)); err == nil {
		t.Fatal("no crash")
	}
	v.Close()
	crashPoint = func(int) error { return nil }
	kf, err := readKeys(kp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kf.keyID(); !errors.Is(err, ErrReencryptPending) {
		t.Fatalf("drive should hold both slot sets: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatalf("card: %v", err)
	}
	if _, ok := w.Secret("openai"); !ok {
		t.Fatal("entry lost")
	}
	w.Close()
	kf, err = readKeys(kp)
	if err != nil {
		t.Fatal(err)
	}
	id, err := kf.keyID()
	if err != nil || len(kf.Slots) != 1 {
		t.Fatalf("after roll-forward: %d slots, %v", len(kf.Slots), err)
	}
	if want, _ := fileKeyID(vp); !bytes.Equal(id, want) {
		t.Fatal("kept slots are not for the key the vault is under")
	}
	if _, err := os.Stat(kp + nextSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file left: %v", err)
	}
}

// refusingFactor is a passphrase factor whose KEK fails with err, counting
// the calls, as a TPM refusing a PIN would.
type refusingFactor struct {
	err   error
	calls *int
}

func (refusingFactor) Kind() string                  { return SlotPassphrase }
func (refusingFactor) Enroll() (Slot, []byte, error) { return Slot{}, nil, errors.New("unused") }
func (f refusingFactor) KEK(Slot) ([]byte, error) {
	*f.calls++
	return nil, f.err
}

// Security lens C1 on #63: only a plain miss on the keys file looks in the
// staged file. A factor whose KEK fails any other way is asked once, so a
// crashed change does not halve its attempts before lockout.
func TestStagedKeysFileNotTriedAfterFactorError(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	crashAt(t, 1)
	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err == nil {
		t.Fatal("no crash")
	}
	v.Close()
	crashPoint = func(int) error { return nil }
	if _, err := os.Stat(kp + nextSuffix); err != nil {
		t.Fatalf("no staged file: %v", err)
	}
	refused := errors.New("tpm: pin refused")
	calls := 0
	if _, err := OpenSealed(vp, kp, refusingFactor{refused, &calls}); !errors.Is(err, refused) {
		t.Fatalf("factor error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("KEK asked %d times, want 1", calls)
	}
}

// Security lens R1 on #63: a staged file left beside the keys file with no
// change under way is removed at the next open.
func TestStaleStagedKeysFileRemovedOnOpen(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	v.Close()
	putFile(t, kp+nextSuffix, readBytes(t, kp))
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := os.Stat(kp + nextSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale staged file kept: %v", err)
	}
}

// L3 F1 on #63: save can fail after the vault file landed (the directory
// sync failed). The staged file must survive that failure, or the drive
// holds the sealed change, the file before, and nothing the new
// passphrase opens.
func TestRekeySaveFailsAfterRenameKeepsStagedFile(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	afterRename = func(path string) error {
		if path == vp {
			return errors.New("dir sync failed")
		}
		return nil
	}
	t.Cleanup(func() { afterRename = func(string) error { return nil } })
	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err == nil {
		t.Fatal("no failure")
	}
	afterRename = func(string) error { return nil }
	v.Close()
	if _, err := os.Stat(kp + nextSuffix); err != nil {
		t.Fatalf("staged file removed: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(newPass))
	if err != nil {
		t.Fatalf("new passphrase: %v", err)
	}
	w.Close()
}
