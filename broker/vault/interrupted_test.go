package vault

import (
	"errors"
	"os"
	"testing"
)

// REQ: CRED-8, CRED-9

// P2-4g (UX lens on #63): after a passphrase change crashed once the vault
// sealed the next keys file, the old passphrase no longer opens it. That
// refusal says a change was interrupted, so the page can tell the owner
// to try the new passphrase. A passphrase that opens nothing else gets
// the same answer; the new passphrase still opens and finishes the change.
func TestOldPassphraseAfterSealedChangeSaysInterrupted(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	crashAt(t, 1)
	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err == nil {
		t.Fatal("no crash")
	}
	v.Close()
	crashPoint = func(int) error { return nil }

	for name, p := range map[string]string{"old": testPass, "typo": testPass + "x"} {
		_, err := OpenSealed(vp, kp, Passphrase(p))
		if !errors.Is(err, ErrChangeInterrupted) || !errors.Is(err, ErrNoSlotOpens) {
			t.Fatalf("%s passphrase: %v", name, err)
		}
	}
	w, err := OpenSealed(vp, kp, Passphrase(newPass))
	if err != nil {
		t.Fatalf("new passphrase: %v", err)
	}
	if w.ChangeUnfinished() {
		t.Fatal("the change finished, yet reported unfinished")
	}
	w.Close()
	// Finished: a wrong passphrase is plain again.
	if _, err := OpenSealed(vp, kp, Passphrase(testPass)); errors.Is(err, ErrChangeInterrupted) || !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("old passphrase after the change finished: %v", err)
	}
}

// P2-4g: a passphrase change that crashed before the vault sealed it never
// happened. The old passphrase opens, the open vault reports the change
// unfinished (so the page says to change it again), and the staged file
// is gone. The new passphrase, which the vault never took, is a plain
// wrong passphrase, never told to "try your new passphrase".
func TestChangeBeforeSealReportsUnfinished(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	before, beforeVault := readBytes(t, kp), readBytes(t, vp)
	if err := v.Rekey(Passphrase(testPass), Passphrase(newPass)); err != nil {
		t.Fatal(err)
	}
	after := readBytes(t, kp)
	v.Close()
	// The drive as a crash before the seal leaves it.
	putFile(t, vp, beforeVault)
	putFile(t, kp, before)
	putFile(t, kp+nextSuffix, after)

	if _, err := OpenSealed(vp, kp, Passphrase(newPass)); errors.Is(err, ErrChangeInterrupted) || !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("new passphrase the vault never took: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatalf("old passphrase: %v", err)
	}
	if !w.ChangeUnfinished() {
		t.Fatal("the unfinished change was not reported")
	}
	if _, err := os.Stat(kp + nextSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file left: %v", err)
	}
	// Changing it again clears the report.
	if err := w.Rekey(Passphrase(testPass), Passphrase(newPass)); err != nil {
		t.Fatal(err)
	}
	if w.ChangeUnfinished() {
		t.Fatal("still reported after changing it again")
	}
	if err := w.Rekey(Passphrase(newPass), Passphrase(testPass)); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := os.Stat(kp + nextSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged file left: %v", err)
	}
	w, err = OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if w.ChangeUnfinished() {
		t.Fatal("reported again after the staged file was removed")
	}
	w.Close()
}

// P2-4g: only a passphrase change is reported. A trusted-host change
// interrupted the same way leaves the passphrase as it was, so a wrong
// passphrase is plain and an open reports nothing unfinished.
func TestOtherSlotChangeIsNotAPassphraseChange(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	before, beforeVault := readBytes(t, kp), readBytes(t, vp)
	alpha := newHost("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	after := readBytes(t, kp)
	v.Close()
	putFile(t, vp, beforeVault)
	putFile(t, kp, before)
	putFile(t, kp+nextSuffix, after)

	if _, err := OpenSealed(vp, kp, Passphrase(newPass)); errors.Is(err, ErrChangeInterrupted) || !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("wrong passphrase beside a host change: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if w.ChangeUnfinished() {
		t.Fatal("a host change reported as a passphrase change")
	}
	w.Close()
}
