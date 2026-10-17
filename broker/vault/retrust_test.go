package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// REQ: CRED-8, CRED-9

// VAULT-RETRUST (#1847): re-trusting a PC already trusted replaces its
// TPM slot. A crash after the change sealed the next keys file and before
// it wrote it leaves the file before on the drive, whose old slot still
// opens; the PC's own factor must roll the change forward, not be refused.

var errPIN = errors.New("tpm: wrong pin")

// pinHost is hostFactor with a PIN: a slot sealed on this PC under another
// PIN fails the unlock (a TPM authorisation failure counts toward lockout)
// instead of being skipped. fails counts those failures.
type pinHost struct {
	host, pin string
	fails     *int
}

func newPinHost(host, pin string, fails *int) pinHost { return pinHost{host, pin, fails} }

func (pinHost) Kind() string { return SlotTPM }

func (h pinHost) Enroll() (Slot, []byte, error) {
	return Slot{Kind: SlotTPM, Sealed: []byte(h.host + "|" + h.pin)}, bytes.Repeat([]byte(h.host[:1]), KeySize), nil
}

func (h pinHost) KEK(s Slot) ([]byte, error) {
	host, pin, _ := strings.Cut(string(s.Sealed), "|")
	if host != h.host {
		return nil, ErrSkipSlot
	}
	if pin != h.pin {
		*h.fails++
		return nil, errPIN
	}
	return bytes.Repeat([]byte(h.host[:1]), KeySize), nil
}

func samePinHost(host string) func(Slot) bool {
	return func(s Slot) bool { h, _, _ := strings.Cut(string(s.Sealed), "|"); return h == host }
}

// interruptedChange runs change on v with a crash after the seal, closes v
// and returns the keys file before the change and the sealed next file.
func interruptedChange(t *testing.T, v *Vault, kp string, change func(*Vault) error) (before, next []byte) {
	t.Helper()
	before = readBytes(t, kp)
	crashAt(t, 1)
	if err := change(v); !errors.Is(err, ErrSlotDecided) {
		t.Fatalf("no crash after the seal: %v", err)
	}
	next = v.nextKeys
	v.Close()
	crashPoint = func(int) error { return nil }
	return before, next
}

// Stage by outcome: a same-PC re-trust interrupted after the seal, with
// the file before or the file after on the drive, opens with that PC's
// factor alone (unattended restart), rolls forward, and the file before
// put back afterwards is refused.
func TestInterruptedSameHostRetrustRollsForward(t *testing.T) {
	for _, onDrive := range []string{"before", "after"} {
		v, vp, kp := openWithPassphrase(t)
		alpha := newHost("alpha")
		if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
			t.Fatal(err)
		}
		before, next := interruptedChange(t, v, kp, func(v *Vault) error { return v.AddSlot(alpha, sameHost(alpha)) })
		if onDrive == "after" {
			putFile(t, kp, next)
		}
		w, err := OpenSealed(vp, kp, alpha)
		if err != nil {
			t.Fatalf("%s: re-trusted PC refused after the crash: %v", onDrive, err)
		}
		if w.nextKeys != nil || !bytes.Equal(readBytes(t, kp), next) {
			t.Fatalf("%s: did not roll forward", onDrive)
		}
		if _, ok := w.Secret("openai"); !ok {
			t.Fatalf("%s: entry lost after roll-forward", onDrive)
		}
		w.Close()
		if _, err := OpenSealed(vp, kp, alpha); err != nil {
			t.Fatalf("%s: second open: %v", onDrive, err)
		}
		putFile(t, kp, before)
		if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrRolledBack) {
			t.Fatalf("%s: the file before still opens: %v", onDrive, err)
		}
	}
}

// Control: a removal interrupted after the seal adds no slot, so the
// removed PC's old slot, still in the file before, opens nothing; the
// passphrase rolls the removal forward.
func TestInterruptedRemovalStillRefusesTheRemovedHost(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	alpha := newHost("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	_, next := interruptedChange(t, v, kp, func(v *Vault) error {
		_, err := v.RemoveSlots(SlotTPM, sameHost(alpha))
		return err
	})
	if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("removed host opened mid-change: %v", err)
	}
	w, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if !bytes.Equal(readBytes(t, kp), next) {
		t.Fatal("did not roll forward to the file without alpha")
	}
}

// Control: a change that drops alpha's slot and adds another PC's opens
// nothing for alpha: its factor must open the added slot, and another PC's
// is skipped.
func TestReplacementByAnotherHostDoesNotOpen(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	alpha, beta := newHost("alpha"), newHost("beta")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	interruptedChange(t, v, kp, func(v *Vault) error { return v.AddSlot(beta, sameHost(alpha)) })
	if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("alpha opened through beta's replacement: %v", err)
	}
	if _, err := OpenSealed(vp, kp, beta); err != nil {
		t.Fatalf("beta: %v", err)
	}
}

// PINs: a re-trust keeping the PIN rolls forward with it. A wrong PIN
// fails once, as before: it opens no slot in the file before, so the
// added slot is never asked. A re-trust that changed the PIN (old PIN
// opens the old slot, the new slot refuses it) asks the TPM once more and
// fails closed (ErrNoSlotOpens); the new PIN fails on the old slot and the
// staged file is not tried, so neither PIN doubles its attempts.
func TestInterruptedRetrustWithPIN(t *testing.T) {
	t.Run("same PIN", func(t *testing.T) {
		fails := 0
		v, vp, kp := openWithPassphrase(t)
		a := newPinHost("alpha", "1234", &fails)
		if err := v.AddSlot(a, samePinHost("alpha")); err != nil {
			t.Fatal(err)
		}
		interruptedChange(t, v, kp, func(v *Vault) error { return v.AddSlot(a, samePinHost("alpha")) })
		if _, err := OpenSealed(vp, kp, newPinHost("alpha", "9999", &fails)); !errors.Is(err, errPIN) || fails != 1 {
			t.Fatalf("wrong PIN: %v, %d TPM failures", err, fails)
		}
		if _, err := OpenSealed(vp, kp, a); err != nil || fails != 1 {
			t.Fatalf("same PIN: %v, %d TPM failures", err, fails)
		}
	})
	t.Run("changed PIN", func(t *testing.T) {
		fails := 0
		v, vp, kp := openWithPassphrase(t)
		if err := v.AddSlot(newPinHost("alpha", "1234", &fails), samePinHost("alpha")); err != nil {
			t.Fatal(err)
		}
		interruptedChange(t, v, kp, func(v *Vault) error {
			return v.AddSlot(newPinHost("alpha", "5678", &fails), samePinHost("alpha"))
		})
		if _, err := OpenSealed(vp, kp, newPinHost("alpha", "1234", &fails)); !errors.Is(err, ErrNoSlotOpens) || fails != 1 {
			t.Fatalf("old PIN: %v, %d TPM failures", err, fails)
		}
		if _, err := OpenSealed(vp, kp, newPinHost("alpha", "5678", &fails)); !errors.Is(err, errPIN) || fails != 2 {
			t.Fatalf("new PIN: %v, %d TPM failures", err, fails)
		}
		if _, err := OpenSealed(vp, kp, Passphrase(testPass)); err != nil {
			t.Fatalf("passphrase recovers: %v", err)
		}
		if _, err := OpenSealed(vp, kp, newPinHost("alpha", "5678", &fails)); err != nil {
			t.Fatalf("new PIN after roll-forward: %v", err)
		}
	})
}
