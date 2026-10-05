package tpmseal_test

// REQ: CRED-8, REC-2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

func vaultID(t *testing.T) []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func counterAuth(t *testing.T) []byte {
	return []byte(hex.EncodeToString(vaultID(t)))
}

func srkName(t *testing.T, s *swtpm.TPM) []byte {
	n, err := tpmseal.Identity(s.TPM())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func read(t *testing.T, s *swtpm.TPM, srk []byte, ref tpmseal.CounterRef, auth []byte) uint64 {
	t.Helper()
	n, err := tpmseal.ReadCounter(s.TPM(), srk, ref, auth)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A vault's counter is found only after it is defined, counts up by one,
// and keeps its value across a power cycle (it is not orderly).
func TestCounterDefineReadIncrement(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, auth := srkName(t, s), vaultID(t), counterAuth(t)
	if ok, err := tpmseal.FindCounter(s.TPM(), id); err != nil || ok {
		t.Fatalf("before define: found=%v err=%v", ok, err)
	}
	ref, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := tpmseal.FindCounter(s.TPM(), id); err != nil || !ok {
		t.Fatalf("after define: found=%v err=%v", ok, err)
	}
	n := read(t, s, srk, ref, auth)
	for i := 0; i < 3; i++ {
		if err := tpmseal.IncrementCounter(s.TPM(), srk, ref, auth); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(t, s, srk, ref, auth); got != n+3 {
		t.Fatalf("after 3 increments: %d, want %d", got, n+3)
	}
	s.Reboot()
	if got := read(t, s, srk, ref, auth); got != n+3 {
		t.Fatalf("after power cycle: %d, want %d", got, n+3)
	}
	// Defining again finds the same counter.
	again, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil || again.Handle != ref.Handle {
		t.Fatalf("redefine: %+v, %v", again, err)
	}
	if other, _ := tpmseal.FindCounter(s.TPM(), vaultID(t)); other {
		t.Fatal("another vault ID found this counter")
	}
}

// Only the vault's auth value reads or advances its counter, and wrong
// tries do not spend the TPM's lockout (noDA), which guards the boot PIN.
func TestCounterNeedsItsAuth(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, auth := srkName(t, s), vaultID(t), counterAuth(t)
	ref, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	n := read(t, s, srk, ref, auth)
	wrong := counterAuth(t)
	for i := 0; i < 40; i++ {
		if _, err := tpmseal.ReadCounter(s.TPM(), srk, ref, wrong); err == nil {
			t.Fatal("read with the wrong auth")
		}
		if err := tpmseal.IncrementCounter(s.TPM(), srk, ref, wrong); err == nil {
			t.Fatal("increment with the wrong auth")
		}
	}
	if got := read(t, s, srk, ref, auth); got != n {
		t.Fatalf("counter moved to %d", got)
	}
	// The lockout is untouched: a PIN slot still unseals.
	boot(s, releaseA)
	key := newKey(t)
	sec, sealed, pols := enroll(t, s, key, "2468")
	got, err := tpmseal.Unseal(s.TPM(), sealed, pols, "2468")
	if err != nil || string(got) != string(sec) {
		t.Fatalf("PIN slot after 80 wrong counter auths: %v", err)
	}
}

// Deleting the counter and defining it again cannot lower it: a new TPM
// counter starts at the highest value any counter has had. So an attacker
// with owner access can only stop the vault, not revive an old copy.
func TestRedefinedCounterDoesNotGoBack(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, auth := srkName(t, s), vaultID(t), counterAuth(t)
	ref, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := tpmseal.IncrementCounter(s.TPM(), srk, ref, auth); err != nil {
			t.Fatal(err)
		}
	}
	high := read(t, s, srk, ref, auth)
	if _, err := (tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(ref.Handle), Name: tpm2.TPM2BName{Buffer: ref.Name}},
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	ref2, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, s, srk, ref2, auth); got < high {
		t.Fatalf("redefined counter at %d, below %d", got, high)
	}
}

// Another index sitting on the derived handle is skipped, and a counter
// reference that names one index does not read another.
func TestCounterHandleCollision(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, auth := srkName(t, s), vaultID(t), counterAuth(t)
	ref, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	// Replace it with an ordinary index someone else defined at the same
	// handle, holding whatever value they like.
	h := tpm2.TPMHandle(ref.Handle)
	if _, err := (tpm2.NVUndefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: ref.Name}},
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		Auth:       tpm2.TPM2BAuth{Buffer: auth},
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: h, NameAlg: tpm2.TPMAlgSHA256,
			Attributes: tpm2.TPMANV{NT: tpm2.TPMNTOrdinary, AuthWrite: true, AuthRead: true, NoDA: true},
			DataSize:   8,
		}),
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	name := mustNVName(t, s, h)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: name, Auth: tpm2.PasswordAuth(auth)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: name},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: make([]byte, 8)},
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmseal.ReadCounter(s.TPM(), srk, ref, auth); err == nil {
		t.Fatal("the old reference read an ordinary index")
	}
	if ok, err := tpmseal.FindCounter(s.TPM(), id); err != nil || ok {
		t.Fatalf("ordinary index taken for the counter: %v %v", ok, err)
	}
	ref2, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	if ref2.Handle == ref.Handle {
		t.Fatal("defined over the occupied handle")
	}
	read(t, s, srk, ref2, auth)
}

func mustNVName(t *testing.T, s *swtpm.TPM, h tpm2.TPMHandle) tpm2.TPM2BName {
	rsp, err := tpm2.NVReadPublic{NVIndex: h}.Execute(s.TPM())
	if err != nil {
		t.Fatal(err)
	}
	return rsp.NVName
}

// The counter is used only through this TPM's own storage root key: a
// session salted to a key with another name is refused before the auth
// value is sent.
func TestCounterPinsTheSRK(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, auth := srkName(t, s), vaultID(t), counterAuth(t)
	ref, err := tpmseal.DefineCounter(s.TPM(), srk, id, auth)
	if err != nil {
		t.Fatal(err)
	}
	other := swtpm.Start(t)
	if _, err := tpmseal.ReadCounter(s.TPM(), srkName(t, other), ref, auth); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("read with another SRK name: %v", err)
	}
	if _, err := tpmseal.DefineCounter(s.TPM(), srkName(t, other), vaultID(t), auth); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("define with another SRK name: %v", err)
	}
}
