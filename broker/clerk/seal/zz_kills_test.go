package seal

// REQ: STO-2, CLK-1, HW-5a, REC-4

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// killRecovery is a fresh recovery factor whose key is n bytes of fill.
func killRecovery(fill byte, n int) Recovery {
	return Recovery{Key: secret.Hide(slices.Repeat([]byte{fill}, n))}
}

// killStore is a real store (real file writes) with one recovery slot.
func killStore(t *testing.T) (string, *Store, Recovery) {
	t.Helper()
	r := killRecovery(0x5a, RecoveryLen)
	path := filepath.Join(t.TempDir(), "store")
	s, err := Create(path, r)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return path, s, r
}

// killTPM is a booted software TPM, a policy key and n boot paths it signed: the first is the
// current boot, the rest predicted ones.
func killTPM(t *testing.T, n int) (*swtpm.TPM, *ecdsa.PrivateKey, []tpmseal.Policy) {
	t.Helper()
	sw := swtpm.Start(t)
	sw.Reboot()
	sw.Measure(9, "initrd-A")
	sw.Measure(12, "usrhash=aaaa quiet")
	key, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpmseal.SignCurrent(sw.TPM(), key, []uint{9, 12})
	if err != nil {
		t.Fatal(err)
	}
	ps := []tpmseal.Policy{p}
	for i := 1; i < n; i++ {
		q, err := tpmseal.Sign(key, []uint{9, 12}, [][]byte{swtpm.Predict(fmt.Sprintf("initrd-%d", i)), swtpm.Predict("usrhash=bbbb quiet")})
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, q)
	}
	return sw, key, ps
}

// A closed store refuses every call that needs its key with ErrClosed, and writes nothing
// (STO-2, CLK-1): Anchor, AddSlot, RemoveSlot, SetPolicies and HeadKey.
func TestAClosedStoreRefusesEveryKeyedCall(t *testing.T) {
	path, s, r := killStore(t)
	id := s.Slots()[0].ID
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	a, err1 := s.Anchor()
	sid, err2 := s.AddSlot(killRecovery(1, RecoveryLen))
	err3 := s.RemoveSlot(id)
	err4 := s.SetPolicies(id, nil)
	hk, err5 := s.HeadKey()
	for i, err := range []error{err1, err2, err3, err4, err5} {
		if !errors.Is(err, ErrClosed) {
			t.Errorf("call %d on a closed store: %v, want ErrClosed", i+1, err)
		}
	}
	if a != nil || sid != "" || hk != nil {
		t.Errorf("a closed store returned %x, %q, %x", a, sid, hk)
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
		t.Errorf("a call on a closed store changed the file (%v)", err)
	}
	if u, err := Unlock(path, r); err != nil || len(u.Slots()) != 1 {
		t.Fatalf("after the refused calls: %v", err)
	} else {
		u.Close()
	}
}

// HeadKey wipes the seed it derived, once (CLK-1).
func TestHeadKeyWipesItsSeed(t *testing.T) {
	_, s, _ := killStore(t)
	held := refusalWipes(t)
	k, err := s.HeadKey()
	if err != nil {
		t.Fatal(err)
	}
	seed := derive(s.key.Get(), s.f.ID, "head", keyLen)
	if string(k.Seed()) != string(seed) || refusalCount(*held, seed) != 1 {
		t.Errorf("HeadKey wiped its seed %d times, want once", refusalCount(*held, seed))
	}
}

// A store holds MaxSlots slots and no more; an unknown slot is ErrNoSlot to RemoveSlot and
// SetPolicies, and so is a slot that is not a tpm slot to SetPolicies (STO-2).
func TestSlotBounds(t *testing.T) {
	path, s, r := killStore(t)
	for i := 1; i < MaxSlots; i++ {
		if _, err := s.AddSlot(killRecovery(byte(i), RecoveryLen)); err != nil {
			t.Fatalf("slot %d of %d: %v", i+1, MaxSlots, err)
		}
	}
	if id, err := s.AddSlot(killRecovery(0xee, RecoveryLen)); err == nil || id != "" || len(s.Slots()) != MaxSlots {
		t.Fatalf("slot %d: %q, %v; want a refusal", MaxSlots+1, id, err)
	}
	if err := s.RemoveSlot("0000000000000000"); !errors.Is(err, ErrNoSlot) {
		t.Errorf("RemoveSlot of an unknown slot: %v, want ErrNoSlot", err)
	}
	if err := s.SetPolicies("0000000000000000", nil); !errors.Is(err, ErrNoSlot) {
		t.Errorf("SetPolicies of an unknown slot: %v, want ErrNoSlot", err)
	}
	if err := s.SetPolicies(s.Slots()[0].ID, nil); !errors.Is(err, ErrNoSlot) {
		t.Errorf("SetPolicies of a recovery slot: %v, want ErrNoSlot", err)
	}
	if u, err := Unlock(path, r); err != nil || len(u.Slots()) != MaxSlots {
		t.Fatalf("a full store: %v", err)
	} else {
		u.Close()
	}
}

// A slot write that fails before its rename returns no slot ID; one whose rename is done returns
// its ID with the directory sync's error, wherever the slot sits (REC-4).
func TestASlotIDIsReturnedOnlyOnceInPlace(t *testing.T) {
	path, s, _ := killStore(t)
	fail := errors.New("disk full")
	restore := FailWrite(fail)
	id, err := s.AddSlot(killRecovery(1, RecoveryLen))
	restore()
	if id != "" || !errors.Is(err, fail) || len(s.Slots()) != 1 {
		t.Fatalf("a failed write: %q, %v, %d slots; want no ID", id, err, len(s.Slots()))
	}
	r2 := killRecovery(2, RecoveryLen)
	restore = FailDirSync(fail)
	id, err = s.Replace(s.Slots()[0].ID, r2) // the new slot is at index 0
	restore()
	if id == "" || !errors.Is(err, fail) || s.Slots()[0].ID != id {
		t.Fatalf("a renamed write with a failed sync: %q, %v; want the slot's ID", id, err)
	}
	if u, err := Unlock(path, r2); err != nil {
		t.Fatal(err)
	} else {
		u.Close()
	}
}

// Create checks for an existing file before it makes a slot or writes, refuses a factor it
// cannot make a slot for, and reports its write's and its directory sync's errors (STO-2).
func TestCreateRefusals(t *testing.T) {
	path, _, _ := killStore(t)
	fail := errors.New("disk full")
	restore := FailWrite(fail)
	_, err := Create(path, killRecovery(1, RecoveryLen))
	restore()
	if !errors.Is(err, ErrExists) {
		t.Errorf("Create over a store with writes failing: %v, want ErrExists before any write", err)
	}
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	if s, err := Create(short, killRecovery(1, RecoveryLen-1)); err == nil || s != nil {
		t.Errorf("Create with a short recovery key: %v", err)
	}
	restore = FailWrite(fail)
	_, err = Create(filepath.Join(dir, "nowrite"), killRecovery(1, RecoveryLen))
	restore()
	if !errors.Is(err, fail) {
		t.Errorf("Create with its write failing: %v, want the write's error", err)
	}
	restore = FailDirSync(fail)
	s, err := Create(filepath.Join(dir, "nosync"), killRecovery(1, RecoveryLen))
	restore()
	if !errors.Is(err, fail) || s != nil {
		t.Errorf("Create with its directory sync failing: %v, want the sync's error", err)
	}
	if _, err := Create(filepath.Join(dir, "missing", "store"), killRecovery(1, RecoveryLen)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Create in a missing directory: %v, want ErrNotExist", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 1 { // nosync's file is linked in place; nothing else
		t.Errorf("Create left %v", left)
	}
}

// Every store file is mode 0600 whatever the umask, and a write leaves no file open (STO-2).
func TestWritesAreOwnerOnlyAndCloseTheirFiles(t *testing.T) {
	path, s, _ := killStore(t)
	old := syscall.Umask(0o277)
	err := s.Put("x/a", []byte("v"))
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the store file is %v (%v), want 0600", fi.Mode(), err)
	}
	fds := func() int {
		e, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("no /proc/self/fd")
		}
		return len(e)
	}
	n := fds()
	for i := range 8 {
		if err := s.Put("x/a", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if m := fds(); m > n {
		t.Errorf("8 writes left %d more files open", m-n)
	}
}

// A temporary file that cannot be written in full is removed and its error returned: the store
// file is not replaced (STO-2). RLIMIT_FSIZE makes the write fail.
func TestAShortWriteReplacesNothing(t *testing.T) {
	path, s, r := killStore(t)
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Skip(err)
	}
	small := lim
	small.Cur = 64
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &small); err != nil {
		t.Skip(err)
	}
	err := s.Put("x/a", []byte("v"))
	if e := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); e != nil {
		t.Fatal(e)
	}
	if !errors.Is(err, syscall.EFBIG) {
		t.Errorf("a write past RLIMIT_FSIZE: %v, want EFBIG", err)
	}
	if left, _ := os.ReadDir(filepath.Dir(path)); len(left) != 1 {
		t.Errorf("the failed write left %v", left)
	}
	if u, err := Unlock(path, r); err != nil || len(u.Entries()) != 0 {
		t.Fatalf("after a failed write: %v, %v", err, u)
	} else {
		u.Close()
	}
}

// syncDir and readFile report the open's own error (STO-2).
func TestOpenErrorsAreReported(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if err := syncDir(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("syncDir of a missing directory: %v, want ErrNotExist", err)
	}
	if _, err := Unlock(missing, killRecovery(1, RecoveryLen)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Unlock of a missing file: %v, want ErrNotExist", err)
	}
}

// derive and gcm panic on a misuse no caller makes: a key past HKDF's length, a key that is not
// an AES key. open refuses a blob shorter than a nonce as ErrCorrupt, and a blob of only a nonce
// is GCM's own refusal (STO-2).
func TestTheInternalGuards(t *testing.T) {
	for name, f := range map[string]func(){
		"derive past 255 hashes": func() { derive(make([]byte, keyLen), nil, "x", 255*32+1) },
		"gcm with a 31-byte key": func() { gcm(make([]byte, 31)) },
	} {
		func() {
			defer func() {
				// The guard's own error, not a nil dereference past a deleted guard.
				if r, ok := recover().(error); !ok || errors.As(r, new(runtime.Error)) {
					t.Errorf("%s panicked with %v, want its guard's error", name, r)
				}
			}()
			f()
		}()
	}
	key := make([]byte, keyLen)
	if _, err := open(key, make([]byte, 11), nil); !errors.Is(err, ErrCorrupt) {
		t.Errorf("open of 11 bytes: %v, want ErrCorrupt", err)
	}
	if _, err := open(key, make([]byte, 12), nil); err == nil || errors.Is(err, ErrCorrupt) {
		t.Errorf("open of a bare nonce: %v, want GCM's refusal", err)
	}
}

// slotKey refuses a recovery key of the wrong length before any HKDF (REC-1, STO-2).
func TestSlotKeyRefusesAShortRecoveryKey(t *testing.T) {
	sl, err := makeSlot(make([]byte, idLen), make([]byte, keyLen), killRecovery(1, RecoveryLen))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{RecoveryLen - 1, RecoveryLen + 1} {
		if k, err := slotKey(&sl, killRecovery(1, n)); !errors.Is(err, ErrWrongFactor) || k != nil {
			t.Errorf("slotKey with a %d-byte recovery key: %x, %v; want ErrWrongFactor", n, k, err)
		}
	}
}

// A passphrase of exactly MinPassphrase bytes makes a slot (STO-2).
func TestAPassphraseOfTheMinimumLength(t *testing.T) {
	path, s, _ := killStore(t)
	p := Passphrase{Phrase: secret.Hide([]byte(strings.Repeat("p", MinPassphrase)))}
	if _, err := s.AddSlot(p); err != nil {
		t.Fatalf("a %d-byte passphrase: %v", MinPassphrase, err)
	}
	if u, err := Unlock(path, p); err != nil {
		t.Fatal(err)
	} else {
		u.Close()
	}
}

// encode writes a file of exactly MaxFile bytes and refuses one past it. The file's version
// (which parse checks, not encode) and one value's length are tuned to land on MaxFile.
func TestEncodeTakesExactlyMaxFile(t *testing.T) {
	_, s, _ := killStore(t)
	size := func(v int, name string, n int) (int, error) {
		nf := s.f
		nf.V = v
		b, err := s.encode(nf, map[string][]byte{name: make([]byte, n)})
		return len(b), err
	}
	base, err := size(1, "x/b", 0)
	if err != nil {
		t.Fatal(err)
	}
	guess := (MaxFile - base) * 9 / 16
	for _, v := range []int{1, 10, 100, 1000} {
		for _, name := range []string{"x/b", "x/bb", "x/bbb"} {
			for n := guess - 12; n < guess+12; n++ {
				if got, err := size(v, name, n); err == nil && got == MaxFile {
					if _, err := size(v, name, n+3); err == nil {
						t.Fatalf("encode took a file past MaxFile")
					}
					return
				}
			}
		}
	}
	t.Fatal("no file of exactly MaxFile bytes was taken")
}

// The TPM factor's bounds (HW-5a): a tpm slot keeps 1 to MaxPolicies boot paths, each signed by
// the policy key, at enrollment (makeSlot), at SetPolicies and when the file is parsed; Slots
// reports each slot's policy key and a copy of its boot paths. Each tpm slot makeSlot seals
// wipes the key it sealed, once (CLK-1).
func TestTPMSlotBounds(t *testing.T) {
	sw, key, ps := killTPM(t, MaxPolicies+1)
	r := killRecovery(0x5a, RecoveryLen)
	path := filepath.Join(t.TempDir(), "store")
	f := TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Policies: ps[:MaxPolicies], Host: "Test PC"}
	s, err := Create(path, f) // the tpm slot is at index 0
	if err != nil {
		t.Fatalf("a tpm slot with %d boot paths: %v", MaxPolicies, err)
	}
	defer s.Close()
	if _, err := s.AddSlot(r); err != nil {
		t.Fatal(err)
	}
	id := s.Slots()[0].ID
	if u, err := Unlock(path, r); err != nil { // parse takes MaxPolicies boot paths
		t.Fatalf("a store whose tpm slot holds %d boot paths: %v", MaxPolicies, err)
	} else {
		u.Close()
	}
	if err := s.SetPolicies(id, ps[1:]); err != nil {
		t.Fatalf("SetPolicies with %d boot paths at slot 0: %v", MaxPolicies, err)
	}
	for name, bad := range map[string][]tpmseal.Policy{"none": nil, "too many": ps} {
		if err := s.SetPolicies(id, bad); err == nil {
			t.Errorf("SetPolicies with %s boot paths was taken", name)
		}
	}
	other, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := tpmseal.SignCurrent(sw.TPM(), other, []uint{9, 12})
	if err != nil {
		t.Fatal(err)
	}
	for name, g := range map[string]TPM{
		"no TPM":           {PolicyKey: &key.PublicKey, Policies: ps[:1]},
		"no policy key":    {TPM: sw.TPM(), Policies: ps[:1]},
		"no boot path":     {TPM: sw.TPM(), PolicyKey: &key.PublicKey},
		"too many":         {TPM: sw.TPM(), PolicyKey: &key.PublicKey, Policies: ps},
		"another's signed": {TPM: sw.TPM(), PolicyKey: &key.PublicKey, Policies: []tpmseal.Policy{ps[0], foreign}},
	} {
		if sid, err := s.AddSlot(g); err == nil || sid != "" {
			t.Errorf("a tpm slot with %s was made", name)
		}
	}

	got := s.Slots()
	if got[0].PolicyKey == nil || !got[0].PolicyKey.Equal(&key.PublicKey) || got[0].Host != "Test PC" || len(got[0].Policies) != MaxPolicies {
		t.Fatalf("Slots()[0] = %+v", got[0])
	}
	got[0].Policies[0].PCRs[0], got[0].Policies[0].Digest[0], got[0].Policies[0].Signature[0] = 99, ^got[0].Policies[0].Digest[0], ^got[0].Policies[0].Signature[0]
	again := s.Slots()[0].Policies[0]
	if again.PCRs[0] == 99 || again.Digest[0] == got[0].Policies[0].Digest[0] || again.Signature[0] == got[0].Policies[0].Signature[0] {
		t.Error("a change to Slots' boot paths reached the store")
	}

	// A tpm slot whose policy key does not parse: SetPolicies reports the parse error.
	bad := []byte("not a key")
	_, want := x509.ParsePKIXPublicKey(bad)
	sealed := *s.f.Slots[0].Sealed
	sealed.PolicyKey = bad
	s.f.Slots[0].Sealed = &sealed
	if err := s.SetPolicies(id, ps[:1]); err == nil || want == nil || err.Error() != want.Error() {
		t.Errorf("SetPolicies on a slot whose key does not parse: %v, want %v", err, want)
	}

	held := refusalWipes(t)
	sl, err := makeSlot(make([]byte, idLen), make([]byte, keyLen), f)
	if err != nil {
		t.Fatal(err)
	}
	k, err := slotKey(&sl, f)
	if err != nil {
		t.Fatal(err)
	}
	if n := refusalCount(*held, k); n != 1 {
		t.Errorf("makeSlot wiped the tpm slot's key %d times, want once", n)
	}
}
