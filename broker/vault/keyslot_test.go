package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CRED-8, CRED-1

const testPass = "tulip orbit canary mosaic t-shirt quartz lantern"

// fastKDF lowers the Argon2id floor and default for one test, so the slot
// logic is exercised without paying 256 MiB per derivation. The spec
// parameters are checked separately (TestDefaultKDFMeetsTheSpec) and by
// one full-cost round trip.
func fastKDF(t *testing.T) {
	t.Helper()
	floor, def := kdfFloor, defaultKDF
	kdfFloor = KDF{Time: 1, MemoryKiB: 8, Threads: 1}
	defaultKDF = KDF{Time: 1, MemoryKiB: 8, Threads: 1}
	t.Cleanup(func() { kdfFloor, defaultKDF = floor, def })
}

func sealedPaths(t *testing.T) (string, string) {
	dir := t.TempDir()
	return filepath.Join(dir, "vault"), filepath.Join(dir, "vault.keys")
}

func TestPassphraseSlotOpensTheVault(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	val := canary(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put("openai", KindAPIKey, val); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Scanned or typed: case and runs of whitespace do not matter
	// (card.NormalizePassphrase's canonical form, P2-2). A hyphen inside
	// a word list entry such as "t-shirt" is part of the word.
	for _, typed := range []string{testPass, "  " + strings.ToUpper(testPass) + "\n", strings.ReplaceAll(testPass, " ", " \t ")} {
		v2, err := OpenSealed(vp, kp, Passphrase(typed))
		if err != nil {
			t.Fatalf("%q: %v", typed, err)
		}
		s, ok := v2.Secret("openai")
		if !ok || s.Reveal() != string(val) {
			t.Fatalf("%q: secret not restored", typed)
		}
		v2.Close()
	}
}

func TestWrongPassphraseOpensNothing(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := OpenSealed(vp, kp, Passphrase(strings.ReplaceAll(testPass, "t-shirt", "t shirt"))); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("hyphen dropped: %v", err)
	}
	if _, err := OpenSealed(vp, kp, Passphrase(testPass+"-x")); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := OpenSealed(vp, kp, Passphrase("")); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("empty passphrase: %v", err)
	}
}

// A8: nothing on the drive alone releases the key. The keys file and the
// vault file hold no copy of the data key, the passphrase, or a value
// stored inside (an approval-code seed among them) in any common encoding.
func TestDriveHoldsNoKeyMaterial(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	seed := canary(t)
	if err := v.Put("owner-totp-seed", KindTOTPSeed, seed); err != nil {
		t.Fatal(err)
	}
	v.Close()

	kf, err := readKeys(kp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := kf.unwrap(Passphrase(testPass), nil)
	if err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{key, []byte(testPass), normalize(testPass), seed}
	// Everything the drive holds: the whole state directory, temporary
	// files included.
	files, err := os.ReadDir(filepath.Dir(vp))
	if err != nil || len(files) < 2 {
		t.Fatalf("state dir: %v %v", files, err)
	}
	for _, f := range files {
		path := filepath.Join(filepath.Dir(vp), f.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range secrets {
			for _, form := range [][]byte{s, []byte(hex.EncodeToString(s)), []byte(base64.StdEncoding.EncodeToString(s)), []byte(base64.RawStdEncoding.EncodeToString(s))} {
				if bytes.Contains(raw, form) {
					t.Fatalf("%s holds key material in the clear", f.Name())
				}
			}
		}
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", f.Name(), fi.Mode().Perm())
		}
	}
}

func TestPassphraseBytesAreWipedAfterUse(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	f := Passphrase(testPass)
	v, err := CreateSealed(vp, kp, f)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	g := Passphrase(testPass)
	v, err = OpenSealed(vp, kp, g)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	for _, p := range []Factor{f, g} {
		if bytes.Count(p.(passphrase), []byte{0}) != len(p.(passphrase)) {
			t.Fatal("passphrase bytes left in memory")
		}
	}
}

// The slot's kind and Argon2id parameters are bound into the wrap: a keys
// file edited to relabel or reparameterize a slot opens nothing.
func TestSlotFieldsAreBoundIntoTheWrap(t *testing.T) {
	fastKDF(t)
	edits := map[string]func(*Slot){
		"salt":    func(s *Slot) { s.KDF.Salt[0] ^= 1 },
		"time":    func(s *Slot) { s.KDF.Time++ },
		"wrapped": func(s *Slot) { s.Wrapped[0] ^= 1 },
		"nonce":   func(s *Slot) { s.Nonce[0] ^= 1 },
	}
	for name, edit := range edits {
		vp, kp := sealedPaths(t)
		v, err := CreateSealed(vp, kp, Passphrase(testPass))
		if err != nil {
			t.Fatal(err)
		}
		v.Close()
		kf, err := readKeys(kp)
		if err != nil {
			t.Fatal(err)
		}
		edit(&kf.Slots[0])
		if err := writeKeys(kp, kf); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSealed(vp, kp, Passphrase(testPass)); !errors.Is(err, ErrNoSlotOpens) {
			t.Fatalf("edited %s: %v", name, err)
		}
	}
}

// A keys file can never talk the box into a cheap derivation: a slot below
// the Argon2id floor is refused before any guess is checked, and so is one
// whose cost would exhaust the floor profile's memory.
func TestKDFBoundsAreEnforced(t *testing.T) {
	vp, kp := sealedPaths(t)
	fastKDF(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	kdfFloor = specFloor
	if _, err := OpenSealed(vp, kp, Passphrase(testPass)); err == nil || errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("slot below the floor: %v", err)
	}
	kf, _ := readKeys(kp)
	kf.Slots[0].KDF.MemoryKiB = kdfCeiling.MemoryKiB + 1
	writeKeys(kp, kf)
	if _, err := OpenSealed(vp, kp, Passphrase(testPass)); err == nil || errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("slot above the ceiling: %v", err)
	}
}

func TestDefaultKDFMeetsTheSpec(t *testing.T) {
	// CRED-8: Argon2id with at least 256 MiB.
	if specFloor.MemoryKiB < 256<<10 || defaultKDF.MemoryKiB < specFloor.MemoryKiB || defaultKDF.Time < specFloor.Time || kdfFloor.MemoryKiB != specFloor.MemoryKiB || kdfFloor.Time != specFloor.Time {
		t.Fatalf("default %+v or floor %+v below CRED-8", defaultKDF, kdfFloor)
	}
	if defaultKDF.MemoryKiB > kdfCeiling.MemoryKiB {
		t.Fatal("default above the ceiling")
	}
}

// One round trip at the real cost, so the shipped parameters are exercised.
func TestFullCostRoundTrip(t *testing.T) {
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	kf, _ := readKeys(kp)
	if got := *kf.Slots[0].KDF; got.MemoryKiB != defaultKDF.MemoryKiB || got.Time != defaultKDF.Time || len(got.Salt) < 16 {
		t.Fatalf("slot params %+v", got)
	}
	v, err = OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
}

func TestShortPassphraseIsRefusedAtEnrollment(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	if _, err := CreateSealed(vp, kp, Passphrase("short words")); err == nil {
		t.Fatal("short passphrase enrolled")
	}
	if _, err := os.Stat(vp); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused enrollment left a vault behind")
	}
}

func TestCreateSealedRefusesToReplace(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	before, _ := os.ReadFile(kp)
	if _, err := CreateSealed(vp, kp, Passphrase(testPass)); err == nil {
		t.Fatal("replaced an existing vault")
	}
	if after, _ := os.ReadFile(kp); !bytes.Equal(before, after) {
		t.Fatal("keys file changed")
	}
}

// CRED-8, REC-4: replacing the passphrase needs the old one; afterwards
// only the new one opens this keys file, while a copy taken earlier still
// opens with the old one (rotation protects only against later copies).
func TestRekeyReplacesThePassphrase(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(kp)
	oldVault, _ := os.ReadFile(vp)
	const next = "harbor violet canary signal maple cobalt fern"
	if err := v.Rekey(Passphrase("not-the-passphrase-at-all"), Passphrase(next)); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("rekey without the old passphrase: %v", err)
	}
	if err := v.Rekey(Passphrase(testPass), Passphrase(next)); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if _, err := OpenSealed(vp, kp, Passphrase(testPass)); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("old passphrase still opens: %v", err)
	}
	v, err = OpenSealed(vp, kp, Passphrase(next))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	kf, _ := readKeys(kp)
	if len(kf.Slots) != 1 {
		t.Fatalf("%d slots after rekey, want 1", len(kf.Slots))
	}
	// The earlier keys file beside the current vault is refused (F1);
	// the earlier keys file with its own earlier vault, a whole earlier
	// copy of the drive, still opens with the old passphrase.
	copyPath := kp + ".copy"
	os.WriteFile(copyPath, old, 0o600)
	if _, err := OpenSealed(vp, copyPath, Passphrase(testPass)); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("earlier keys file beside the current vault: %v", err)
	}
	vaultCopy := vp + ".copy"
	os.WriteFile(vaultCopy, oldVault, 0o600)
	v, err = OpenSealed(vaultCopy, copyPath, Passphrase(testPass))
	if err != nil {
		t.Fatalf("earlier copy of both: %v", err)
	}
	v.Close()
}

func writeKeys(path string, kf *keyFile) error {
	raw, err := json.Marshal(kf)
	if err != nil {
		return err
	}
	return writeAtomic(path, raw)
}

// forceKeys installs kf as the keys file and records it in the vault, as
// a slot change would.
func forceKeys(t *testing.T, vp, kp string, f Factor, kf *keyFile) {
	t.Helper()
	v, err := OpenSealed(vp, kp, f)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.replaceKeys(kf); err != nil {
		t.Fatal(err)
	}
}

// The TPM (P2-4b) and recovery-key (REC-1) slots are known kinds that this
// build cannot open yet: a keys file carrying one still loads, the
// passphrase slot still opens, and a rekey leaves them in place. An
// unknown kind fails the whole file closed.
func TestOtherSlotKindsAreKeptAndUnknownKindsRefused(t *testing.T) {
	fastKDF(t)
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	kf, _ := readKeys(kp)
	kf.Slots = append(kf.Slots, Slot{Kind: SlotTPM, Sealed: []byte("opaque tpm blob"), Nonce: make([]byte, 12), Wrapped: make([]byte, 48)})
	forceKeys(t, vp, kp, Passphrase(testPass), kf)
	v, err = OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	const next = "harbor violet canary signal maple cobalt fern"
	if err := v.Rekey(Passphrase(testPass), Passphrase(next)); err != nil {
		t.Fatal(err)
	}
	v.Close()
	kf, _ = readKeys(kp)
	if len(kf.Slots) != 2 || kf.Slots[0].Kind != SlotTPM {
		t.Fatalf("slots after rekey: %+v", kf.Slots)
	}

	kf.Slots = append(kf.Slots, Slot{Kind: "usb-token"})
	writeKeys(kp, kf)
	if _, err := OpenSealed(vp, kp, Passphrase(next)); err == nil {
		t.Fatal("unknown slot kind accepted")
	}
	raw, _ := json.Marshal(map[string]any{"magic": "agentos-vault-keys", "version": 2})
	os.WriteFile(kp, raw, 0o600)
	if _, err := OpenSealed(vp, kp, Passphrase(next)); err == nil {
		t.Fatal("unknown keys version accepted")
	}
}
