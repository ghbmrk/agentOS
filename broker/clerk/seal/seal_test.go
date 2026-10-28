package seal_test

// REQ: STO-2, A8, HW-5a, CLK-1, REC-4, BAK-1

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func recovery(t *testing.T) seal.Recovery {
	return seal.Recovery{Key: random(t, seal.RecoveryLen)}
}

func create(t *testing.T, f seal.Factor) (string, *seal.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	s, err := seal.Create(path, f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return path, s
}

func unlock(t *testing.T, path string, f seal.Factor) *seal.Store {
	t.Helper()
	s, err := seal.Unlock(path, f)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// The same store opened twice derives the same keys: the log written under
// one boot opens under the next.
func sameKeys(t *testing.T, a, b *seal.Store) {
	t.Helper()
	ka, err := a.LogKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.LogKey()
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb {
		t.Fatal("the log key changed between unlocks")
	}
}

func TestRecoveryRoundTrip(t *testing.T) {
	r := recovery(t)
	path, s := create(t, r)
	sameKeys(t, s, unlock(t, path, r))
	if _, err := seal.Unlock(path, recovery(t)); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("another recovery key: got %v, want ErrWrongFactor", err)
	}
	if _, err := seal.Unlock(path, seal.Passphrase{Phrase: []byte("seven words from the card here")}); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("a passphrase on a store without one: got %v, want ErrNoSlot", err)
	}
}

func TestCreateRefusesAnExistingStore(t *testing.T) {
	path, _ := create(t, recovery(t))
	if _, err := seal.Create(path, recovery(t)); !errors.Is(err, seal.ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

// STO-2: a wrong passphrase does not unlock; a passphrase slot added and
// then removed no longer unlocks; Replace retires the old passphrase.
func TestPassphraseSlot(t *testing.T) {
	r := recovery(t)
	path, s := create(t, r)
	pass := seal.Passphrase{Phrase: []byte("correct horse battery staple ocean lamp")}
	id, err := s.AddSlot(pass)
	if err != nil {
		t.Fatal(err)
	}
	sameKeys(t, s, unlock(t, path, pass))
	if _, err := seal.Unlock(path, seal.Passphrase{Phrase: []byte("correct horse battery staple ocean lamb")}); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("wrong passphrase: got %v, want ErrWrongFactor", err)
	}

	next := seal.Passphrase{Phrase: []byte("a new card printed after rotation")}
	nid, err := s.Replace(id, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.Unlock(path, pass); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("replaced passphrase: got %v, want ErrWrongFactor", err)
	}
	if err := s.RemoveSlot(nid); err != nil {
		t.Fatal(err)
	}
	if _, err := seal.Unlock(path, next); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("removed passphrase: got %v, want ErrNoSlot", err)
	}
	unlock(t, path, r)
}

func TestPassphraseBounds(t *testing.T) {
	_, s := create(t, recovery(t))
	if _, err := s.AddSlot(seal.Passphrase{Phrase: []byte("short")}); err == nil {
		t.Error("a short passphrase made a slot")
	}
	low := seal.Passphrase{Phrase: []byte("long enough passphrase here"), Argon: seal.Argon{Time: 1, MemKiB: 64 << 10, Threads: 1}}
	if _, err := s.AddSlot(low); err == nil {
		t.Error("an Argon2id cost below 256 MiB made a slot")
	}
	if _, err := s.AddSlot(seal.Recovery{Key: make([]byte, 16)}); err == nil {
		t.Error("a short recovery key made a slot")
	}
}

func TestTheLastSlotStays(t *testing.T) {
	r := recovery(t)
	path, s := create(t, r)
	id := s.Slots()[0].ID
	if err := s.RemoveSlot(id); !errors.Is(err, seal.ErrLastSlot) {
		t.Fatalf("got %v, want ErrLastSlot", err)
	}
	unlock(t, path, r)
}

// A8: no store-key material is on the drive, in any encoding, and neither
// are the derived keys, the recovery key or the passphrase.
func TestCanaryKeyIsNotOnTheDrive(t *testing.T) {
	r := recovery(t)
	path, s := create(t, r)
	pass := []byte("canary passphrase 7f3a9c1e5b")
	if _, err := s.AddSlot(seal.Passphrase{Phrase: pass}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("ch4/seed", []byte("canary-ch4-seed-0b9d2e")); err != nil {
		t.Fatal(err)
	}
	logKey, _ := s.LogKey()
	head, _ := s.HeadKey()
	secrets := map[string][]byte{
		"store key":    seal.StoreKey(s),
		"log key":      logKey[:],
		"head seed":    head.Seed(),
		"recovery key": r.Key,
		"passphrase":   pass,
		"ch4 seed":     []byte("canary-ch4-seed-0b9d2e"),
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range secrets {
		for _, form := range [][]byte{k, []byte(hex.EncodeToString(k)), []byte(base64.StdEncoding.EncodeToString(k)),
			[]byte(base64.RawStdEncoding.EncodeToString(k)), []byte(base64.URLEncoding.EncodeToString(k))} {
			if bytes.Contains(disk, form) {
				t.Errorf("the %s is on the drive", name)
			}
		}
	}
	// No temporary file is left beside the store.
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Errorf("the store's directory holds %d files", len(ents))
	}
}

// CLK-1, MAIL-keys: the clerk root key is the same at every unlock, apart
// from the log and head keys, and each clerk's sealer derived from it
// (clerkkey.Derive, then Key.Sealer) is its own: one clerk's cannot open
// another's Secrets, and the same clerk's opens it after a restart.
func TestClerkRootGivesEachClerkItsOwnSealer(t *testing.T) {
	r := recovery(t)
	path, s := create(t, r)
	root, err := s.ClerkRoot()
	if err != nil {
		t.Fatal(err)
	}
	lk, _ := s.LogKey()
	hk, _ := s.HeadKey()
	if root == ([32]byte{}) || root == lk || bytes.Equal(root[:], hk.Seed()) {
		t.Fatal("the clerk root key is empty or another purpose's key")
	}
	sealer := func(root [32]byte, name string) clerk.Sealer {
		t.Helper()
		k, err := clerkkey.Derive(&root, name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := k.Sealer()
		if err != nil {
			t.Fatal(err)
		}
		sl, err := clerk.NewAESSealer(b)
		if err != nil {
			t.Fatal(err)
		}
		return sl
	}
	var atRest []byte
	sec := clerk.NewSecrets(sealer(root, "mail"), func(b []byte) error { atRest = bytes.Clone(b); return nil })
	if err := sec.Put("mail/acct", clerk.KindStatic, []byte("canary-mail-password")); err != nil {
		t.Fatal(err)
	}
	if err := clerk.NewSecrets(sealer(root, "exit"), nil).UnmarshalBinary(atRest); err == nil {
		t.Error("the exit clerk's sealer opened the mail clerk's Secrets")
	}
	again, err := unlock(t, path, r).ClerkRoot()
	if err != nil || again != root {
		t.Fatalf("the clerk root key after a restart differs: %v", err)
	}
	if err := clerk.NewSecrets(sealer(again, "mail"), nil).UnmarshalBinary(atRest); err != nil {
		t.Errorf("the mail clerk's sealer after a restart: %v", err)
	}
	s.Close()
	if _, err := s.ClerkRoot(); err == nil {
		t.Error("a closed store gave the clerk root key")
	}
}

// A truncated or partly written file fails closed, as does any changed byte.
func TestDamagedFileFailsClosed(t *testing.T) {
	r := recovery(t)
	path, _ := create(t, r)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(good); n++ {
		if err := os.WriteFile(path, good[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := seal.Unlock(path, r); !errors.Is(err, seal.ErrCorrupt) {
			t.Fatalf("truncated at %d of %d: got %v, want ErrCorrupt", n, len(good), err)
		}
	}
	for i := 0; i < len(good); i++ {
		b := bytes.Clone(good)
		b[i] ^= 0x01
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := seal.Unlock(path, r); !errors.Is(err, seal.ErrCorrupt) && !errors.Is(err, seal.ErrTampered) && !errors.Is(err, seal.ErrWrongFactor) {
			t.Fatalf("byte %d changed: got %v, want the store refused", i, err)
		}
	}
}

// The boot path a trusted host measures, as in broker/tpmseal's tests: the
// initrd into PCR 9 and the kernel command line into PCR 12.
var pcrs = []uint{9, 12}

func boot(s *swtpm.TPM, initrd, cmdline string) {
	s.Reboot()
	s.Measure(9, initrd)
	s.Measure(12, cmdline)
}

func tpmFactor(t *testing.T, s *swtpm.TPM, key *ecdsa.PrivateKey, pin string) seal.TPM {
	t.Helper()
	p, err := tpmseal.SignCurrent(s.TPM(), key, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	return seal.TPM{TPM: s.TPM(), PIN: pin, PolicyKey: &key.PublicKey, Policies: []tpmseal.Policy{p}, Host: "Test PC"}
}

// STO-2, HW-5a, A8: the trusted host restarts unattended; a modified boot
// path does not unlock; an update that signs the next release's boot path
// first still restarts unattended; a boot PIN is needed when one was set.
func TestTrustedHostSlot(t *testing.T) {
	sw := swtpm.Start(t)
	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	key, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	f := tpmFactor(t, sw, key, "")
	r := recovery(t)
	path, s := create(t, r)
	id, err := s.AddSlot(f)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := s.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Slots(); len(got) != 2 || got[1].Kind != seal.KindTPM || got[1].Host != "Test PC" ||
		len(got[1].Policies) != 1 || !slices.Equal(got[1].Policies[0].PCRs, pcrs) || got[0].Policies != nil {
		t.Fatalf("slots: %+v", got)
	}

	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	sameKeys(t, s, unlock(t, path, seal.TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor}))
	if _, err := seal.Unlock(path, seal.TPM{TPM: sw.TPM(), Anchor: anchor}); !errors.Is(err, seal.ErrNoPolicyKey) {
		t.Fatalf("no policy key: got %v, want ErrNoPolicyKey", err)
	}
	if _, err := seal.Unlock(path, seal.TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey}); !errors.Is(err, seal.ErrNoAnchor) {
		t.Fatalf("no anchor: got %v, want ErrNoAnchor", err)
	}

	boot(sw, "initrd-A-with-a-keylogger", "usrhash=aaaa quiet")
	if _, err := seal.Unlock(path, seal.TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor}); !errors.Is(err, tpmseal.ErrNoPolicy) || !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("modified initrd: got %v, want ErrNoPolicy", err)
	}

	// An A/B update: the updater signs release B's boot path while A runs.
	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	pb, err := tpmseal.Sign(key, pcrs, [][]byte{swtpm.Predict("initrd-B"), swtpm.Predict("usrhash=bbbb quiet")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicies(id, append(f.Policies, pb)); err != nil {
		t.Fatal(err)
	}
	other, _ := tpmseal.NewPolicyKey()
	pOther, _ := tpmseal.Sign(other, pcrs, [][]byte{swtpm.Predict("initrd-B"), swtpm.Predict("usrhash=bbbb quiet")})
	if err := s.SetPolicies(id, []tpmseal.Policy{pOther}); err == nil {
		t.Fatal("a boot path signed by another key was accepted")
	}
	boot(sw, "initrd-B", "usrhash=bbbb quiet")
	sameKeys(t, s, unlock(t, path, seal.TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor}))

	// A boot PIN, replacing the slot: the old slot no longer opens.
	withPIN := tpmFactor(t, sw, key, "4711")
	if _, err := s.Replace(id, withPIN); err != nil {
		t.Fatal(err)
	}
	if _, err := seal.Unlock(path, seal.TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor}); !errors.Is(err, tpmseal.ErrNeedPIN) {
		t.Fatalf("no PIN: got %v, want ErrNeedPIN", err)
	}
	sameKeys(t, s, unlock(t, path, seal.TPM{TPM: sw.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor, PIN: "4711"}))

	// Another PC's TPM has no slot here.
	sw2 := swtpm.Start(t)
	boot(sw2, "initrd-B", "usrhash=bbbb quiet")
	if _, err := seal.Unlock(path, seal.TPM{TPM: sw2.TPM(), PolicyKey: &key.PublicKey, Anchor: anchor}); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("another PC: got %v, want ErrNoSlot", err)
	}
}

// A8, HW-5a (Security blocker on #2834): a store sealed to this TPM under
// any key but the box's does not open. An attacker with brief access seals
// a store of their own to the TPM under their own policy key, signs the
// released boot path with it and puts the file at the store path; the next
// unattended boot must not run on keys the attacker chose.
func TestAStoreSealedUnderAnotherPolicyKeyDoesNotOpen(t *testing.T) {
	sw := swtpm.Start(t)
	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	boxKey, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	path, owner := create(t, tpmFactor(t, sw, boxKey, ""))
	anchor, err := owner.Anchor()
	if err != nil {
		t.Fatal(err)
	}

	// The attacker, booted from a live USB, signs the owner's released
	// boot path with a key of their own.
	boot(sw, "attacker-live-usb", "")
	evilKey, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpmseal.Sign(evilKey, pcrs, [][]byte{swtpm.Predict("initrd-A"), swtpm.Predict("usrhash=aaaa quiet")})
	if err != nil {
		t.Fatal(err)
	}
	evilPath, evil := create(t, seal.TPM{TPM: sw.TPM(), PolicyKey: &evilKey.PublicKey, Policies: []tpmseal.Policy{p}})
	evil.Close()
	b, err := os.ReadFile(evilPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	s, err := seal.Unlock(path, seal.TPM{TPM: sw.TPM(), PolicyKey: &boxKey.PublicKey, Anchor: anchor})
	if err == nil {
		s.Close()
		t.Fatal("the box opened a store sealed under the attacker's policy key")
	}
	if !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("got %v, want ErrNoSlot", err)
	}
}

// STO-2a-g, REC-4 (release finding on #2834): once the rename is done, a
// failed directory sync still leaves the store at the new slots, so the
// next write cannot put a replaced passphrase back.
func TestAFailedDirSyncDoesNotReviveAReplacedSlot(t *testing.T) {
	r := recovery(t)
	path, s := create(t, r)
	old := seal.Passphrase{Phrase: []byte("a passphrase seen over a shoulder")}
	id, err := s.AddSlot(old)
	if err != nil {
		t.Fatal(err)
	}
	restore := seal.FailDirSync(errors.New("directory sync failed"))
	nid, err := s.Replace(id, recovery(t))
	restore()
	if err == nil {
		t.Fatal("Replace hid the directory sync's error")
	}
	if nid == "" {
		t.Fatal("Replace returned no ID for the slot now in place")
	}
	if err := s.Put("ch4/seed", []byte("next write")); err != nil {
		t.Fatal(err)
	}
	if _, err := seal.Unlock(path, old); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("the replaced passphrase after the next write: got %v, want ErrNoSlot", err)
	}
	unlock(t, path, r)
}

// A8, HW-5a (second Security blocker on #2834): a whole store someone wrote
// under the box's own policy key does not open. Sealing to the TPM under
// that key needs only its public half, and the owner's signed boot paths
// are in the owner's file, so the attacker's slot unseals on the genuine
// boot; only the off-drive anchor, which commits to the store key, tells
// their store from the owner's.
func TestAWholeStoreUnderTheBoxsPolicyKeyDoesNotOpen(t *testing.T) {
	sw := swtpm.Start(t)
	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	boxKey, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	f := tpmFactor(t, sw, boxKey, "")
	path, owner := create(t, f)
	anchor, err := owner.Anchor()
	if err != nil {
		t.Fatal(err)
	}

	// The attacker, booted from a live USB, needs no private key: the
	// box's public policy key and its signed boot paths are on the drive.
	boot(sw, "attacker-live-usb", "")
	evilPath, evil := create(t, seal.TPM{TPM: sw.TPM(), PolicyKey: &boxKey.PublicKey, Policies: f.Policies})
	if err := evil.Put("ch4/seed", []byte("attacker-known")); err != nil {
		t.Fatal(err)
	}
	evil.Close()
	b, err := os.ReadFile(evilPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	boot(sw, "initrd-A", "usrhash=aaaa quiet")
	s, err := seal.Unlock(path, seal.TPM{TPM: sw.TPM(), PolicyKey: &boxKey.PublicKey, Anchor: anchor})
	if err == nil {
		s.Close()
		t.Fatal("the box opened a whole store the attacker wrote under its policy key")
	}
	if !errors.Is(err, seal.ErrTampered) {
		t.Fatalf("got %v, want ErrTampered", err)
	}
}

// MIG-4-recovery-r2 (REC-4, BAK-1): the recovery slot and the backup
// recipient change in one write. A write that fails before the rename
// leaves the old slot opening and the old entry, in the file and in the
// open store; a write that succeeds leaves only the new.
func TestReplaceAndPutIsOneWrite(t *testing.T) {
	old := recovery(t)
	path, s := create(t, old)
	if err := s.Put("backup/recipient", []byte("old recipient")); err != nil {
		t.Fatal(err)
	}
	id := s.Slots()[0].ID
	next := recovery(t)
	restore := seal.FailWrite(errors.New("disk full"))
	_, err := s.ReplaceAndPut(id, next, "backup/recipient", []byte("new recipient"))
	restore()
	if err == nil {
		t.Fatal("ReplaceAndPut hid the write's error")
	}
	for _, st := range []*seal.Store{s, unlock(t, path, old)} {
		if v, _, _ := st.Get("backup/recipient"); string(v) != "old recipient" {
			t.Fatalf("after a failed write the entry is %q", v)
		}
		if got := st.Slots(); len(got) != 1 || got[0].ID != id {
			t.Fatalf("after a failed write the slots are %v", got)
		}
	}
	if _, err := seal.Unlock(path, next); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("the new key after a failed write: got %v, want ErrWrongFactor", err)
	}

	nid, err := s.ReplaceAndPut(id, next, "backup/recipient", []byte("new recipient"))
	if err != nil || nid == "" || nid == id {
		t.Fatalf("ReplaceAndPut: %q, %v", nid, err)
	}
	if _, err := seal.Unlock(path, old); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("the old key after the write: got %v, want ErrWrongFactor", err)
	}
	for _, st := range []*seal.Store{s, unlock(t, path, next)} {
		if v, _, _ := st.Get("backup/recipient"); string(v) != "new recipient" {
			t.Fatalf("after the write the entry is %q", v)
		}
		if got := st.Slots(); len(got) != 1 || got[0].ID != nid {
			t.Fatalf("after the write the slots are %v", got)
		}
	}
	if _, err := s.ReplaceAndPut("0123456789abcdef", recovery(t), "backup/recipient", nil); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("an unknown slot: got %v, want ErrNoSlot", err)
	}
	if _, err := s.ReplaceAndPut(nid, recovery(t), "Bad Name", nil); err == nil {
		t.Fatal("a bad entry name was taken")
	}
	unlock(t, path, next)
}
