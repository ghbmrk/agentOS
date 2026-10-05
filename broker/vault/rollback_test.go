package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// REQ: CRED-8, REC-2

// fakePC is one PC's counters, standing in for its TPM (tpmseal has the
// swtpm tests). Like a TPM, a new counter starts at the highest value any
// counter on the PC has had, and nothing lowers one.
type fakePC struct {
	host     string
	counters map[string]uint64
	max      uint64
	auth     map[string][]byte
	broken   bool // the TPM stops answering
	noIncr   bool // increments fail
}

func newPC(host string) *fakePC {
	return &fakePC{host: host, counters: map[string]uint64{}, auth: map[string][]byte{}, max: 100}
}

var errTPM = errors.New("tpm not answering")

func (p *fakePC) Host() string { return p.host }

func (p *fakePC) Find(id []byte) ([]byte, bool, error) {
	if p.broken {
		return nil, false, errTPM
	}
	_, ok := p.counters[hex.EncodeToString(id)]
	return id, ok, nil
}

func (p *fakePC) Define(id, auth []byte) ([]byte, error) {
	if p.broken {
		return nil, errTPM
	}
	k := hex.EncodeToString(id)
	if _, ok := p.counters[k]; !ok {
		p.counters[k], p.auth[k] = p.max, append([]byte(nil), auth...)
	}
	return id, nil
}

func (p *fakePC) Read(ref, auth []byte) (uint64, error) {
	k := hex.EncodeToString(ref)
	n, ok := p.counters[k]
	if p.broken || !ok || !bytes.Equal(auth, p.auth[k]) {
		return 0, errTPM
	}
	return n, nil
}

func (p *fakePC) Increment(ref, auth []byte) error {
	k := hex.EncodeToString(ref)
	if p.broken || p.noIncr || !bytes.Equal(auth, p.auth[k]) {
		return errTPM
	}
	p.counters[k]++
	if p.counters[k] > p.max {
		p.max = p.counters[k]
	}
	return nil
}

// drive is a vault on a drive the test can copy and put back.
type drive struct {
	t    *testing.T
	path string
	key  []byte
}

func newDrive(t *testing.T) *drive {
	d := &drive{t: t, path: filepath.Join(t.TempDir(), "vault"), key: testKey(t)}
	v, err := Create(d.path, d.key)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	return d
}

func (d *drive) open() *Vault {
	d.t.Helper()
	v, err := Open(d.path, d.key)
	if err != nil {
		d.t.Fatal(err)
	}
	return v
}

func (d *drive) copy() []byte {
	d.t.Helper()
	b, err := os.ReadFile(d.path)
	if err != nil {
		d.t.Fatal(err)
	}
	return b
}

func (d *drive) putBack(b []byte) {
	d.t.Helper()
	if err := os.WriteFile(d.path, b, 0o600); err != nil {
		d.t.Fatal(err)
	}
}

func mustPut(t *testing.T, v *Vault, name string, val string) {
	t.Helper()
	if err := v.Put(name, KindAPIKey, []byte(val)); err != nil {
		t.Fatal(err)
	}
}

// The attack V6 names: copy the drive, wait for the owner to revoke a
// credential, put the copy back. On the anchored PC the copy is refused.
func TestOldCopyIsRefusedOnAnchoredPC(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, "openai", "sk-canary-revoked-0001")
	v.Close()
	old := d.copy()

	v = d.open()
	if err := v.Bind(pc); err != nil {
		t.Fatalf("current file refused: %v", err)
	}
	if err := v.Delete("openai"); err != nil { // the owner revokes it
		t.Fatal(err)
	}
	v.Close()

	d.putBack(old)
	v = d.open() // the key still opens it: only the counter can tell
	defer v.Close()
	if err := v.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("old copy: Bind = %v, want ErrRolledBack", err)
	}
}

// Every write advances the counter, and the current file keeps binding
// across reopen: no false rollback in normal use.
func TestEveryWriteAdvancesTheCounter(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	start := pc.counters[hex.EncodeToString(v.id)]
	for i := 0; i < 5; i++ {
		mustPut(t, v, "openai", "sk-canary-value-000"+string(rune('0'+i)))
	}
	if got := pc.counters[hex.EncodeToString(v.id)]; got != start+5 {
		t.Fatalf("counter went %d -> %d over 5 writes", start, got)
	}
	v.Close()
	for i := 0; i < 3; i++ {
		v = d.open()
		if err := v.Bind(pc); err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		v.Close()
	}
}

// A crash after the file is written but before the counter advances leaves
// the file one ahead; the next bind finishes the increment, and the file
// before that write is then refused.
func TestCrashBetweenWriteAndIncrement(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	v.Close()
	before := d.copy()

	v = d.open()
	if err := v.Bind(pc); err != nil {
		t.Fatal(err)
	}
	pc.noIncr = true
	mustPut(t, v, "openai", "sk-canary-after-crash1")
	v.Close()
	pc.noIncr = false

	v = d.open()
	if err := v.Bind(pc); err != nil {
		t.Fatalf("file one ahead of the counter: %v", err)
	}
	if s, ok := v.Secret("openai"); !ok || s.Reveal() != "sk-canary-after-crash1" {
		t.Fatal("the write was lost")
	}
	v.Close()

	d.putBack(before)
	v = d.open()
	defer v.Close()
	if err := v.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("file from before the crash: Bind = %v, want ErrRolledBack", err)
	}
}

// A copy taken before the PC was anchored has no anchor for it, but the PC
// holds this vault's counter: refused too.
func TestCopyFromBeforeAnchoringIsRefused(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	old := d.copy()
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	v.Close()

	d.putBack(old)
	v = d.open()
	defer v.Close()
	if err := v.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("pre-anchor copy: Bind = %v, want ErrRolledBack", err)
	}
}

// Moving the drive is not a rollback: writes on PC beta leave alpha's
// anchor and counter alone, and both PCs keep binding.
func TestTwoPCsShareTheDrive(t *testing.T) {
	d, a, b := newDrive(t), newPC("alpha"), newPC("beta")
	v := d.open()
	if err := v.Anchor(a); err != nil {
		t.Fatal(err)
	}
	if err := v.Anchor(b); err != nil {
		t.Fatal(err)
	}
	if n := len(v.Anchors()); n != 2 {
		t.Fatalf("%d anchors, want 2", n)
	}
	v.Close()
	for i, pc := range []*fakePC{b, a, b, b, a} {
		v = d.open()
		if err := v.Bind(pc); err != nil {
			t.Fatalf("step %d on %s: %v", i, pc.host, err)
		}
		mustPut(t, v, "openai", "sk-canary-moving-"+pc.host+"-"+string(rune('0'+i)))
		v.Close()
	}
}

// An unknown host has no anchor and no counter: nothing is checked and
// nothing is bound, so its writes touch no counter.
func TestUnknownHostBindsNothing(t *testing.T) {
	d, a, stranger := newDrive(t), newPC("alpha"), newPC("stranger")
	v := d.open()
	if err := v.Anchor(a); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v = d.open()
	if err := v.Bind(stranger); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v, "openai", "sk-canary-stranger-01")
	v.Close()
	if len(stranger.counters) != 0 {
		t.Fatal("an unknown host got a counter")
	}
	v = d.open()
	defer v.Close()
	if err := v.Bind(a); err != nil {
		t.Fatalf("back on alpha: %v", err)
	}
}

// An anchored PC whose TPM does not answer fails closed; an unanchored one
// goes on to the owner's unknown-host unlock.
func TestCounterUnavailable(t *testing.T) {
	d, a, other := newDrive(t), newPC("alpha"), newPC("other")
	v := d.open()
	if err := v.Anchor(a); err != nil {
		t.Fatal(err)
	}
	v.Close()
	a.broken, other.broken = true, true
	v = d.open()
	defer v.Close()
	if err := v.Bind(a); err == nil {
		t.Fatal("anchored PC bound without reading its counter")
	}
	if err := v.Bind(other); err != nil {
		t.Fatalf("unanchored PC with a silent TPM: %v", err)
	}
}

// A write is refused, and nothing changes, if the counter cannot be read.
func TestWriteFailsClosedWithoutCounter(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	defer v.Close()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	before := d.copy()
	pc.broken = true
	if err := v.Put("openai", KindAPIKey, []byte("sk-canary-unwritten-1")); err == nil {
		t.Fatal("write succeeded without the counter")
	}
	if _, ok := v.Secret("openai"); ok {
		t.Fatal("failed write left the entry in memory")
	}
	if !bytes.Equal(before, d.copy()) {
		t.Fatal("failed write changed the file")
	}
}

// A second process writing the same vault advances the counter under the
// first, whose next write is refused rather than forking the history.
func TestCounterMovedUnderOpenVault(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v1, v2 := d.open(), d.open()
	defer v1.Close()
	defer v2.Close()
	if err := v1.Bind(pc); err != nil {
		t.Fatal(err)
	}
	if err := v2.Bind(pc); err != nil {
		t.Fatal(err)
	}
	mustPut(t, v1, "openai", "sk-canary-first-write")
	if err := v2.Put("openai", KindAPIKey, []byte("sk-canary-second-wrt")); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("stale writer: %v, want ErrRolledBack", err)
	}
}

// Anchoring stopped after the pending anchor was written: with no counter
// made, the vault opens unbound and Anchor finishes; with the counter
// made, the next bind adopts it.
func TestInterruptedAnchoring(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	pc.broken = true // Define fails after the pending anchor is written
	if err := v.Anchor(pc); err == nil {
		t.Fatal("Anchor succeeded with a silent TPM")
	}
	v.Close()
	pc.broken = false

	v = d.open()
	if a := v.Anchors(); len(a) != 1 || !a[0].Pending {
		t.Fatalf("anchors after interruption: %+v", a)
	}
	if err := v.Bind(pc); err != nil {
		t.Fatalf("pending anchor, no counter: %v", err)
	}
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	v.Close()

	// Counter made but the anchor never recorded it.
	d2, pc2 := newDrive(t), newPC("beta")
	v = d2.open()
	if err := v.ensureID(); err != nil {
		t.Fatal(err)
	}
	v.anchors = []Anchor{{Host: "beta", Pending: true}}
	if err := v.write(v.anchors); err != nil {
		t.Fatal(err)
	}
	if _, err := pc2.Define(v.id, v.counterAuth); err != nil {
		t.Fatal(err)
	}
	v.Close()
	v = d2.open()
	defer v.Close()
	if err := v.Bind(pc2); err != nil {
		t.Fatalf("pending anchor with its counter made: %v", err)
	}
	if a := v.Anchors(); len(a) != 1 || a[0].Pending {
		t.Fatalf("anchor not adopted: %+v", a)
	}
}

// A restore with the recovery key (REC-1) is a deliberate rollback: after
// Rebase the restored vault opens on the PC that refused the old copy, and
// it no longer matches that PC's old counter. Rebase takes the recovery key
// and drops every trusted-host slot with the anchors, so it cannot launder
// an old copy into one this PC opens unattended (review of #45, F2).
func TestRebaseAfterRestore(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	rec := recoveryish{bytes.Repeat([]byte{9}, KeySize)}
	if err := v.AddSlot(rec, func(s Slot) bool { return s.Kind == SlotRecovery }); err != nil {
		t.Fatal(err)
	}
	alpha, pc := newHost("alpha"), newPC("alpha")
	if err := v.AddSlot(alpha, sameHost(alpha)); err != nil {
		t.Fatal(err)
	}
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	backupVault, backupKeys := readBytes(t, vp), readBytes(t, kp)
	mustPut(t, v, "anthropic", "sk-canary-after-backup")
	oldID := append([]byte(nil), v.id...)
	v.Close()

	for p, b := range map[string][]byte{vp: backupVault, kp: backupKeys} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	v, err := OpenSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Bind(pc); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("backup before Rebase: %v", err)
	}
	if _, err := v.Rebase(Passphrase(testPass)); err == nil {
		t.Fatal("Rebase without the recovery key")
	}
	if _, err := v.Rebase(recoveryish{bytes.Repeat([]byte{8}, KeySize)}); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("Rebase with a wrong recovery key: %v", err)
	}
	if n, err := v.Rebase(rec); err != nil || n != 1 {
		t.Fatalf("Rebase: dropped %d, %v; want 1", n, err)
	}
	if bytes.Equal(v.id, oldID) || len(v.Anchors()) != 0 {
		t.Fatal("Rebase kept the vault ID or its anchors")
	}
	v.Close()

	if _, err := OpenSealed(vp, kp, alpha); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("trusted-host slot survived Rebase: %v", err)
	}
	if slots, _ := ReadSlots(kp); len(slots) != 2 {
		t.Fatalf("%d slots after Rebase, want passphrase and recovery", len(slots))
	}
	v, err = OpenSealed(vp, kp, rec)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if err := v.Bind(pc); err != nil {
		t.Fatalf("rebased vault: %v", err)
	}
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
}

// The anchors are inside the seal: editing the file to drop or lower one
// breaks decryption rather than skipping the check.
func TestAnchorsAreSealed(t *testing.T) {
	d, pc := newDrive(t), newPC("alpha")
	v := d.open()
	if err := v.Anchor(pc); err != nil {
		t.Fatal(err)
	}
	v.Close()
	raw := d.copy()
	if bytes.Contains(raw, []byte("alpha")) || bytes.Contains(raw, []byte("anchors")) {
		t.Fatal("anchor visible in the file")
	}
}

// A version 1 file (P1-3 to P2-4b) still opens, has nothing to check, and
// is written as version 2 with an ID on its next write.
func TestVersion1FileUpgrades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault")
	key := testKey(t)
	writeV1(t, path, key, map[string]record{"openai": {Kind: KindAPIKey, Value: []byte("sk-canary-version-one")}})
	v, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Bind(newPC("alpha")); err != nil {
		t.Fatal(err)
	}
	if s, ok := v.Secret("openai"); !ok || s.Reveal() != "sk-canary-version-one" {
		t.Fatal("version 1 entry lost")
	}
	mustPut(t, v, "anthropic", "sk-canary-version-two")
	v.Close()
	v, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if len(v.id) != idSize || len(v.counterAuth) != authSize || len(v.List()) != 2 {
		t.Fatalf("not upgraded: id %d auth %d entries %d", len(v.id), len(v.counterAuth), len(v.List()))
	}
	if bytes.IndexByte(v.counterAuth, 0) >= 0 {
		t.Fatal("counter auth holds a zero byte")
	}
}

// writeV1 writes a vault file in the version 1 format.
func writeV1(t *testing.T, path string, key []byte, entries map[string]record) {
	t.Helper()
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	raw, err := json.Marshal(envelope{Magic: fileMagic, Version: 1, Nonce: nonce,
		Sealed: aead.Seal(nil, nonce, plain, aad(1, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
