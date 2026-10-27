package main

// REQ: STO-2, STO-1, HW-5a, CLK-1, UPD-10

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

var testPCRs = []uint{9, 12}

// box is a PC at first boot: a software TPM, empty state, and the Owner
// Card's factors in root-only files.
type box struct {
	t        *testing.T
	sw       *swtpm.TPM
	c        config
	pass     []byte
	recovery []byte
}

func newBox(t *testing.T) *box {
	t.Helper()
	b := &box{t: t, sw: swtpm.Start(t)}
	b.reboot()
	dir := t.TempDir()
	b.pass = []byte("seven words from the owner card list")
	b.recovery = make([]byte, seal.RecoveryLen)
	get(rand.Read(b.recovery))
	pf, rf := filepath.Join(dir, "passphrase"), filepath.Join(dir, "recovery")
	noErr(t, os.WriteFile(pf, append(bytes.Clone(b.pass), '\n'), 0o600))
	noErr(t, os.WriteFile(rf, []byte(hex.EncodeToString(b.recovery)+"\n"), 0o600))
	state, kdir := filepath.Join(dir, "store"), filepath.Join(dir, "kernel")
	noErr(t, os.Mkdir(state, 0o700))
	noErr(t, os.Mkdir(kdir, 0o700))
	b.c = config{
		state: state, anchorDir: filepath.Join(kdir, "anchor"), log: filepath.Join(kdir, "log"),
		host: "Test PC", passphrase: pf, recovery: rf, pcrs: testPCRs,
		kernelUID: os.Getuid(), kernelGID: os.Getgid(), built: testBuilt,
	}
	return b
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// get returns v, and panics (failing the test) on err.
func get[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// reboot is a power cycle into the approved boot path. It also drops the
// objects a cut TPM connection left loaded, as the kernel's resource
// manager does when a process dies.
func (b *box) reboot() {
	b.sw.Reboot()
	b.sw.Measure(9, "initrd-A")
	b.sw.Measure(12, "usrhash=aaaa quiet")
}

func (b *box) srk() []byte {
	b.t.Helper()
	n, err := tpmseal.Identity(b.sw.TPM())
	if err != nil {
		b.t.Fatal(err)
	}
	return n
}

// nv lists every index in the owner NV range the pins and counters use,
// by handle and name, so a test can say that nothing on the TPM changed.
func nv(t *testing.T, tpm transport.TPM) map[uint32]string {
	t.Helper()
	out := map[uint32]string{}
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: 0x01800000, PropertyCount: 256}.Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	hs, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hs.Handle {
		if h >= 0x01C00000 {
			break
		}
		p, err := tpm2.NVReadPublic{NVIndex: h}.Execute(tpm)
		if err != nil {
			t.Fatal(err)
		}
		out[uint32(h)] = hex.EncodeToString(p.NVName.Buffer)
	}
	return out
}

// files reads every file under the box's state and kernel directories.
func (b *box) files() map[string]string {
	b.t.Helper()
	out := map[string]string{}
	for _, root := range []string{b.c.state, filepath.Dir(b.c.anchorDir)} {
		noErr(b.t, filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				out[p] = "dir " + fi.Mode().String()
				return nil
			}
			c, err := os.ReadFile(p)
			out[p] = string(c)
			return err
		}))
	}
	return out
}

func sameMap[K comparable](a, b map[K]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// enrolled checks a finished enrollment: the store opens through the pins
// on this TPM and through each of the owner's factors, the pinned key is
// the one kept in the store, and the counter anchor opens. The TPM holds
// exactly the store's pins and counter.
func (b *box) enrolled() *seal.Store {
	t := b.t
	t.Helper()
	f, err := seal.Pinned(b.sw.TPM(), b.c.storePath())
	if err != nil {
		t.Fatalf("no pins for the store: %v", err)
	}
	st, err := seal.Unlock(b.c.storePath(), f)
	if err != nil {
		t.Fatalf("the pinned TPM unlock: %v", err)
	}
	t.Cleanup(st.Close)
	kinds := map[seal.Kind]int{}
	for _, s := range st.Slots() {
		kinds[s.Kind]++
	}
	if kinds[seal.KindTPM] != 1 || kinds[seal.KindPassphrase] != 1 || kinds[seal.KindRecovery] != 1 {
		t.Fatalf("slots: %v", kinds)
	}
	der, ok, err := st.Get(policyKeyEntry)
	if err != nil || !ok {
		t.Fatalf("no policy key in the store: %v", err)
	}
	k, err := tpmseal.ParsePolicyKey(der)
	if err != nil || !k.PublicKey.Equal(f.PolicyKey) {
		t.Fatalf("the pinned key is not the store's: %v", err)
	}
	for _, fac := range []seal.Factor{seal.Passphrase{Phrase: b.pass}, seal.Recovery{Key: b.recovery}} {
		o, err := seal.Unlock(b.c.storePath(), fac)
		if err != nil {
			t.Fatalf("%T: %v", fac, err)
		}
		o.Close()
	}
	b.openAnchor(st)
	if n := nv(t, b.sw.TPM()); len(n) != 2 {
		t.Fatalf("the TPM holds %d indexes, not the store's pins and counter", len(n))
	}
	if _, err := os.Lstat(b.c.stagedPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the staged store is left: %v", err)
	}
	return st
}

func (b *box) counter(st *seal.Store) tpmseal.Counter {
	b.t.Helper()
	raw, ok, err := st.Get(counterEntry)
	if err != nil || !ok {
		b.t.Fatalf("no counter in the store: %v", err)
	}
	var r counterRec
	noErr(b.t, json.Unmarshal(raw, &r))
	return r.Counter(b.sw.TPM(), b.srk())
}

// openAnchor opens the kernel's counter anchor as a boot would.
func (b *box) openAnchor(st *seal.Store) error {
	b.t.Helper()
	head, err := st.HeadKey()
	if err != nil {
		b.t.Fatal(err)
	}
	_, err = proc.OpenCounterAnchor(b.c.anchorDir, b.counter(st), head)
	if err != nil {
		b.t.Fatalf("the counter anchor: %v", err)
	}
	return err
}

// End to end: enrollment on a blank TPM and empty state, then each boot
// (a power cycle, the same boot path) unlocks through the pins and opens the
// counter anchor the last boot left.
func TestEnrollThenBoot(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	st := b.enrolled()
	st.Close()
	for range 2 {
		b.reboot()
		f := get(seal.Pinned(b.sw.TPM(), b.c.storePath()))
		st := get(seal.Unlock(b.c.storePath(), f))
		b.openAnchor(st)
		st.Close()
	}
	// Another boot path opens nothing through the tpm slot.
	b.sw.Reboot()
	b.sw.Measure(9, "initrd-EVIL")
	b.sw.Measure(12, "usrhash=aaaa quiet")
	f := get(seal.Pinned(b.sw.TPM(), b.c.storePath()))
	if _, err := seal.Unlock(b.c.storePath(), f); err == nil {
		t.Fatal("another boot path unlocked the store")
	}
}

// REQ: BAK-1
// MIG-4-recovery-e1: enrollment keeps the recovery key's backup recipient
// in the store, and only its public half: the entry is exactly the tag and
// the two public keys, holds no run of the recovery key, and names the
// recipient the recovery key alone derives.
func TestEnrollStoresTheBackupRecipient(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	st := b.enrolled()
	v, ok, err := st.Get(handoff.RecipientEntry)
	if err != nil || !ok {
		t.Fatalf("no backup recipient in the store: %v", err)
	}
	want := get(backup.RecipientFor(b.recovery))
	if got := get(handoff.ParseRecipient(v)); !bytes.Equal(got, append(bytes.Clone(want.X), want.EK...)) {
		t.Fatal("the store's recipient is not the recovery key's")
	}
	if len(v) != len(get(handoff.EncodeRecipient(want.X, want.EK))) {
		t.Fatalf("the entry is %d bytes, more than the recipient", len(v))
	}
	for i := 0; i+8 <= len(b.recovery); i++ {
		if bytes.Contains(v, b.recovery[i:i+8]) {
			t.Fatalf("the entry holds the recovery key's bytes %d to %d", i, i+8)
		}
	}
	// Another recovery key derives another recipient.
	other := bytes.Clone(b.recovery)
	other[0] ^= 1
	if get(backup.RecipientFor(other)).ID() == want.ID() {
		t.Fatal("two recovery keys share a recipient")
	}
}

// testBuilt stands for the image's build time.
var testBuilt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// REQ: CH-9, BAK-1
// MIG-4-recovery-f1: enrollment makes the page authority and keeps it in
// the store, for the unlock step to hand the kernel: an authority for the
// page name only, whose certificate opens with its key, dated from the
// build time and never the clock. Without a build time it makes no store.
func TestEnrollStoresThePageAuthority(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	v, ok, err := b.enrolled().Get(handoff.PageCAEntry)
	if err != nil || !ok {
		t.Fatalf("no page authority in the store: %v", err)
	}
	a, err := pageca.Unmarshal(get(handoff.ParsePageCA(v)))
	if err != nil || a.Name() != pageca.DefaultName {
		t.Fatalf("the store's authority does not open for the page name: %v", err)
	}
	cert := get(x509.ParseCertificate(a.Certificate()))
	if !cert.NotBefore.Equal(testBuilt.Add(-24*time.Hour)) || len(cert.PermittedDNSDomains) != 1 || !cert.IsCA {
		t.Fatalf("the authority is not the page's, from the build time: %v %v", cert.NotBefore, cert.PermittedDNSDomains)
	}
	if a.Fingerprint() != pageca.Fingerprint(cert.Raw) {
		t.Fatal("no fingerprint to print")
	}
	// A leaf it issues verifies under it for the page name.
	pk := get(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	leaf := get(x509.ParseCertificate(get(a.Issue(get(x509.MarshalPKIXPublicKey(&pk.PublicKey)), testBuilt.Add(48*time.Hour), nil))))
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: pageca.DefaultName, Roots: pool, CurrentTime: testBuilt.Add(72 * time.Hour)}); err != nil {
		t.Fatalf("the authority's leaf does not verify: %v", err)
	}

	z := newBox(t)
	z.c.built = time.Time{}
	if err := enroll(z.c, z.sw.TPM()); err == nil {
		t.Fatal("enrolled with no build time")
	}
	if ok, _ := exists(z.c.storePath()); ok {
		t.Fatal("a store without a page authority is in place")
	}
}

// A second enrollment over a store, a log or another store's locked pins
// refuses and changes nothing, byte for byte and NV for NV.
func TestEnrollRefusesAndChangesNothing(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	check := func(want error) {
		t.Helper()
		files, idx := b.files(), nv(t, b.sw.TPM())
		if err := enroll(b.c, b.sw.TPM()); !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
		if !sameMap(files, b.files()) || !sameMap(idx, nv(t, b.sw.TPM())) {
			t.Fatal("a refused enrollment changed something")
		}
	}
	check(errEnrolled)

	noErr(t, os.Rename(b.c.storePath(), b.c.storePath()+".gone"))
	noErr(t, os.WriteFile(b.c.log, []byte("a log"), 0o600))
	check(errLogExists)

	// No store and no log, but the TPM still pins the old store.
	noErr(t, os.Remove(b.c.log))
	check(errOtherPins)

	// A staged store that does not parse is not guessed at.
	noErr(t, os.WriteFile(b.c.stagedPath(), []byte("{}"), 0o600))
	check(errStaged)
}

// A crash after each step finishes on the rerun into a store whose pins,
// counter and slots agree, and the TPM keeps nothing of the dead attempt.
func TestEnrollCrashAfterEachStep(t *testing.T) {
	for _, step := range []string{"cleaned", "created", "slots", "counter", "head-file", "anchor", "pins"} {
		t.Run(step, func(t *testing.T) {
			b := newBox(t)
			c := b.c
			c.stop = func(s string) bool { return s == step }
			if err := enroll(c, b.sw.TPM()); !errors.Is(err, errCrash) {
				t.Fatalf("got %v, want the crash", err)
			}
			if _, err := os.Lstat(b.c.storePath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("a store is in place before its pins")
			}
			noErr(t, enroll(b.c, b.sw.TPM()))
			b.enrolled()
		})
	}
}

// cutTPM forwards the first n commands and fails every one after, as a
// power cut part way through would leave the TPM.
type cutTPM struct {
	tpm transport.TPM
	n   int
}

var errCut = errors.New("test: the TPM is gone")

func (c *cutTPM) Send(cmd []byte) ([]byte, error) {
	if c.n <= 0 {
		return nil, errCut
	}
	c.n--
	return c.tpm.Send(cmd)
}

// countTPM counts the commands sent.
type countTPM struct {
	tpm transport.TPM
	n   int
}

func (c *countTPM) Send(cmd []byte) ([]byte, error) { c.n++; return c.tpm.Send(cmd) }

// A cut after every TPM command of an enrollment, inside the counter's
// definition and the pins' write and lock too: the rerun always ends with a
// store whose pins and counter agree with it, and nothing else on the TPM.
func TestEnrollCutAfterEachTPMCommand(t *testing.T) {
	probe := newBox(t)
	ct := &countTPM{tpm: probe.sw.TPM()}
	noErr(t, enroll(probe.c, ct))
	total := ct.n
	if testing.Short() {
		t.Skip("short")
	}
	step := 1
	if total > 60 {
		step = total / 60
	}
	for n := 0; n < total; n += step {
		b := newBox(t)
		if err := enroll(b.c, &cutTPM{tpm: b.sw.TPM(), n: n}); err == nil {
			// Only a cut of a last flush, whose error nothing reads, lets
			// the run finish; the box must then be whole.
			b.reboot()
			b.enrolled()
			continue
		}
		if _, err := os.Lstat(b.c.storePath()); !errors.Is(err, os.ErrNotExist) {
			// Only the rename follows the last TPM command.
			t.Fatalf("cut after %d: a store is in place", n)
		}
		b.reboot()
		if err := enroll(b.c, b.sw.TPM()); err != nil {
			t.Fatalf("rerun after a cut at %d: %v", n, err)
		}
		b.enrolled()
	}
}

// lossyTPM runs every command but reports an error for the first fail[cc]
// answers to each command code cc, as a TPM that defined the counter and
// then failed its first increment, or an answer lost on the way back.
type lossyTPM struct {
	tpm  transport.TPM
	fail map[uint32]int
	cut  bool // after the last lost answer, the TPM answers nothing
	lost int
}

func (l *lossyTPM) Send(cmd []byte) ([]byte, error) {
	if l.cut && l.lost > 0 {
		return nil, errCut
	}
	rsp, err := l.tpm.Send(cmd)
	if len(cmd) >= 10 {
		if cc := binary.BigEndian.Uint32(cmd[6:10]); l.fail[cc] > 0 {
			l.fail[cc]--
			l.lost++
			return nil, errors.New("test: the answer was lost")
		}
	}
	return rsp, err
}

const (
	ccNVDefineSpace = 0x0000012A
	ccNVIncrement   = 0x00000134
)

// #2905 requirement (from #2907): a counter made by a create that reported
// an error never reads as a rollback.
func TestCounterMadeByAFailedCreate(t *testing.T) {
	// 1. The first increment's answer is lost once: the same call finds the
	// counter and adopts it.
	for _, cc := range []uint32{ccNVDefineSpace, ccNVIncrement} {
		b := newBox(t)
		noErr(t, enroll(b.c, &lossyTPM{tpm: b.sw.TPM(), fail: map[uint32]int{cc: 1}}))
		b.enrolled()
	}
	// 2. Lost twice (the define's answer, then the adopting increment's):
	// the call fails, records no counter, and the rerun frees it and enrolls
	// whole.
	b := newBox(t)
	if err := enroll(b.c, &lossyTPM{tpm: b.sw.TPM(), fail: map[uint32]int{ccNVDefineSpace: 1, ccNVIncrement: 1}}); err == nil {
		t.Fatal("two lost answers: enrollment reported success")
	}
	noErr(t, enroll(b.c, b.sw.TPM()))
	b.enrolled()
	// 5. The TPM stops answering during the failure: no store keeps a
	// pending counter, and the rerun leaves nothing of it.
	b = newBox(t)
	if err := enroll(b.c, &lossyTPM{tpm: b.sw.TPM(), fail: map[uint32]int{ccNVIncrement: 1}, cut: true}); err == nil {
		t.Fatal("a TPM gone mid-define: enrollment reported success")
	}
	b.reboot()
	noErr(t, enroll(b.c, b.sw.TPM()))
	st := b.enrolled()

	// 3. The rollback check holds afterwards: a head file from before a
	// boot is refused once the counter has moved past it.
	old := get(os.ReadFile(filepath.Join(b.c.anchorDir, anchorFile)))
	b.openAnchor(st)
	noErr(t, os.WriteFile(filepath.Join(b.c.anchorDir, anchorFile), old, 0o600))
	head := get(st.HeadKey())
	if _, err := proc.OpenCounterAnchor(b.c.anchorDir, b.counter(st), head); !errors.Is(err, proc.ErrAnchorRolledBack) {
		t.Fatalf("an old head file: got %v, want ErrAnchorRolledBack", err)
	}
	// 4. A box whose counter was deleted keeps failing closed: the anchor
	// does not open and enrollment does not start over.
	noErr(t, tpmseal.FreeCounter(b.sw.TPM(), b.srk(), st.ID()))
	if _, err := proc.OpenCounterAnchor(b.c.anchorDir, b.counter(st), head); err == nil {
		t.Fatal("the anchor opened with its counter gone")
	}
	if err := enroll(b.c, b.sw.TPM()); !errors.Is(err, errEnrolled) {
		t.Fatalf("enrollment over a store whose counter is gone: %v", err)
	}
}

// who reports which policy key the store unlocks under now: the pinned one,
// with the pinned TPM unlock succeeding, or nil when the TPM holds no pins
// and only the passphrase opens it. Any other outcome fails the test.
func (b *box) who() []byte {
	t := b.t
	t.Helper()
	f, err := seal.Pinned(b.sw.TPM(), b.c.storePath())
	if errors.Is(err, tpmseal.ErrNoPins) {
		st, err := seal.Unlock(b.c.storePath(), seal.Passphrase{Phrase: b.pass})
		if err != nil {
			t.Fatalf("no pins and the passphrase fails: %v", err)
		}
		st.Close()
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	st, err := seal.Unlock(b.c.storePath(), f)
	if err != nil {
		t.Fatalf("the pinned key unlocks nothing: %v", err)
	}
	st.Close()
	return get(f.PolicyKey.Bytes())
}

// Rotation unlocks under the new key and not the old. A crash after each
// step leaves a store that the old key, the new key or the passphrase
// opens, and nothing else, and the rerun finishes.
func TestRotate(t *testing.T) {
	for _, step := range []string{"", "next-key", "new-slot", "pins-freed", "pins-new", "old-slot"} {
		t.Run("crash-"+step, func(t *testing.T) {
			b := newBox(t)
			noErr(t, enroll(b.c, b.sw.TPM()))
			old := b.who()
			st := b.enrolled()
			oldAnchor := get(st.Anchor())
			oldKey := parseKey(t, st)
			st.Close()
			if step != "" {
				c := b.c
				c.stop = func(s string) bool { return s == step }
				if err := rotate(c, b.sw.TPM()); !errors.Is(err, errCrash) {
					t.Fatalf("got %v, want the crash", err)
				}
				now := b.who()
				nst := get(seal.Unlock(b.c.storePath(), seal.Passphrase{Phrase: b.pass}))
				next, ok, _ := nst.Get(nextKeyEntry)
				nst.Close()
				var nextPub []byte
				if ok {
					nextPub = get(get(tpmseal.ParsePolicyKey(next)).PublicKey.Bytes())
				}
				if now != nil && !bytes.Equal(now, old) && !bytes.Equal(now, nextPub) {
					t.Fatal("after the crash the store unlocks under a key the owner did not enrol")
				}
			}
			noErr(t, rotate(b.c, b.sw.TPM()))
			now := b.who()
			if now == nil || bytes.Equal(now, old) {
				t.Fatal("the rotation did not move the pins to a new key")
			}
			st = b.enrolled()
			if _, ok, _ := st.Get(nextKeyEntry); ok {
				t.Fatal("the next key is left in the store")
			}
			// The old key, with the store's own anchor, opens no slot.
			if _, err := seal.Unlock(b.c.storePath(), seal.TPM{TPM: b.sw.TPM(), PolicyKey: &oldKey.PublicKey, Anchor: oldAnchor}); !errors.Is(err, seal.ErrNoSlot) {
				t.Fatalf("the old key: got %v, want ErrNoSlot", err)
			}
		})
	}
}

// Deleting a store frees its pins and counter (NV_ReadPublic reports them
// absent) and removes it; a crash between the two finishes on the rerun,
// and the box can then be enrolled again.
func TestDeleteFreesTheStoresIndexes(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	c := b.c
	c.stop = func(s string) bool { return s == "freed" }
	if err := deleteStore(c, b.sw.TPM()); !errors.Is(err, errCrash) {
		t.Fatalf("got %v, want the crash", err)
	}
	if n := nv(t, b.sw.TPM()); len(n) != 0 {
		t.Fatalf("the TPM still holds %d of the store's indexes", len(n))
	}
	if b.who() != nil {
		t.Fatal("a store with its pins freed unlocked through the TPM")
	}
	noErr(t, deleteStore(b.c, b.sw.TPM()))
	if _, err := os.Lstat(b.c.storePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the store is still there")
	}
	noErr(t, os.RemoveAll(b.c.anchorDir))
	noErr(t, enroll(b.c, b.sw.TPM()))
	b.enrolled()
}

// Owner auth stays empty (ASSUMPTIONS STO-2c-c): after enrollment a raw
// owner-hierarchy command with an empty password still succeeds. This is
// the stated limit: anyone who can send TPM commands on this PC can undefine
// and redefine the pins, which the TPM device allowlist bounds to the
// trusted side.
func TestOwnerAuthStaysEmpty(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	h := tpm2.TPMHandle(0x01BFFFF0)
	pub := tpm2.TPMSNVPublic{NVIndex: h, NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTOrdinary, OwnerWrite: true, OwnerRead: true, NoDA: true}, DataSize: 8}
	owner := tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: owner, PublicInfo: tpm2.New2B(pub)}).Execute(b.sw.TPM()); err != nil {
		t.Fatalf("an empty owner auth was refused: %v", err)
	}
}

func TestParse(t *testing.T) {
	good := []string{"-state", "/s", "-anchor-dir", "/k/a", "-log", "/k/l", "-kernel-uid", "980", "-kernel-gid", "980",
		"-passphrase-file", "/p", "-recovery-file", "/r"}
	c, err := parse(good, io.Discard)
	if err != nil || c.kernelUID != 980 || len(c.pcrs) != 4 || c.tpm != "/dev/tpmrm0" {
		t.Fatalf("parse: %+v %v", c, err)
	}
	if _, err := parse([]string{"-state", "/s", "-rotate"}, io.Discard); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for _, bad := range [][]string{
		good[:len(good)-2],
		append(append([]string{}, good[:6]...), "-kernel-uid", "0", "-kernel-gid", "980", "-passphrase-file", "/p", "-recovery-file", "/r"),
		{"-state", "s", "-rotate"},
		{"-state", "/s", "-rotate", "-delete"},
		append(append([]string{}, good...), "-pcrs", "24"),
		append(append([]string{}, good...), "-pcrs", "16,23"), // nothing the unlock step can cap (#2977)
	} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// The factors' files must be root-only (here: only the test's uid).
func TestFactorFilesMustBePrivate(t *testing.T) {
	b := newBox(t)
	noErr(t, os.Chmod(b.c.passphrase, 0o644))
	if err := enroll(b.c, b.sw.TPM()); err == nil {
		t.Fatal("a world-readable passphrase file was used")
	}
	if _, err := os.Lstat(b.c.stagedPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused enrollment left a staged store")
	}
}

func parseKey(t *testing.T, st *seal.Store) *ecdsa.PrivateKey {
	t.Helper()
	der, found, err := st.Get(policyKeyEntry)
	if err != nil || !found {
		t.Fatalf("no policy key: %v", err)
	}
	return get(tpmseal.ParsePolicyKey(der))
}

// A cut after every TPM command of a rotation, inside the pins' free and
// rewrite too: the store then opens under the old key, the next key or the
// passphrase, and the rerun finishes the rotation.
func TestRotateCutAfterEachTPMCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	probe := newBox(t)
	noErr(t, enroll(probe.c, probe.sw.TPM()))
	ct := &countTPM{tpm: probe.sw.TPM()}
	noErr(t, rotate(probe.c, ct))
	total, step := ct.n, 1
	if total > 40 {
		step = total / 40
	}
	for n := 0; n < total; n += step {
		b := newBox(t)
		noErr(t, enroll(b.c, b.sw.TPM()))
		old := b.who()
		err := rotate(b.c, &cutTPM{tpm: b.sw.TPM(), n: n})
		b.reboot()
		now := b.who()
		st := get(seal.Unlock(b.c.storePath(), seal.Passphrase{Phrase: b.pass}))
		var nextPub []byte
		if next, found, _ := st.Get(nextKeyEntry); found {
			nextPub = get(get(tpmseal.ParsePolicyKey(next)).PublicKey.Bytes())
		}
		st.Close()
		if now != nil && !bytes.Equal(now, old) && !bytes.Equal(now, nextPub) && err != nil {
			t.Fatalf("cut after %d of %d: the store unlocks under a key the owner did not enrol", n, total)
		}
		noErr(t, rotate(b.c, b.sw.TPM()))
		if now := b.who(); now == nil || bytes.Equal(now, old) {
			t.Fatalf("cut after %d: the rerun did not finish the rotation", n)
		}
		b.enrolled()
	}
}

// tpmPCRs is the PCR selections of the store's one tpm slot.
func tpmPCRs(st *seal.Store) [][]uint {
	for _, sl := range st.Slots() {
		if sl.Kind == seal.KindTPM {
			var out [][]uint
			for _, p := range sl.Policies {
				out = append(out, p.PCRs)
			}
			return out
		}
	}
	return nil
}

// A rotation without -pcrs re-signs over the selection the box was enrolled
// with (here 9,12, not the default), and the next boot still unlocks
// through the pins (#2959). A -pcrs that names another selection is refused
// and changes nothing; the same selection in another order is the same.
func TestRotateKeepsTheEnrolledPCRs(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	c := b.c
	c.pcrs = []uint{9}
	files, idx := b.files(), nv(t, b.sw.TPM())
	if err := rotate(c, b.sw.TPM()); !errors.Is(err, errPCRs) {
		t.Fatalf("-pcrs 9: got %v, want errPCRs", err)
	}
	if !sameMap(files, b.files()) || !sameMap(idx, nv(t, b.sw.TPM())) {
		t.Fatal("a refused rotation changed something")
	}

	old := b.who()
	c.pcrs = nil
	noErr(t, rotate(c, b.sw.TPM()))
	b.reboot()
	if now := b.who(); now == nil || bytes.Equal(now, old) {
		t.Fatal("the rotation did not move the pins to a new key")
	}
	if got := tpmPCRs(b.enrolled()); len(got) != 1 || !slices.Equal(got[0], testPCRs) {
		t.Fatalf("the new slot's selections are %v, want [%v]", got, testPCRs)
	}

	c.pcrs = []uint{12, 9}
	noErr(t, rotate(c, b.sw.TPM()))
	if got := tpmPCRs(b.enrolled()); len(got) != 1 || !slices.Equal(got[0], testPCRs) {
		t.Fatalf("the new slot's selections are %v, want [%v]", got, testPCRs)
	}
}

// #2977: a rotation on a running box, after the unlock step capped the
// slot's boot path, re-signs the slot's boot paths instead of reading the
// capped PCRs, so the next boot unlocks under the new key, on the enrolled
// boot path and on one an update approved (the A/B update of T6). The
// capped slot opens nothing, so it opens the store by the passphrase.
func TestRotateAfterTheCapOpensOnTheNextBoot(t *testing.T) {
	b := newBox(t)
	noErr(t, enroll(b.c, b.sw.TPM()))
	old := b.who()
	st := b.enrolled()
	var slot string
	var pols []tpmseal.Policy
	for _, sl := range st.Slots() {
		if sl.Kind == seal.KindTPM {
			slot, pols = sl.ID, sl.Policies
		}
	}
	update := get(tpmseal.Sign(parseKey(t, st), testPCRs, [][]byte{swtpm.Predict("initrd-B"), swtpm.Predict("usrhash=bbbb quiet")}))
	noErr(t, st.SetPolicies(slot, append(pols, update)))
	st.Close()

	noErr(t, tpmseal.Cap(b.sw.TPM(), [][]uint{testPCRs}))
	// The capped slot opens nothing, so a rotation now needs the passphrase.
	noPass := b.c
	noPass.passphrase = ""
	if err := rotate(noPass, b.sw.TPM()); !errors.Is(err, errCapped) {
		t.Fatalf("after the cap, no passphrase: got %v, want errCapped", err)
	}
	noErr(t, rotate(b.c, b.sw.TPM()))
	b.reboot()
	if now := b.who(); now == nil || bytes.Equal(now, old) {
		t.Fatal("the rotation did not move the pins to a new key")
	}
	b.sw.Reboot()
	b.sw.Measure(9, "initrd-B")
	b.sw.Measure(12, "usrhash=bbbb quiet")
	if now := b.who(); now == nil || bytes.Equal(now, old) {
		t.Fatal("the update's boot path does not unlock under the new key")
	}
}

// The anchor's directory is made and handed over by descriptor (#2960): a
// symlink swapped in for it after the head file is written does not
// redirect the chown, and a symlink left where it goes is refused, not
// followed.
func TestAnchorDirIsNotRedirected(t *testing.T) {
	t.Run("swapped before the chown", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("a chown to another uid needs root")
		}
		b := newBox(t)
		b.c.kernelUID, b.c.kernelGID = 4242, 4242
		decoy, moved := t.TempDir(), b.c.anchorDir+".moved"
		noErr(t, os.WriteFile(filepath.Join(decoy, anchorFile), []byte("root's"), 0o600))
		c := b.c
		c.stop = func(s string) bool {
			if s == "head-file" {
				noErr(t, os.Rename(c.anchorDir, moved))
				noErr(t, os.Symlink(decoy, c.anchorDir))
			}
			return false
		}
		noErr(t, enroll(c, b.sw.TPM()))
		owner := func(p string) uint32 { return get(os.Lstat(p)).Sys().(*syscall.Stat_t).Uid }
		if owner(filepath.Join(decoy, anchorFile)) != 0 {
			t.Fatal("the chown went through the symlink")
		}
		if owner(filepath.Join(moved, anchorFile)) != 4242 || owner(moved) != 4242 {
			t.Fatal("the head file enrollment made is not the kernel's")
		}
	})
	t.Run("symlink left in place", func(t *testing.T) {
		b := newBox(t)
		decoy := t.TempDir()
		noErr(t, os.WriteFile(filepath.Join(decoy, anchorFile), []byte("not enrollment's"), 0o600))
		noErr(t, os.Symlink(decoy, b.c.anchorDir))
		if err := enroll(b.c, b.sw.TPM()); err == nil {
			t.Fatal("enrollment went through a symlinked anchor directory")
		}
		if _, err := os.Lstat(filepath.Join(decoy, anchorFile)); err != nil {
			t.Fatalf("enrollment removed a file through the symlink: %v", err)
		}
	})
}

// writeCapture writes the link port's capture of a hello by the edge key
// seeded with seed, as agentos-link's pre-store mode would, and points the
// box's enrollment at it.
func (b *box) writeCapture(seed byte) ed25519.PublicKey {
	b.t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	nonce := bytes.Repeat([]byte{0x6e}, 32)
	v := append(append(bytes.Clone(priv.Public().(ed25519.PublicKey)), nonce...), ed25519.Sign(priv, kernel.HelloMsg(nonce))...)
	if b.c.firstEdge == "" {
		b.c.firstEdge = filepath.Join(b.t.TempDir(), "first-edge")
	}
	noErr(b.t, os.WriteFile(b.c.firstEdge, v, 0o600))
	return priv.Public().(ed25519.PublicKey)
}

func gone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the capture file is still there: %v", err)
	}
}

// REQ: HW-15, BAK-1
// EDGE-link-core-b: enrollment makes the core's link key and keeps it in
// the store only, and takes the first edge key the link port captured: the
// store holds it and the capture file is gone. A capture that is
// malformed, badly signed, or writable by anyone but root stores no first
// key, is removed too, and enrollment still finishes. No capture file
// stores none.
// Revert mutants: `ed25519.Verify` dropped from readCapture (the badly
// signed capture stores a key); commitAndDrop's Remove dropped (the file
// stays).
func TestEnrollMakesALinkKeyAndTakesTheFirstEdge(t *testing.T) {
	b := newBox(t)
	edge := b.writeCapture(8)
	noErr(t, enroll(b.c, b.sw.TPM()))
	st := b.enrolled()
	seed, ok, err := st.Get(handoff.LinkKeyEntry)
	if err != nil || !ok {
		t.Fatalf("no link key in the store: %v", err)
	}
	if _, err := handoff.ParseLinkKey(seed); err != nil {
		t.Fatalf("the link key does not read: %v", err)
	}
	v, ok, err := st.Get(handoff.FirstEdgeEntry)
	if err != nil || !ok || !bytes.Equal(v, edge) {
		t.Fatalf("the store's first edge is %x, want the captured %x (%v)", v, edge, err)
	}
	gone(t, b.c.firstEdge)

	// A second box makes another link key: each enrollment its own.
	o := newBox(t)
	noErr(t, enroll(o.c, o.sw.TPM()))
	if other, _, _ := o.enrolled().Get(handoff.LinkKeyEntry); bytes.Equal(other, seed) {
		t.Fatal("two enrollments made one link key")
	}
	if _, ok, _ := o.enrolled().Get(handoff.FirstEdgeEntry); ok {
		t.Fatal("no capture stored a first edge")
	}

	for name, spoil := range map[string]func(path string){
		"short":     func(p string) { noErr(t, os.WriteFile(p, []byte("hello"), 0o600)) },
		"long":      func(p string) { noErr(t, os.WriteFile(p, append(get(os.ReadFile(p)), 0), 0o600)) },
		"bad sig":   func(p string) { v := get(os.ReadFile(p)); v[len(v)-1] ^= 1; noErr(t, os.WriteFile(p, v, 0o600)) },
		"other key": func(p string) { v := get(os.ReadFile(p)); v[0] ^= 1; noErr(t, os.WriteFile(p, v, 0o600)) },
		"writable":  func(p string) { noErr(t, os.Chmod(p, 0o622)) },
		"symlink": func(p string) {
			real := p + ".real"
			noErr(t, os.Rename(p, real))
			noErr(t, os.Symlink(real, p))
		},
	} {
		x := newBox(t)
		x.writeCapture(8)
		spoil(x.c.firstEdge)
		if err := enroll(x.c, x.sw.TPM()); err != nil {
			t.Fatalf("%s capture: enrollment did not finish: %v", name, err)
		}
		if _, ok, _ := x.enrolled().Get(handoff.FirstEdgeEntry); ok {
			t.Errorf("%s capture: stored a first edge", name)
		}
		gone(t, x.c.firstEdge)
	}
}

// REQ: HW-15, REC-2
// EDGE-link-core-b: a restore's enrollment removes a capture file it finds
// and stores no first edge key, so a restored box trusts no edge until the
// owner's page step; it still makes a new link key.
// Revert mutant: `|| c.restore` dropped from putLinkKeys (the restore
// stores the captured key).
func TestRestoreEnrollStoresNoFirstEdge(t *testing.T) {
	b := newBox(t)
	b.writeCapture(8)
	b.c.restore = true
	noErr(t, enroll(b.c, b.sw.TPM()))
	st := b.enrolled()
	if _, ok, _ := st.Get(handoff.FirstEdgeEntry); ok {
		t.Fatal("a restore's enrollment stored a first edge")
	}
	if _, ok, _ := st.Get(handoff.LinkKeyEntry); !ok {
		t.Fatal("a restore's enrollment made no link key")
	}
	gone(t, b.c.firstEdge)
}

// REQ: HW-15
// EDGE-link-core-b2 (#3364): the capture is taken only from a file its
// owner uid holds, and never for a small-order key, whose hello anyone can
// forge (the identity key, with R the identity and S zero, verifies over
// any nonce). The owner is a parameter so a plain-user test sees the check
// refuse a file of another uid's; enrollment passes its euid, root.
// Revert mutants: `int(st.Uid) != owner` made false (the other uid's file is
// taken); `kernel.SmallOrder(edge) ||` dropped (the forged capture is
// taken).
func TestCaptureIsTheOwnersAndNoSmallOrderKey(t *testing.T) {
	dir := t.TempDir()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	nonce := bytes.Repeat([]byte{0x6e}, 32)
	real := filepath.Join(dir, "real")
	noErr(t, os.WriteFile(real, append(append(bytes.Clone(priv.Public().(ed25519.PublicKey)), nonce...), ed25519.Sign(priv, kernel.HelloMsg(nonce))...), 0o600))
	if k, err := readCapture(real, os.Geteuid()); err != nil || !k.Equal(priv.Public()) {
		t.Fatalf("the owner's capture was not taken: %x, %v", k, err)
	}
	if k, err := readCapture(real, os.Geteuid()+1); !errors.Is(err, errCapture) || k != nil {
		t.Fatalf("another uid's capture was taken: %x, %v", k, err)
	}

	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1
	forged := append(bytes.Clone(identity), make([]byte, 32)...)
	if !ed25519.Verify(identity, kernel.HelloMsg(nonce), forged) {
		t.Fatal("the identity key's forged hello no longer verifies: the premise moved")
	}
	small := filepath.Join(dir, "small")
	noErr(t, os.WriteFile(small, append(append(bytes.Clone(identity), nonce...), forged...), 0o600))
	if k, err := readCapture(small, os.Geteuid()); !errors.Is(err, errCapture) || k != nil {
		t.Fatalf("a small-order capture was taken: %x, %v", k, err)
	}
}
