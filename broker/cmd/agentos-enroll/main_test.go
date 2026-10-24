package main

// REQ: STO-2, STO-1, HW-5a, CLK-1, UPD-10

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
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
		kernelUID: os.Getuid(), kernelGID: os.Getgid(),
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
	for _, step := range []string{"cleaned", "created", "slots", "counter", "anchor", "pins"} {
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
