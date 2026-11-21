package main

// MUT-kill-6305-unlock (#6368): each test here fails when one statement of
// main.go is deleted, on a path the rest of the package's tests do not
// reach. Most run on a plain store (seal.Create with a recovery slot) with
// no TPM; the ones through unlock need swtpm.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
)

// REQ: STO-2, CLK-1, REC-4, CH-4

// plainStore is a store in its own directory with one recovery slot.
func plainStore(t *testing.T) (*seal.Store, []byte) {
	t.Helper()
	rk := bytes.Repeat([]byte{7}, seal.RecoveryLen)
	st, err := seal.Create(filepath.Join(t.TempDir(), "store"), seal.Recovery{Key: rk})
	must(t, err)
	t.Cleanup(st.Close)
	return st, rk
}

// closedStore is a plain store, closed: every read of it fails.
func closedStore(t *testing.T) *seal.Store {
	t.Helper()
	st, _ := plainStore(t)
	st.Close()
	return st
}

// fdsTo counts this process's descriptors open on path.
func fdsTo(t *testing.T, path string) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	must(t, err)
	n := 0
	for _, e := range ents {
		if l, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && l == path {
			n++
		}
	}
	return n
}

// said runs f and returns what it wrote on stderr.
func said(t *testing.T, f func()) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	must(t, err)
	saved := os.Stderr
	os.Stderr = pw
	out := make(chan string)
	go func() { b, _ := io.ReadAll(pr); out <- string(b) }()
	defer func() {
		os.Stderr = saved
		pw.Close()
	}()
	f()
	os.Stderr = saved
	pw.Close()
	return <-out
}

// fifo makes a FIFO in a fresh directory.
func fifo(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fifo")
	must(t, syscall.Mkfifo(p, 0o600))
	return p
}

// withoutDAC runs f on a thread of its own whose effective capabilities
// are cleared, so even root is held to a file's mode bits there, as the
// unlock step's uid on a box with a damaged disk would be. Capabilities
// are per thread; the thread ends with f, never unlocked.
func withoutDAC(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		var data [2]unix.CapUserData
		if err := unix.Capget(&hdr, &data[0]); err != nil {
			t.Error(err)
			return
		}
		data[0].Effective, data[1].Effective = 0, 0
		if err := unix.Capset(&hdr, &data[0]); err != nil {
			t.Error(err)
			return
		}
		f()
	}()
	<-done
}

// A TPM path that does not open stops the step before any pin is read.
func TestUnlockStopsAtATPMThatDoesNotOpen(t *testing.T) {
	c := config{tpm: filepath.Join(t.TempDir(), "no-tpm")}
	pins := func(transport.TPM) (*ecdsa.PublicKey, []byte, error) {
		t.Error("the pins were read with no TPM")
		return nil, nil, errors.New("no pins")
	}
	if _, err := unlock(c, pins); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unlock on a missing TPM: %v, want ErrNotExist", err)
	}
}

// The step's own TPM connection is closed when it returns, here on a
// failure: a device it opened is not left open.
func TestUnlockClosesItsTPM(t *testing.T) {
	const dev = "/dev/null" // a character device, so linuxtpm opens it
	before := fdsTo(t, dev)
	refused := errors.New("no pins on this TPM")
	pins := func(transport.TPM) (*ecdsa.PublicKey, []byte, error) { return nil, nil, refused }
	if _, err := unlock(config{tpm: dev}, pins); !errors.Is(err, refused) {
		t.Fatalf("unlock: %v, want the pins' error", err)
	}
	if after := fdsTo(t, dev); after != before {
		t.Fatalf("%d descriptors on the TPM after unlock, %d before", after, before)
	}
}

// readRequest closes the file, refuses a FIFO by name, and refuses a file
// one byte over maxRequest; one of maxRequest bytes reads whole.
func TestReadRequestBounds(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "request")
	must(t, os.WriteFile(p, bytes.Repeat([]byte{1}, maxRequest), 0o600))
	before := fdsTo(t, p)
	if b, err := readRequest(p); err != nil || len(b) != maxRequest {
		t.Fatalf("a request of maxRequest bytes: %d bytes, %v", len(b), err)
	}
	if after := fdsTo(t, p); after != before {
		t.Fatalf("readRequest left %d descriptors on the file, %d before", after, before)
	}
	must(t, os.WriteFile(p, bytes.Repeat([]byte{1}, maxRequest+1), 0o600))
	if _, err := readRequest(p); err == nil || !strings.Contains(err.Error(), "is over") {
		t.Fatalf("a request over maxRequest: %v", err)
	}
	if _, err := readRequest(fifo(t)); err == nil || !strings.Contains(err.Error(), "is not a file") {
		t.Fatalf("a FIFO request: %v", err)
	}
}

// lockStore on a missing directory says the open failed, not the lock.
func TestLockStoreNamesAMissingDirectory(t *testing.T) {
	if _, err := lockStore(filepath.Join(t.TempDir(), "none")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lockStore on a missing directory: %v, want ErrNotExist", err)
	}
}

// lostStore is a store in dir as enrollment leaves it for the lost-card
// route: its recovery key's backup recipient, and one passphrase slot.
func lostStore(t *testing.T, dir string) (*seal.Store, []byte, ed25519.PrivateKey) {
	t.Helper()
	rk := bytes.Repeat([]byte{7}, seal.RecoveryLen)
	st, err := seal.Create(filepath.Join(dir, "store"), seal.Recovery{Key: rk})
	must(t, err)
	t.Cleanup(st.Close)
	must(t, st.Put(handoff.RecipientEntry, recipientEntry(t, rk)))
	_, err = st.AddSlot(seal.Passphrase{Phrase: []byte("correct horse battery staple")})
	must(t, err)
	head, err := st.HeadKey()
	must(t, err)
	return st, rk, head
}

func signedLost(t *testing.T, head ed25519.PrivateKey, old string) []byte {
	t.Helper()
	b, err := handoff.SignApproval(head, lostCardApproval(old))
	must(t, err)
	return b
}

func slotIDs(st *seal.Store) []string {
	var ids []string
	for _, s := range st.Slots() {
		ids = append(ids, s.ID)
	}
	return ids
}

// lostCard refuses a request that is no approval with the approval's own
// error, and one the store's recipient cannot be read for, changing no
// slot.
func TestLostCardRefusesBeforeAnyChange(t *testing.T) {
	st, _, head := lostStore(t, t.TempDir())
	pub := head.Public().(ed25519.PublicKey)
	now := time.Now().UnixMilli()
	if _, err := lostCard(st, []byte("not an approval"), pub, now); !errors.Is(err, handoff.ErrApproval) {
		t.Fatalf("a request that is no approval: %v, want ErrApproval", err)
	}
	ids := slotIDs(st)
	must(t, st.Put(handoff.RecipientEntry, []byte("not a recipient")))
	if bits, err := lostCard(st, signedLost(t, head, ""), pub, now); err == nil || bits != nil {
		t.Fatalf("a store whose recipient does not read: %x, %v", bits, err)
	}
	if got := slotIDs(st); strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Fatalf("slots %v after a refused request, %v before", got, ids)
	}
}

// A new card the store cannot keep (its directory is gone, so the write
// fails before the rename) is not handed on.
func TestLostCardTheStoreCannotKeepIsNotHanded(t *testing.T) {
	dir := t.TempDir()
	st, rk, head := lostStore(t, dir)
	must(t, os.RemoveAll(dir))
	bits, err := lostCard(st, signedLost(t, head, recipientOf(t, rk)), head.Public().(ed25519.PublicKey), time.Now().UnixMilli())
	if err == nil || bits != nil {
		t.Fatalf("a card the store could not keep: %x, %v", bits, err)
	}
}

// A new card in place whose directory sync fails is handed on, and the
// step says the sync failed.
func TestLostCardInPlaceDespiteTheSyncIsHanded(t *testing.T) {
	dir := t.TempDir()
	st, rk, head := lostStore(t, dir)
	req := signedLost(t, head, recipientOf(t, rk))
	// Write and search, no read: the temporary and the rename work, the
	// directory's open for its sync does not.
	must(t, os.Chmod(dir, 0o300))
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	var bits []byte
	var err error
	out := said(t, func() {
		withoutDAC(t, func() {
			bits, err = lostCard(st, req, head.Public().(ed25519.PublicKey), time.Now().UnixMilli())
		})
	})
	if err != nil || len(bits) != handoff.MadeCardLen {
		t.Fatalf("a card in place with a failed sync: %d bits, %v", len(bits), err)
	}
	if !strings.Contains(out, "directory sync failed") {
		t.Fatalf("the failed sync was not said: %q", out)
	}
	if id, err := storeRecipientID(st); err != nil || id == recipientOf(t, rk) {
		t.Fatalf("the store's recipient after the card: %q, %v", id, err)
	}
}

// storeRecipientID is "" for a store with none, the recipient's ID for
// one that reads, and an error for one that does not or a closed store.
func TestStoreRecipientID(t *testing.T) {
	st, rk := plainStore(t)
	if id, err := storeRecipientID(st); id != "" || err != nil {
		t.Fatalf("no recipient: %q, %v", id, err)
	}
	must(t, st.Put(handoff.RecipientEntry, recipientEntry(t, rk)))
	if id, err := storeRecipientID(st); id != recipientOf(t, rk) || err != nil {
		t.Fatalf("the recipient: %q, %v, want %q", id, err, recipientOf(t, rk))
	}
	must(t, st.Put(handoff.RecipientEntry, []byte("not a recipient")))
	if id, err := storeRecipientID(st); id != "" || !errors.Is(err, handoff.ErrHandoff) {
		t.Fatalf("a recipient that does not read: %q, %v", id, err)
	}
	if _, err := storeRecipientID(closedStore(t)); !errors.Is(err, seal.ErrClosed) {
		t.Fatalf("a closed store: %v, want ErrClosed", err)
	}
}

// setupLog writes a kernel log whose first entry is the owner's setup of
// keys, under logKey and for box, as a setup kernel's first frame.
func setupLog(t *testing.T, path string, logKey [32]byte, box ed25519.PublicKey, keys ...key.Signer) {
	t.Helper()
	body, err := json.Marshal(kernel.SignSetup(box, keys...))
	must(t, err)
	pt, err := json.Marshal(kernel.Entry{Seq: 1, Type: kernel.TAnchorsSet, V: 1, Body: body})
	must(t, err)
	b, err := aes.NewCipher(logKey[:])
	must(t, err)
	a, err := cipher.NewGCM(b)
	must(t, err)
	nonce := make([]byte, a.NonceSize())
	fr := a.Seal(nonce, nonce, pt, binary.BigEndian.AppendUint64(nil, 1))
	must(t, os.WriteFile(path, append(binary.BigEndian.AppendUint32(nil, uint32(len(fr))), fr...), 0o600))
}

// keysOf is what unlock hands for st: its log and head keys.
func keysOf(t *testing.T, st *seal.Store) handoff.KernelKeys {
	t.Helper()
	lk, err := st.LogKey()
	must(t, err)
	head, err := st.HeadKey()
	must(t, err)
	return handoff.KernelKeys{Log: secret.Hide(lk), Head: secret.Hide(head)}
}

// clerkAnchors: a store it cannot read, or a clerks' entry that does not
// read, is an error; a log that cannot be read, has no setup, or a first
// entry that does not open, gives none and says why (or nothing, for no
// setup yet); a setup the store cannot keep gives none and says so.
func TestClerkAnchorsEachWayToNone(t *testing.T) {
	if _, err := clerkAnchors(closedStore(t), handoff.KernelKeys{}, "/nonexistent"); !errors.Is(err, seal.ErrClosed) {
		t.Fatalf("a closed store: %v, want ErrClosed", err)
	}
	st, _ := plainStore(t)
	k := keysOf(t, st)
	d := t.TempDir()
	none := func(name, log, want string) {
		t.Helper()
		var a []key.PublicKey
		var err error
		out := said(t, func() { a, err = clerkAnchors(st, k, log) })
		if a != nil || err != nil {
			t.Errorf("%s: %v, %v, want none", name, a, err)
		}
		if want == "" && out != "" || !strings.Contains(out, want) {
			t.Errorf("%s: said %q, want %q", name, out, want)
		}
	}
	none("a log that is a FIFO", fifo(t), "the clerks get no hardware keys: my log:")
	empty := filepath.Join(d, "empty")
	must(t, os.WriteFile(empty, nil, 0o600))
	none("an empty log", empty, "")
	bad := filepath.Join(d, "bad")
	must(t, os.WriteFile(bad, append(binary.BigEndian.AppendUint32(nil, 64), make([]byte, 64)...), 0o600))
	none("a first frame that does not open", bad, "my log's first entry:")

	box := k.Head.Get().Public().(ed25519.PublicKey)
	hw1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	hw2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))
	good := filepath.Join(d, "good")
	setupLog(t, good, k.Log.Get(), box, key.Ed25519Signer(hw1), key.Ed25519Signer(hw2))
	a, err := clerkAnchors(st, k, good)
	if err != nil || len(a) != 2 || a[0] != key.Ed25519(hw1.Public().(ed25519.PublicKey)) {
		t.Fatalf("a setup log: %v, %v", a, err)
	}

	// The same log, for a store whose directory is gone: the Put fails.
	gone := t.TempDir()
	st2, err := seal.Create(filepath.Join(gone, "store"), seal.Recovery{Key: bytes.Repeat([]byte{8}, seal.RecoveryLen)})
	must(t, err)
	t.Cleanup(st2.Close)
	k2 := keysOf(t, st2)
	setupLog(t, good, k2.Log.Get(), k2.Head.Get().Public().(ed25519.PublicKey), key.Ed25519Signer(hw1), key.Ed25519Signer(hw2))
	must(t, os.RemoveAll(gone))
	st = st2
	k = k2
	none("a setup the store cannot keep", good, "keep them in my store:")

	st3, _ := plainStore(t)
	must(t, st3.Put(handoff.ClerkAnchorsEntry, []byte("short")))
	if _, err := clerkAnchors(st3, handoff.KernelKeys{}, "/nonexistent"); err == nil || !strings.Contains(err.Error(), "the clerks' copy") {
		t.Fatalf("a clerks' entry that does not read: %v", err)
	}
}

// logStart: no log is an empty start; a link is refused by the open, a
// FIFO by name, and a file whose read fails with that error; the file is
// closed after.
func TestLogStartRefusals(t *testing.T) {
	d := t.TempDir()
	if b, err := logStart(filepath.Join(d, "none")); b != nil || err != nil {
		t.Fatalf("no log: %v, %v", b, err)
	}
	p := filepath.Join(d, "log")
	must(t, os.WriteFile(p, []byte("abc"), 0o600))
	before := fdsTo(t, p)
	if b, err := logStart(p); string(b) != "abc" || err != nil {
		t.Fatalf("a short log: %q, %v", b, err)
	}
	if after := fdsTo(t, p); after != before {
		t.Fatalf("logStart left %d descriptors on the log, %d before", after, before)
	}
	link := filepath.Join(d, "link")
	must(t, os.Symlink(p, link))
	if _, err := logStart(link); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a link: %v, want ELOOP", err)
	}
	if _, err := logStart(fifo(t)); err == nil || !strings.Contains(err.Error(), "is not a file") {
		t.Fatalf("a FIFO: %v", err)
	}
	// A regular file whose read fails: this process's memory at address 0.
	if _, err := logStart("/proc/self/mem"); !errors.Is(err, syscall.EIO) {
		t.Fatalf("a log whose read fails: %v, want EIO", err)
	}
}

// putClerkAnchors writes anchors that encode, world-readable, and refuses
// ones that do not, leaving an earlier file; a write that fails is said by
// writeClerkAnchors, which removes the file. A crash (stop) before the
// rename leaves the earlier boot's file, after it the new one.
func TestClerkAnchorsWriteAndRefuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clerks")
	path := filepath.Join(dir, "anchors")
	one := []key.PublicKey{key.Ed25519(gen(1))}
	two := []key.PublicKey{key.Ed25519(gen(1)), key.Ed25519(gen(2))}
	must(t, putClerkAnchors(path, two, nil))
	b, err := os.ReadFile(path)
	must(t, err)
	if a, err := handoff.ParseAnchors(b); err != nil || len(a) != 2 {
		t.Fatalf("written anchors: %v, %v", a, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("the anchors file: %v, %v", fi, err)
	}
	dup := []key.PublicKey{key.Ed25519(gen(1)), key.Ed25519(gen(1))}
	if err := putClerkAnchors(path, dup, nil); !errors.Is(err, handoff.ErrHandoff) {
		t.Fatalf("anchors that do not encode: %v, want ErrHandoff", err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, b) {
		t.Fatal("anchors that do not encode changed the file")
	}
	out := said(t, func() { writeClerkAnchors(path, dup, nil) })
	if !strings.Contains(out, "the clerks' hardware keys:") {
		t.Fatalf("a failed write was not said: %q", out)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed write left the file: %v", err)
	}
	for i := range 6 {
		must(t, putClerkAnchors(path, two, nil))
		err := putClerkAnchors(path, one, func(at int) bool { return at == i })
		if !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("stop at %d: %v", i, err)
		}
		got, err := os.ReadFile(path)
		must(t, err)
		a, err := handoff.ParseAnchors(got)
		must(t, err)
		if want := 2 - min(1, i/4); len(a) != want {
			t.Errorf("stop at %d: %d anchors, want %d", i, len(a), want)
		}
	}
}

// putCheckerSeed: a store it cannot read is an error; a store with no seed
// removes the earlier boot's file; a seed entry that does not read says
// it is the store's; a zero clerk root is refused as a key; a good one
// writes a seed the checker's key opens.
func TestPutCheckerSeedEachWay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seed")
	path := filepath.Join(dir, "seed")
	root := [32]byte{1}
	if err := putCheckerSeed(path, closedStore(t), &root, nil); !errors.Is(err, seal.ErrClosed) {
		t.Fatalf("a closed store: %v, want ErrClosed", err)
	}
	st, _ := plainStore(t)
	must(t, os.WriteFile(path, []byte("an earlier boot's"), 0o600))
	if err := putCheckerSeed(path, st, &root, nil); err != nil {
		t.Fatalf("no seed: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no seed left the earlier file: %v", err)
	}
	must(t, st.Put(handoff.CheckerSeedEntry, []byte("not a seed")))
	if err := putCheckerSeed(path, st, &root, nil); err == nil || !strings.Contains(err.Error(), "in my store") {
		t.Fatalf("a seed that does not read: %v", err)
	}
	seed, err := handoff.EncodeCodeSeed(handoff.CodeSeed{Seed: secret.Hide(bytes.Repeat([]byte{3}, 32)), Step: 5})
	must(t, err)
	must(t, st.Put(handoff.CheckerSeedEntry, seed))
	if err := putCheckerSeed(path, st, new([32]byte), nil); !errors.Is(err, clerkkey.ErrKey) {
		t.Fatalf("a zero clerk root: %v, want ErrKey", err)
	}
	must(t, putCheckerSeed(path, st, &root, nil))
	blob, err := os.ReadFile(path)
	must(t, err)
	k, err := clerkkey.Derive(&root, handoff.CheckerName)
	must(t, err)
	sealer, err := k.Sealer()
	must(t, err)
	s, err := handoff.OpenCodeSeed(sealer, blob)
	if err != nil || s.Step != 5 || !bytes.Equal(s.Seed.Get(), bytes.Repeat([]byte{3}, 32)) {
		t.Fatalf("the written seed: %v, %v", s, err)
	}
	out := said(t, func() { writeCheckerSeed(path, closedStore(t), &root, nil) })
	if !strings.Contains(out, "the checker's code seed:") {
		t.Fatalf("a failed seed was not said: %q", out)
	}
}

// counter: a closed store's error, and a store with no counter told to
// set up again.
func TestCounterRefusals(t *testing.T) {
	if _, err := counter(closedStore(t)); !errors.Is(err, seal.ErrClosed) {
		t.Fatalf("a closed store: %v, want ErrClosed", err)
	}
	st, _ := plainStore(t)
	if _, err := counter(st); err == nil || !strings.Contains(err.Error(), "holds no counter") {
		t.Fatalf("no counter: %v", err)
	}
}

// A clerks' entry that does not read stops the unlock, rather than
// writing the clerks no keys.
func TestUnlockStopsAtAClerksEntryThatDoesNotRead(t *testing.T) {
	r := newRig(t, false)
	st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
	must(t, err)
	must(t, st.Put(handoff.ClerkAnchorsEntry, []byte("short")))
	st.Close()
	r.reboot()
	role := r.role(&r.policy.PublicKey, r.anchor)
	c := role.Config()
	c.clerkAnchors, c.log = filepath.Join(r.dir, "clerks", "anchors"), r.mainConfig().Log
	if b, err := unlock(c, role.pins); err == nil || !strings.Contains(err.Error(), "the clerks' copy") {
		clear(b)
		t.Fatalf("a clerks' entry that does not read: %v", err)
	}
}
