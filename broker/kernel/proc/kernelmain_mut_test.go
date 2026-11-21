package proc

// REQ: STO-2, BAK-1, REC-4, MAIL-keys, KRN-2
//
// MUT-kill-6305-proc (#6367): the kernel process's start, its refusals and
// what it says, its sockets' lives, and the held recovery card, each
// checked by what they return, print or leave.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
	"github.com/ghbmrk/agentos/broker/sockets/peers"
)

// stderrOf is what fn writes to os.Stderr.
func stderrOf(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); got <- b }()
	was := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = was }()
	fn()
	os.Stderr = was
	w.Close()
	return string(<-got)
}

// markUp makes its file once, keeps no descriptor to it, and says so when it
// cannot; with no path it does nothing.
func TestMarkUpMakesItsFileOnceAndSaysWhenItCannot(t *testing.T) {
	p := filepath.Join(t.TempDir(), "up")
	if out := stderrOf(t, func() { markUp("") }); out != "" {
		t.Fatalf("markUp with no path said %q", out)
	}
	if out := stderrOf(t, func() { markUp(p) }); out != "" {
		t.Fatalf("markUp said %q", out)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	if n := openFDsTo(t, p); n != 0 {
		t.Fatalf("%d descriptors to the up file stay open", n)
	}
	if out := stderrOf(t, func() { markUp(p) }); !strings.Contains(out, "mark that I am up") {
		t.Fatalf("markUp over a file there said %q", out)
	}
}

// madeCard is a made card's bytes and its recipient's ID.
func madeCard(t *testing.T, b byte) ([]byte, string) {
	t.Helper()
	c := bytes.Repeat([]byte{b}, handoff.MadeCardLen)
	sk, err := handoff.StoreRecoveryKey(c[:handoff.CardKeyLen])
	if err != nil {
		t.Fatal(err)
	}
	return c, recipientID(t, sk)
}

// A held card is wiped when another replaces it, and a card that is no
// made card is wiped and drops the one held.
func TestHoldRecoveryCardWipesWhatItDrops(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	a, _ := madeCard(t, 0x11)
	c, cid := madeCard(t, 0x22)
	b.h.HoldRecoveryCard(a)
	b.h.HoldRecoveryCard(c)
	if !bytes.Equal(a, make([]byte, len(a))) {
		t.Fatal("the replaced card was not wiped")
	}
	if id, err := b.h.RecoveryCardID(); err != nil || id != cid {
		t.Fatalf("held %q %v, want the new card's %q", id, err, cid)
	}
	bad := bytes.Repeat([]byte{0x33}, handoff.MadeCardLen-1)
	b.h.HoldRecoveryCard(bad)
	if !bytes.Equal(bad, make([]byte, len(bad))) {
		t.Fatal("a card that is no made card was not wiped")
	}
	if _, err := b.h.RecoveryCardID(); !errors.Is(err, ErrNoRecoveryCard) {
		t.Fatalf("after a bad card: %v, want ErrNoRecoveryCard", err)
	}
}

// inWith waits until some goroutine is inside (*Kernel).With.
func inWith(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if bytes.Contains(buf[:runtime.Stack(buf, true)], []byte("proc.(*Kernel).With(")) {
			return
		}
	}
	t.Fatal("no call reached the kernel's lock")
}

// A card confirmed while its tap is being checked is not shown.
func TestACardDoneDuringItsTapIsNotShown(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	c, id := madeCard(t, 0x44)
	b.h.HoldRecoveryCard(c)
	tap := key.Approve(key.Ed25519Signer(ownerPriv), kernel.RecoveryCardHash(id))
	type shown struct {
		b   []byte
		err error
	}
	got := make(chan shown, 1)
	b.h.mu.Lock()
	go func() { k, err := b.h.RecoveryCard(tap); got <- shown{k, err} }()
	inWith(t)
	b.h.RecoveryCardDone()
	b.h.mu.Unlock()
	if s := <-got; !errors.Is(s.err, ErrNoRecoveryCard) || s.b != nil {
		t.Fatalf("a card done during its tap: %x, %v; want ErrNoRecoveryCard", s.b, s.err)
	}
}

// mainCfg is a kernel process's config over the data folder of b, with its
// sockets in a short folder.
func mainCfg(t *testing.T, b *bbox) MainConfig {
	d := shortDir(t)
	return MainConfig{Log: b.cfg.Log, KeyDir: b.cfg.KeyDir, ContentDir: b.cfg.ContentDir, BackupDir: b.cfg.BackupDir,
		OwnerSock: filepath.Join(d, "o.sock"), OwnerUID: os.Getuid(), MeterSock: filepath.Join(d, "m.sock"), MeterUID: os.Getuid(),
		Up: filepath.Join(d, "up"), Tick: 10 * time.Millisecond}
}

func mainKeys() handoff.KernelKeys {
	return handoff.KernelKeys{Log: secret.Hide([32]byte{7}), Head: secret.Hide(headPriv), Anchors: anchors, Slot: handoff.SlotTPM}
}

// runMain runs the kernel process until it is up and returns its cancel
// and its end, which carries its error.
func runMain(t *testing.T, cfg MainConfig, keys handoff.KernelKeys, a kernel.Anchor) (context.CancelFunc, <-chan error) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the kernel never runs as root; CI runs these as a plain user")
	}
	os.Remove(cfg.Up)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunKernel(ctx, cfg, keys, a) }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(2 * time.Millisecond) {
		if _, err := os.Stat(cfg.Up); err == nil {
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("the kernel did not come up: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the kernel did not come up in time")
		}
	}
	t.Cleanup(cancel)
	return cancel, done
}

// stopMain ends a kernel process runMain started and returns its error.
func stopMain(cancel context.CancelFunc, done <-chan error) error {
	cancel()
	return <-done
}

// startFails runs the kernel process and wants it refused before it is up.
func startFails(t *testing.T, cfg MainConfig, keys handoff.KernelKeys, a kernel.Anchor) error {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the kernel never runs as root; CI runs these as a plain user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := RunKernel(ctx, cfg, keys, a)
	if _, up := os.Stat(cfg.Up); err == nil || up == nil {
		t.Fatalf("the kernel came up (%v)", err)
	}
	return err
}

// The kernel process refuses to start as one of its peers, without the
// head key, on a log under another key, over a key table open to others,
// and where it cannot listen; each refusal is its own error.
func TestTheKernelProcessRefusesAStartItCannotHold(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject() // a log entry, which another key does not open
	b.h.Close()
	a := anchor(t, b.cfg.Log)
	cfg := mainCfg(t, b)
	cfg.Peers = []int{os.Getuid()}
	if err := startFails(t, cfg, mainKeys(), a); err == nil || !strings.Contains(err.Error(), "procguard") {
		t.Fatalf("a start as a peer's uid: %v", err)
	}
	cfg = mainCfg(t, b)
	keys := mainKeys()
	keys.Head = secret.Hide(ed25519.PrivateKey(nil))
	if err := startFails(t, cfg, keys, a); err == nil || !strings.Contains(err.Error(), "unlock step's keys") {
		t.Fatalf("a start with no head key: %v", err)
	}
	keys = mainKeys()
	keys.Log = secret.Hide([32]byte{8})
	if err := startFails(t, cfg, keys, a); !errors.Is(err, ErrLogKey) {
		t.Fatalf("a start on a log under another key: %v, want ErrLogKey", err)
	}
	if err := os.Chmod(cfg.KeyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := startFails(t, cfg, mainKeys(), a); err == nil || !strings.Contains(err.Error(), "subject-key table") {
		t.Fatalf("a start over a key table open to others: %v", err)
	}
	if err := os.Chmod(cfg.KeyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.OwnerSock = filepath.Join(cfg.OwnerSock+"-none", "o.sock")
	if err := startFails(t, cfg, mainKeys(), a); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a start whose owner socket cannot listen: %v", err)
	}
	cfg = mainCfg(t, b)
	cfg.ClerkKeys = map[string]KeyClerk{"checker": {Socket: filepath.Join(cfg.Up+"-none", "k.sock"), Cgroup: "/x/c.service"}}
	keys = mainKeys()
	keys.ClerkRoot = secret.Hide([32]byte{9})
	if err := startFails(t, cfg, keys, a); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a start whose key socket cannot listen: %v", err)
	}
}

// A start says what its store lacks (a backup recipient, a page
// authority) and what its stores hold that no entry names, and says
// nothing of those it has; the card made at this boot is held for the
// owner's page.
func TestTheKernelProcessSaysWhatItLacksAndHoldsTheCard(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	stray := filepath.Join(b.cfg.ContentDir, "vision", itemName(kernel.Hash{4}))
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.h.Close()
	a := anchor(t, b.cfg.Log)
	cfg := mainCfg(t, b)
	out := stderrOf(t, func() {
		cancel, done := runMain(t, cfg, mainKeys(), a)
		if err := stopMain(cancel, done); err != nil {
			t.Error(err)
		}
	})
	for _, want := range []string{ErrNoRecipient.Error(), ErrNoAuthority.Error(), "the stores hold 1 items no entry names"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the start said %q, want %q", out, want)
		}
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	ca, _ := testPageCA(t)
	card, id := madeCard(t, 0x55)
	keys := mainKeys()
	keys.Recipient, keys.PageCA, keys.NewRecovery = recipientWire(t, testRK), secret.Hide(ca), secret.Hide(card)
	out = stderrOf(t, func() {
		cancel, done := runMain(t, cfg, keys, a)
		var got struct {
			ID string `json:"id"`
		}
		if err := (Conn{Socket: cfg.OwnerSock, UID: os.Getuid(), Timeout: 5 * time.Second}).Call("recoverycardid", nil, &got); err != nil || got.ID != id {
			t.Errorf("the card held: %q %v, want %q", got.ID, err, id)
		}
		if err := stopMain(cancel, done); err != nil {
			t.Error(err)
		}
	})
	if out != "" {
		t.Fatalf("a start with all it needs said %q", out)
	}
	if _, err := net.Dial("unix", cfg.OwnerSock); err == nil {
		t.Fatal("the owner socket still answers after the kernel stopped")
	}
}

// A clerk's key socket that stops serving stops the kernel process with
// its error.
func TestAKeySocketThatStopsStopsTheKernel(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.h.Close()
	cfg := mainCfg(t, b)
	cfg.ClerkKeys = map[string]KeyClerk{"checker": {Socket: filepath.Join(filepath.Dir(cfg.Up), "k.sock")}}
	keys := mainKeys()
	keys.ClerkRoot = secret.Hide([32]byte{9})
	if os.Geteuid() == 0 {
		t.Skip("the kernel never runs as root; CI runs these as a plain user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := RunKernel(ctx, cfg, keys, anchor(t, b.cfg.Log)); err == nil || !strings.Contains(err.Error(), "no unit") {
		t.Fatalf("a key socket with no unit: %v, want its error", err)
	}
}

// The kernel process returns only once a key hand-off in progress is over:
// the clerk root it reads is cleared after.
func TestTheKernelWaitsForAKeyHandOff(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.h.Close()
	cfg := mainCfg(t, b)
	sock := filepath.Join(filepath.Dir(cfg.Up), "k.sock")
	cfg.ClerkKeys = map[string]KeyClerk{"checker": {Socket: sock, Cgroup: "/x/c.service"}}
	keys := mainKeys()
	keys.ClerkRoot = secret.Hide([32]byte{9})
	entered, release := make(chan struct{}), make(chan struct{})
	wasCg, wasLn := keyCgroup, listenClerkKey
	keyCgroup = func(int32) (string, error) { close(entered); <-release; return "/x/c.service", nil }
	// The key socket admits uid 0 alone; this test's uid stands in for it.
	listenClerkKey = func(p string) (net.Listener, error) { return peers.ListenUnix(p, os.Getuid()) }
	t.Cleanup(func() { keyCgroup, listenClerkKey = wasCg, wasLn })
	cancel, done := runMain(t, cfg, keys, anchor(t, b.cfg.Log))
	c, err := net.Dial("unix", sock)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer c.Close()
	<-entered
	cancel()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("the kernel returned during a key hand-off: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the kernel never returned")
	}
	if got, err := io.ReadAll(c); err != nil || len(got) == 0 {
		t.Fatalf("the hand-off gave %d bytes, %v", len(got), err)
	}
}

// A Tick of the kernel process re-seals a backup an erase left due.
func TestTheKernelProcessTicks(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone := b.subject()
	dir := b.addTarget("drive", false)
	id := b.backup()[0].Backup.BackupID
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err }); err != nil {
		t.Fatal(err)
	}
	b.h.Close()
	if !gives(t, dir, id, gone) {
		t.Fatal("the backup was re-sealed before the kernel process ran")
	}
	keys := mainKeys()
	keys.Recipient = recipientWire(t, testRK)
	cancel, done := runMain(t, mainCfg(t, b), keys, anchor(t, b.cfg.Log))
	defer stopMain(cancel, done)
	for deadline := time.Now().Add(5 * time.Second); gives(t, dir, id, gone); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no Tick re-sealed the backup")
		}
	}
}

// The kernel process never runs as root: in a user namespace where this
// test is uid 0 it refuses at once.
func TestTheKernelProcessRefusesRoot(t *testing.T) {
	if os.Getenv("AGENTOS_TEST_ROOT_CHILD") == "1" {
		if os.Geteuid() != 0 {
			os.Exit(3)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		d := t.TempDir()
		err := RunKernel(ctx, MainConfig{Log: filepath.Join(d, "log"), KeyDir: d, ContentDir: d, BackupDir: d}, mainKeys(), &kernel.MemAnchor{})
		os.Stdout.WriteString("child: " + strings.ReplaceAll(errString(err), "\n", " ") + "\n")
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("already root; CI runs these as a plain user")
	}
	// A RunKernel earlier in this process made it non-dumpable
	// (procguard.Isolate), which leaves a child's uid map unwritable.
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 1, 0, 0, 0, 0); e != 0 {
		t.Fatal(e)
	}
	// A -cover binary's counters go to -test.gocoverdir, else to a
	// directory of its own it then drops: an inherited GOCOVERDIR is
	// handed on, so the child's run counts as this test's.
	cmd := exec.Command(os.Args[0], "-test.run=^TestTheKernelProcessRefusesRoot$", "-test.count=1")
	if d := os.Getenv("GOCOVERDIR"); d != "" {
		cmd.Args = append(cmd.Args, "-test.gocoverdir="+d)
	}
	cmd.Env = append(os.Environ(), "AGENTOS_TEST_ROOT_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child in a user namespace: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "child: run: the kernel never runs as root") {
		t.Fatalf("the kernel process as root: %s", out)
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// checkLogKey refuses a log that is a link, keeps no descriptor to the log,
// and a zero clerk root pins no checker.
func TestCheckLogKeyRefusesALinkAndCheckerPinAZeroRoot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), p); err != nil {
		t.Fatal(err)
	}
	if err := checkLogKey(p, [32]byte{7}); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a log that is a link: %v, want ELOOP", err)
	}
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	for range 3 {
		if err := checkLogKey(b.cfg.Log, [32]byte{7}); err != nil {
			t.Fatal(err)
		}
		if n := openFDsTo(t, b.cfg.Log); n != 1 { // the open kernel's own
			t.Fatalf("%d descriptors to the log, want the kernel's one", n)
		}
	}
	if pin, err := CheckerPin(map[string]KeyClerk{handoff.CheckerName: {}}, &[32]byte{}); err == nil || pin != nil {
		t.Fatalf("a zero clerk root pinned %x, %v", pin, err)
	}
}
